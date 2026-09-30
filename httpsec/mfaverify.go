package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// MFAResult is what a successful second factor produced, handed to whatever
// writes the response.
type MFAResult struct {
	// Token is the access token issued for the rotated session.
	Token string

	// Session is the session, carrying its new handle.
	Session *session.Session
}

// MFAResponder writes the response to a successful second factor.
//
// It is called instead of the downstream handler, because the verify endpoint
// is the library's own and the application has no route behind it. An error it
// returns leaves the chain as the request's refusal.
type MFAResponder func(ex *Exchange, result MFAResult) error

//go:generate mockgen -destination=mfamethod_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/mfa Method
//go:generate mockgen -destination=enrolmentstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/mfa EnrolmentStore

// DefaultMFAVerifyPrefix is the prefix the second-factor endpoint answers POST
// requests under when the consumer names none: each configured method is
// verified at the prefix followed by "/" and the method's name, so TOTP's
// default verify path is "/mfa/verify/totp". It is a constant rather than a
// bare literal so a client, a test or a proxy rule naming the same endpoint
// names the same thing this package does.
const DefaultMFAVerifyPrefix = "/mfa/verify"

// mfaInterceptor is both halves of the second factor: the endpoint a pending
// session resolves its challenge at, and the gate that holds every other
// request that session makes.
type mfaInterceptor struct {
	// methods are the configured methods in the order EnableMFA was given
	// them, byName indexes them by the path segment that names each, and
	// lookups are the same methods as the policies consult them.
	methods []mfa.Method
	byName  map[string]mfa.Method
	lookups []policy.MFAMethodLookup

	sessions *session.Manager
	tokens   token.Generator
	throttle *mfa.VerifyThrottle

	// respond writes the response a successful verification answers with.
	respond MFAResponder

	// throttleOpts are what the consumer's MFA options asked of the throttle.
	// The throttle itself is built once the chain exists, because its logger
	// is the chain's and an option applied after EnableMFA may still replace
	// that.
	throttleOpts []mfa.ThrottleOption

	now func() time.Time

	verifyPrefix string

	// beginPrefix is where a challenge method's pending challenge is issued,
	// beginRespond answers a successful begin, and challengeTTL and
	// challengeStore are what the pending challenges are issued with.
	// challenges holds one manager per challenge method, keyed by name, built
	// at assembly.
	beginPrefix    string
	beginRespond   MFABeginResponder
	challengeTTL   time.Duration
	challengeStore onetime.Store
	challenges     map[string]*onetime.Manager

	// challengeCap is how many challenges begin issues a user for one method
	// within the store's issuance window (WithMFAChallengeLimit), and sweeps
	// spaces each challenge method's sweeps of its expired challenges, keyed
	// by name and built at assembly with the managers.
	challengeCap int
	sweeps       map[string]*sweepClock

	// log and sampler are the chain's, handed over once the chain exists: a
	// sweep that fails is logged through them.
	log     *slog.Logger
	sampler *logsample.Sampler

	// listing is the method-listing endpoint's configuration, and nil while
	// the endpoint is off (WithMFAMethodListing).
	listing *listingConfig

	// logoutPath is handed over at assembly, never configured here.
	logoutPath string
}

// wireMFA hands every registered second factor what only the assembled
// configuration knows.
//
// Two things are settled here rather than by EnableMFA. The throttle, because
// it writes its refusal records through the chain's logger and which logger
// that is is not decided until every option has been applied. And the logout
// path, because the gate exempts it: a consumer who moves logout moves the
// exemption with it, whereas an option on EnableMFA would let them set one and
// not the other and leave the gate exempting a path nothing serves.
func (c *config) wireMFA() error {
	return eachInterceptor(c, func(i *mfaInterceptor) error {
		opts := append([]mfa.ThrottleOption{mfa.WithVerifyLogger(c.logger)}, i.throttleOpts...)

		throttle, err := mfa.NewVerifyThrottle(opts...)
		if err != nil {
			return newConfigError("EnableMFA could not build the verification throttle: %s", err)
		}

		// The endpoint answers every POST under its prefix, so a logout there
		// would be answered as an unknown method and a pending session could
		// never log out.
		if c.logoutPath != "" && underPrefix(c.logoutPath, i.verifyPrefix) {
			return newConfigError("EnableMFA's verify prefix %q claims the logout path %q, so a "+
				"session owing a second factor could not log out", i.verifyPrefix, c.logoutPath)
		}

		if c.logoutPath != "" && underPrefix(c.logoutPath, i.beginPrefix) {
			return newConfigError("EnableMFA's begin prefix %q claims the logout path %q, so a "+
				"session owing a second factor could not log out", i.beginPrefix, c.logoutPath)
		}

		// The listing answers GET on exactly its path, and logout POST on
		// its own, but one path serving both would be a route whose meaning
		// depends on the verb, and a proxy rule naming either would catch the
		// other.
		if i.listing != nil && c.logoutPath != "" && i.listing.path == c.logoutPath {
			return newConfigError("EnableMFA's WithMFAMethodListing path %q is the logout path",
				i.listing.path)
		}

		if err := i.wireChallenges(c); err != nil {
			return err
		}

		i.throttle = throttle
		i.sessions = c.sessions
		i.logoutPath = c.logoutPath

		// The chain's sampler is built after every option has been applied,
		// so it is handed over with the chain.
		c.wire(func(ch *Chain) {
			i.log = ch.logger
			i.sampler = ch.sampler
		})

		return nil
	})
}

// flushRefusalLogs reports what the verification throttle is holding back.
func (i *mfaInterceptor) flushRefusalLogs() {
	if i.throttle != nil {
		_ = i.throttle.FlushRefusalLogs() // documented never to fail
	}
}

// Intercept is every part of the second factor: the verify endpoint and the
// begin endpoint under their prefixes, the method listing when it is on, and
// the gate for everything else.
//
// They are one interceptor rather than several registrations because the
// endpoints are the gate's own exemptions. Split apart, a consumer or a later
// release could order the gate outside the endpoint and leave a pending
// session unable to reach the one request that resolves it.
func (i *mfaInterceptor) Intercept(ex *Exchange, next Next) error {
	if i.isVerifyRequest(ex.Request) {
		return i.verify(ex)
	}

	if i.isBeginRequest(ex.Request) {
		return i.begin(ex)
	}

	if i.isListingRequest(ex.Request) {
		return i.list(ex)
	}

	return i.gate(ex, next)
}

// isVerifyRequest reports whether r is a second-factor submission.
//
// Only POST, and only under the verify prefix: verifying a second factor
// resolves a challenge, which is a change, and one a link could trigger is one
// another site could trigger for a caller who never asked. Every POST under the
// prefix is the endpoint's, including one whose path names no method, so that
// one is refused as unknown rather than passed to the gate or the application.
func (i *mfaInterceptor) isVerifyRequest(r Request) bool {
	return r.Method() == http.MethodPost && underPrefix(r.Path(), i.verifyPrefix)
}

// verify answers a second-factor submission.
//
// The order is deliberate, and each step's placement is a requirement rather
// than a convenience. Steps 1 to 4 are decided from the session and the path
// alone, before the body is read, and none of them is counted against the
// user:
//
//  1. No session, or one carrying no resolved caller: there is nothing to add
//     a second factor to, and nobody to issue the rotated credential to.
//  2. The path names no configured method: ErrUnknownMFAMethod. The method is
//     read from the path and nowhere else.
//  3. The method is on the first factor's channel: mfa.ErrSameChannel. A
//     response that would arrive the way the first factor did is not a second
//     factor. The user has not failed anything, the deployment has.
//  4. The user may not use the method, as policy.UsableMFAMethods decides for
//     the policies too: ErrMFAMethodNotUsable. A lookup that fails is returned
//     behind fixed text, never read as "not enrolled".
//  5. The throttle, before the response is read, so guessing costs attempts
//     rather than time, and a locked-out user learns nothing from a body the
//     endpoint cannot read. It counts per user across every method.
//  6. The response, read the way the method's format declares and never from
//     the URL. A response that cannot be read is ErrCredentialsMissing and one
//     over the method's limit is ErrRequestTooLarge; neither is counted,
//     because none was presented.
//  7. For a challenge method only, the challenge the response answers is
//     checked against the ones issued to this session and spent, whatever
//     happens next. One that is absent, unreadable, unknown, expired, spent
//     or another session's is mfa.ErrInvalidCode, and counted.
//  8. The method verifies it. A wrong response is recorded against the user,
//     and the method's error is returned unchanged, so a consumer sees mfa's
//     own sentinel.
//  9. Success: resolve, rotate, publish, answer.
func (i *mfaInterceptor) verify(ex *Exchange) error {
	s, method, err := i.admit(ex, i.verifyPrefix, anyMethod)
	if err != nil {
		return err
	}

	ctx := ex.Context()
	user := s.UserID

	if err := i.throttle.Check(ctx, user); err != nil {
		return err
	}

	response, err := readResponse(ex.Request, method.Response())
	if err != nil {
		return err
	}

	if cm, ok := method.(mfa.ChallengeMethod); ok {
		if err := i.spendChallenge(ctx, cm, s, response); err != nil {
			i.throttle.RecordFailure(ctx, user)

			return err
		}
	}

	if err := method.Verify(ctx, user, response); err != nil {
		i.throttle.RecordFailure(ctx, user)

		return err
	}

	return i.resolve(ex, s)
}

// spendChallenge checks the challenge a challenge method's response presents
// against those issued to session s, and spends it. Only a nil return lets the
// method verify the response.
//
// Every attempt that presents a live challenge spends it, whether the method
// then accepts the response or not. That departs from check-then-consume as
// the one-time package frames it — where a refusal between the two leaves the
// token redeemable — on purpose: a pending challenge is not a credential the
// user holds and would lose, only the server's nonce for one attempt, and one
// try per challenge is the simpler guarantee to state and to keep. It also
// settles a race: of several attempts presenting one challenge, the store's
// compare-and-set lets exactly one through to Verify.
//
// Every failure is mfa.ErrInvalidCode, the refusal the method itself gives a
// wrong response, so a caller learns only that the answer was not good. That
// includes a store that could not answer: the one-time manager reports its
// store's failures as an invalid token too, and logs them, so this fails
// closed rather than letting an attempt reach the method unspent.
func (i *mfaInterceptor) spendChallenge(
	ctx context.Context,
	cm mfa.ChallengeMethod,
	s *session.Session,
	response []byte,
) error {
	presented, err := cm.PresentedChallenge(response)
	if err != nil || presented == "" {
		return mfa.ErrInvalidCode
	}

	mgr := i.challenges[cm.Name()]

	checked, err := mgr.Check(ctx, presented, s.ID)
	if err != nil {
		return mfa.ErrInvalidCode
	}

	if err := mgr.Consume(ctx, checked); err != nil {
		return mfa.ErrInvalidCode
	}

	return nil
}

// admit makes the refusals the verify and begin endpoints share, steps 1 to 4
// of verify, all decided from the session and the path before the body is
// read, and returns the session and the method the path names under prefix.
// serves reports whether the endpoint serves a configured method at all: a
// path naming one it does not is refused as unknown, like one naming nothing.
func (i *mfaInterceptor) admit(
	ex *Exchange,
	prefix string,
	serves func(mfa.Method) bool,
) (*session.Session, mfa.Method, error) {
	s := ex.Session
	if s == nil {
		return nil, nil, ErrAuthenticationRequired
	}

	// There must also be a resolved caller. The response hands back a
	// credential issued for somebody, and a session whose first factor
	// published no caller names nobody to issue one to — see WithCaller, which
	// is how every built-in first factor publishes both together.
	if ex.Authentication == nil || ex.Authentication.Principal == nil {
		return nil, nil, ErrAuthenticationRequired
	}

	name, ok := methodSegment(ex.Request.Path(), prefix)
	method, known := i.byName[name]
	if !ok || !known || !serves(method) {
		return nil, nil, ErrUnknownMFAMethod
	}

	if err := i.usable(ex.Context(), method, s); err != nil {
		return nil, nil, err
	}

	return s, method, nil
}

// anyMethod is what the verify endpoint serves: every configured method.
func anyMethod(mfa.Method) bool { return true }

// usable refuses a method the session's user may not use as their second
// factor: one on the first factor's own channel, which has no override, and
// one policy.UsableMFAMethods does not report, which is the same decision the
// policies made when they raised the challenge. A lookup that fails is the
// consumer's enrolment store failing: it is returned behind the same fixed
// text a challenge is, with the store's error still reachable through
// errors.Is and errors.As.
func (i *mfaInterceptor) usable(ctx context.Context, method mfa.Method, s *session.Session) error {
	if method.Channel() == s.FirstFactor.Channel() {
		return mfa.ErrSameChannel
	}

	usable, err := policy.UsableMFAMethods(ctx, i.lookups, s.UserID, s.FirstFactor)
	if err != nil {
		return diag.Wrap(err, msgMFAMethodsUnavailable)
	}

	name := method.Name()
	if !slices.ContainsFunc(usable, func(m policy.MFAMethodLookup) bool { return m.Name() == name }) {
		return ErrMFAMethodNotUsable
	}

	return nil
}

// resolve records the second factor and moves the session to a new handle.
//
// The state is set before the rotation, because Rotate writes the session as it
// stands: setting the fields afterwards would persist a challenge that is still
// pending under the new handle. For a session that came through the enrolment
// path, its deadlines are restored before the rotation for the same reason, so
// the new handle carries the deadline a login would have had rather than the
// enrolment-only one.
//
// Everything set here is put back if the restore or the rotation fails, so the
// caller is left exactly as they were found — challenge pending, deadlines and
// enrolment marker as they were, handle unchanged — rather than in memory
// upgraded and in the store not. A session already past its lowered deadline
// is refused as one that has ended, and is not rotated: the restore is what
// finds that, and a rotation after it would move an expired session to a fresh
// handle.
//
// The rotation itself is the point. A handle obtained before the second factor
// must not still answer requests after it, which is session fixation with extra
// steps, and it is why this endpoint answers the request rather than passing it
// on: the handle the caller should now be using is not the one they sent.
//
// A failed rotation or token issue comes back behind fixed text, never the
// store's or the generator's own, with their error still reachable through
// errors.Is and errors.As; the session manager words its store's failures so,
// and the generator's is wrapped here.
func (i *mfaInterceptor) resolve(ex *Exchange, s *session.Session) error {
	was := *s
	rollback := func() {
		s.MFA, s.MFASatisfiedAt = was.MFA, was.MFASatisfiedAt
		s.AbsoluteExpiresAt, s.IdleExpiresAt = was.AbsoluteExpiresAt, was.IdleExpiresAt
		s.EnrolmentOriginDeadline, s.EnrolmentGeneration = was.EnrolmentOriginDeadline, was.EnrolmentGeneration
	}

	s.MFA = session.MFASatisfied
	s.MFASatisfiedAt = i.now()

	if err := i.sessions.RestoreEnrolmentDeadlines(s); err != nil {
		rollback()

		// The session has ended, which to the caller is a session they no
		// longer hold. The manager's own error stays reachable.
		return errors.Join(ErrAuthenticationRequired, err)
	}

	rotated, err := i.sessions.Rotate(ex.Context(), s)
	if err != nil {
		rollback()

		return err
	}

	// Published on the exchange and on the context, so a consumer's error
	// handling and their responder read the handle the caller is to present
	// from now on rather than the one that has just been deleted.
	ex.Session = rotated
	ex.SetContext(withSession(ex.Context(), rotated))

	// Issued after the rotation, against the new identifier. The session
	// identifier is the token's jti, so a token minted before the rotation
	// would name the session that is about to be deleted — which is exactly
	// how completing a second factor came to sign a caller out.
	tok, err := i.tokens.Generate(ex.Context(), rotated.ID, ex.Authentication.Principal)
	if err != nil {
		return diag.Wrap(err, msgTokenNotIssued)
	}

	return i.respond(ex, MFAResult{Token: tok, Session: rotated})
}

// writeMFAResult is the response a second factor succeeds with when the
// consumer supplies no responder.
//
// It writes login.go's document, so a client that can read a login can read
// this, and the empty refresh token field carries the same forward-
// compatibility promise it does there.
func writeMFAResult(ex *Exchange, result MFAResult) error {
	body := loginDocument{AccessToken: result.Token}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	return writeSuccessDocument(ex, body)
}

// gate refuses a request whose session owes a second factor.
//
// A request carrying no session passes: the gate guards sessions, and whether
// an anonymous request may go on is the business of the authentication
// interceptors outside it.
//
// Logout is exempt, which is not obvious. The gate's slot is outside logout's,
// so without this a caller mid-challenge could not end their own session, and
// on a device that is not theirs that is the one thing they most need to do.
// The verify, begin and listing endpoints need no exemption here because they
// never reach this function.
func (i *mfaInterceptor) gate(ex *Exchange, next Next) error {
	s := ex.Session
	if s == nil || s.MFA != session.MFAPending {
		return next(ex)
	}

	if i.isLogoutRequest(ex.Request) {
		return next(ex)
	}

	// No token: the caller already holds the credential this session was
	// reached with, and a gate issues nothing.
	return i.challenge(ex.Context(), s, "")
}

// isLogoutRequest reports whether r is the logout the chain was configured
// with. It is empty when the consumer enabled no logout, and nothing is exempt
// then.
func (i *mfaInterceptor) isLogoutRequest(r Request) bool {
	return i.logoutPath != "" && r.Method() == http.MethodPost && r.Path() == i.logoutPath
}
