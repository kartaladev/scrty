package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/onetime"
)

// MFAResult is what a successful second factor produced, handed to whatever
// writes the response.
type MFAResult struct {
	// Token is the credential issued for the rotated session: an access
	// token from WithMFATokens, or, with EnableSessionBearer on, the rotated
	// session's own identifier.
	Token string

	// Session is the session, carrying its new handle.
	Session *session.Session

	// TokenType is how Token is presented: TokenTypeDPoP when the session is
	// bound to a DPoP key, TokenTypeBearer otherwise.
	TokenType TokenType
}

// MFAResponder writes the response to a successful second factor.
//
// It is called instead of the downstream handler, because the verify endpoint
// is the library's own and the application has no route behind it. An error it
// returns leaves the chain as the request's refusal.
type MFAResponder func(ex *Exchange, result MFAResult) error

//go:generate mockgen -destination=mfamethod_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate/mfa Method
//go:generate mockgen -destination=enrolmentstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate/mfa EnrolmentStore
//go:generate mockgen -destination=mfamethodlookup_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy MFAMethodLookup

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

	sessions *session.Sessions
	tokens   token.Generator
	throttle *mfa.VerifyThrottle

	// issue issues the rotated session's credential as the chain's bearer
	// mode decides, settled at assembly (wireMFA).
	issue credentialIssuer

	// respond writes the response a successful verification answers with.
	respond MFAResponder

	// throttleOpts are what the consumer's MFA options asked of the throttle.
	// The throttle itself is built once the chain exists, because its logger
	// is the chain's and an option applied after EnableMFA may still replace
	// that.
	throttleOpts []mfa.ThrottleOption

	now func() time.Time

	// verifyPrefix and beginPrefix are where the options placed the endpoints,
	// and where they answer under the base path once resolved.
	verifyPrefix endpointPath

	// beginPrefix is where a challenge method's pending challenge is issued,
	// beginRespond answers a successful begin, and challengeTTL and
	// challengeStore are what the pending challenges are issued with.
	// challenges holds one manager per challenge method, keyed by name, built
	// at assembly.
	beginPrefix    endpointPath
	beginRespond   MFABeginResponder
	challengeTTL   time.Duration
	challengeStore onetime.Store
	challenges     map[string]*onetime.Tokens

	// challengeStoreGiven records that WithMFAChallengeStore was given, because
	// the slot may default its store later and re-authentication has to know
	// whether the consumer chose one.
	challengeStoreGiven bool

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
		// The chain's factory first, so a limiter the consumer gave the flow
		// (WithMFAVerifyLimiter) wins and the factory is never asked. It is
		// handed over only when the consumer configured one: without it the
		// throttle builds its own in-memory default on the chain's logger and
		// clock. The clock also times the sampling of the throttle's refusal
		// records; a limiter the consumer gave keeps its own.
		opts := []mfa.ThrottleOption{mfa.WithThrottleLogger(c.logger), mfa.WithThrottleClock(c.clock)}
		if c.limiterFactory != nil {
			opts = append(opts, mfa.WithThrottleLimiterFactory(c.limiterFactory))
		}

		opts = append(opts, i.throttleOpts...)

		throttle, err := mfa.NewVerifyThrottle(opts...)
		if err != nil {
			return newConfigError("EnableMFA could not build the verification throttle: %s", err)
		}

		if err := i.wireChallenges(c); err != nil {
			return err
		}

		i.throttle = throttle
		i.sessions = c.sessions
		i.issue = c.credentialIssuer(i.tokens)
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
func (i *mfaInterceptor) flushRefusalLogs() error {
	if i.throttle != nil {
		return i.throttle.FlushRefusalLogs()
	}

	return nil
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
	return r.Method() == http.MethodPost && underPrefix(r.Path(), i.verifyPrefix.at())
}

// verify answers a second-factor submission.
//
// The order is deliberate, and each step's placement is a requirement rather
// than a convenience. Steps 1 to 4 are decided from the session and the path
// alone, before the body is read, and none of them is counted against the
// user:
//
//  1. No session, or one carrying no resolved caller: there is nothing to add
//     a second factor to, and nobody to issue the rotated credential to. A
//     session that is not pending, whether it already satisfied its second
//     factor or none was ever asked of it, is refused with
//     ErrNoMFAChallengePending: the endpoint serves only a pending session,
//     and re-proving a signed-in one belongs to re-authentication (/reauth),
//     not here. Nothing is counted or changed. A caller who is not the
//     session's user, because a consumer interceptor past the first factor
//     published another principal, is refused with ErrAuthenticationRequired
//     once steps 2 to 4 have passed and before the throttle
//     (requireSessionUser): nothing is counted, verified or judged for the
//     substituted principal, and the session stays pending.
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
//     endpoint cannot read. It counts per user across every method. Before
//     it, a DPoP proof the request carries beside the Bearer credential of an
//     unbound or certificate-bound session is verified and recorded
//     (continuingProof): a refused one
//     is ErrInvalidDPoPProof, counted nowhere and spending no challenge.
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
//     own sentinel. A refusal wrapping mfa.ErrAuthenticatorRefused, of the
//     authenticator rather than its response, is returned unchanged too but
//     not recorded: it is not a guess. So is a refusal matching
//     mfa.ErrVerifyThrottled, such as a refused attempt charge: nothing was
//     compared, so nothing is recorded.
//  9. The post-authentication phase is judged again with the login's input
//     for the session, the second factor satisfied (behindSecondFactor), so a
//     challenge or a deny the second-factor challenge hid at login is not
//     lost. A deny refuses with the policy's reason, and a kind nothing
//     enforces as a configuration error, leaving the session pending and
//     counting nothing.
//  10. Success: resolve, rotate, publish, answer. A challenge step 9 raised
//     is marked on the rotated session before its credential is issued, and
//     answered as a login answers one: a *ChallengeError carrying the rotated
//     session and its credential.
func (i *mfaInterceptor) verify(ex *Exchange) error {
	s, method, err := i.admit(ex, i.verifyPrefix.at(), anyMethod)
	if err != nil {
		return err
	}

	// Step 1's last refusal: admit refused a session whose first factor
	// published no caller, and this one a caller who is not its user.
	if err := requireSessionUser(ex, s); err != nil {
		return err
	}

	// A proof given beside the session's credential, before the throttle
	// counts anything or a challenge is spent.
	if err := continuingProof(ex, s); err != nil {
		return err
	}

	// Steps 5 to 8.
	if err := checkResponse(ex, i.throttle, i.challenges, method, s, event.MFAVerifyFail); err != nil {
		return err
	}

	// Step 9.
	raised, err := i.behindSecondFactor(ex, s)
	if err != nil {
		return err
	}

	return i.resolve(ex, s, raised)
}

// continuingProof verifies the DPoP proof a request continuing the sign-in s
// carries, at an endpoint that issues a credential for a sign-in already
// created (second-factor verification, session renewal and
// re-authentication) and so adds no binding: the sign-in keeps the one it was
// created with.
//
// A DPoP-bound sign-in reaches here only under the DPoP scheme, with a proof
// from its own key that the bearer verified and recorded, so nothing more is
// read. Any other sign-in is presented under the Bearer scheme, whose
// credential the bearer judges without a proof: an unbound one, and one bound
// to a certificate, whose binding stays the certificate. A proof the request
// carries beside such a credential is verified here, and its jti recorded,
// before the endpoint spends anything. Its ath is judged against the
// credential the chain's bearer authenticated (Exchange.RecordPresentedToken),
// as RFC 9449 section 4.2 requires of a proof used with an access token: it
// must hash that credential, under whatever scheme the bearer read it, and be
// absent when no bearer authenticated one, as for a sign-in carried by a
// cookie. A refusal is ErrInvalidDPoPProof.
//
// A request carrying no proof, and a chain without DPoP, check nothing: the
// sign-in's binding rules are the bearer's, unchanged.
func continuingProof(ex *Exchange, s *session.Session) error {
	v := ex.dpop()
	if v == nil || s.KeyBinding.JKT != "" || len(ex.Request.HeaderValues(dpopHeader)) == 0 {
		return nil
	}

	ctx := ex.Context()

	p, err := v.verify(ctx, ex.Request, ex.bearerCredential)
	if err != nil {
		return err
	}

	return v.record(ctx, p)
}

// behindSecondFactor judges the post-authentication phase again for s, whose
// second factor has just been verified, and returns the challenge it then
// raises, policy.ChallengeNone when it raises none.
//
// A login that left s pending judged the phase once, and the engine returned
// its first challenge only: the second factor's, with every challenge
// registered after it hidden behind it. So the phase is judged again with the
// login's input for the session's user and first factor (sessionLoginInput),
// at the chain's now, saying the request has satisfied a second factor
// (policy.Input.MFASatisfied), which it has, and that the session already
// exists (policy.Input.Reauthenticating): it is counted among the user's, and
// verification adds none. A policy.ChallengeMFA is then dropped, the factor
// being the one just presented (judgeBehindSecondFactor).
//
// It judges every pending session the endpoint serves alike, whatever left it
// pending: a login's challenge, a challenge the per-request phase marked, or
// an enrolment or a recovery binding that moved it on to verification. Each
// is judged as a login of its user on its first factor would be judged now,
// as a second-factor re-proof is.
//
// A deny refuses with the policy's reason. A challenge of a kind nothing on the
// chain enforces refuses as at login (refuseUnenforced). Either refusal comes
// before anything is satisfied, rotated or stored, so the session stays
// pending under the credential the caller arrived with; the verified code is
// not counted, being valid. With no engine on the chain the phase allows.
func (i *mfaInterceptor) behindSecondFactor(ex *Exchange, s *session.Session) (policy.ChallengeKind, error) {
	ph := ex.perRequest
	if ph == nil {
		return policy.ChallengeNone, nil
	}

	in := sessionLoginInput(ex.Authentication, s, i.now())
	in.MFASatisfied = true

	ctx := ex.Context()
	d := judgeBehindSecondFactor(ctx, ph.engine, in, evaluatePhase(ctx, ph.engine, policy.PostAuthentication, in))

	switch d.Outcome {
	case policy.Deny:
		return policy.ChallengeNone, policyDenyReason(d)
	case policy.Challenge:
		if err := refuseUnenforced(ph.enforced, d.Challenge); err != nil {
			return policy.ChallengeNone, err
		}

		return d.Challenge, nil
	case policy.Allow:
	}

	return policy.ChallengeNone, nil
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

	if err := requirePending(s); err != nil {
		return nil, nil, err
	}

	name, ok := oneSegmentBelow(ex.Request.Path(), prefix)
	method, known := i.byName[name]
	if !ok || !known || !serves(method) {
		return nil, nil, ErrUnknownMFAMethod
	}

	if err := i.usable(ex.Context(), method, s); err != nil {
		return nil, nil, err
	}

	return s, method, nil
}

// requirePending refuses a session that owes no second factor with
// ErrNoMFAChallengePending: one already satisfied, or one no challenge was ever
// raised on, such as the session of a user enrolled after signing in. Both
// endpoints serve only a pending session, so neither can move a signed-in
// session through the second factor again, and a session's authentication time
// is never refreshed by a code. Proving a signed-in session afresh is
// re-authentication's business. The refusal reads nothing, counts nothing and
// issues nothing.
func requirePending(s *session.Session) error {
	if s.MFA != session.MFAPending {
		return ErrNoMFAChallengePending
	}

	return nil
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
// The state is set before the rotation, because the rotation writes the
// session as it stands: setting the fields afterwards would persist a
// challenge that is still pending under the new handle. For a session that
// came through the enrolment path, its deadlines are restored before the
// rotation for the same reason, so the new handle carries the deadline a login
// would have had rather than the enrolment-only one.
//
// All of it is set on a copy of s, never on s itself, so a refusal at any step
// leaves the caller exactly as they were found — challenge pending, deadlines
// and enrolment marker as they were, handle unchanged — with nothing to put
// back, rather than in memory upgraded and in the store not. A session already
// past its lowered deadline is refused as one that has ended, and is not
// rotated: the restore is what finds that, and a rotation after it would move
// an expired session to a fresh handle.
//
// The rotation itself is the point. A handle obtained before the second factor
// must not still answer requests after it, which is session fixation with extra
// steps, and it is why this endpoint answers the request rather than passing it
// on: the handle the caller should now be using is not the one they sent.
//
// The credential is issued against the successor's identifier inside the
// rotation (session.Sessions.RotateIssuing), before anything is stored. A
// signed token names its session through its jti, and a session reference is
// the identifier itself, so it must name the successor; and issuing it before
// the store is written means a credential that cannot be issued refuses the
// verification with nothing stored or rotated, leaving the session pending
// under the credential the caller arrived with, rather than signing them out.
//
// A failed rotation is refused as rotationRefusal words it: a lost race with a
// concurrent verification, re-proof or renewal of the session, through this
// server or any other sharing the session store, is ErrSessionRenewalConflict
// (409) inside the winner's in-flight window. A failed rotation or token issue
// comes back behind fixed text, never the store's or the generator's own, with
// their error still reachable through errors.Is and errors.As; the session
// manager words its store's failures so, and the generator's is wrapped by the
// chain's credential issuer.
//
// raised is a challenge the post-authentication phase raised behind the second
// factor (behindSecondFactor), policy.ChallengeNone for none, already checked
// to be one the chain enforces. It is completed as a login completes one: the
// second factor is satisfied and the session rotated as on success, the
// challenge is marked on the copy the successor is built from, so it is
// stored in the successor's creating write before the credential is issued,
// and verification is refused with a *ChallengeError of that kind carrying the
// rotated session and its credential, published on the exchange, rather than
// answered through the responder.
func (i *mfaInterceptor) resolve(ex *Exchange, s *session.Session, raised policy.ChallengeKind) error {
	satisfied := *s

	satisfied.MFA = session.MFASatisfied
	// Satisfying the second factor is an authentication, so it refreshes the
	// time freshness checks read. The rotation below carries both into the
	// successor's creating write.
	satisfied.MFASatisfiedAt = i.now()
	satisfied.AuthenticatedAt = satisfied.MFASatisfiedAt

	if err := i.sessions.RestoreEnrolmentDeadlines(&satisfied); err != nil {
		// The session has ended, which to the caller is a session they no
		// longer hold. The manager's own error stays reachable.
		return errors.Join(ErrAuthenticationRequired, err)
	}

	// A challenge the phase raised behind the second factor is marked before
	// the rotation, on the copy the successor is built from, so the
	// successor's creating write already carries it and the credential issued
	// for the successor is never one for a session whose mark did not persist,
	// as at login. A kind no gate reads marks nothing.
	if raised != policy.ChallengeNone {
		marker := challengeMarker{sessions: i.sessions}
		if ex.perRequest != nil {
			marker.enrolmentLifetime = ex.perRequest.enrolmentLifetime
		}

		marker.mark(&satisfied, raised)
	}

	ctx := ex.Context()
	principal := ex.Authentication.Principal

	// issueErr keeps the issuer's failure apart from the rotation's, so it is
	// returned as the issuer worded it and never read as a session sentinel.
	var issueErr error

	rotated, tok, err := i.sessions.RotateIssuing(ctx, &satisfied, func(successor *session.Session) (string, error) {
		tok, err := i.issue(ctx, successor, principal)
		issueErr = err

		return tok, err
	})
	if issueErr != nil {
		return issueErr
	}
	if err != nil {
		return rotationRefusal(err)
	}

	// The rotated session is stored, and its credential is handed out below,
	// with the challenge error when one is still raised.
	emitEvent(ctx, sessionEvent(event.MFAVerified, event.OutcomeSuccess, rotated))
	emitEvent(ctx, sessionEvent(event.SessionRenewed, event.OutcomeSuccess, rotated))

	// Published on the exchange and on the context, so a consumer's error
	// handling and their responder read the handle the caller is to present
	// from now on rather than the one the rotation has just superseded.
	ex.Session = rotated
	ex.SetContext(withSession(ex.Context(), rotated))

	// A challenge is answered as a login answers one: refused with it,
	// carrying the rotated session and its credential for the consumer's
	// prompt, and never through the success responder.
	if raised != policy.ChallengeNone {
		return &ChallengeError{Kind: raised, Session: rotated, Token: tok}
	}

	return i.respond(ex, MFAResult{Token: tok, Session: rotated, TokenType: tokenTypeOf(rotated)})
}

// rotationRefusal is what a failed strict rotation is refused with at the
// endpoint. A session a concurrent renewal superseded inside its window is a
// lost race, and so is one a concurrent strict rotation rotated away first
// (two valid codes, or two re-proofs, from one session at once), through this
// server or any other manager sharing the session store: the store keeps the
// rotated row, marked, for the winner's in-flight window, so the loser finds
// the evidence wherever it runs. Both are refused with
// ErrSessionRenewalConflict (409) so the client carries on with the credential
// the winner was handed. One presented after the window has ended, as reuse or
// as needing renewal, and one that has vanished from the store since the
// endpoint loaded it (its family revoked meanwhile, or its rotated row swept
// after the window), are sessions the caller no longer holds, refused with
// ErrAuthenticationRequired (401); the manager's error stays reachable, so
// reuse remains identifiable. Anything else, a store failure, comes back as
// the manager worded it.
func rotationRefusal(err error) error {
	switch {
	case errors.Is(err, session.ErrRenewalConflict):
		return ErrSessionRenewalConflict
	case errors.Is(err, session.ErrExpired), errors.Is(err, session.ErrNotFound):
		return errors.Join(ErrAuthenticationRequired, err)
	default:
		return err
	}
}

// writeMFAResult is the response a second factor succeeds with when the
// consumer supplies no responder.
//
// It writes login.go's document, so a client that can read a login can read
// this, and the empty refresh token field carries the same forward-
// compatibility promise it does there.
func writeMFAResult(ex *Exchange, result MFAResult) error {
	body := loginDocument{AccessToken: result.Token, TokenType: result.TokenType}
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

// msgMFAMethodsUnavailable is the fixed text a second-factor challenge is
// replaced with when the methods it would offer could not be looked up. The
// failure is the consumer's enrolment store's, and its own text stays out.
const msgMFAMethodsUnavailable = "httpsec: the usable MFA methods could not be looked up"

// challenge is the second-factor challenge the gate refuses s with: the
// challenge on s, carrying token when one was issued with it, and the methods
// s's user can answer it with. A login that raises one builds the same
// challenge from the same methods (usableMethods), looked up before its
// session is created.
//
// The methods are decided by policy.UsableMFAMethods over the same lookups the
// policies were built from, so the challenge never offers a method the verify
// endpoint would refuse as not usable. A lookup that fails replaces the
// challenge with that failure, behind fixed text: a partial list would hide a
// method the user holds, and an empty one would read as "nothing left".
func (i *mfaInterceptor) challenge(ctx context.Context, s *session.Session, token string) error {
	methods, err := i.usableMethods(ctx, s.UserID, s.FirstFactor)
	if err != nil {
		return err
	}

	return &ChallengeError{Kind: policy.ChallengeMFA, Session: s, Token: token, Methods: methods}
}

// usableMethods is the methods a second-factor challenge to user, whose first
// factor was first, offers. A lookup that fails is returned behind fixed text.
func (i *mfaInterceptor) usableMethods(
	ctx context.Context,
	user identity.UserID,
	first factor.Kind,
) ([]MFAMethod, error) {
	usable, err := policy.UsableMFAMethods(ctx, i.lookups, user, first)
	if err != nil {
		return nil, diag.Wrap(err, msgMFAMethodsUnavailable)
	}

	methods := make([]MFAMethod, 0, len(usable))
	for _, l := range usable {
		methods = append(methods, MFAMethod{
			Name:    l.Name(),
			Channel: l.Channel(),
			Begins:  isChallengeMethod(i.byName[l.Name()]),
		})
	}

	return methods, nil
}

// challengeMethodsFunc looks up the methods a raised challenge of kind offers
// user, whose first factor was first. A login calls it before it creates the
// session, so a lookup that fails leaves no session behind.
type challengeMethodsFunc func(
	ctx context.Context,
	kind policy.ChallengeKind,
	user identity.UserID,
	first factor.Kind,
) ([]MFAMethod, error)

// challengeMethods is the chain's challengeMethodsFunc. A second-factor
// challenge offers the methods the MFA interceptor finds usable; every other
// kind offers none. A second-factor challenge on a chain with no MFA
// interceptor is refused at assembly as unenforced, except through a test
// gate, which gets the bare challenge.
func (c *Chain) challengeMethods(
	ctx context.Context,
	kind policy.ChallengeKind,
	user identity.UserID,
	first factor.Kind,
) ([]MFAMethod, error) {
	if kind == policy.ChallengeMFA && c.mfa != nil {
		return c.mfa.usableMethods(ctx, user, first)
	}

	return nil, nil
}

// mfaOf is the chain's MFA interceptor, or nil when EnableMFA was not given.
func (c *config) mfaOf() *mfaInterceptor {
	var found *mfaInterceptor

	_ = eachInterceptor(c, func(i *mfaInterceptor) error {
		found = i

		return nil
	})

	return found
}

// DefaultMFAMethodListingPath is the path the method-listing endpoint answers
// GET requests on when the consumer names none. The endpoint is off unless
// WithMFAMethodListing is given.
const DefaultMFAMethodListingPath = "/mfa/methods"

// MFAListingResponder writes the response to a method listing. methods are the
// methods the session's user can use, in the order EnableMFA was given them:
// the same list, from the same decision, an MFA ChallengeError carries.
//
// It is called instead of the downstream handler, because the listing
// endpoint is the library's own. An error it returns leaves the chain as the
// request's refusal.
type MFAListingResponder func(ex *Exchange, methods []MFAMethod) error

// listingConfig is the method-listing endpoint's configuration. It is
// unexported, so its settings can be written only through the ListingSetting
// values WithMFAMethodListing applies, and nowhere else.
type listingConfig struct {
	// path is where the options placed the endpoint, whether the consumer set
	// it, and where it answers under the base path once resolved.
	path    endpointPath
	respond MFAListingResponder
}

// ListingSetting configures the method-listing endpoint. Each replaces one of
// the defaults named on WithMFAMethodListing, and only WithMFAMethodListing
// applies one.
type ListingSetting func(*listingConfig) error

// ListingPath answers the listing on path instead.
//
// Default: DefaultMFAMethodListingPath, "/mfa/methods". The path is within the
// base path (WithBasePath). Only GET on exactly path is the listing. An empty
// path is refused rather than read as the default, and so is one that does not
// start with "/", which matches no request path. New also refuses a path the
// chain's logout answers, or one that is exactly the MFA verify or begin
// prefix, since each of those endpoints claims its path. A path under either
// prefix builds: the listing answers GET only, and the prefix endpoint passes
// other methods on.
func ListingPath(path string) ListingSetting {
	return func(l *listingConfig) error {
		if err := checkEndpointPath("ListingPath", path); err != nil {
			return err
		}

		l.path.give("WithMFAMethodListing", path)

		return nil
	}
}

// ListingResponder writes the listing with fn instead.
//
// Default: a 200 JSON document,
// {"methods":[{"name":…,"channel":…,"begins":…}]}, which no cache may keep.
// "begins" is true for a method with a begin step. An absent fn is refused
// rather than read as the default.
func ListingResponder(fn MFAListingResponder) ListingSetting {
	return func(l *listingConfig) error {
		if fn == nil {
			return newConfigError("ListingResponder was given no function; omit the setting " +
				"to keep the default document")
		}

		l.respond = fn

		return nil
	}
}

// WithMFAMethodListing turns on the method-listing endpoint, which the
// endpoint is off without: a GET a session owing a second factor sends to
// learn which methods its user can answer with.
//
// It answers only GET on its exact path, and never reads the URL query or the
// body: the session decides whose methods are listed. A request with no
// session is refused with ErrAuthenticationRequired, and a session that owes
// no second factor, a fully authenticated one included, with
// ErrNoMFAChallengePending (403). An enrolment-only session never reaches it:
// the enrolment gate refuses it first, like any other route. The MFA gate
// lets the listing through for a session that owes a second factor.
//
// The list is decided by policy.UsableMFAMethods over the methods EnableMFA
// was given, which is the decision the policies and the MFA challenge make,
// so the three never disagree. A lookup that fails is a refusal behind fixed
// text, with the lookup's error reachable through errors.Is and errors.As,
// and never a shorter or empty list. The lookups succeeding with nothing
// usable is an empty list.
//
// Defaults, each replaced by the setting named: the path is
// DefaultMFAMethodListingPath (ListingPath), and the response the JSON
// document ListingResponder describes (ListingResponder). A setting is
// written only here; an explicitly empty path or absent responder is refused.
func WithMFAMethodListing(settings ...ListingSetting) MFAOption {
	return func(i *mfaInterceptor) error {
		l := &listingConfig{path: defaultPath(DefaultMFAMethodListingPath), respond: writeMethodListing}

		for _, set := range settings {
			if set == nil {
				continue
			}
			if err := set(l); err != nil {
				return err
			}
		}

		// The last WithMFAMethodListing is the one that applies: it replaces the
		// whole listing, so a path an earlier call set is neither judged nor
		// answered at.
		i.listing = l

		return nil
	}
}

// resolvePaths places the verify and begin endpoints and the listing under
// base, from the paths the options declared.
func (i *mfaInterceptor) resolvePaths(base string) {
	i.verifyPrefix.resolve(base)
	i.beginPrefix.resolve(base)

	if i.listing != nil {
		i.listing.path.resolve(base)
	}
}

// declaredPaths reports the verify and begin prefixes and the listing path the
// consumer set. The listing's is that of the last WithMFAMethodListing, which
// replaced every earlier one.
func (i *mfaInterceptor) declaredPaths() []declaredPath {
	paths := []endpointPath{i.verifyPrefix, i.beginPrefix}
	if i.listing != nil {
		paths = append(paths, i.listing.path)
	}

	return declarations(paths...)
}

// isListingRequest reports whether r asks for the method listing: the
// listing is on, and r is a GET on exactly its path. Any other method passes
// on to the gate and the application, as a GET to a verify path does.
func (i *mfaInterceptor) isListingRequest(r Request) bool {
	return i.listing != nil && r.Method() == http.MethodGet && r.Path() == i.listing.path.at()
}

// list answers the method listing for the session's user.
func (i *mfaInterceptor) list(ex *Exchange) error {
	s := ex.Session
	if s == nil {
		return ErrAuthenticationRequired
	}

	if s.MFA != session.MFAPending {
		return ErrNoMFAChallengePending
	}

	methods, err := i.usableMethods(ex.Context(), s.UserID, s.FirstFactor)
	if err != nil {
		return err
	}

	return i.listing.respond(ex, methods)
}

// methodListingDocument is the default body of both method listings, the MFA
// slot's and re-authentication's. Its member names are the documented
// contract of the endpoints. Password is re-authentication's own member: nil,
// and so absent, in the MFA listing.
type methodListingDocument struct {
	Methods  []methodListingEntry `json:"methods"`
	Password *bool                `json:"password,omitempty"`
}

type methodListingEntry struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
	Begins  bool   `json:"begins"`
}

// writeMethodListing is the listing's response when the consumer supplies no
// responder: 200, the methods as JSON, {"methods":[{"name":…,"channel":…,
// "begins":…}]}, written by writeMethodsDocument.
func writeMethodListing(ex *Exchange, methods []MFAMethod) error {
	return writeMethodsDocument(ex, methods, nil)
}

// writeMethodsDocument is the one writer of a default method listing, shared
// by the MFA listing and the re-authentication listing so the two cannot
// drift: 200 and a JSON document of methods, an empty list as [] rather than
// null, marked Cache-Control: no-store because it describes the user's
// factors. password is the re-authentication listing's extra member, written
// when it is non-nil and left out when it is nil.
func writeMethodsDocument(ex *Exchange, methods []MFAMethod, password *bool) error {
	doc := methodListingDocument{Methods: make([]methodListingEntry, 0, len(methods)), Password: password}
	for _, m := range methods {
		doc.Methods = append(doc.Methods, methodListingEntry{
			Name:    m.Name,
			Channel: string(m.Channel),
			Begins:  m.Begins,
		})
	}

	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(body)

	return err
}

// endpoints declares the begin and verify steps, each answering every POST
// under its prefix, and the method listing when it is on.
func (i *mfaInterceptor) endpoints() []Endpoint {
	const feature = "EnableMFA"

	eps := []Endpoint{
		declare(feature, "WithMFABeginPrefix", OperationMFAChallenge, withSegment(i.beginPrefix.at(), "method"),
			MatchSubtree, OtherMethodsPassThrough, RequiresPendingSecondFactor, http.MethodPost),
		declare(feature, "WithMFAVerifyPrefix", OperationMFAVerify, withSegment(i.verifyPrefix.at(), "method"),
			MatchSubtree, OtherMethodsPassThrough, RequiresPendingSecondFactor, http.MethodPost),
	}

	if i.listing != nil {
		eps = append(eps, declare(feature, "WithMFAMethodListing", OperationMFAMethods, i.listing.path.at(),
			MatchExact, OtherMethodsPassThrough, RequiresPendingSecondFactor, http.MethodGet))
	}

	return eps
}
