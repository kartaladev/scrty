package httpsec

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/mfa"
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

		i.throttle = throttle
		i.sessions = c.sessions
		i.logoutPath = c.logoutPath

		return nil
	})
}

// flushRefusalLogs reports what the verification throttle is holding back.
func (i *mfaInterceptor) flushRefusalLogs() {
	if i.throttle != nil {
		_ = i.throttle.FlushRefusalLogs() // documented never to fail
	}
}

// Intercept is both halves of the second factor: the verify endpoint on its
// own path, and the gate for everything else.
//
// They are one interceptor rather than two registrations because the endpoint
// is the gate's own exemption. Split apart, a consumer or a later release could
// order the gate outside the endpoint and leave a pending session unable to
// reach the one request that resolves it.
func (i *mfaInterceptor) Intercept(ex *Exchange, next Next) error {
	if i.isVerifyRequest(ex.Request) {
		return i.verify(ex)
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
//     as it is, never read as "not enrolled".
//  5. The throttle, before the response is read, so guessing costs attempts
//     rather than time, and a locked-out user learns nothing from a body the
//     endpoint cannot read. It counts per user across every method.
//  6. The response, read the way the method's format declares and never from
//     the URL. A response that cannot be read is ErrCredentialsMissing and one
//     over the method's limit is ErrRequestTooLarge; neither is counted,
//     because none was presented.
//  7. The method verifies it. A wrong response is recorded against the user,
//     and the method's error is returned unchanged, so a consumer sees mfa's
//     own sentinel.
//  8. Success: resolve, rotate, publish, answer.
func (i *mfaInterceptor) verify(ex *Exchange) error {
	s := ex.Session
	if s == nil {
		return ErrAuthenticationRequired
	}

	// There must also be a resolved caller. The response hands back a
	// credential issued for somebody, and a session whose first factor
	// published no caller names nobody to issue one to — see WithCaller, which
	// is how every built-in first factor publishes both together.
	if ex.Authentication == nil || ex.Authentication.Principal == nil {
		return ErrAuthenticationRequired
	}

	name, ok := methodSegment(ex.Request.Path(), i.verifyPrefix)
	method, known := i.byName[name]
	if !ok || !known {
		return ErrUnknownMFAMethod
	}

	ctx := ex.Context()
	user := s.UserID

	if err := i.usable(ctx, method, s); err != nil {
		return err
	}

	if err := i.throttle.Check(ctx, user); err != nil {
		return err
	}

	response, err := readResponse(ex.Request, method.Response())
	if err != nil {
		return err
	}

	if err := method.Verify(ctx, user, response); err != nil {
		i.throttle.RecordFailure(ctx, user)

		return err
	}

	return i.resolve(ex, s)
}

// usable refuses a method the session's user may not use as their second
// factor: one on the first factor's own channel, which has no override, and
// one policy.UsableMFAMethods does not report, which is the same decision the
// policies made when they raised the challenge. A lookup error is returned
// unchanged.
func (i *mfaInterceptor) usable(ctx context.Context, method mfa.Method, s *session.Session) error {
	if method.Channel() == s.FirstFactor.Channel() {
		return mfa.ErrSameChannel
	}

	usable, err := policy.UsableMFAMethods(ctx, i.lookups, s.UserID, s.FirstFactor)
	if err != nil {
		return err
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
// The verify endpoint needs no exemption here because it never reaches this
// function.
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
	return &ChallengeError{Kind: policy.ChallengeMFA, Session: s}
}

// isLogoutRequest reports whether r is the logout the chain was configured
// with. It is empty when the consumer enabled no logout, and nothing is exempt
// then.
func (i *mfaInterceptor) isLogoutRequest(r Request) bool {
	return i.logoutPath != "" && r.Method() == http.MethodPost && r.Path() == i.logoutPath
}
