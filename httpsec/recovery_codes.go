package httpsec

import (
	"net/http"
	"time"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// defaultRegenerationFreshness is how recent a session's latest authentication
// must be for it to regenerate the user's saved codes when the consumer names
// no window.
const defaultRegenerationFreshness = 15 * time.Minute

// RecoveryCodesResponder writes the response to a regeneration: the user's new
// saved codes, shown this once.
//
// With none supplied, the library answers 200 with the JSON document
// {"recovery_codes":[…]}; a consumer replaces that whole response with
// WithRecoveryCodesResponder. The endpoint sets Cache-Control: no-store before
// calling it, since the codes are a lasting credential; a responder may
// replace that header. The set is already replaced when it runs, so a
// responder that drops the codes leaves the user with a set nobody can read.
type RecoveryCodesResponder func(ex *Exchange, codes []string) error

// RecoveryCountResponder writes the response to a count of the user's saved
// codes.
//
// With none supplied, the library answers 200 with the JSON document
// {"remaining":n,"low":bool}; a consumer replaces that whole response with
// WithRecoveryCountResponder.
type RecoveryCountResponder func(ex *Exchange, count recovery.RemainingCodes) error

// WithRecoveryRegenerationFreshness sets how recent a session's latest authentication
// must be for it to regenerate the user's saved codes. Freshness reads the
// session's authentication time (sign-in, satisfied second factor or
// re-authentication), never a renewal, and admits a session exactly at the
// window's end.
//
// Default: 15 minutes. A regeneration mints a lasting credential and is rare,
// so the default asks for a recent login; a consumer who wants a longer window,
// such as two hours, sets it here. A window of zero or less is refused, since
// it would refuse every regeneration.
//
// A session past the window is refreshed by signing in again or, on a chain
// that enables EnableReauthentication, by a re-proof. On a chain with the
// second-factor slot and without re-authentication, signing in again is the
// only way.
func WithRecoveryRegenerationFreshness(d time.Duration) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if d <= 0 {
			return newConfigError("WithRecoveryRegenerationFreshness was given %s; the window must be above "+
				"zero, or no session could ever regenerate its codes", d)
		}

		i.freshness = d

		return nil
	}
}

// WithRecoveryCodesResponder writes the response to a regeneration through fn.
//
// Default: 200 with the JSON document {"recovery_codes":[…]}. Whichever
// responder runs, the endpoint has already set Cache-Control: no-store, which
// fn may replace. A nil responder is refused: a regeneration that wrote
// nothing would replace the user's set with codes nobody can read.
func WithRecoveryCodesResponder(fn RecoveryCodesResponder) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if fn == nil {
			return newConfigError("WithRecoveryCodesResponder was given no responder; omit it to " +
				"keep the default JSON response")
		}

		i.respondCodes = fn

		return nil
	}
}

// WithRecoveryCountResponder writes the response to a count of the user's
// saved codes through fn.
//
// Default: 200 with the JSON document {"remaining":n,"low":bool}. A nil
// responder is refused.
func WithRecoveryCountResponder(fn RecoveryCountResponder) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if fn == nil {
			return newConfigError("WithRecoveryCountResponder was given no responder; omit it to " +
				"keep the default JSON response")
		}

		i.respondCount = fn

		return nil
	}
}

// answersCodes reports whether r is a request the saved-code endpoints answer:
// a GET or a POST on the codes path, while the core enables saved codes.
func (i *recoveryInterceptor) answersCodes(r Request) bool {
	if !i.codesEnabled || r.Path() != i.codesPath {
		return false
	}

	m := r.Method()

	return m == http.MethodGet || m == http.MethodPost
}

// codes answers a request answersCodes accepted. The recovery gate calls it,
// after refusing a recovery-pending session, so only a session with no pending
// recovery ever arrives.
//
// The endpoints answer only a full session, with nothing else outstanding,
// judged by the check re-proof admission and passkey management also make
// (fullSession). A request with no session is ErrAuthenticationRequired. A
// session with any other challenge pending (a second factor, an enrolment, a
// password change), or one the per-request policy phase raised for the
// consumer (Exchange.RaisedChallenge), is passed on, so the gate enforcing
// that challenge refuses it. A session that owes no challenge but is still
// not full (a confinement marker left without its state, or a second-factor
// state outside the named ones, which no library path produces) has no gate
// to pass to, and is ErrAuthenticationRequired. A POST regenerates and a GET
// counts.
func (i *recoveryInterceptor) codes(ex *Exchange, next Next) error {
	s := ex.Session
	if s == nil {
		return ErrAuthenticationRequired
	}

	if owedChallenge(s) != policy.ChallengeNone || ex.RaisedChallenge() != policy.ChallengeNone {
		return next(ex)
	}

	if !fullSession(s) {
		return ErrAuthenticationRequired
	}

	if ex.Request.Method() == http.MethodGet {
		return i.count(ex, s)
	}

	return i.regenerate(ex, s)
}

// regenerate replaces the session user's saved codes, when the session's
// authentication time (sign-in, satisfied second factor or re-authentication)
// is within the window by session.Session.AuthenticatedWithin, through the
// core, which also sends the user the notice. The window's end is inclusive,
// and a session with no recorded authentication time is never within it. A
// renewal is not an authentication and never moves that time. Outside the
// window it is
// recovery.ErrReauthenticationRequired, and nothing changes.
//
// Only a sign-in or a re-proof moves the time, and a re-proof is available
// only when the chain enables EnableReauthentication. Without it there is no
// way to refresh a session in place: a user whose session is stale, on an MFA
// chain or any other, regenerates their codes only after signing in again.
// EnableReauthentication is the remedy.
//
// Cache-Control: no-store is set before the responder runs, since the
// response carries the new codes.
func (i *recoveryInterceptor) regenerate(ex *Exchange, s *session.Session) error {
	if !s.AuthenticatedWithin(i.now(), i.freshness) {
		return recovery.ErrReauthenticationRequired
	}

	codes, err := i.recoverer.Regenerate(ex.Context(), s.UserID)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Cache-Control", "no-store")

	return i.respondCodes(ex, codes)
}

// count reports how many saved codes the session's user holds. It needs no
// recent authentication, since it reveals no secret.
func (i *recoveryInterceptor) count(ex *Exchange, s *session.Session) error {
	n, err := i.deps.Codes.Remaining(ex.Context(), s.UserID)
	if err != nil {
		return err
	}

	return i.respondCount(ex, n)
}

// writeRecoveryCodes is the response a regeneration succeeds with when the
// consumer supplies no responder. It is never cached.
func writeRecoveryCodes(ex *Exchange, codes []string) error {
	ex.Writer.SetHeader("Cache-Control", "no-store")

	return writeSuccessDocument(ex, recoveryCodesDocument{RecoveryCodes: codes})
}

// recoveryCodesDocument is the default regeneration body.
type recoveryCodesDocument struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// writeRecoveryCount is the response a count succeeds with when the consumer
// supplies no responder.
func writeRecoveryCount(ex *Exchange, count recovery.RemainingCodes) error {
	return writeSuccessDocument(ex, recoveryCountDocument{Remaining: count.N, Low: count.Low})
}

// recoveryCountDocument is the default count body.
type recoveryCountDocument struct {
	Remaining int  `json:"remaining"`
	Low       bool `json:"low"`
}
