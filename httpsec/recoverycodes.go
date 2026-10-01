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
type RecoveryCountResponder func(ex *Exchange, count recovery.Count) error

// WithRegenerationFreshness sets how recent a session's latest authentication
// must be for it to regenerate the user's saved codes. The latest
// authentication is the later of the session's creation and its second
// factor's satisfaction.
//
// Default: 15 minutes. A regeneration mints a lasting credential and is rare,
// so the default asks for a recent login; a consumer who wants a longer window,
// such as two hours, sets it here. A window of zero or less is refused, since
// it would refuse every regeneration.
func WithRegenerationFreshness(d time.Duration) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if d <= 0 {
			return newConfigError("WithRegenerationFreshness was given %s; the window must be above "+
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
// A request with no session is ErrAuthenticationRequired. A session with any
// other challenge pending (a second factor, an enrolment, a password change),
// or one the per-request policy phase raised for the consumer
// (Exchange.RaisedChallenge), is passed on, so the gate enforcing that
// challenge refuses it: the endpoints answer only a full session, with
// nothing else outstanding. A POST regenerates and a GET counts.
func (i *recoveryInterceptor) codes(ex *Exchange, next Next) error {
	s := ex.Session
	if s == nil {
		return ErrAuthenticationRequired
	}

	if challengePending(s) || ex.RaisedChallenge() != policy.ChallengeNone {
		return next(ex)
	}

	if ex.Request.Method() == http.MethodGet {
		return i.count(ex, s)
	}

	return i.regenerate(ex, s)
}

// challengePending reports whether s owes a built-in challenge that a later
// gate enforces. It says nothing about a consumer challenge the per-request
// policy phase raised on this request: codes checks Exchange.RaisedChallenge
// for that separately, since such a challenge is never marked on the session.
func challengePending(s *session.Session) bool {
	switch s.MFA {
	case session.MFAPending, session.MFAEnrolmentPending, session.MFARecoveryPending:
		return true
	case session.MFANone, session.MFASatisfied:
	}

	return s.PasswordChangePending
}

// regenerate replaces the session user's saved codes, when the session's
// latest authentication is within the window, through the core, which also
// sends the user the notice. Outside the window it is
// recovery.ErrReauthenticationRequired, and nothing changes.
//
// Cache-Control: no-store is set before the responder runs, since the
// response carries the new codes.
func (i *recoveryInterceptor) regenerate(ex *Exchange, s *session.Session) error {
	latest := s.CreatedAt
	if s.MFASatisfiedAt.After(latest) {
		latest = s.MFASatisfiedAt
	}

	if i.now().Sub(latest) > i.freshness {
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
func writeRecoveryCount(ex *Exchange, count recovery.Count) error {
	return writeSuccessDocument(ex, recoveryCountDocument{Remaining: count.N, Low: count.Low})
}

// recoveryCountDocument is the default count body.
type recoveryCountDocument struct {
	Remaining int  `json:"remaining"`
	Low       bool `json:"low"`
}
