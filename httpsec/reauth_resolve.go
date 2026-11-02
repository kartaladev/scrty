package httpsec

import (
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/session"
)

// resolve records a successful re-proof on s and moves it to a new handle.
//
// The authentication time is set from the chain's clock, always: that is what
// freshness is. The second factor is recorded as satisfied at that time only
// when method is a second factor whose channel differs from the channel of the
// session's first factor, the test /mfa/verify applies to refuse a
// same-channel factor. A re-proof on the first factor's own channel is not a
// second factor, so it refreshes freshness and leaves the second-factor state
// and its time alone, as does a password re-proof, which passes a nil method.
// The enrolment deadlines are not restored: only a full session is admitted,
// and a full session carries none to restore.
//
// The fields are set on a copy of s, which the rotation carries into the
// successor's creating write, so s itself is never changed: a refusal leaves
// the exchange's session exactly as it was found, with nothing to put back.
//
// The rotation is the strict one a second factor at login makes, so a handle
// obtained before the re-proof does not answer after it. The credential is
// issued in the chain's bearer mode against the successor's identifier inside
// the rotation (session.Sessions.RotateIssuing), before anything is stored. A
// credential that cannot be issued refuses the re-proof with the issuer's
// failure as it is (a generator's behind fixed text, its own error reachable
// through errors.Is), never as a rotation refusal, and leaves nothing stored
// or rotated, so the credential the caller arrived with keeps authenticating.
//
// Any other failed rotation is refused as rotationRefusal words it: a renewal
// that superseded the session inside its window, or a concurrent re-proof or
// second-factor verification of the same session that rotated it first,
// through this server or any other sharing the session store, is
// ErrSessionRenewalConflict (409) inside the winner's in-flight window, and a
// session no longer held is ErrAuthenticationRequired. A spent TOTP step or
// re-proof challenge stays spent.
//
// binding is the key the re-proof's own DPoP proof named (reauthBinding),
// the zero value when it named none. A re-authentication is a fresh proof of
// the user's factor, so it binds an unbound session's successor to it
// (session.WithReauthenticationBinding); a bound session keeps its own.
//
// The rotated session is published on the exchange and its context, and the
// responder answers with it and its credential.
func (i *reauthInterceptor) resolve(ex *Exchange, s *session.Session, method mfa.Method, binding session.KeyBinding) error {
	now := i.now()

	reproved := *s
	reproved.AuthenticatedAt = now
	if method != nil && method.Channel() != s.FirstFactor.Channel() {
		reproved.MFA = session.MFASatisfied
		reproved.MFASatisfiedAt = now
	}

	ctx := ex.Context()
	principal := ex.Authentication.Principal

	// issueErr keeps the issuer's failure apart from the rotation's, so it is
	// returned as the issuer worded it and never read as a session sentinel.
	var issueErr error

	rotated, tok, err := i.sessions.RotateIssuing(ctx, &reproved, func(successor *session.Session) (string, error) {
		tok, err := i.issue(ctx, successor, principal)
		issueErr = err

		return tok, err
	}, reauthRotation(binding)...)
	if issueErr != nil {
		return issueErr
	}
	if err != nil {
		return rotationRefusal(err)
	}

	ex.Session = rotated
	ex.SetContext(withSession(ex.Context(), rotated))

	return i.respond(ex, ReauthenticationResult{Token: tok, Session: rotated, TokenType: tokenTypeOf(rotated)})
}

// reauthBinding is the key a re-proof binds its successor to: the key of the
// DPoP proof the request carries when the session is unbound, verified among
// the re-proof's checks, before anything is spent (issuingBinding). A bound
// session reached here under the DPoP scheme with a proof from its own key,
// which the bearer verified and recorded, so it keeps its binding and nothing
// more is read. The zero value binds nothing.
func reauthBinding(ex *Exchange, s *session.Session) (session.KeyBinding, error) {
	if !s.KeyBinding.IsZero() {
		return session.KeyBinding{}, nil
	}

	return issuingBinding(ex.Context(), ex.dpop(), ex.Request)
}

// reauthRotation is the rotation option binding asks for: none for the zero
// value, which carries the session's own binding over.
func reauthRotation(binding session.KeyBinding) []session.RotateOption {
	if binding.IsZero() {
		return nil
	}

	return []session.RotateOption{session.WithReauthenticationBinding(binding)}
}
