package httpsec

import (
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/session"
)

// resolve records a successful re-proof on s and moves it to a new handle.
//
// The authentication time is set from the chain's clock, always: that is what
// freshness is. The second factor is recorded as satisfied at that time, before
// the rotation, because Rotate writes the session as it stands, only when method
// is a second factor whose channel differs from the channel of the session's
// first factor, the test /mfa/verify applies to refuse a same-channel factor.
// A re-proof on the first factor's own channel is not a second factor, so it
// refreshes freshness and leaves the second-factor state and its time alone, as
// does a password re-proof, which passes a nil method. The enrolment deadlines
// are not restored: only a full session is admitted, and a full session carries
// none to restore.
//
// The rotation is the strict one a second factor at login makes, so a handle
// obtained before the re-proof does not answer after it. When it fails, every
// field set here is put back, so the caller is left exactly as they were
// found, and the failure is refused as rotationRefusal words it: a renewal
// that superseded the session inside its window, or a concurrent re-proof or
// second-factor verification of the same session on this server that rotated
// it first, is ErrSessionRenewalConflict (409), and a session no longer held
// is ErrAuthenticationRequired. Across servers sharing a store, the loser of
// such a race may still be refused as no longer holding a session. A spent
// TOTP step or re-proof challenge stays spent.
//
// The rotated session is published on the exchange and its context, its
// credential is issued against the new identifier in the chain's bearer mode,
// and the responder answers.
func (i *reauthInterceptor) resolve(ex *Exchange, s *session.Session, method mfa.Method) error {
	was := *s
	rollback := func() {
		s.AuthenticatedAt, s.MFA, s.MFASatisfiedAt = was.AuthenticatedAt, was.MFA, was.MFASatisfiedAt
	}

	now := i.now()

	s.AuthenticatedAt = now
	if method != nil && method.Channel() != s.FirstFactor.Channel() {
		s.MFA = session.MFASatisfied
		s.MFASatisfiedAt = now
	}

	rotated, err := i.sessions.Rotate(ex.Context(), s)
	if err != nil {
		rollback()

		return rotationRefusal(err)
	}

	ex.Session = rotated
	ex.SetContext(withSession(ex.Context(), rotated))

	// Issued after the rotation, against the new identifier: a credential
	// issued before it would name the session the rotation superseded, marked,
	// for its in-flight window.
	tok, err := i.issue(ex.Context(), rotated, ex.Authentication.Principal)
	if err != nil {
		return err
	}

	return i.respond(ex, ReauthenticationResult{Token: tok, Session: rotated})
}
