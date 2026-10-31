package httpsec

import (
	"github.com/kartaladev/scrty/session"
)

// resolve records a successful re-proof on s and moves it to a new handle.
//
// The authentication time is set from the chain's clock, and for a second
// factor the second factor is recorded as satisfied at that time, before the
// rotation, because Rotate writes the session as it stands. A password
// re-proof leaves the second-factor state alone. The enrolment deadlines are
// not restored: only a full session is admitted, and a full session carries
// none to restore.
//
// The rotation is the strict one a second factor at login makes, so a handle
// obtained before the re-proof does not answer after it. When it fails, every
// field set here is put back, so the caller is left exactly as they were
// found, and the failure is refused as rotationRefusal words it: a renewal
// that superseded the session inside its window is ErrSessionRenewalConflict
// (409), and a session no longer held is ErrAuthenticationRequired. A spent
// TOTP step or re-proof challenge stays spent.
//
// The rotated session is published on the exchange and its context, its
// credential is issued against the new identifier in the chain's bearer mode,
// and the responder answers.
func (i *reauthInterceptor) resolve(ex *Exchange, s *session.Session, secondFactor bool) error {
	was := *s
	rollback := func() {
		s.AuthenticatedAt, s.MFA, s.MFASatisfiedAt = was.AuthenticatedAt, was.MFA, was.MFASatisfiedAt
	}

	now := i.now()

	s.AuthenticatedAt = now
	if secondFactor {
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
	// issued before it would name the session the rotation deleted.
	tok, err := i.issue(ex.Context(), rotated, ex.Authentication.Principal)
	if err != nil {
		return err
	}

	return i.respond(ex, ReauthenticationResult{Token: tok, Session: rotated})
}
