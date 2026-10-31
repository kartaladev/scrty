package httpsec

import (
	"github.com/kartaladev/scrty/session"
)

// resolve records a successful re-proof on s and moves it to a new handle.
//
// The authentication time is set from the chain's clock, and for a second
// factor so is the time the second factor was satisfied, before the rotation,
// because Rotate writes the session as it stands. The rotation is the same
// strict one a second factor at login makes, so a handle obtained before the
// re-proof does not answer after it. The rotated session is published on the
// exchange and its context, its credential is issued against the new
// identifier, and the responder answers.
func (i *reauthInterceptor) resolve(ex *Exchange, s *session.Session, secondFactor bool) error {
	now := i.now()

	s.AuthenticatedAt = now
	if secondFactor {
		s.MFA = session.MFASatisfied
		s.MFASatisfiedAt = now
	}

	rotated, err := i.sessions.Rotate(ex.Context(), s)
	if err != nil {
		return rotationRefusal(err)
	}

	ex.Session = rotated
	ex.SetContext(withSession(ex.Context(), rotated))

	tok, err := i.issue(ex.Context(), rotated, ex.Authentication.Principal)
	if err != nil {
		return err
	}

	return i.respond(ex, ReauthenticationResult{Token: tok, Session: rotated})
}
