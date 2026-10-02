package httpsec

import (
	"context"
	"net/http"

	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/session"
)

// passkeyCodeBodyLimit is how many body bytes a confirmation endpoint reads:
// a code is a few bytes.
const passkeyCodeBodyLimit int64 = 4 << 10

// confirmSaved confirms that the session's user kept the saved recovery codes
// their pending passkey awaits. The code is read from the "code" field of a
// URL-encoded body and nowhere else; the manager checks it, throttled per
// user, and clears the reason. A confirmation that activates the passkey
// moves a confined session on to its second factor.
func (p *passkeyInterceptor) confirmSaved(ex *Exchange, s *session.Session) error {
	return p.confirm(ex, s, p.deps.Passkeys.ConfirmSavedCode)
}

// confirmEmail redeems the code emailed for the session's user's pending
// passkey. The code is read as confirmSaved reads it; the manager charges an
// attempt before comparing, under the confirmation limiter the registration
// context names, and clears the reason last.
func (p *passkeyInterceptor) confirmEmail(ex *Exchange, s *session.Session) error {
	return p.confirm(ex, s, p.deps.Passkeys.ConfirmEmailCode)
}

// confirmFunc is one of the manager's two confirmations.
type confirmFunc func(
	ctx context.Context, s *session.Session, code string, rc passkey.RegistrationContext,
) (*passkey.Credential, error)

// confirm reads the code, runs the confirmation and answers 204. A code the
// endpoint cannot read is ErrCredentialsMissing and reaches no limiter.
func (p *passkeyInterceptor) confirm(ex *Exchange, s *session.Session, run confirmFunc) error {
	code, err := postedFieldLimited(ex.Request, "code", passkeyCodeBodyLimit)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	activated, err := run(ctx, s, code, p.registrationContext(s))
	if err != nil {
		return err
	}

	if activated != nil {
		if err := p.bound(ctx, s); err != nil {
			return err
		}
	}

	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}
