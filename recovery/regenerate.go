package recovery

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
)

// Regenerate replaces user's saved codes with a new set, returns it, and sends
// the user the Regenerated notice. This is the only time the new codes exist
// in readable form. The caller decides who may regenerate: an HTTP layer, for
// example, asks for a recent authentication first.
//
// The notice goes to the address the contact resolver gives (the default is
// mfa.UsernameAsAddress), is built by the recovery's Messages (the default is
// DefaultMessages) and is queued through its sender, so the consumer's
// configuration of each reaches it. It names the time and carries no code.
//
// A set that cannot be generated or written is returned as an error, the
// previous set standing and nothing sent. Once the set is written it stands: a
// user who cannot be loaded, an address that cannot be resolved and a sender
// that refuses the notice are logged, and the codes are still returned. No log
// record or error carries a code.
//
// Calling it on a recoverer without ProofSaved enabled is a wiring mistake,
// and returns an error wrapping ErrConfig rather than a dedicated sentinel: no
// request can make it succeed, only a different configuration.
func (r *Recoverer) Regenerate(ctx context.Context, user identity.UserID) ([]string, error) {
	if !r.Enabled(ProofSaved) {
		return nil, fmt.Errorf("%w: saved codes are not enabled, so there is no set to regenerate", ErrConfig)
	}

	codes, err := r.codes.Generate(ctx, user)
	if err != nil {
		return nil, err
	}

	now := r.clock.Now()

	details, err := r.users.LoadByUserID(ctx, user)

	switch {
	case err != nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeUserLookupFail, diag.Failure("user-loader", err)...)

		return codes, nil
	case details == nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeUserLookupFail, slog.String("reason", "user-loader-no-details"))

		return codes, nil
	}

	subject, body := r.messages.Regenerated(now)
	r.notify(ctx, details, subject, body)

	return codes, nil
}
