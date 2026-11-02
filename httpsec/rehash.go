package httpsec

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
)

// RehashFunc stores a password hash upgraded at login.
//
// user is the record the user store reported, replaced is the hash that record
// held, and upgraded is the same password encoded with the chain's current
// encoder. Write upgraded only while replaced is still the stored hash: a login
// that verified the old password can finish after a password change stored a
// new one, and an unconditional write would put the old password back.
// [github.com/kartaladev/scrty/authenticate/password.ConditionalProvisionerRehash]
// is that write for the library's identity stores.
//
// It runs on the request, after the outcome is decided, and its error never
// changes the outcome: it is logged by its Go type, never its text. It must
// not retain replaced or upgraded beyond the call.
type RehashFunc func(ctx context.Context, user *identity.Details, replaced, upgraded []byte) error

// msgRehashFailed is the record a rehash write that failed is reported with.
// It is a constant, and the record carries the error's type and nothing of the
// user, the password or either hash.
const msgRehashFailed = "httpsec: an upgraded password hash could not be stored"

// requestRehash returns ctx asking the password provider to prepare an
// upgraded hash, and the handle it leaves it in, or ctx unchanged and no handle
// when no write is configured: without a write nothing is encoded.
func requestRehash(ctx context.Context, fn RehashFunc) (context.Context, *authenticate.PasswordUpgrade) {
	if fn == nil {
		return ctx, nil
	}

	return authenticate.RequestPasswordUpgrade(ctx)
}

// runRehash hands what the provider prepared to fn, once the request's outcome
// is decided. A write that fails is logged and nothing more.
//
// The client's cancellation is not passed on: the key derivation is spent and
// the password is proved, so a client that hangs up after sending it does not
// cancel the store write.
func runRehash(ctx context.Context, log *slog.Logger, fn RehashFunc, up *authenticate.PasswordUpgrade) {
	if fn == nil || up == nil {
		return
	}

	user, replaced, upgraded, ok := up.Result()
	if !ok {
		return
	}

	if err := fn(context.WithoutCancel(ctx), user, replaced, upgraded); err != nil {
		log.LogAttrs(ctx, slog.LevelError, msgRehashFailed, diag.Failure("rehash-write", err)...)
	}
}
