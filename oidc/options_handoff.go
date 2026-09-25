package oidc

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

// HandoffOption customises a HandoffManager at construction.
//
// Every option replaces a default that already works. An option given nil
// fails construction with ErrConfig rather than silently keeping the default:
// a consumer who passed one meant to replace it. A nil option is ignored.
//
// There is deliberately no option for the code's lifetime; see HandoffTTL.
type HandoffOption func(*HandoffManager) error

// WithHandoffRandom replaces the source the token id and the secret of every
// code are drawn from. The default is crypto/rand.Reader. A nil reader,
// including a nil pointer inside a non-nil interface, is refused.
//
// It exists so a test can fix or fail the source; production code has no
// reason to replace it, and a source that is not cryptographically secure
// makes every code guessable.
func WithHandoffRandom(r io.Reader) HandoffOption {
	return func(h *HandoffManager) error {
		if nilcheck.IsNil(r) {
			return fmt.Errorf("%w: WithHandoffRandom was given nil", ErrConfig)
		}
		h.random = r
		return nil
	}
}

// WithHandoffClock replaces the clock issuance stamps and redemption judges
// expiry and consumption by. The default is time.Now.
func WithHandoffClock(now func() time.Time) HandoffOption {
	return func(h *HandoffManager) error {
		if now == nil {
			return fmt.Errorf("%w: WithHandoffClock was given nil", ErrConfig)
		}
		h.now = now
		return nil
	}
}

// WithHandoffIDGenerator replaces the generator of each handoff record's ID.
// The default is id.NewV7Generator(). A nil generator, including a nil pointer
// inside a non-nil interface, is refused.
//
// The record ID names the record for the store; it is not part of the code,
// which carries its own random token id.
func WithHandoffIDGenerator(g id.Generator) HandoffOption {
	return func(h *HandoffManager) error {
		if nilcheck.IsNil(g) {
			return fmt.Errorf("%w: WithHandoffIDGenerator was given nil", ErrConfig)
		}
		h.ids = g
		return nil
	}
}

// WithHandoffLogger replaces the logger every refused and failed redemption
// is reported to. The default is slog.Default(). A nil logger is refused.
//
// Redemption returns one error whatever went wrong, so this log is the only
// place the cause appears: a miss, an inactive user or a reference mismatch at
// DEBUG, a store or loader failure at ERROR. No record carries the code, its
// secret, the ID token or a claim value.
func WithHandoffLogger(l *slog.Logger) HandoffOption {
	return func(h *HandoffManager) error {
		if l == nil {
			return fmt.Errorf("%w: WithHandoffLogger was given nil", ErrConfig)
		}
		h.log = l
		return nil
	}
}
