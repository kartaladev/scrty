package httpsec

// The paths that issue through signedTokens (MFA verification, session renewal)
// hand its error to a status classifier that walks it with a bound and writes
// its own abort record, so a black-box test cannot tell whether signedTokens
// sanitized the generator's error itself. This test calls it directly.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

type signedPanicUnwrap struct{}

func (signedPanicUnwrap) Error() string { return "signed: panicking unwrap" }
func (signedPanicUnwrap) Unwrap() error { panic("signed: hostile unwrap") }

// signedGenerator is a token generator failing every issue with err.
type signedGenerator struct {
	token.Generator // only Generate is ever called

	err error
}

func (g signedGenerator) Generate(context.Context, string, *identity.Principal) (string, error) {
	return "", g.err
}

// lockedBuffer is a bytes.Buffer safe for the logger to write to.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// TestSignedTokens_SanitizesTheGeneratorsError pins that signedTokens itself,
// not a later classifier, replaces a generator error whose chain cannot be
// walked: the error it returns is walkable and marked as an issuing failure,
// and the one abort record is on the logger it was given.
func TestSignedTokens_SanitizesTheGeneratorsError(t *testing.T) {
	t.Parallel()

	plain := errors.New("signed: key source unavailable")

	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{name: "plain error", err: plain},
		{name: "self-cycle through Unwrap() error", err: &refusedCycle{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &refusedCycleMany{}, reason: "budget"},
		{name: "panicking Unwrap", err: signedPanicUnwrap{}, reason: "panic"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &lockedBuffer{}
			issue := signedTokens(signedGenerator{err: tc.err}, slog.New(slog.NewJSONHandler(logs, nil)))

			ctx := t.Context()
			s := &session.Session{ID: "s-1"}

			done := make(chan error, 1)

			go func() {
				_, err := issue(ctx, s, &identity.Principal{ID: "u-1", Username: "ada"})
				// Walking what came back is what a charge decision or a
				// status mapping does next: it must finish.
				_ = errors.Is(err, plain)

				done <- err
			}()

			var err error

			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("a hostile generator error hung the issuer")
			}

			require.Error(t, err)

			var failure *issueFailure
			require.ErrorAs(t, err, &failure, "marked as an issuing failure")

			out := logs.String()
			if tc.reason == "" {
				assert.NotContains(t, out, msgClassificationAborted, "a plain error writes no abort record")
				assert.NotErrorIs(t, err, porterr.ErrUnwalkable)

				return
			}

			assert.ErrorIs(t, err, porterr.ErrUnwalkable)
			assert.Equal(t, 1, strings.Count(out, "\"reason\":\""+tc.reason+"\""), "one abort record on the given logger")
		})
	}
}
