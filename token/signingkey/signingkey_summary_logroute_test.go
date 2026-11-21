package signingkey_test

// TestLogRouteSummary_Keys replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/token/signingkey"
)

// summaryCount counts the records of the suppressed-count summary a recorder
// received.
func summaryCount(t *testing.T, r *logRecorder) int {
	t.Helper()

	n := 0

	for _, rec := range r.records(t) {
		if rec["msg"] == "signingkey: repeated failures suppressed" {
			n++
		}
	}

	return n
}

// The loops take the context Start was given, detached from its cancellation
// and keeping its values, so a chain on that context is where a request-driven
// start writes: the failure records and the summary of what they suppressed go
// to the same destination.
func TestLogRouteSummary_Keys(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		own    bool
		chain  bool
		assert func(t *testing.T, chain, own, def *logRecorder)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain: the summary follows the key's records",
			chain: true,
			assert: func(t *testing.T, chain, _, def *logRecorder) {
				assert.Equal(t, 1, summaryCount(t, chain))
				assert.Empty(t, def.records(t), "the default received a record of the chain's key")
			},
		},
		{
			name: "no chain: the summary goes to the default",
			assert: func(t *testing.T, chain, _, def *logRecorder) {
				assert.Equal(t, 1, summaryCount(t, def))
				assert.Empty(t, chain.records(t))
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, chain, own, def *logRecorder) {
				assert.Equal(t, 1, summaryCount(t, own))
				assert.Empty(t, chain.records(t))
				assert.Empty(t, def.records(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			chain, chainLogger := newLogRecorder()
			own, ownLogger := newLogRecorder()
			def, defLogger := newLogRecorder()

			prev := slog.Default()
			slog.SetDefault(defLogger)
			t.Cleanup(func() { slog.SetDefault(prev) })

			clk := newClock()
			report := &failureReport{}

			opts := []signingkey.Option{
				signingkey.WithKeyStore(failingStore(t, report, opRotate)),
				signingkey.WithClock(clk),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithErrorHook(report.hook),
				signingkey.WithLogInterval(time.Hour),
				signingkey.WithRotateInterval(time.Minute),
				signingkey.WithReloadInterval(30 * time.Second),
				signingkey.WithHousekeepingInterval(12 * time.Hour),
				signingkey.WithKeyLifetime(24 * time.Hour),
			}
			if tc.own {
				opts = append(opts, signingkey.WithLogger(ownLogger))
			}

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, chainLogger)
			}

			km, err := signingkey.New(ctx, opts...)
			require.NoError(t, err)
			shutdownAndVerify(t, km)

			require.NoError(t, km.Start(ctx))

			// The first failure is written; the second falls in the same
			// window and is suppressed until shutdown accounts for it.
			advance(t, clk, time.Minute, loopCount)
			require.Equal(t, 1, report.hooks())
			advance(t, clk, time.Minute, loopCount)
			require.Equal(t, 2, report.hooks())

			require.NoError(t, km.Shutdown(t.Context()))

			tc.assert(t, chain, own, def)
		})
	}
}
