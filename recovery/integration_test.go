package recovery_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/recovery"
)

func TestDefaultLimiter_WarnsThroughConfiguredLogger(t *testing.T) {
	t.Parallel()

	const warning = "counts only this replica"

	type testCase struct {
		name string
		// use builds the component with the logger and makes its first use of the
		// default limiter.
		use    func(t *testing.T, logger *slog.Logger)
		assert func(t *testing.T, logs string)
	}

	cases := []testCase{
		{
			name: "codes",
			use: func(t *testing.T, logger *slog.Logger) {
				c := newCodes(t, recovery.WithCodesLogger(logger))
				_, _ = c.Check(t.Context(), anaID, wrongCode)
			},
			assert: func(t *testing.T, logs string) {
				assert.Contains(t, logs, warning, "the codes default limiter must warn through the configured logger")
			},
		},
		{
			name: "recoverer",
			use: func(t *testing.T, logger *slog.Logger) {
				e := newRecoverEnv(t)
				e.defaults()
				r, err := recovery.NewRecoverer(e.deps(), e.fixture.opts(recovery.WithLogger(logger))...)
				require.NoError(t, err)
				_, _ = r.Verify(t.Context(), recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued})
			},
			assert: func(t *testing.T, logs string) {
				assert.Contains(t, logs, warning, "the recoverer default limiter must warn through the configured logger")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			tc.use(t, slog.New(slog.NewTextHandler(&buf, nil)))
			tc.assert(t, buf.String())
		})
	}
}

// limiterProbe drives a component's default limiter: exhaust spends the limit,
// and refused reports whether the component now refuses the user for being at
// that limit.
type limiterProbe struct {
	exhaust func()
	refused func() bool
}

func TestDefaultLimiter_ReadsConfiguredClock(t *testing.T) {
	t.Parallel()

	// Both defaults allow five failures per fifteen minutes.
	const pastWindow = 15*time.Minute + time.Second

	type testCase struct {
		name string
		// build configures the component with clk alone and returns its probe.
		build  func(t *testing.T, clk clockwork.Clock) limiterProbe
		assert func(t *testing.T, refusedAtLimit, refusedAfterWindow bool)
	}

	cases := []testCase{
		{
			name: "codes",
			build: func(t *testing.T, clk clockwork.Clock) limiterProbe {
				c := newCodes(t, recovery.WithCodesClock(clk))
				codes := mustGenerate(t, c, anaID)

				return limiterProbe{
					exhaust: func() {
						for range 5 {
							require.ErrorIs(t, c.Confirm(t.Context(), anaID, wrongCode), recovery.ErrRefused)
						}
					},
					refused: func() bool {
						_, err := c.Check(t.Context(), anaID, codes[0])

						return err != nil
					},
				}
			},
			assert: func(t *testing.T, atLimit, afterWindow bool) {
				assert.True(t, atLimit, "the codes default limiter must refuse at its limit")
				assert.False(t, afterWindow, "the codes default limiter must age failures out on the configured clock")
			},
		},
		{
			name: "recoverer",
			build: func(t *testing.T, clk clockwork.Clock) limiterProbe {
				e := newRecoverEnv(t)
				e.defaults()
				logs := &syncBuffer{}
				logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				r, err := recovery.NewRecoverer(e.deps(), e.fixture.opts(recovery.WithClock(clk), recovery.WithLogger(logger))...)
				require.NoError(t, err)

				// A valid saved code with a wrong issued one fails the proof
				// without touching the saved-code limiter, which reads the
				// fixture's own clock.
				attempt := func() {
					_, _ = r.Verify(t.Context(), recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: "wrong"})
				}

				return limiterProbe{
					exhaust: func() {
						for range 5 {
							attempt()
						}
					},
					refused: func() bool {
						logs.buf.Reset()
						attempt()

						return strings.Contains(logs.String(), "the user is at the recovery limit")
					},
				}
			},
			assert: func(t *testing.T, atLimit, afterWindow bool) {
				assert.True(t, atLimit, "the recoverer default limiter must refuse at its limit")
				assert.False(t, afterWindow, "the recoverer default limiter must age failures out on the configured clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(codesTime)
			p := tc.build(t, clk)

			p.exhaust()
			atLimit := p.refused()

			clk.Advance(pastWindow)

			tc.assert(t, atLimit, p.refused())
		})
	}
}
