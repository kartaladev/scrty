package mfa_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// summaryCount counts the lines of buf that are the throttle's summary.
func summaryCount(buf *bytes.Buffer, reason string) int {
	n := 0

	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.Contains(line, `"msg":"mfa: verification refusals suppressed"`) &&
			strings.Contains(line, `"reason":"`+reason+`"`) {
			n++
		}
	}

	return n
}

// TestLogRoute_VerifyThrottleSummaryPerKey pins that each reason's summary goes
// to the chain that reason's records went to, never to another chain's log.
func TestLogRoute_VerifyThrottleSummaryPerKey(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const (
		exceeded     = "throttled"
		limiterError = "limiter-error"
	)

	type testCase struct {
		name string
		own  bool
		// run writes refusals through check(ctx, user): "u-1" is throttled,
		// "u-2" makes the limiter fail.
		run    func(bare, a, b context.Context, check func(context.Context, string))
		assert func(t *testing.T, a, b, def, own *bytes.Buffer)
	}

	three := func(ctx context.Context, check func(context.Context, string), user string) {
		for range 3 {
			check(ctx, user)
		}
	}

	cases := []testCase{
		{
			name: "two chains: each summary stays on its own chain",
			run: func(_, a, b context.Context, check func(context.Context, string)) {
				three(a, check, "u-1")
				three(b, check, "u-2")
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Equal(t, 1, summaryCount(a, exceeded))
				assert.Zero(t, summaryCount(a, limiterError))
				assert.Equal(t, 1, summaryCount(b, limiterError))
				assert.Zero(t, summaryCount(b, exceeded))
				assert.Empty(t, def.String())
			},
		},
		{
			name: "key written under A then suppressed under B: summary on A only",
			run: func(_, a, b context.Context, check func(context.Context, string)) {
				three(a, check, "u-1")
				three(b, check, "u-1")
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Equal(t, 1, summaryCount(a, exceeded))
				assert.Empty(t, b.String())
				assert.Empty(t, def.String())
			},
		},
		{
			name: "no chain: the default logger",
			run: func(bare, _, _ context.Context, check func(context.Context, string)) {
				three(bare, check, "u-1")
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Equal(t, 1, summaryCount(def, exceeded))
				assert.Empty(t, a.String())
				assert.Empty(t, b.String())
			},
		},
		{
			name: "own option wins",
			own:  true,
			run: func(_, a, _ context.Context, check func(context.Context, string)) {
				three(a, check, "u-1")
			},
			assert: func(t *testing.T, a, _, def, own *bytes.Buffer) {
				assert.Equal(t, 1, summaryCount(own, exceeded))
				assert.Empty(t, a.String())
				assert.Empty(t, def.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := lrSetup(t)

			var chainB bytes.Buffer

			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), "mfa-verify|u-1").Return(true, nil).AnyTimes()
			limiter.EXPECT().Exceeded(gomock.Any(), "mfa-verify|u-2").Return(false, errors.New("limiter down")).AnyTimes()

			opts := []mfa.ThrottleOption{mfa.WithThrottleLimiter(limiter)}
			if tc.own {
				opts = append(opts, mfa.WithThrottleLogger(lrLogger(&b.own)))
			}

			throttle, err := mfa.NewVerifyThrottle(opts...)
			require.NoError(t, err)

			check := func(ctx context.Context, user string) { _ = throttle.Check(ctx, identity.UserID(user)) }

			tc.run(t.Context(),
				ctxlog.With(t.Context(), lrLogger(&b.chain)), ctxlog.With(t.Context(), lrLogger(&chainB)), check)

			require.NoError(t, throttle.FlushRefusalLogs())
			tc.assert(t, &b.chain, &chainB, &b.def, &b.own)
		})
	}
}
