package lockout_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

func TestLogRoute_Lockout(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		own    bool
		nilOpt bool
		chain  bool
		assert func(t *testing.T, own, chain, def *lockoutPortLogs, err error)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, _, chain, def *lockoutPortLogs, err error) {
				require.NoError(t, err)
				assert.Len(t, chain.aborts(), 1, "the chain's logger receives the record")
				assert.Empty(t, def.aborts(), "slog.Default() receives none")
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, own, chain, def *lockoutPortLogs, err error) {
				require.NoError(t, err)
				assert.Len(t, own.aborts(), 1, "the policy's own logger receives the record")
				assert.Empty(t, chain.aborts())
				assert.Empty(t, def.aborts())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, chain, def *lockoutPortLogs, err error) {
				require.NoError(t, err)
				assert.Len(t, def.aborts(), 1, "slog.Default(), as set when the record is written")
				assert.Empty(t, chain.aborts())
			},
		},
		{
			name:   "nil option",
			nilOpt: true,
			assert: func(t *testing.T, _, _, _ *lockoutPortLogs, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.ErrorContains(t, err, "WithLogger")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			own, chain, def := &lockoutPortLogs{}, &lockoutPortLogs{}, &lockoutPortLogs{}

			s := NewMockAttemptStore(gomock.NewController(t))
			s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).AnyTimes().Return(100, &lockoutPortCycleOne{})

			opts := []lockout.Option{lockout.WithAttemptStore(s)}

			switch {
			case tc.nilOpt:
				opts = append(opts, lockout.WithLogger(nil))
			case tc.own:
				opts = append(opts, lockout.WithLogger(slog.New(own)))
			}

			p, err := lockout.New(opts...)

			// The default is swapped after construction: it is read when the
			// record is written.
			prev := slog.Default()
			slog.SetDefault(slog.New(def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			if err == nil {
				ctx := t.Context()
				if tc.chain {
					ctx = ctxlog.With(ctx, slog.New(chain))
				}

				p.Evaluate(ctx, lockoutInput("ada"))
			}

			tc.assert(t, own, chain, def, err)
		})
	}
}
