package policy_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/policy"
)

// logRouteSinks are the three destinations a record can reach.
type logRouteSinks struct{ own, chain, def *recordSink }

// logRouteAborts counts the walk-abort records a sink received.
func logRouteAborts(s *recordSink) int {
	n := 0

	for _, r := range s.records() {
		if r.Message == porterr.MsgClassificationAborted {
			n++
		}
	}

	return n
}

// logRouteSubject is one component under test: build wires it with the logger
// option given (own), or with a nil logger option (nilOpt), or with no option,
// and returns a call that makes it write one abort record.
type logRouteSubject struct {
	option string
	build  func(t *testing.T, own *slog.Logger, nilOpt bool) (func(ctx context.Context), error)
}

// runLogRoute runs the routing rows decision 12 names against one component.
func runLogRoute(t *testing.T, subject logRouteSubject) {
	t.Helper()

	type testCase struct {
		name   string
		own    bool
		nilOpt bool
		chain  bool
		assert func(t *testing.T, s logRouteSinks, buildErr error)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, s logRouteSinks, buildErr error) {
				require.NoError(t, buildErr)
				assert.Equal(t, 1, logRouteAborts(s.chain), "the chain's logger receives the record")
				assert.Zero(t, logRouteAborts(s.def), "slog.Default() receives none")
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, s logRouteSinks, buildErr error) {
				require.NoError(t, buildErr)
				assert.Equal(t, 1, logRouteAborts(s.own), "the component's own logger receives the record")
				assert.Zero(t, logRouteAborts(s.chain))
				assert.Zero(t, logRouteAborts(s.def))
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, s logRouteSinks, buildErr error) {
				require.NoError(t, buildErr)
				assert.Equal(t, 1, logRouteAborts(s.def), "slog.Default(), as set when the record is written")
				assert.Zero(t, logRouteAborts(s.chain))
			},
		},
		{
			name:   "nil option",
			nilOpt: true,
			assert: func(t *testing.T, _ logRouteSinks, buildErr error) {
				require.ErrorIs(t, buildErr, policy.ErrConfig)
				assert.ErrorContains(t, buildErr, subject.option)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			s := logRouteSinks{own: &recordSink{}, chain: &recordSink{}, def: &recordSink{}}

			var ownLogger *slog.Logger
			if tc.own {
				ownLogger = slog.New(s.own)
			}

			call, err := subject.build(t, ownLogger, tc.nilOpt)

			// The default is swapped after construction: it is read when the
			// record is written.
			prev := slog.Default()
			slog.SetDefault(slog.New(s.def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			if err == nil {
				ctx := t.Context()
				if tc.chain {
					ctx = ctxlog.With(ctx, slog.New(s.chain))
				}

				call(ctx)
			}

			tc.assert(t, s, err)
		})
	}
}

func TestLogRoute_MFA(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runLogRoute(t, logRouteSubject{
		option: "WithMFALogger",
		build: func(t *testing.T, own *slog.Logger, nilOpt bool) (func(ctx context.Context), error) {
			var opts []policy.MFAOption

			switch {
			case nilOpt:
				opts = append(opts, policy.WithMFALogger(nil))
			case own != nil:
				opts = append(opts, policy.WithMFALogger(own))
			}

			p, err := policy.NewMFA(
				mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, &peCycleOne{})), opts...)
			if err != nil {
				return nil, err
			}

			return func(ctx context.Context) { p.Evaluate(ctx, mfaInput(factor.Password)) }, nil
		},
	})
}

func TestLogRoute_MFARequirement(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runLogRoute(t, logRouteSubject{
		option: "WithMFARequirementLogger",
		build: func(t *testing.T, own *slog.Logger, nilOpt bool) (func(ctx context.Context), error) {
			var opts []policy.MFARequirementOption

			switch {
			case nilOpt:
				opts = append(opts, policy.WithMFARequirementLogger(nil))
			case own != nil:
				opts = append(opts, policy.WithMFARequirementLogger(own))
			}

			p, err := policy.NewMFARequirement(
				mfaRequirementLookup(t, true, false, &peCycleOne{}),
				mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)), opts...)
			if err != nil {
				return nil, err
			}

			return func(ctx context.Context) {
				p.Evaluate(policy.ContextWithPhase(ctx, policy.PostAuthentication), mfaInput(factor.Password))
			}, nil
		},
	})
}

// TestLogRoute_ConcurrentSessions has no logger option: its rows are the chain
// and no-chain destinations of the record its counter's hostile error writes.
func TestLogRoute_ConcurrentSessions(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		chain  bool
		assert func(t *testing.T, s logRouteSinks)
	}

	cases := []testCase{
		{
			name:  "inside a configured chain",
			chain: true,
			assert: func(t *testing.T, s logRouteSinks) {
				assert.Equal(t, 1, logRouteAborts(s.chain), "the chain's logger receives the record")
				assert.Zero(t, logRouteAborts(s.def))
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, s logRouteSinks) {
				assert.Equal(t, 1, logRouteAborts(s.def))
				assert.Zero(t, logRouteAborts(s.chain))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			s := logRouteSinks{chain: &recordSink{}, def: &recordSink{}}

			counter := NewMockSessionCounter(gomock.NewController(t))
			counter.EXPECT().CountActiveByUser(gomock.Any(), gomock.Any()).AnyTimes().Return(0, &peCycleOne{})

			p, err := policy.NewConcurrentSessions(counter, 3)
			require.NoError(t, err)

			prev := slog.Default()
			slog.SetDefault(slog.New(s.def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(s.chain))
			}

			p.Evaluate(ctx, &policy.Input{User: mfaUser})
			tc.assert(t, s)
		})
	}
}
