package policy_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/policy"
)

// summaryKeys lists the keys of the suppressed-count summaries a sink received
// under msg.
func summaryKeys(s *recordSink, msg string) []string {
	var keys []string

	for _, r := range s.records() {
		if r.Message != msg {
			continue
		}

		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "key" {
				keys = append(keys, a.Value.String())
			}

			return true
		})
	}

	return keys
}

// summarySubject is one component under test: build wires it (with own as its
// logger option when non-nil) and returns a call that writes a sampled record
// keyed by user, and the flush that reports what the sampler held back.
type summarySubject struct {
	msg   string
	build func(t *testing.T, own *slog.Logger) (eval func(ctx context.Context, user identity.UserID), flush func() error)
}

// summaryRoute is where each user's summary landed.
type summaryRoute struct{ a, b, def, own *recordSink }

// has reports whether the sink received a summary whose key names user.
func (summaryRoute) has(s *recordSink, msg string, user string) bool {
	for _, k := range summaryKeys(s, msg) {
		if containsUser(k, user) {
			return true
		}
	}

	return false
}

func containsUser(key, user string) bool {
	for i := 0; i+len(user) <= len(key); i++ {
		if key[i:i+len(user)] == user {
			return true
		}
	}

	return false
}

// runSummaryRoute runs the summary rows decision 12 names against one component.
func runSummaryRoute(t *testing.T, subject summarySubject) {
	t.Helper()

	type testCase struct {
		name string
		own  bool
		// again records u-a once more, under chain B, after the first round.
		again  bool
		assert func(t *testing.T, r summaryRoute)
	}

	cases := []testCase{
		{
			name: "each key's summary goes to the chain its records went to",
			assert: func(t *testing.T, r summaryRoute) {
				assert.Equal(t, 1, len(summaryKeys(r.a, subject.msg)), "chain A: exactly its own key")
				assert.True(t, r.has(r.a, subject.msg, "u-a"), "chain A lacks its key's summary")
				assert.Equal(t, 1, len(summaryKeys(r.b, subject.msg)), "chain B: exactly its own key")
				assert.True(t, r.has(r.b, subject.msg, "u-b"), "chain B lacks its key's summary")
			},
		},
		{
			name:  "a key written under A and suppressed under B is summarised on A only",
			again: true,
			assert: func(t *testing.T, r summaryRoute) {
				assert.True(t, r.has(r.a, subject.msg, "u-a"), "chain A lacks its key's summary")
				assert.False(t, r.has(r.b, subject.msg, "u-a"), "chain B received chain A's key summary")
				assert.False(t, r.has(r.def, subject.msg, "u-a"), "the default received chain A's key summary")
			},
		},
		{
			name: "a key whose records went to no chain is summarised on the default",
			assert: func(t *testing.T, r summaryRoute) {
				assert.Equal(t, 1, len(summaryKeys(r.def, subject.msg)))
				assert.True(t, r.has(r.def, subject.msg, "u-none"))
				assert.False(t, r.has(r.a, subject.msg, "u-none"), "chain A received another key's summary")
				assert.False(t, r.has(r.b, subject.msg, "u-none"), "chain B received another key's summary")
			},
		},
		{
			name: "the component's own logger receives every summary",
			own:  true,
			assert: func(t *testing.T, r summaryRoute) {
				assert.Len(t, summaryKeys(r.own, subject.msg), 3)
				assert.Empty(t, summaryKeys(r.a, subject.msg))
				assert.Empty(t, summaryKeys(r.b, subject.msg))
				assert.Empty(t, summaryKeys(r.def, subject.msg))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			r := summaryRoute{a: &recordSink{}, b: &recordSink{}, def: &recordSink{}, own: &recordSink{}}

			var ownLogger *slog.Logger
			if tc.own {
				ownLogger = slog.New(r.own)
			}

			eval, flush := subject.build(t, ownLogger)

			prev := slog.Default()
			slog.SetDefault(slog.New(r.def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctxA := ctxlog.With(t.Context(), slog.New(r.a))
			ctxB := ctxlog.With(t.Context(), slog.New(r.b))

			for range 2 {
				eval(ctxA, "u-a")
				eval(ctxB, "u-b")
				eval(t.Context(), "u-none")
			}

			if tc.again {
				eval(ctxB, "u-a")
				eval(ctxB, "u-a")
			}

			require.NoError(t, flush())

			tc.assert(t, r)
		})
	}
}

func TestLogRouteSummary_MFA(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runSummaryRoute(t, summarySubject{
		msg: logMFASuppressed,
		build: func(t *testing.T, own *slog.Logger) (func(context.Context, identity.UserID), func() error) {
			var opts []policy.MFAOption
			if own != nil {
				opts = append(opts, policy.WithMFALogger(own))
			}

			p, err := policy.NewMFA(mfaMethods(mfaMethod(t, factor.Email, true, nil)), opts...)
			require.NoError(t, err)

			return func(ctx context.Context, user identity.UserID) {
				in := mfaInput(factor.MagicLink)
				in.User = user
				p.Evaluate(ctx, in)
			}, p.FlushRefusalLogs
		},
	})
}

func TestLogRouteSummary_MFARequirement(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runSummaryRoute(t, summarySubject{
		msg: logRequirementSuppressed,
		build: func(t *testing.T, own *slog.Logger) (func(context.Context, identity.UserID), func() error) {
			var opts []policy.MFARequirementOption
			if own != nil {
				opts = append(opts, policy.WithMFARequirementLogger(own))
			}

			p, err := policy.NewMFARequirement(
				mfaRequirementLookup(t, true, true, nil),
				mfaMethods(mfaMethod(t, factor.AuthenticatorApp, false, nil)), opts...)
			require.NoError(t, err)

			return func(ctx context.Context, user identity.UserID) {
				in := mfaInput(factor.Password)
				in.User = user
				p.Evaluate(policy.ContextWithPhase(ctx, policy.PerRequest), in)
			}, p.FlushRefusalLogs
		},
	})
}
