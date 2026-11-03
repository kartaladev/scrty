package password_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

func TestPolicy_Construction(t *testing.T) {
	t.Parallel()

	enc := fastArgon2id(t)

	type testCase struct {
		name   string
		opts   func(ctrl *gomock.Controller) []password.PolicyOption
		assert func(t *testing.T, p *password.Policy, err error)
	}

	consumerHistory := func(ctrl *gomock.Controller) password.History { return NewMockHistory(ctrl) }

	// reuse is a policy over enc with the reuse rule at depth over h.
	reuse := func(h func(*gomock.Controller) password.History, depth int, opts ...password.ReuseOption) func(*gomock.Controller) []password.PolicyOption {
		return func(ctrl *gomock.Controller) []password.PolicyOption {
			var history password.History
			if h != nil {
				history = h(ctrl)
			}

			return []password.PolicyOption{password.WithEncoder(enc), password.NoReuse(history, depth, opts...)}
		}
	}

	// with is a fixed list of options.
	with := func(opts ...password.PolicyOption) func(*gomock.Controller) []password.PolicyOption {
		return func(*gomock.Controller) []password.PolicyOption { return opts }
	}

	// consumerClockAt is what a consumer's own read-only clock reports, for
	// the "consumer clock" row below.
	consumerClockAt := time.Date(2032, time.March, 3, 4, 5, 6, 0, time.UTC)

	refused := func(word string) func(t *testing.T, p *password.Policy, err error) {
		return func(t *testing.T, p *password.Policy, err error) {
			t.Helper()

			require.ErrorIs(t, err, password.ErrConfig)
			assert.Contains(t, err.Error(), word)
			assert.Nil(t, p)
		}
	}

	built := func(t *testing.T, p *password.Policy, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, p)
	}

	cases := []testCase{
		{
			name:   "a reuse rule with a nil history port",
			opts:   reuse(nil, 5),
			assert: refused("history port"),
		},
		{
			name:   "a reuse rule with a typed-nil history port",
			opts:   reuse(func(*gomock.Controller) password.History { return (*memHistory)(nil) }, 5),
			assert: refused("history port"),
		},
		{
			name:   "a nil encoder",
			opts:   with(password.WithEncoder(nil)),
			assert: refused("encoder"),
		},
		{
			name:   "a typed-nil encoder",
			opts:   with(password.WithEncoder((*plainEncoder)(nil))),
			assert: refused("encoder"),
		},
		{
			name:   "reuse depth zero",
			opts:   reuse(consumerHistory, 0),
			assert: refused("reuse depth"),
		},
		{
			name:   "a negative reuse depth",
			opts:   reuse(consumerHistory, -1),
			assert: refused("reuse depth"),
		},
		{
			name:   "a nil reuse matcher",
			opts:   reuse(consumerHistory, 5, password.WithReuseMatchers(nil)),
			assert: refused("matcher"),
		},
		{
			name:   "a typed-nil reuse matcher",
			opts:   reuse(consumerHistory, 5, password.WithReuseMatchers(plainEncoder{}, (*plainEncoder)(nil))),
			assert: refused("matcher"),
		},
		{
			name:   "a nil logger",
			opts:   with(password.WithPolicyLogger(nil)),
			assert: refused("WithPolicyLogger"),
		},
		{
			name:   "a typed-nil logger is the same nil",
			opts:   with(password.WithPolicyLogger((*slog.Logger)(nil))),
			assert: refused("WithPolicyLogger"),
		},
		{
			name:   "a nil clock",
			opts:   with(password.WithClock(nil)),
			assert: refused("clock"),
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only a reflect-based check catches it before the
			// first Change reads from a nil receiver.
			name:   "a typed-nil clock",
			opts:   with(password.WithClock((*clockwork.FakeClock)(nil))),
			assert: refused("clock"),
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and Change reads
			// the change time from the consumer's clock: depth 1 over a fresh
			// user touches no history, so the write is the only place the
			// clock could have come from.
			name: "a consumer's own read-only clock is the policy's time source",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return append(reuse(consumerHistory, 1)(ctrl), password.WithClock(fixedClock{at: consumerClockAt}))
			},
			assert: func(t *testing.T, p *password.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)

				user := &identity.Details{ID: identity.UserID("u-consumer-clock")}
				w := &recordingWrite{}
				require.NoError(t, p.Change(t.Context(), user, p1, w.write))
				assert.True(t, consumerClockAt.Equal(w.at),
					"the write did not get the consumer clock's time")
			},
		},
		{
			name:   "the consumer's own history port, depth 5",
			opts:   reuse(consumerHistory, 5),
			assert: built,
		},
		{
			name:   "no options",
			opts:   with(),
			assert: built,
		},
		{
			name:   "a minimum length below 8",
			opts:   with(password.MinLength(6)),
			assert: refused("minimum length"),
		},
		{
			name:   "a minimum length of 8",
			opts:   with(password.MinLength(8)),
			assert: built,
		},
		{
			name:   "a maximum length below 64",
			opts:   with(password.MaxLength(32)),
			assert: refused("maximum length"),
		},
		{
			name:   "a maximum length of 64",
			opts:   with(password.MaxLength(64)),
			assert: built,
		},
		{
			name:   "a maximum length below the minimum",
			opts:   with(password.MinLength(100), password.MaxLength(80)),
			assert: refused("maximum length"),
		},
		{
			name:   "a maximum length equal to the minimum",
			opts:   with(password.MinLength(80), password.MaxLength(80)),
			assert: built,
		},
		{
			name:   "an empty replacement common-password list",
			opts:   with(password.CommonPasswords(nil)),
			assert: refused("common-password list"),
		},
		{
			name:   "a replacement common-password list of blank entries only",
			opts:   with(password.CommonPasswords([]string{"", "\r"})),
			assert: refused("common-password list"),
		},
		{
			name:   "a nil context-word function",
			opts:   with(password.ContextWords(nil)),
			assert: refused("context-word"),
		},
		{
			name:   "the common-password list removed after an empty replacement",
			opts:   with(password.CommonPasswords(nil), password.WithoutCommonPasswords()),
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(tc.opts(gomock.NewController(t))...)
			tc.assert(t, p, err)
		})
	}
}
