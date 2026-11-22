package password_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestLogRoute_Policy pins where the record of an accepted breach-lookup
// failure goes: the policy's own logger when given, else the logger of the
// chain handling the request, else slog.Default() as it is when the record is
// written. It swaps the default logger, so it does not run in parallel.
func TestLogRoute_Policy(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		opt    func(own *recordingHandler) []password.PolicyOption
		chain  bool
		assert func(t *testing.T, err error, own, chain, def *recordingHandler)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, err error, _, chain, def *recordingHandler) {
				require.NoError(t, err)
				assert.Len(t, chain.all(), 1)
				assert.Empty(t, def.all(), "the default logger must see nothing")
			},
		},
		{
			name: "own option wins",
			opt: func(own *recordingHandler) []password.PolicyOption {
				return []password.PolicyOption{password.WithPolicyLogger(slog.New(own))}
			},
			chain: true,
			assert: func(t *testing.T, err error, own, chain, def *recordingHandler) {
				require.NoError(t, err)
				assert.Len(t, own.all(), 1)
				assert.Empty(t, chain.all())
				assert.Empty(t, def.all())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, err error, _, _, def *recordingHandler) {
				require.NoError(t, err)
				assert.Len(t, def.all(), 1, "the default as swapped at record time")
			},
		},
		{
			name: "nil option",
			opt: func(*recordingHandler) []password.PolicyOption {
				return []password.PolicyOption{password.WithPolicyLogger(nil)}
			},
			assert: func(t *testing.T, err error, _, _, _ *recordingHandler) {
				require.ErrorIs(t, err, password.ErrConfig)
				assert.ErrorContains(t, err, "WithPolicyLogger")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			own, chain, def := &recordingHandler{}, &recordingHandler{}, &recordingHandler{}

			previous := slog.Default()
			slog.SetDefault(slog.New(def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			prefix, _ := sha1Hex(breachCandidate)
			src := NewMockBreachSource(gomock.NewController(t))
			src.EXPECT().Range(gomock.Any(), prefix).Return(nil, errors.New("down")).AnyTimes()

			opts := []password.PolicyOption{password.Breached(src, password.Accept)}
			if tc.opt != nil {
				opts = append(opts, tc.opt(own)...)
			}

			p, err := password.NewPolicy(opts...)
			if err != nil {
				tc.assert(t, err, own, chain, def)

				return
			}

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(chain))
			}

			require.NoError(t, p.Check(ctx, checkUser(), breachCandidate))
			tc.assert(t, nil, own, chain, def)
		})
	}
}
