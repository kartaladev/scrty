package session_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/session"
)

func TestLogRoute_Sessions(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		own    bool
		nilOpt bool
		chain  bool
		assert func(t *testing.T, own, chain, def *peRecorder, err error)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, _, chain, def *peRecorder, err error) {
				require.NoError(t, err)
				assert.Len(t, chain.aborts(), 1, "the chain's logger receives the record")
				assert.Empty(t, def.aborts(), "slog.Default() receives none")
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, own, chain, def *peRecorder, err error) {
				require.NoError(t, err)
				assert.Len(t, own.aborts(), 1, "the manager's own logger receives the record")
				assert.Empty(t, chain.aborts())
				assert.Empty(t, def.aborts())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, chain, def *peRecorder, err error) {
				require.NoError(t, err)
				assert.Len(t, def.aborts(), 1, "slog.Default(), as set when the record is written")
				assert.Empty(t, chain.aborts())
			},
		},
		{
			name:   "nil option",
			nilOpt: true,
			assert: func(t *testing.T, _, _, _ *peRecorder, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.ErrorContains(t, err, "WithLogger")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			own, chain, def := &peRecorder{}, &peRecorder{}, &peRecorder{}

			opts := []session.Option{session.WithRandom(&randomFlakyReader{err: &peCycleOne{}})}

			switch {
			case tc.nilOpt:
				opts = append(opts, session.WithLogger(nil))
			case tc.own:
				opts = append(opts, session.WithLogger(slog.New(own)))
			}

			m, err := session.New(opts...)

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

				_, _ = m.Create(ctx, testUser)
			}

			tc.assert(t, own, chain, def, err)
		})
	}
}

// TestLogRoute_EncryptedStore has no logger option: its rows are the chain and
// no-chain destinations of the record an inner store's hostile error writes.
func TestLogRoute_EncryptedStore(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		chain  bool
		assert func(t *testing.T, chain, def *peRecorder)
	}

	cases := []testCase{
		{
			name:  "inside a configured chain",
			chain: true,
			assert: func(t *testing.T, chain, def *peRecorder) {
				assert.Len(t, chain.aborts(), 1, "the chain's logger receives the record")
				assert.Empty(t, def.aborts())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, chain, def *peRecorder) {
				assert.Len(t, def.aborts(), 1, "slog.Default(), as set when the record is written")
				assert.Empty(t, chain.aborts())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			chain, def := &peRecorder{}, &peRecorder{}

			ctrl := gomock.NewController(t)
			sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
			inner.EXPECT().Delete(gomock.Any(), "route-del").Return(&peCycleOne{})

			prev := slog.Default()
			slog.SetDefault(slog.New(def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(chain))
			}

			require.Error(t, sealing.Delete(ctx, "route-del"))
			tc.assert(t, chain, def)
		})
	}
}
