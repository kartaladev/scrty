package signingkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

// TestNewKeyManagerConstructionContext pins what the caller's context reaches.
//
// Construction reads the store and may write to it, and a store is where a
// deployment's slowest dependency sits: a database, a KMS. The context the
// caller passes is the only way to give up on one that never answers, so what
// matters here is not that the manager inspects the context itself, but that
// the store is handed the caller's own — cancellation and deadline included —
// rather than one that can never be cancelled.
//
// Each case therefore reads the context inside the store, which is the only
// place the difference is observable.
func TestNewKeyManagerConstructionContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// ctx modifies the context construction is given; nil means the
		// subtest's own, which is live.
		ctx func(ctx context.Context) context.Context
		// store is the store construction is given; nil means no
		// WithKeyStore at all, so the default in-memory one.
		store  func(t *testing.T, ctrl *gomock.Controller) signingkey.KeyStore
		assert func(t *testing.T, km *signingkey.KeyManager, err error)
	}

	cases := []testCase{
		{
			name: "loading the store sees the caller's cancellation",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			store: func(_ *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				// The store answers from the context it was given, as a
				// durable one would. No write is expected: a load that failed
				// must never be treated as an empty store.
				store.EXPECT().LoadAll(gomock.Any()).
					DoAndReturn(func(ctx context.Context) ([]signingkey.Record, error) {
						return nil, ctx.Err()
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, km)
			},
		},
		{
			name: "loading the store sees the caller's expired deadline",
			ctx: func(ctx context.Context) context.Context {
				dctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Minute))
				t.Cleanup(cancel)

				return dctx
			},
			store: func(_ *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).
					DoAndReturn(func(ctx context.Context) ([]signingkey.Record, error) {
						return nil, ctx.Err()
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, err error) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Nil(t, km)
			},
		},
		{
			name: "writing the initial key sees the caller's cancellation",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			store: func(_ *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				// The load ignores the context and reports an empty store, so
				// the only place this case can fail is the write that follows.
				store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
				store.EXPECT().Store(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ signingkey.Record) error {
						return ctx.Err()
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, km)
			},
		},
		{
			name: "a live context constructs, and the store sees no cancellation",
			store: func(t *testing.T, ctrl *gomock.Controller) signingkey.KeyStore {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).
					DoAndReturn(func(ctx context.Context) ([]signingkey.Record, error) {
						assert.NoError(t, ctx.Err(), "the store was handed a context already done")

						return nil, nil
					})
				store.EXPECT().Store(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ signingkey.Record) error {
						assert.NoError(t, ctx.Err(), "the store was handed a context already done")

						return nil
					})

				return store
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, err error) {
				require.NoError(t, err)
				require.NotNil(t, km)

				_, _, ok := km.GetSigner(signingkey.RS256)
				assert.True(t, ok, "construction left no current key")
			},
		},
		{
			// Nothing here is a loophole: the manager inspects the context
			// nowhere, and the default store performs no I/O, so a cancelled
			// context reaches a store with nothing to abandon. That is a
			// documented limit of the default store rather than a rule about
			// cancellation, and it is pinned so that adding a ctx.Err() gate
			// to construction cannot quietly change the contract instead of
			// being a decision someone makes deliberately.
			name: "the default store cannot be cancelled",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, err error) {
				require.NoError(t, err, "the default store has no I/O to cancel")
				require.NotNil(t, km)

				_, _, ok := km.GetSigner(signingkey.RS256)
				assert.True(t, ok, "construction left no current key")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var opts []signingkey.Option
			if tc.store != nil {
				ctrl := gomock.NewController(t)
				opts = append(opts, signingkey.WithKeyStore(tc.store(t, ctrl)))
			}

			km, err := signingkey.NewKeyManager(ctx, opts...)
			tc.assert(t, km, err)
		})
	}
}
