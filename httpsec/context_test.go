package httpsec_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// runChainCapturingContext assembles a chain whose one interceptor publishes a
// session and continues, and whose terminal captures the context the handler
// would be called with. It is what every case here inspects: the chain must
// hand the handler a context derived from the one the exchange started with.
func runChainCapturingContext(ctx context.Context, t *testing.T) (context.Context, error) {
	t.Helper()

	publisher := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.SetContext(httpsec.WithSession(ex.Context(), &session.Session{ID: "sess-1"}))
		return next(ex)
	})

	chain, err := httpsec.New(httpsec.RegisterInterceptor(publisher, httpsec.OrderBearerToken))
	require.NoError(t, err)

	var seen context.Context
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		seen = ex.Context()
		return nil
	})

	err = run(httpsec.NewExchange(ctx, stubRequest{}, &stubWriter{}))
	require.NotNil(t, seen, "the handler must have been reached")
	return seen, err
}

func TestChainContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, seen context.Context, err error)
	}

	cases := []testCase{
		{
			name: "an upstream value survives the chain",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-7")
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)
				assert.Equal(t, "r-7", seen.Value(ctxKey("request-id")))
			},
		},
		{
			name: "state an interceptor adds reaches the handler",
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)

				s, ok := httpsec.SessionFromContext(seen)
				require.True(t, ok)
				assert.Equal(t, "sess-1", s.ID)
			},
		},
		{
			name: "an interceptor's state does not displace an upstream value",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-8")
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)

				_, ok := httpsec.SessionFromContext(seen)
				require.True(t, ok)
				assert.Equal(t, "r-8", seen.Value(ctxKey("request-id")))
			},
		},
		{
			name: "cancellation reaches an in-flight lookup",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)
				require.ErrorIs(t, seen.Err(), context.Canceled)
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

			seen, err := runChainCapturingContext(ctx, t)
			tc.assert(t, seen, err)
		})
	}
}

func TestSessionFromContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, s *session.Session, ok bool)
	}

	cases := []testCase{
		{
			name: "no session published",
			assert: func(t *testing.T, s *session.Session, ok bool) {
				assert.False(t, ok)
				assert.Nil(t, s)
			},
		},
		{
			name: "a published session is read back",
			ctx: func(ctx context.Context) context.Context {
				return httpsec.WithSession(ctx, &session.Session{ID: "sess-2"})
			},
			assert: func(t *testing.T, s *session.Session, ok bool) {
				require.True(t, ok)
				require.NotNil(t, s)
				assert.Equal(t, "sess-2", s.ID)
			},
		},
		{
			name: "a nil session is reported absent, not present and empty",
			ctx: func(ctx context.Context) context.Context {
				return httpsec.WithSession(ctx, nil)
			},
			assert: func(t *testing.T, s *session.Session, ok bool) {
				assert.False(t, ok, "a caller ignoring ok must not be handed something it reads as a live session")
				assert.Nil(t, s)
			},
		},
		{
			name: "a later publication replaces an earlier one",
			ctx: func(ctx context.Context) context.Context {
				ctx = httpsec.WithSession(ctx, &session.Session{ID: "sess-old"})
				return httpsec.WithSession(ctx, &session.Session{ID: "sess-new"})
			},
			assert: func(t *testing.T, s *session.Session, ok bool) {
				require.True(t, ok)
				require.NotNil(t, s)
				assert.Equal(t, "sess-new", s.ID)
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

			s, ok := httpsec.SessionFromContext(ctx)
			tc.assert(t, s, ok)
		})
	}
}
