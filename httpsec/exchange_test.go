package httpsec_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

type ctxKey string

func TestExchangeContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		act    func(ex *httpsec.Exchange)
		assert func(t *testing.T, ex *httpsec.Exchange)
	}

	cases := []testCase{
		{
			name: "derives from the seed context",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-1")
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				assert.Equal(t, "r-1", ex.Context().Value(ctxKey("request-id")))
			},
		},
		{
			name: "SetContext is visible to a later reader",
			act: func(ex *httpsec.Exchange) {
				ex.SetContext(context.WithValue(ex.Context(), ctxKey("principal"), "alice"))
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				assert.Equal(t, "alice", ex.Context().Value(ctxKey("principal")))
			},
		},
		{
			name: "SetContext ignores a nil context rather than losing the one it has",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-2")
			},
			act: func(ex *httpsec.Exchange) {
				ex.SetContext(nil) //nolint:staticcheck // the point of the case
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				require.NotNil(t, ex.Context())
				assert.Equal(t, "r-2", ex.Context().Value(ctxKey("request-id")))
			},
		},
		{
			name: "cancellation on the seed reaches the exchange",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				require.ErrorIs(t, ex.Context().Err(), context.Canceled)
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

			ex := httpsec.NewExchange(ctx, stubRequest{}, &stubWriter{})
			require.NotNil(t, ex)
			if tc.act != nil {
				tc.act(ex)
			}
			tc.assert(t, ex)
		})
	}
}

func TestExchangeCarriesTheRequestAndWriter(t *testing.T) {
	t.Parallel()

	req := stubRequest{method: "GET", path: "/health"}
	w := &stubWriter{}

	ex := httpsec.NewExchange(t.Context(), req, w)
	require.NotNil(t, ex)
	assert.Equal(t, "/health", ex.Request.Path())
	assert.Same(t, w, ex.Writer)
}

func TestInterceptorFunc(t *testing.T) {
	t.Parallel()

	called := false
	var i httpsec.Interceptor = httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		called = true
		return next(ex)
	})

	ex := httpsec.NewExchange(t.Context(), stubRequest{}, &stubWriter{})
	require.NotNil(t, ex)

	reached := false
	err := i.Intercept(ex, func(*httpsec.Exchange) error {
		reached = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called, "the adapted function was not run")
	assert.True(t, reached, "the adapted function did not continue the chain")
}
