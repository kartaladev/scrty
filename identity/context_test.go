package identity_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

func TestPrincipalContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil leaves the context unchanged
		assert func(t *testing.T, ctx context.Context)
	}

	cases := []testCase{
		{
			name: "a principal attached is read back from a child context",
			ctx: func(ctx context.Context) context.Context {
				return context.WithoutCancel(identity.WithPrincipal(ctx, &identity.Principal{ID: "u-1"}))
			},
			assert: func(t *testing.T, ctx context.Context) {
				p, ok := identity.PrincipalFromContext(ctx)
				require.True(t, ok)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-1"), p.ID)
			},
		},
		{
			name: "a cancelled context still carries its principal",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(
					identity.WithPrincipal(ctx, &identity.Principal{ID: "u-2"}))
				cancel()

				return cctx
			},
			assert: func(t *testing.T, ctx context.Context) {
				require.ErrorIs(t, ctx.Err(), context.Canceled)

				p, ok := identity.PrincipalFromContext(ctx)
				require.True(t, ok, "cancellation ends the request, it does not erase who made it")
				assert.Equal(t, identity.UserID("u-2"), p.ID)
			},
		},
		{
			name: "the optional read reports absence",
			assert: func(t *testing.T, ctx context.Context) {
				p, ok := identity.PrincipalFromContext(ctx)
				assert.False(t, ok)
				assert.Nil(t, p)
			},
		},
		{
			name: "a nil principal does not read back as present",
			ctx: func(ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, nil)
			},
			assert: func(t *testing.T, ctx context.Context) {
				p, ok := identity.PrincipalFromContext(ctx)
				assert.False(t, ok,
					"reporting a nil principal as present would hand callers a nil to dereference")
				assert.Nil(t, p)
			},
		},
		{
			name: "the mandatory read returns the principal when one is present",
			ctx: func(ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, &identity.Principal{ID: "u-3"})
			},
			assert: func(t *testing.T, ctx context.Context) {
				p := identity.MustPrincipalFromContext(ctx)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-3"), p.ID)
			},
		},
		{
			name: "the mandatory read panics with an identifiable error",
			assert: func(t *testing.T, ctx context.Context) {
				defer func() {
					r := recover()
					require.NotNil(t, r, "the mandatory read must panic when no principal is present")

					err, ok := r.(error)
					require.True(t, ok, "the panic value must be an error a recovering caller can inspect")
					assert.ErrorIs(t, err, identity.ErrNoPrincipal)
				}()

				identity.MustPrincipalFromContext(ctx)
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

			tc.assert(t, ctx)
		})
	}
}
