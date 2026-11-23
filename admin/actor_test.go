package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

func TestActorFrom(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(t *testing.T) context.Context
		assert func(t *testing.T, actor string, err error)
	}

	cases := []testCase{
		{
			name: "principal",
			ctx: func(t *testing.T) context.Context {
				return identity.WithPrincipal(t.Context(), &identity.Principal{ID: "u-1"})
			},
			assert: func(t *testing.T, actor string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "u-1", actor)
			},
		},
		{
			name: "system actor",
			ctx:  func(t *testing.T) context.Context { return admin.WithSystemActor(t.Context(), "sync") },
			assert: func(t *testing.T, actor string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "system:sync", actor)
			},
		},
		{
			name: "principal wins over system actor",
			ctx: func(t *testing.T) context.Context {
				ctx := admin.WithSystemActor(t.Context(), "sync")
				return identity.WithPrincipal(ctx, &identity.Principal{ID: "u-1"})
			},
			assert: func(t *testing.T, actor string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "u-1", actor)
			},
		},
		{
			name: "neither",
			ctx:  func(t *testing.T) context.Context { return t.Context() },
			assert: func(t *testing.T, actor string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
				assert.Empty(t, actor)
			},
		},
		{
			name: "nil principal",
			ctx: func(t *testing.T) context.Context {
				return identity.WithPrincipal(t.Context(), nil)
			},
			assert: func(t *testing.T, _ string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
			},
		},
		{
			name: "principal with no identifier",
			ctx: func(t *testing.T) context.Context {
				return identity.WithPrincipal(t.Context(), &identity.Principal{})
			},
			assert: func(t *testing.T, _ string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
			},
		},
		{
			name: "blank system actor name",
			ctx:  func(t *testing.T) context.Context { return admin.WithSystemActor(t.Context(), "  ") },
			assert: func(t *testing.T, _ string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
			},
		},
		{
			name: "principal whose identifier reads as a system actor",
			ctx: func(t *testing.T) context.Context {
				return identity.WithPrincipal(t.Context(), &identity.Principal{ID: "system:sync"})
			},
			assert: func(t *testing.T, actor string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
				assert.Empty(t, actor)
			},
		},
		{
			name: "invalid principal is not replaced by an attached system actor",
			ctx: func(t *testing.T) context.Context {
				ctx := admin.WithSystemActor(t.Context(), "sync")
				return identity.WithPrincipal(ctx, &identity.Principal{ID: "system:other"})
			},
			assert: func(t *testing.T, actor string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
				assert.Empty(t, actor)
			},
		},
		{
			name: "principal with no identifier falls through to the system actor",
			ctx: func(t *testing.T) context.Context {
				ctx := admin.WithSystemActor(t.Context(), "sync")
				return identity.WithPrincipal(ctx, &identity.Principal{})
			},
			assert: func(t *testing.T, actor string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "system:sync", actor)
			},
		},
		{
			name: "principal identifier at the bound",
			ctx: func(t *testing.T) context.Context {
				return identity.WithPrincipal(t.Context(), &identity.Principal{ID: identity.UserID(strings.Repeat("u", admin.MaxActorBytes))})
			},
			assert: func(t *testing.T, actor string, err error) {
				require.NoError(t, err)
				assert.Len(t, actor, admin.MaxActorBytes)
			},
		},
		{
			name: "principal identifier beyond the bound",
			ctx: func(t *testing.T) context.Context {
				return identity.WithPrincipal(t.Context(), &identity.Principal{ID: identity.UserID(strings.Repeat("u", admin.MaxActorBytes+1))})
			},
			assert: func(t *testing.T, _ string, err error) { assert.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{
			name: "system actor beyond the bound",
			ctx: func(t *testing.T) context.Context {
				return admin.WithSystemActor(t.Context(), strings.Repeat("s", admin.MaxActorBytes))
			},
			assert: func(t *testing.T, _ string, err error) { assert.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{
			name: "system actor name with a control character",
			ctx:  func(t *testing.T) context.Context { return admin.WithSystemActor(t.Context(), "sy\nnc") },
			assert: func(t *testing.T, _ string, err error) {
				assert.ErrorIs(t, err, admin.ErrNoActor)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			actor, err := admin.ActorFrom(tc.ctx(t))
			tc.assert(t, actor, err)
		})
	}
}
