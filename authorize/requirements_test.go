package authorize_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// withScopes returns a context carrying a service principal holding scopes,
// which is the only kind of caller that carries any.
func withScopes(ctx context.Context, scopes ...string) context.Context {
	return identity.WithPrincipal(ctx, &identity.Principal{
		ID:     "svc-1",
		Kind:   identity.KindService,
		Scopes: scopes,
	})
}

func TestRequirements(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		req    func(t *testing.T) authorize.Requirement
		ctx    func(t *testing.T, ctx context.Context) context.Context // nil means an anonymous caller
		assert func(t *testing.T, err error)
	}

	allowed := func(t *testing.T, err error) { require.NoError(t, err) }
	denied := func(t *testing.T, err error) {
		require.ErrorIs(t, err, authorize.ErrAccessDenied)
		assert.NotErrorIs(t, err, authorize.ErrAuthenticationRequired,
			"a caller who cannot be allowed was told to authenticate again")
	}
	anonymous := func(t *testing.T, err error) {
		require.ErrorIs(t, err, authorize.ErrAuthenticationRequired)
		assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
			"a caller who has not identified themselves was refused outright")
	}

	// always names a requirement that needs no per-case construction.
	always := func(r authorize.Requirement) func(*testing.T) authorize.Requirement {
		return func(*testing.T) authorize.Requirement { return r }
	}

	withPrincipal := func(_ *testing.T, ctx context.Context) context.Context {
		return withRole(ctx, "viewer")
	}

	// laterMemberCalls counts the members AnyOf consults after one allows. Only
	// the short-circuit case touches it.
	laterMemberCalls := 0

	cases := []testCase{
		{
			name:   "PermitAll allows anonymously",
			req:    always(authorize.PermitAll()),
			assert: allowed,
		},
		{
			name:   "PermitAll allows a known caller",
			req:    always(authorize.PermitAll()),
			ctx:    withPrincipal,
			assert: allowed,
		},
		{
			name:   "DenyAll denies an authenticated caller",
			req:    always(authorize.DenyAll()),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			// Authenticating would not help, so the answer must not be the one
			// that asks the caller to try.
			name:   "DenyAll denies anonymously without asking for authentication",
			req:    always(authorize.DenyAll()),
			assert: denied,
		},
		{
			name:   "Authenticated allows a known caller",
			req:    always(authorize.Authenticated()),
			ctx:    withPrincipal,
			assert: allowed,
		},
		{
			name:   "Authenticated refuses anonymously with the anonymous sentinel",
			req:    always(authorize.Authenticated()),
			assert: anonymous,
		},
		{
			name: "Authenticated refuses a context carrying an absent principal",
			req:  always(authorize.Authenticated()),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, nil)
			},
			assert: anonymous,
		},
		{
			name:   "HasAnyRole allows the holder of one named role",
			req:    always(authorize.HasAnyRole("admin", "viewer")),
			ctx:    withPrincipal,
			assert: allowed,
		},
		{
			name:   "HasAnyRole denies a known caller without the role",
			req:    always(authorize.HasAnyRole("admin")),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name:   "HasAnyRole refuses anonymously with the anonymous sentinel",
			req:    always(authorize.HasAnyRole("admin")),
			assert: anonymous,
		},
		{
			name:   "HasAnyRole naming no roles denies",
			req:    always(authorize.HasAnyRole()),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			// Role identifiers are the consumer's own and are never case-folded
			// by scrty, so a near miss is a miss rather than a quiet match.
			name:   "HasAnyRole matches role names exactly",
			req:    always(authorize.HasAnyRole("Viewer")),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name: "HasAnyRole ignores a role that is assigned but not active",
			req:  always(authorize.HasAnyRole("admin")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				active := &identity.AssignedRole{ID: "r-1", Name: "viewer", Primary: true}
				spare := &identity.AssignedRole{ID: "r-2", Name: "admin"}

				return identity.WithPrincipal(ctx, &identity.Principal{
					ID:         "u-1",
					Roles:      []*identity.AssignedRole{active, spare},
					ActiveRole: active,
				})
			},
			assert: denied,
		},
		{
			name: "HasAnyRole denies a caller with no active role",
			req:  always(authorize.HasAnyRole("viewer")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, &identity.Principal{ID: "u-1"})
			},
			assert: denied,
		},
		{
			name: "HasAnyScope allows a principal holding one of them",
			req:  always(authorize.HasAnyScope("orders:read", "orders:write")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return withScopes(ctx, "orders:read")
			},
			assert: allowed,
		},
		{
			name:   "HasAnyScope denies a principal with no scopes",
			req:    always(authorize.HasAnyScope("orders:read")),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			// An empty set that allowed would turn a typo into an open
			// endpoint, so it denies.
			name:   "HasAnyScope with an empty set denies",
			req:    always(authorize.HasAnyScope()),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name:   "HasAnyScope refuses anonymously with the anonymous sentinel",
			req:    always(authorize.HasAnyScope("orders:read")),
			assert: anonymous,
		},
		{
			name: "HasAllScopes allows a principal holding every one",
			req:  always(authorize.HasAllScopes("orders:read", "orders:write")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return withScopes(ctx, "orders:write", "billing:read", "orders:read")
			},
			assert: allowed,
		},
		{
			name: "HasAllScopes denies when one is missing",
			req:  always(authorize.HasAllScopes("orders:read", "orders:write")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return withScopes(ctx, "orders:read")
			},
			assert: denied,
		},
		{
			name: "HasAllScopes matches scopes exactly",
			req:  always(authorize.HasAllScopes("orders:read")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return withScopes(ctx, "Orders:Read")
			},
			assert: denied,
		},
		{
			name:   "HasAllScopes with an empty set denies",
			req:    always(authorize.HasAllScopes()),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name:   "HasAllScopes refuses anonymously with the anonymous sentinel",
			req:    always(authorize.HasAllScopes("orders:read")),
			assert: anonymous,
		},
		{
			// A requirement satisfied by none of no members cannot be
			// satisfied at all.
			name:   "AnyOf with no members denies",
			req:    always(authorize.AnyOf()),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name:   "AnyOf allows when one member allows",
			req:    always(authorize.AnyOf(authorize.DenyAll(), authorize.PermitAll())),
			ctx:    withPrincipal,
			assert: allowed,
		},
		{
			name: "AnyOf stops at the member that allows",
			req: func(*testing.T) authorize.Requirement {
				return authorize.AnyOf(authorize.PermitAll(), func(context.Context) error {
					laterMemberCalls++

					return nil
				})
			},
			ctx: withPrincipal,
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
				assert.Zero(t, laterMemberCalls, "a member was consulted after the decision was made")
			},
		},
		{
			name:   "AnyOf reports anonymous only when every member did",
			req:    always(authorize.AnyOf(authorize.Authenticated(), authorize.HasAnyRole("admin"))),
			assert: anonymous,
		},
		{
			name:   "AnyOf reports denial when a known caller meets no member",
			req:    always(authorize.AnyOf(authorize.HasAnyRole("admin"), authorize.HasAnyScope("orders:read"))),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			// One member wants authentication and the other would refuse the
			// caller whatever they did, so the caller is refused rather than
			// sent to log in for nothing.
			name:   "AnyOf mixing an anonymous outcome with a forbidden one denies",
			req:    always(authorize.AnyOf(authorize.HasAnyRole("admin"), authorize.DenyAll())),
			assert: denied,
		},
		{
			name:   "AnyOf treats an absent member as one that cannot be satisfied",
			req:    always(authorize.AnyOf(nil)),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name:   "AnyOf still allows when an absent member sits beside a permitting one",
			req:    always(authorize.AnyOf(nil, authorize.PermitAll())),
			ctx:    withPrincipal,
			assert: allowed,
		},
		{
			name:   "HasPrivilege denies with no authorizer in context",
			req:    always(authorize.HasPrivilege("billing", "invoice", "write")),
			ctx:    withPrincipal,
			assert: denied,
		},
		{
			name: "HasPrivilege denies when the context carries an absent authorizer",
			req:  always(authorize.HasPrivilege("billing", "invoice", "write")),
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				var absent *authorize.Manager

				return authorize.WithAuthorizer(withRole(ctx, "viewer"), absent)
			},
			assert: denied,
		},
		{
			name: "HasPrivilege hands the authorizer the attributes it names",
			req:  always(authorize.HasPrivilege("billing", "invoice", "read", "write")),
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				authorizer := NewMockAuthorizer(gomock.NewController(t))
				authorizer.EXPECT().
					Authorize(gomock.Any(), authorize.PrivilegeAttributes{
						Group:    "billing",
						Resource: "invoice",
						Required: []string{"read", "write"},
						Mode:     authorize.MatchAllOf,
					}).
					Return(nil)

				return authorize.WithAuthorizer(withRole(ctx, "viewer"), authorizer)
			},
			assert: allowed,
		},
		{
			name: "HasPrivilege returns the authorizer's refusal",
			req:  always(authorize.HasPrivilege("billing", "invoice", "write")),
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				authorizer := NewMockAuthorizer(gomock.NewController(t))
				authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).
					Return(authorize.ErrAccessDenied)

				return authorize.WithAuthorizer(withRole(ctx, "viewer"), authorizer)
			},
			assert: denied,
		},
		{
			name: "HasPrivilege returns the authorizer's outage unchanged",
			req:  always(authorize.HasPrivilege("billing", "invoice", "write")),
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				authorizer := NewMockAuthorizer(gomock.NewController(t))
				authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(errBackendDown)

				return authorize.WithAuthorizer(withRole(ctx, "viewer"), authorizer)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown, "the cause was collapsed into a denial")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t, ctx)
			}

			tc.assert(t, tc.req(t)(ctx))
		})
	}
}
