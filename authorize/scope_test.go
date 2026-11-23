package authorize_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// withSuperRole returns a context carrying a principal whose active role is a
// super role.
func withSuperRole(ctx context.Context) context.Context {
	super := &identity.AssignedRole{ID: "r-0", Name: "root", SuperRole: true}

	return identity.WithPrincipal(ctx, &identity.Principal{
		ID:         "u-0",
		Roles:      []*identity.AssignedRole{super},
		ActiveRole: super,
	})
}

// grantingLead returns a context whose caller acts as clerk, and whose
// authorizer is a privilege authorizer over a loader granting privileges on
// crm/lead. A nil privileges list means the loader must not be asked.
func grantingLead(ctx context.Context, t *testing.T, privileges ...identity.Privilege) context.Context {
	t.Helper()

	roles := NewMockRoleLoader(gomock.NewController(t))
	if privileges != nil {
		roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(scoped("crm", "lead", privileges...), nil)
	}

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	return authorize.WithAuthorizer(withRole(ctx, "clerk"), authorizer)
}

func TestHasPrivilegeAnyScope_ReportsStrongest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(t *testing.T, ctx context.Context) context.Context
		assert func(t *testing.T, scope identity.Scope, err error)
	}

	reports := func(want identity.Scope) func(t *testing.T, scope identity.Scope, err error) {
		return func(t *testing.T, scope identity.Scope, err error) {
			require.NoError(t, err)
			assert.Equal(t, want, scope)
		}
	}

	cases := []testCase{
		{
			name: "an own-only grant reports own",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t, identity.Privilege{Name: "view", Granted: true, Scope: identity.ScopeOwn})
			},
			assert: reports(identity.ScopeOwn),
		},
		{
			name: "a grant stored without a scope reports all",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t, identity.Privilege{Name: "view", Granted: true})
			},
			assert: reports(identity.ScopeAll),
		},
		{
			name: "all wins over own when both are granted",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t,
					identity.Privilege{Name: "view", Granted: true, Scope: identity.ScopeOwn},
					identity.Privilege{Name: "view", Granted: true, Scope: identity.ScopeAll})
			},
			assert: reports(identity.ScopeAll),
		},
		{
			name: "a super role reports all",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				authorizer, err := authorize.NewPrivilegeAuthorizer(NewMockRoleLoader(gomock.NewController(t)))
				require.NoError(t, err)

				return authorize.WithAuthorizer(withSuperRole(ctx), authorizer)
			},
			assert: reports(identity.ScopeAll),
		},
		{
			name: "the privilege authorizer behind a FirstOf still reports",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				roles := NewMockRoleLoader(gomock.NewController(t))
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(scoped("crm", "lead",
					identity.Privilege{Name: "view", Granted: true, Scope: identity.ScopeOwn}), nil)

				privileges, err := authorize.NewPrivilegeAuthorizer(roles)
				require.NoError(t, err)

				manager, err := authorize.NewFirstOf(authorize.NewOwnershipAuthorizer(), privileges)
				require.NoError(t, err)

				return authorize.WithAuthorizer(withRole(ctx, "clerk"), manager)
			},
			assert: reports(identity.ScopeOwn),
		},
		{
			name: "an undefined scope covers nothing",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t, identity.Privilege{Name: "view", Granted: true, Scope: "team"})
			},
			assert: func(t *testing.T, scope identity.Scope, err error) {
				deniedFor(authorize.ErrWrongScope)(t, err)
				assert.Empty(t, scope)
			},
		},
		{
			name: "not granted is denied",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t, identity.Privilege{Name: "update", Granted: true})
			},
			assert: func(t *testing.T, scope identity.Scope, err error) {
				deniedFor(authorize.ErrNotGranted)(t, err)
				assert.Empty(t, scope)
			},
		},
		{
			name: "no authorizer in the context is denied",
			ctx: func(_ *testing.T, ctx context.Context) context.Context {
				return withRole(ctx, "clerk")
			},
			assert: func(t *testing.T, scope identity.Scope, err error) {
				deniedFor(authorize.ErrNotGranted)(t, err)
				assert.Empty(t, scope)
			},
		},
		{
			// A consumer authorizer that knows nothing of scopes allows: the
			// scope it held with is unknown, and is not guessed.
			name: "an authorizer that allows without reporting a scope is a configuration error",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				authorizer := NewMockAuthorizer(gomock.NewController(t))
				authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)

				return authorize.WithAuthorizer(withRole(ctx, "clerk"), authorizer)
			},
			assert: func(t *testing.T, scope identity.Scope, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied)
				assert.Empty(t, scope)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scope, err := authorize.CheckAnyScope(tc.ctx(t, t.Context()), "crm", "lead", "view")
			tc.assert(t, scope, err)
		})
	}
}

func TestHasPrivilegeAnyScope(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(t *testing.T, ctx context.Context) context.Context
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "an own-only grant is allowed",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t, identity.Privilege{Name: "view", Granted: true, Scope: identity.ScopeOwn})
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a consumer authorizer that reports no scope still decides the guard",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				authorizer := NewMockAuthorizer(gomock.NewController(t))
				authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)

				return authorize.WithAuthorizer(withRole(ctx, "clerk"), authorizer)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "an undefined scope is denied",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				return grantingLead(ctx, t, identity.Privilege{Name: "view", Granted: true, Scope: "team"})
			},
			assert: deniedFor(authorize.ErrWrongScope),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, authorize.HasPrivilegeAnyScope("crm", "lead", "view")(tc.ctx(t, t.Context())))
		})
	}
}

func TestHasPrivilegeFor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// privileges the clerk role holds on crm/lead; nil means the loader is
		// not asked.
		privileges []identity.Privilege
		owned      func(port *MockOwnership) authorize.OwnershipAttributes
		required   []string // nil means update alone
		assert     func(t *testing.T, err error)
	}

	update := func(scope identity.Scope) []identity.Privilege {
		return []identity.Privilege{{Name: "update", Granted: true, Scope: scope}}
	}

	// owner sets port up to resolve L-1 and answer owns for it.
	owner := func(owns bool) func(port *MockOwnership) authorize.OwnershipAttributes {
		return func(port *MockOwnership) authorize.OwnershipAttributes {
			port.EXPECT().ResolveID(gomock.Any()).Return("L-1", nil)
			port.EXPECT().OwnedBy(gomock.Any(), gomock.Any(), "L-1").Return(owns, nil)

			return ownedBy(port)
		}
	}

	// untouched expects no call on port: gomock fails the test on any.
	untouched := func(port *MockOwnership) authorize.OwnershipAttributes { return ownedBy(port) }

	cases := []testCase{
		{
			name:       "an all grant needs no ownership check",
			privileges: update(identity.ScopeAll),
			owned:      untouched,
			assert:     func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:       "a grant stored without a scope needs no ownership check",
			privileges: update(""),
			owned:      untouched,
			assert:     func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:       "an own grant on a record the caller owns is allowed",
			privileges: update(identity.ScopeOwn),
			owned:      owner(true),
			assert:     func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:       "an own grant on a record the caller does not own is denied as not the owner",
			privileges: update(identity.ScopeOwn),
			owned:      owner(false),
			assert:     deniedFor(authorize.ErrNotOwner),
		},
		{
			name:       "a resolver error is wrapped as an outage, not a denial",
			privileges: update(identity.ScopeOwn),
			owned: func(port *MockOwnership) authorize.OwnershipAttributes {
				port.EXPECT().ResolveID(gomock.Any()).Return("", errUnparsableID)

				return ownedBy(port)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errUnparsableID)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "an outage became a denial")
			},
		},
		{
			name:       "an ownership check error is wrapped as an outage, not a denial",
			privileges: update(identity.ScopeOwn),
			owned: func(port *MockOwnership) authorize.OwnershipAttributes {
				port.EXPECT().ResolveID(gomock.Any()).Return("L-1", nil)
				port.EXPECT().OwnedBy(gomock.Any(), gomock.Any(), "L-1").Return(true, errBackendDown)

				return ownedBy(port)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "an outage became a denial")
			},
		},
		{
			name:       "not granted is denied without an ownership check",
			privileges: []identity.Privilege{{Name: "view", Granted: true}},
			owned:      untouched,
			assert:     deniedFor(authorize.ErrNotGranted),
		},
		{
			name:       "an undefined scope is denied without an ownership check",
			privileges: update("team"),
			owned:      untouched,
			assert:     deniedFor(authorize.ErrWrongScope),
		},
		{
			name: "several privileges reach only as far as the narrowest grant",
			privileges: []identity.Privilege{
				{Name: "update", Granted: true, Scope: identity.ScopeAll},
				{Name: "print", Granted: true, Scope: identity.ScopeOwn},
			},
			required: []string{"update", "print"},
			owned:    owner(false),
			assert:   deniedFor(authorize.ErrNotOwner),
		},
		{
			name: "ownership attributes missing a function are refused before anything is loaded",
			owned: func(port *MockOwnership) authorize.OwnershipAttributes {
				attrs := ownedBy(port)
				attrs.OwnedBy = nil

				return attrs
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name: "ownership attributes naming another resource are refused",
			owned: func(port *MockOwnership) authorize.OwnershipAttributes {
				attrs := ownedBy(port)
				attrs.Resource = "deal"

				return attrs
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrInvalidAttributes) },
		},
		{
			name:       "blank ownership group and resource default to the privilege's",
			privileges: update(identity.ScopeOwn),
			owned: func(port *MockOwnership) authorize.OwnershipAttributes {
				attrs := owner(true)(port)
				attrs.Group, attrs.Resource = "", " "

				return attrs
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			port := NewMockOwnership(gomock.NewController(t))
			ctx := grantingLead(t.Context(), t, tc.privileges...)

			required := tc.required
			if required == nil {
				required = []string{"update"}
			}

			tc.assert(t, authorize.HasPrivilegeFor("crm", "lead", tc.owned(port), required...)(ctx))
		})
	}
}

// mutatingAuthorizer returns a consumer authorizer that, on its first call
// only, overwrites the first element of the Accept and Required slices it is
// handed, then declines so the next authorizer in a FirstOf judges.
func mutatingAuthorizer(t *testing.T) authorize.Authorizer {
	t.Helper()

	var calls atomic.Int32

	mock := NewMockAuthorizer(gomock.NewController(t))
	mock.EXPECT().Authorize(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, attrs authorize.Attributes) error {
			if calls.Add(1) == 1 {
				if p, ok := attrs.(authorize.PrivilegeAttributes); ok {
					if len(p.Accept) > 0 {
						p.Accept[0] = "tampered"
					}

					if len(p.Required) > 0 {
						p.Required[0] = "tampered"
					}
				}
			}

			return authorize.ErrUnsupportedAttributes
		}).AnyTimes()

	return mock
}

// grantingAlways returns a context whose authorizer is the mutating consumer
// authorizer in front of a privilege authorizer granting update with all.
func grantingAlways(t *testing.T) context.Context {
	t.Helper()

	roles := NewMockRoleLoader(gomock.NewController(t))
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
		Return(scoped("crm", "lead", identity.Privilege{Name: "update", Granted: true, Scope: identity.ScopeAll}), nil).
		AnyTimes()

	privileges, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	manager, err := authorize.NewFirstOf(mutatingAuthorizer(t), privileges)
	require.NoError(t, err)

	return authorize.WithAuthorizer(withRole(t.Context(), "clerk"), manager)
}

func TestScopedChecks_SurviveAMutatingAuthorizer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// check runs one scoped check against ctx.
		check func(ctx context.Context) error
	}

	owned := func() authorize.OwnershipAttributes {
		return authorize.OwnershipAttributes{
			ResolveID: func(context.Context) (string, error) { return "L-1", nil },
			OwnedBy:   func(context.Context, *identity.Principal, string) (bool, error) { return true, nil },
		}
	}

	cases := []testCase{
		{
			name: "HasPrivilegeAnyScope",
			check: func(ctx context.Context) error {
				return authorize.HasPrivilegeAnyScope("crm", "lead", "update")(ctx)
			},
		},
		{
			name: "HasPrivilegeFor",
			check: func(ctx context.Context) error {
				return authorize.HasPrivilegeFor("crm", "lead", owned(), "update")(ctx)
			},
		},
		{
			name: "CheckAnyScope",
			check: func(ctx context.Context) error {
				_, err := authorize.CheckAnyScope(ctx, "crm", "lead", "update")
				return err
			},
		},
		{
			name: "HasPrivilege",
			check: func(ctx context.Context) error {
				return authorize.HasPrivilege("crm", "lead", "update")(ctx)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := grantingAlways(t)

			// The first check meets the mutation, and its own outcome is not the
			// subject. Every check after it must behave as it did before.
			_ = tc.check(ctx)

			for range 3 {
				require.NoError(t, tc.check(ctx), "an authorizer's write reached a later check")
			}

			// The shared accept list also feeds the other scoped checks.
			_, err := authorize.CheckAnyScope(ctx, "crm", "lead", "update")
			require.NoError(t, err)
		})
	}
}

func TestHasPrivilege_IgnoresACallerReusingItsSlice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		build func(required ...string) authorize.Requirement
	}

	cases := []testCase{
		{name: "HasPrivilege", build: func(r ...string) authorize.Requirement {
			return authorize.HasPrivilege("crm", "lead", r...)
		}},
		{name: "HasPrivilegeAnyScope", build: func(r ...string) authorize.Requirement {
			return authorize.HasPrivilegeAnyScope("crm", "lead", r...)
		}},
		{name: "HasPrivilegeFor", build: func(r ...string) authorize.Requirement {
			return authorize.HasPrivilegeFor("crm", "lead", authorize.OwnershipAttributes{
				ResolveID: func(context.Context) (string, error) { return "L-1", nil },
				OwnedBy:   func(context.Context, *identity.Principal, string) (bool, error) { return true, nil },
			}, r...)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := grantingAlwaysFrom(t)

			passed := []string{"update"}
			req := tc.build(passed...)

			passed[0] = "delete" // the caller reuses its slice

			require.NoError(t, req(ctx), "the caller's later write rewrote the route's requirement")
		})
	}
}

// grantingAlwaysFrom returns a context whose privilege authorizer grants update
// on crm/lead with all, with no mutating authorizer in front.
func grantingAlwaysFrom(t *testing.T) context.Context {
	t.Helper()

	roles := NewMockRoleLoader(gomock.NewController(t))
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
		Return(scoped("crm", "lead", identity.Privilege{Name: "update", Granted: true, Scope: identity.ScopeAll}), nil).
		AnyTimes()

	privileges, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	return authorize.WithAuthorizer(withRole(t.Context(), "clerk"), privileges)
}

func TestHasPrivilegeFor_FailsWithoutOwnershipCall(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(t *testing.T) context.Context
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "an authorizer that allows without reporting a scope is a configuration error",
			ctx: func(t *testing.T) context.Context {
				consumer := NewMockAuthorizer(gomock.NewController(t))
				consumer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)

				return authorize.WithAuthorizer(withRole(t.Context(), "clerk"), consumer)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name: "a role loader outage is an outage, not a denial",
			ctx: func(t *testing.T) context.Context {
				roles := NewMockRoleLoader(gomock.NewController(t))
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(nil, errBackendDown)

				privileges, err := authorize.NewPrivilegeAuthorizer(roles)
				require.NoError(t, err)

				return authorize.WithAuthorizer(withRole(t.Context(), "clerk"), privileges)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "an outage became a denial")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A MockOwnership with no expectation fails the test on any call.
			port := NewMockOwnership(gomock.NewController(t))

			tc.assert(t, authorize.HasPrivilegeFor("crm", "lead", ownedBy(port), "update")(tc.ctx(t)))
		})
	}
}
