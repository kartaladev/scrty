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

// allowedActions is the role data of the spec's allowed-actions scenario: view
// with all and update with own on crm/lead, delete not mentioned.
func allowedActions() []*identity.ResourcePrivileges {
	return scoped("crm", "lead",
		identity.Privilege{Name: "view", Granted: true, Scope: identity.ScopeAll},
		identity.Privilege{Name: "update", Granted: true, Scope: identity.ScopeOwn},
	)
}

// nothingHeld asserts the holdings report every name of view, update, delete
// as not held, in order, with no error.
func nothingHeld(t *testing.T, holdings authorize.Holdings, err error) {
	t.Helper()

	require.NoError(t, err)
	assert.Equal(t, authorize.Holdings{
		{Privilege: "view"}, {Privilege: "update"}, {Privilege: "delete"},
	}, holdings)
}

// superRole returns a context whose active role is a super role named name.
func superRole(ctx context.Context, name string) context.Context {
	super := &identity.AssignedRole{ID: "r-0", Name: name, SuperRole: true}

	return identity.WithPrincipal(ctx, &identity.Principal{
		ID:         "u-0",
		Roles:      []*identity.AssignedRole{super},
		ActiveRole: super,
	})
}

func TestHeldPrivileges(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// subject puts the caller in the context; nil leaves it anonymous.
		subject func(ctx context.Context) context.Context
		// expect sets what the role loader is asked; nil means it is not.
		expect func(roles *MockRoleLoader)
		// authorizer builds what the context carries from the privilege
		// authorizer; nil carries the privilege authorizer itself.
		authorizer func(t *testing.T, ctrl *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer
		ctx        func(ctx context.Context) context.Context
		names      []string
		assert     func(t *testing.T, holdings authorize.Holdings, err error)
	}

	clerk := func(ctx context.Context) context.Context { return withRole(ctx, "clerk") }
	actions := []string{"view", "update", "delete"}

	// answering carries a consumer inspector that answers the bulk check with
	// answer, as given.
	answering := func(answer authorize.Holdings) func(*testing.T, *gomock.Controller, authorize.Authorizer) authorize.Authorizer {
		return func(_ *testing.T, ctrl *gomock.Controller, _ authorize.Authorizer) authorize.Authorizer {
			inspector := NewMockInspectingAuthorizer(ctrl)
			inspector.EXPECT().InspectPrivileges(gomock.Any(), "crm", "lead", actions).Return(answer, nil)

			return inspector
		}
	}

	// brokenAnswer asserts a consumer inspector's answer was refused as a
	// wiring fault, with no holdings and no denial.
	brokenAnswer := func(t *testing.T, holdings authorize.Holdings, err error) {
		t.Helper()

		require.ErrorIs(t, err, authorize.ErrConfig)
		assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "a broken answer read as a denial")
		assert.Nil(t, holdings)
	}

	valid := func() authorize.Holdings {
		return authorize.Holdings{
			{Privilege: "view", Held: true, Scope: identity.ScopeAll},
			{Privilege: "update", Held: true, Scope: identity.ScopeOwn},
			{Privilege: "delete"},
		}
	}

	// given is the answer the consumer inspector keeps, to show the caller's
	// copy is its own.
	given := valid()

	// broken returns the valid answer with one change.
	broken := func(change func(authorize.Holdings) authorize.Holdings) authorize.Holdings {
		return change(valid())
	}

	cases := []testCase{
		{
			name:    "view all, update own, delete not held, one load",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(allowedActions(), nil).Times(1)
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				assert.Equal(t, authorize.Holdings{
					{Privilege: "view", Held: true, Scope: identity.ScopeAll},
					{Privilege: "update", Held: true, Scope: identity.ScopeOwn},
					{Privilege: "delete"},
				}, holdings)

				update, ok := holdings.Lookup("update")
				require.True(t, ok)
				assert.Equal(t, identity.ScopeOwn, update.Scope)

				_, ok = holdings.Lookup("archive")
				assert.False(t, ok, "a name not asked for was found")
			},
		},
		{
			name:   "no subject: nothing held, no load, no error",
			names:  actions,
			assert: nothingHeld,
		},
		{
			name: "no active role: nothing held, no load, no error",
			subject: func(ctx context.Context) context.Context {
				return identity.WithPrincipal(ctx, &identity.Principal{ID: "u-1"})
			},
			names:  actions,
			assert: nothingHeld,
		},
		{
			name:    "a blank active role: nothing held, no load, no error",
			subject: func(ctx context.Context) context.Context { return withRole(ctx, " ") },
			names:   actions,
			assert:  nothingHeld,
		},
		{
			name:    "a blank super role: nothing held",
			subject: func(ctx context.Context) context.Context { return superRole(ctx, "") },
			names:   actions,
			assert:  nothingHeld,
		},
		{
			name:    "super role holds everything with all, no load",
			subject: func(ctx context.Context) context.Context { return superRole(ctx, "root") },
			names:   actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				assert.Equal(t, authorize.Holdings{
					{Privilege: "view", Held: true, Scope: identity.ScopeAll},
					{Privilege: "update", Held: true, Scope: identity.ScopeAll},
					{Privilege: "delete", Held: true, Scope: identity.ScopeAll},
				}, holdings)
			},
		},
		{
			name:    "a role the loader does not know holds nothing",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(nil, identity.ErrPrivilegesNotFound)
			},
			names:  actions,
			assert: nothingHeld,
		},
		{
			name:    "a refused privilege and an undefined scope are not held",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(scoped("crm", "lead",
					identity.Privilege{Name: "view"},
					identity.Privilege{Name: "update", Granted: true, Scope: "team"},
				), nil)
			},
			names:  actions,
			assert: nothingHeld,
		},
		{
			name:    "empty names are invalid attributes",
			subject: clerk,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
				assert.Nil(t, holdings)
			},
		},
		{
			name:    "a blank name is invalid attributes",
			subject: clerk,
			names:   []string{"view", "  "},
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
				assert.Nil(t, holdings)
			},
		},
		{
			name:    "loader outage: the error matches and nothing is held",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(nil, errConnection)
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, errConnection)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "an outage read as a denial")
				assert.Empty(t, holdings)
			},
		},
		{
			name:    "a cancelled context surfaces the context's error",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
					DoAndReturn(func(ctx context.Context, _ string) ([]*identity.ResourcePrivileges, error) {
						return nil, ctx.Err()
					})
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, holdings)
			},
		},
		{
			name:    "an authorizer without the inspector is unsupported",
			subject: clerk,
			authorizer: func(_ *testing.T, ctrl *gomock.Controller, _ authorize.Authorizer) authorize.Authorizer {
				return NewMockAuthorizer(ctrl)
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrInspectionUnsupported)
				assert.Nil(t, holdings)
			},
		},
		{
			name: "no authorizer in the context denies",
			authorizer: func(*testing.T, *gomock.Controller, authorize.Authorizer) authorize.Authorizer {
				return nil
			},
			subject: clerk,
			names:   actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
				assert.ErrorIs(t, err, authorize.ErrNotGranted)
				assert.Nil(t, holdings)
			},
		},
		{
			name:    "FirstOf(ownership, privilege) forwards",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(allowedActions(), nil)
			},
			authorizer: func(t *testing.T, _ *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				manager, err := authorize.NewFirstOf(authorize.NewOwnershipAuthorizer(), privileges)
				require.NoError(t, err)

				return manager
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				require.Len(t, holdings, 3)
				assert.Equal(t, identity.ScopeOwn, holdings[1].Scope)
			},
		},
		{
			name:    "FirstOf forwards through a nested FirstOf",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(allowedActions(), nil)
			},
			authorizer: func(t *testing.T, _ *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				inner, err := authorize.NewFirstOf(privileges)
				require.NoError(t, err)

				outer, err := authorize.NewFirstOf(authorize.NewOwnershipAuthorizer(), inner)
				require.NoError(t, err)

				return outer
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				require.Len(t, holdings, 3)
				assert.True(t, holdings[0].Held)
			},
		},
		{
			// The consumer's authorizer comes first and may judge privilege
			// attributes itself; answering from the later one could disagree
			// with what Authorize decides, so the manager refuses to guess.
			name:    "FirstOf with a consumer authorizer before the inspector is unsupported",
			subject: clerk,
			authorizer: func(t *testing.T, ctrl *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				manager, err := authorize.NewFirstOf(NewMockAuthorizer(ctrl), privileges)
				require.NoError(t, err)

				return manager
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrInspectionUnsupported)
				assert.Nil(t, holdings)
			},
		},
		{
			name:    "FirstOf with only non-inspectors is unsupported",
			subject: clerk,
			authorizer: func(t *testing.T, _ *gomock.Controller, _ authorize.Authorizer) authorize.Authorizer {
				manager, err := authorize.NewFirstOf(authorize.NewOwnershipAuthorizer())
				require.NoError(t, err)

				return manager
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrInspectionUnsupported)
				assert.Nil(t, holdings)
			},
		},
		{
			name:    "FirstOf passes over an inspector that declines",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(allowedActions(), nil)
			},
			authorizer: func(t *testing.T, ctrl *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				declining := NewMockInspectingAuthorizer(ctrl)
				declining.EXPECT().InspectPrivileges(gomock.Any(), "crm", "lead", []string{"view", "update", "delete"}).
					Return(nil, authorize.ErrUnsupportedAttributes)

				manager, err := authorize.NewFirstOf(declining, privileges)
				require.NoError(t, err)

				return manager
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				require.Len(t, holdings, 3)
				assert.True(t, holdings[0].Held)
			},
		},
		{
			name:    "FirstOf returns an inspector's answer unchanged",
			subject: clerk,
			authorizer: func(t *testing.T, ctrl *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				answering := NewMockInspectingAuthorizer(ctrl)
				answering.EXPECT().InspectPrivileges(gomock.Any(), "crm", "lead", gomock.Any()).
					Return(nil, errConnection)

				manager, err := authorize.NewFirstOf(answering, privileges)
				require.NoError(t, err)

				return manager
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.ErrorIs(t, err, errConnection)
				assert.Nil(t, holdings)
			},
		},
		{
			name:       "a consumer inspector's valid answer is returned as the caller's own copy",
			subject:    clerk,
			authorizer: answering(given),
			names:      actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				assert.Equal(t, valid(), holdings)

				holdings[0].Held = false
				assert.True(t, given[0].Held, "the caller's holdings alias the inspector's answer")
			},
		},
		{
			name:       "a consumer inspector's nil answer is refused",
			subject:    clerk,
			authorizer: answering(nil),
			names:      actions,
			assert:     brokenAnswer,
		},
		{
			name:       "a consumer inspector's short answer is refused",
			subject:    clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings { return h[:2] })),
			names:      actions,
			assert:     brokenAnswer,
		},
		{
			name:    "a consumer inspector's long answer is refused",
			subject: clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings {
				return append(h, authorize.Holding{Privilege: "archive"})
			})),
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "a consumer inspector answering out of order is refused",
			subject: clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings {
				h[0], h[1] = h[1], h[0]

				return h
			})),
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "a consumer inspector answering another spelling is refused",
			subject: clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings {
				h[0].Privilege = "VIEW"

				return h
			})),
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "a consumer inspector holding with an undefined scope is refused",
			subject: clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings {
				h[0].Scope = "team"

				return h
			})),
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "a consumer inspector holding with no scope is refused",
			subject: clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings {
				h[0].Scope = ""

				return h
			})),
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "a consumer inspector not holding but naming a scope is refused",
			subject: clerk,
			authorizer: answering(broken(func(h authorize.Holdings) authorize.Holdings {
				h[2].Scope = identity.ScopeOwn

				return h
			})),
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "FirstOf refuses a member's broken answer",
			subject: clerk,
			authorizer: func(t *testing.T, ctrl *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				manager, err := authorize.NewFirstOf(answering(nil)(t, ctrl, nil), privileges)
				require.NoError(t, err)

				return manager
			},
			names:  actions,
			assert: brokenAnswer,
		},
		{
			name:    "FirstOf asks each member the names asked, whatever a declining member did to them",
			subject: clerk,
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(allowedActions(), nil)
			},
			authorizer: func(t *testing.T, ctrl *gomock.Controller, privileges authorize.Authorizer) authorize.Authorizer {
				mutating := NewMockInspectingAuthorizer(ctrl)
				mutating.EXPECT().InspectPrivileges(gomock.Any(), "crm", "lead", actions).
					DoAndReturn(func(_ context.Context, _, _ string, names []string) (authorize.Holdings, error) {
						names[0], names[2] = "delete", "view"

						return nil, authorize.ErrUnsupportedAttributes
					})

				manager, err := authorize.NewFirstOf(mutating, privileges)
				require.NoError(t, err)

				return manager
			},
			names: actions,
			assert: func(t *testing.T, holdings authorize.Holdings, err error) {
				require.NoError(t, err)
				assert.Equal(t, valid(), holdings)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			roles := NewMockRoleLoader(ctrl)
			if tc.expect != nil {
				tc.expect(roles)
			}

			privileges, err := authorize.NewPrivilegeAuthorizer(roles)
			require.NoError(t, err)

			var carried authorize.Authorizer = privileges
			if tc.authorizer != nil {
				carried = tc.authorizer(t, ctrl, privileges)
			}

			ctx := t.Context()
			if carried != nil {
				ctx = authorize.WithAuthorizer(ctx, carried)
			}

			if tc.subject != nil {
				ctx = tc.subject(ctx)
			}

			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			holdings, err := authorize.HeldPrivileges(ctx, "crm", "lead", tc.names...)
			tc.assert(t, holdings, err)
		})
	}
}

// TestHeldPrivileges_UnderMemo: bulk checks and a route check under one memo
// load once, and a caller that edits the holdings it was given changes nothing
// a later check sees.
func TestHeldPrivileges_UnderMemo(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(allowedActions(), nil).Times(1)

	privileges, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(authorize.WithAuthorizer(t.Context(), privileges), "clerk"))

	first, err := authorize.HeldPrivileges(ctx, "crm", "lead", "delete")
	require.NoError(t, err)
	require.Len(t, first, 1)

	first[0] = authorize.Holding{Privilege: "delete", Held: true, Scope: identity.ScopeAll}

	second, err := authorize.HeldPrivileges(ctx, "crm", "lead", "delete")
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.False(t, second[0].Held)

	require.NoError(t, privileges.Authorize(ctx, authorize.PrivilegeAttributes{
		Group: "crm", Resource: "lead", Required: []string{"view"},
	}))
}
