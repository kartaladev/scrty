package oidc_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// rolesIdentity is a verified corp identity with subject s-1, the one
// brokerSeededLinks links to u-1, carrying claims.
func rolesIdentity(claims map[string]any) oidc.ExternalIdentity {
	ext := brokerCorpIdentity()
	ext.Claims = claims
	return ext
}

// provisionedWithRoles matches the Provision options of an email-named corp
// user holding exactly roles.
func provisionedWithRoles(roles ...string) gomock.Matcher {
	return provisionedWith(
		identity.WithUserName("alice@corp.example"),
		identity.WithUserEmail("alice@corp.example"),
		identity.WithUserRoles(roles...),
	)
}

// roleNamesOf returns the names of p's roles, in order.
func roleNamesOf(p *identity.Principal) []string {
	names := []string{}
	for _, r := range p.Roles {
		names = append(names, r.Name)
	}
	return names
}

func TestBrokerRoles(t *testing.T) {
	t.Parallel()

	realmRoles := func(roles ...any) map[string]any {
		return map[string]any{"realm_access": map[string]any{"roles": roles}}
	}
	realmPath := oidc.WithRoleClaim("corp", "realm_access.roles")
	created := &identity.Details{ID: "u-9", Username: "alice@corp.example", Active: true}

	// provisionsWith expects one Provision naming exactly roles.
	provisionsWith := func(roles ...string) func(prov *MockUserProvisioner, _ *MockUserLoader) {
		return func(prov *MockUserProvisioner, _ *MockUserLoader) {
			prov.EXPECT().Provision(gomock.Any(), "alice@corp.example", provisionedWithRoles(roles...)).Return(created, nil)
		}
	}
	provisioned := func(t *testing.T, _ *identity.Principal, err error, _ string) {
		t.Helper()
		require.NoError(t, err)
	}
	// loads expects u-1 to load as stored.
	loads := func(stored *identity.Details) func(*MockUserProvisioner, *MockUserLoader) {
		return func(_ *MockUserProvisioner, users *MockUserLoader) {
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(stored, nil)
		}
	}
	storedWith := func(roles ...*identity.AssignedRole) *identity.Details {
		return &identity.Details{ID: "u-1", Username: "alice", Active: true, Roles: roles}
	}

	type testCase struct {
		name   string
		linked bool // (corp, s-1) is linked to u-1; otherwise it is provisioned
		opts   []oidc.BrokerOption
		claims map[string]any
		expect func(prov *MockUserProvisioner, users *MockUserLoader)
		assert func(t *testing.T, p *identity.Principal, err error, logs string)
	}

	cases := []testCase{
		// Provisioning.
		{
			name:   "with no claim path the default role is given",
			opts:   []oidc.BrokerOption{oidc.WithDefaultRole("member")},
			expect: provisionsWith("member"),
			assert: provisioned,
		},
		{
			name:   "with neither a claim path nor a default no role is given",
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "a nested claim path gives the roles it holds",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithDefaultRole("member")},
			claims: realmRoles("editor", "viewer"),
			expect: provisionsWith("editor", "viewer"),
			assert: provisioned,
		},
		{
			name:   "a string array leaf is read as roles",
			opts:   []oidc.BrokerOption{realmPath},
			claims: map[string]any{"realm_access": map[string]any{"roles": []string{"viewer", "editor"}}},
			expect: provisionsWith("viewer", "editor"),
			assert: provisioned,
		},
		{
			name:   "a single string leaf is one role",
			opts:   []oidc.BrokerOption{oidc.WithRoleClaim("corp", "role")},
			claims: map[string]any{"role": "editor"},
			expect: provisionsWith("editor"),
			assert: provisioned,
		},
		{
			name:   "an explicitly empty claim path gives no role and no default",
			opts:   []oidc.BrokerOption{oidc.WithRoleClaim("corp", ""), oidc.WithDefaultRole("member")},
			claims: realmRoles("editor"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "a claim path that resolves to nothing does not fall back to the default",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithDefaultRole("member")},
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "a claim path resolving to a number gives no role and one log record",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithDefaultRole("member")},
			claims: map[string]any{"realm_access": map[string]any{"roles": 42.0}},
			expect: provisionsWith(),
			assert: func(t *testing.T, _ *identity.Principal, err error, logs string) {
				require.NoError(t, err, "a malformed role claim does not fail the login")
				lines := linesContaining(logs, "role claim")
				require.Len(t, lines, 1)
				assert.Contains(t, lines[0], "provider=corp")
				assert.NotContains(t, lines[0], "42")
			},
		},
		{
			name:   "an array holding a non-string gives no role",
			opts:   []oidc.BrokerOption{realmPath},
			claims: realmRoles("editor", 7.0),
			expect: provisionsWith(),
			assert: func(t *testing.T, _ *identity.Principal, err error, logs string) {
				require.NoError(t, err)
				assert.Len(t, linesContaining(logs, "role claim"), 1)
			},
		},
		{
			name:   "an array holding an empty string gives no role",
			opts:   []oidc.BrokerOption{realmPath},
			claims: realmRoles("", "admin"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "the allowlist drops a self-assigned administrative role",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithAllowedRoles("corp", "editor", "viewer")},
			claims: realmRoles("admin", "viewer"),
			expect: provisionsWith("viewer"),
			assert: func(t *testing.T, _ *identity.Principal, err error, logs string) {
				require.NoError(t, err)
				assert.NotContains(t, logs, "admin", "no claim value reaches a log")
			},
		},
		{
			name:   "the mapping drops an unmapped value",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleMapping("corp", map[string]string{"corp-editors": "editor"})},
			claims: realmRoles("corp-editors", "corp-admins"),
			expect: provisionsWith("editor"),
			assert: provisioned,
		},
		{
			name: "the allowlist applies to the mapped names",
			opts: []oidc.BrokerOption{
				realmPath,
				oidc.WithRoleMapping("corp", map[string]string{"corp-editors": "editor", "corp-admins": "admin"}),
				oidc.WithAllowedRoles("corp", "editor"),
			},
			claims: realmRoles("corp-admins", "corp-editors"),
			expect: provisionsWith("editor"),
			assert: provisioned,
		},
		{
			name:   "a mapping configured empty drops every role",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleMapping("corp", map[string]string{})},
			claims: realmRoles("editor"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "a nil mapping is a mapping configured empty",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleMapping("corp", nil)},
			claims: realmRoles("editor"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "an allowlist configured empty drops every role",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithAllowedRoles("corp")},
			claims: realmRoles("editor"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "the allowlist also applies to the default role",
			opts:   []oidc.BrokerOption{oidc.WithDefaultRole("member"), oidc.WithAllowedRoles("corp", "editor")},
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "the allowlist matches case-sensitively",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithAllowedRoles("corp", "Editor")},
			claims: realmRoles("editor"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "the mapping matches case-sensitively",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleMapping("corp", map[string]string{"Corp-Editors": "editor"})},
			claims: realmRoles("corp-editors"),
			expect: provisionsWith(),
			assert: provisioned,
		},
		{
			name:   "another provider's mapping and allowlist leave corp alone",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleMapping("social", map[string]string{}), oidc.WithAllowedRoles("social")},
			claims: realmRoles("editor"),
			expect: provisionsWith("editor"),
			assert: provisioned,
		},

		// Role sync.
		{
			name:   "role sync replaces the stored roles and writes nothing",
			linked: true,
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleSync("corp", true)},
			claims: realmRoles("editor"),
			expect: loads(storedWith(&identity.AssignedRole{ID: "g-1", Name: "viewer", Primary: true})),
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"editor"}, roleNamesOf(p))
				assert.Equal(t, &identity.AssignedRole{Name: "editor", Primary: true}, p.Roles[0])
				require.NotNil(t, p.ActiveRole)
				assert.Equal(t, "editor", p.ActiveRole.Name)
			},
		},
		{
			name:   "a stored super role does not survive sync",
			linked: true,
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleSync("corp", true)},
			claims: realmRoles("admin", "viewer"),
			expect: loads(storedWith(&identity.AssignedRole{
				ID: "g-1", Name: "admin", Primary: true, SuperRole: true,
				StartDate: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
			})),
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []*identity.AssignedRole{
					{Name: "admin", Primary: true},
					{Name: "viewer"},
				}, p.Roles, "synced roles carry only the name and the primary flag")
			},
		},
		{
			name:   "role sync applies the mapping and the allowlist",
			linked: true,
			opts: []oidc.BrokerOption{
				realmPath, oidc.WithRoleSync("corp", true),
				oidc.WithRoleMapping("corp", map[string]string{"corp-admins": "admin", "corp-viewers": "viewer"}),
				oidc.WithAllowedRoles("corp", "viewer"),
			},
			claims: realmRoles("corp-admins", "corp-viewers", "corp-editors"),
			expect: loads(storedWith()),
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"viewer"}, roleNamesOf(p))
				assert.True(t, p.Roles[0].Primary)
			},
		},
		{
			name:   "role sync with nothing at the path leaves the principal with no role",
			linked: true,
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleSync("corp", true)},
			expect: loads(storedWith(&identity.AssignedRole{Name: "viewer", Primary: true})),
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, p.Roles)
				assert.Nil(t, p.ActiveRole)
			},
		},
		{
			name:   "without role sync the stored roles are kept",
			linked: true,
			opts:   []oidc.BrokerOption{realmPath},
			claims: realmRoles("editor"),
			expect: loads(storedWith(&identity.AssignedRole{Name: "viewer", Primary: true})),
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"viewer"}, roleNamesOf(p))
			},
		},
		{
			name:   "role sync for another provider leaves corp's stored roles",
			linked: true,
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleClaim("social", "roles"), oidc.WithRoleSync("social", true)},
			claims: realmRoles("editor"),
			expect: loads(storedWith(&identity.AssignedRole{Name: "viewer", Primary: true})),
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"viewer"}, roleNamesOf(p))
			},
		},
		{
			name:   "role sync applies to a provisioned login too",
			opts:   []oidc.BrokerOption{realmPath, oidc.WithRoleSync("corp", true)},
			claims: realmRoles("editor"),
			expect: func(prov *MockUserProvisioner, _ *MockUserLoader) {
				prov.EXPECT().Provision(gomock.Any(), "alice@corp.example", provisionedWithRoles("editor")).
					Return(&identity.Details{
						ID: "u-9", Username: "alice@corp.example", Active: true,
						Roles: []*identity.AssignedRole{{ID: "g-9", Name: "editor", Primary: true, SuperRole: true}},
					}, nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []*identity.AssignedRole{{Name: "editor", Primary: true}}, p.Roles)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			prov := NewMockUserProvisioner(ctrl)
			users := NewMockUserLoader(ctrl)
			tc.expect(prov, users)

			links := oidc.LinkStore(oidc.NewMemoryLinkStore())
			if tc.linked {
				links = brokerSeededLinks(t)
			}

			var logs bytes.Buffer
			opts := append([]oidc.BrokerOption{
				oidc.WithProvisioner(prov),
				oidc.WithJIT("corp"),
				oidc.WithBrokerLogger(testTextLogger(&logs)),
			}, tc.opts...)
			b, err := oidc.NewBroker(links, users, opts...)
			require.NoError(t, err)

			p, err := b.Broker(t.Context(), rolesIdentity(tc.claims))
			tc.assert(t, p, err, logs.String())
		})
	}
}

// TestBrokerRolesSyncIsNotPersisted pins that a synced login leaves the
// record the loader returned untouched, so the next load reads the stored
// roles again. It differs from TestBrokerRoles in keeping the loaded record.
func TestBrokerRolesSyncIsNotPersisted(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	stored := &identity.Details{
		ID: "u-1", Username: "alice", Active: true,
		Roles: []*identity.AssignedRole{{ID: "g-1", Name: "viewer", Primary: true}},
	}
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(stored, nil).Times(2)

	b, err := oidc.NewBroker(brokerSeededLinks(t), users,
		oidc.WithProvisioner(NewMockUserProvisioner(ctrl)), // no Update expected
		oidc.WithRoleClaim("corp", "roles"), oidc.WithRoleSync("corp", true))
	require.NoError(t, err)

	first, err := b.Broker(t.Context(), rolesIdentity(map[string]any{"roles": []any{"editor"}}))
	require.NoError(t, err)
	assert.Equal(t, []string{"editor"}, roleNamesOf(first))
	assert.Equal(t, "viewer", stored.Roles[0].Name, "the stored record is not changed")
	assert.Equal(t, "g-1", stored.Roles[0].ID)

	second, err := b.Broker(t.Context(), rolesIdentity(map[string]any{"roles": []any{"auditor"}}))
	require.NoError(t, err)
	assert.Equal(t, []string{"auditor"}, roleNamesOf(second), "the next login derives them again")
}

func TestBrokerRolesOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.BrokerOption
		assert func(t *testing.T, b *oidc.Broker, err error)
	}

	refused := func(fragments ...string) func(t *testing.T, b *oidc.Broker, err error) {
		return func(t *testing.T, b *oidc.Broker, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, b)
			for _, f := range fragments {
				assert.Contains(t, err.Error(), f)
			}
		}
	}

	cases := []testCase{
		{
			name:   "role sync without a claim path is refused naming the provider",
			opts:   []oidc.BrokerOption{oidc.WithRoleSync("corp", true)},
			assert: refused(`"corp"`, "WithRoleSync"),
		},
		{
			name:   "role sync with an explicitly empty claim path is refused",
			opts:   []oidc.BrokerOption{oidc.WithRoleClaim("corp", ""), oidc.WithRoleSync("corp", true)},
			assert: refused(`"corp"`, "WithRoleSync"),
		},
		{
			name: "role sync turned off needs no claim path",
			opts: []oidc.BrokerOption{oidc.WithRoleSync("corp", false)},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Empty(t, b.RoleSyncProviders())
				assert.Equal(t, []string{"corp"}, b.ConfiguredProviders())
			},
		},
		{
			name: "RoleSyncProviders lists exactly the providers with sync on, sorted",
			opts: []oidc.BrokerOption{
				oidc.WithRoleClaim("social", "roles"), oidc.WithRoleSync("social", true),
				oidc.WithRoleClaim("corp", "roles"), oidc.WithRoleSync("corp", true),
				oidc.WithRoleClaim("partner", "roles"), oidc.WithRoleSync("partner", false),
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				got := b.RoleSyncProviders()
				require.Equal(t, []string{"corp", "social"}, got)
				got[0] = "changed"
				assert.Equal(t, []string{"corp", "social"}, b.RoleSyncProviders(), "the slice is the caller's own")
			},
		},
		{
			name: "a later WithRoleSync for a provider replaces an earlier one",
			opts: []oidc.BrokerOption{
				oidc.WithRoleClaim("corp", "roles"), oidc.WithRoleSync("corp", true), oidc.WithRoleSync("corp", false),
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Empty(t, b.RoleSyncProviders())
			},
		},
		{
			name: "a role claim path equal to the password path is refused",
			opts: []oidc.BrokerOption{
				oidc.WithPasswordClaim("corp", "credentials.password_hash"),
				oidc.WithRoleClaim("corp", "credentials.password_hash"),
			},
			assert: refused(`"corp"`, "role"),
		},
		{
			name: "role options name their providers",
			opts: []oidc.BrokerOption{
				oidc.WithRoleClaim("corp", "roles"), oidc.WithRoleMapping("social", map[string]string{"a": "b"}),
				oidc.WithAllowedRoles("partner", "viewer"),
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corp", "social", "partner"}, b.ConfiguredProviders())
			},
		},
		{
			name:   "an empty provider for the role claim is refused",
			opts:   []oidc.BrokerOption{oidc.WithRoleClaim("", "roles")},
			assert: refused("WithRoleClaim"),
		},
		{
			name:   "an empty provider for the role mapping is refused",
			opts:   []oidc.BrokerOption{oidc.WithRoleMapping("", map[string]string{"a": "b"})},
			assert: refused("WithRoleMapping"),
		},
		{
			name:   "an empty local role in the mapping is refused",
			opts:   []oidc.BrokerOption{oidc.WithRoleMapping("corp", map[string]string{"corp-editors": ""})},
			assert: refused("WithRoleMapping", `"corp"`),
		},
		{
			name:   "an empty provider for the allowlist is refused",
			opts:   []oidc.BrokerOption{oidc.WithAllowedRoles("", "viewer")},
			assert: refused("WithAllowedRoles"),
		},
		{
			name:   "an empty role in the allowlist is refused",
			opts:   []oidc.BrokerOption{oidc.WithAllowedRoles("corp", "viewer", "")},
			assert: refused("WithAllowedRoles", `"corp"`),
		},
		{
			name:   "an empty provider for role sync is refused",
			opts:   []oidc.BrokerOption{oidc.WithRoleSync("", true)},
			assert: refused("WithRoleSync"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			opts := append([]oidc.BrokerOption{oidc.WithPasswordEncoder(fastBcryptEncoder(t))}, tc.opts...)
			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), opts...)
			tc.assert(t, b, err)
		})
	}
}

// A mapping the consumer changes after construction does not change the
// broker's.
func TestBrokerRolesMappingIsCopied(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	prov := NewMockUserProvisioner(ctrl)
	prov.EXPECT().Provision(gomock.Any(), "alice@corp.example", provisionedWithRoles("editor")).
		Return(&identity.Details{ID: "u-9", Username: "alice@corp.example", Active: true}, nil)

	mapping := map[string]string{"corp-editors": "editor"}
	allowed := []string{"editor"}
	b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl),
		oidc.WithProvisioner(prov), oidc.WithJIT("corp"),
		oidc.WithRoleClaim("corp", "roles"), oidc.WithRoleMapping("corp", mapping), oidc.WithAllowedRoles("corp", allowed...))
	require.NoError(t, err)
	mapping["corp-editors"] = "admin"
	allowed[0] = "admin"

	_, err = b.Broker(t.Context(), rolesIdentity(map[string]any{"roles": []any{"corp-editors"}}))
	require.NoError(t, err)
}
