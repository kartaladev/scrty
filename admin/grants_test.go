package admin_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// crmCatalogue declares crm/lead with view and update at any scope and create
// at scope all only, and crm/deal with view.
func crmCatalogue(t *testing.T) *authorize.Catalogue {
	t.Helper()

	cat, err := authorize.NewCatalogue(
		authorize.CatalogueResource{Group: "crm", Name: "lead", Privileges: []authorize.CataloguePrivilege{
			{Name: "view"}, {Name: "update"}, {Name: "create", Scopes: []identity.Scope{identity.ScopeAll}},
		}},
		authorize.CatalogueResource{Group: "crm", Name: "deal", Privileges: []authorize.CataloguePrivilege{{Name: "view"}}},
	)
	require.NoError(t, err)

	return cat
}

func TestNewGrants(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (*admin.Grants, error)
		assert func(t *testing.T, g *admin.Grants, err error)
	}

	refused := func(t *testing.T, g *admin.Grants, err error) {
		assert.ErrorIs(t, err, admin.ErrConfig)
		assert.Nil(t, g)
	}
	store := func(t *testing.T) admin.GrantStore { return NewMockGrantStore(gomock.NewController(t)) }

	cases := []testCase{
		{name: "store and catalogue", build: func(t *testing.T) (*admin.Grants, error) {
			return admin.NewGrants(store(t), crmCatalogue(t))
		}, assert: func(t *testing.T, g *admin.Grants, err error) {
			require.NoError(t, err)
			assert.NotNil(t, g)
		}},
		{name: "nil catalogue", build: func(t *testing.T) (*admin.Grants, error) {
			return admin.NewGrants(store(t), nil)
		}, assert: refused},
		{name: "nil store", build: func(t *testing.T) (*admin.Grants, error) {
			return admin.NewGrants(nil, crmCatalogue(t))
		}, assert: refused},
		{name: "audit given twice", build: func(t *testing.T) (*admin.Grants, error) {
			sink := (&auditRecorder{}).sink
			return admin.NewGrants(store(t), crmCatalogue(t), admin.WithAudit(sink), admin.WithAudit(sink))
		}, assert: refused},
		{name: "nil audit", build: func(t *testing.T) (*admin.Grants, error) {
			return admin.NewGrants(store(t), crmCatalogue(t), admin.WithAudit(nil))
		}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g, err := tc.build(t)
			tc.assert(t, g, err)
		})
	}
}

func TestGrants(t *testing.T) {
	t.Parallel()

	lead := func(grants ...admin.Grant) admin.ResourceGrants {
		return admin.ResourceGrants{Group: "crm", Resource: "lead", Grants: grants}
	}
	grant := func(privilege string, scope identity.Scope) admin.Grant {
		return admin.Grant{Privilege: privilege, Granted: true, Scope: scope}
	}

	type testCase struct {
		name      string
		resources []admin.ResourceGrants
		version   int64
		setup     func(store *MockGrantStore)
		assert    func(t *testing.T, version int64, err error)
	}

	unknownNoCall := func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrUnknownPrivilege) }
	invalidNoCall := func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrInvalidInput) }
	noCall := func(*MockGrantStore) {}

	cases := []testCase{
		{
			name:      "listed privileges reach the store with each grant's resource filled in",
			resources: []admin.ResourceGrants{lead(grant("view", identity.ScopeAll), grant("update", identity.ScopeOwn))},
			version:   4,
			setup: func(store *MockGrantStore) {
				want := []admin.ResourceGrants{{Group: "crm", Resource: "lead", Grants: []admin.Grant{
					{Group: "crm", Resource: "lead", Privilege: "view", Granted: true, Scope: identity.ScopeAll},
					{Group: "crm", Resource: "lead", Privilege: "update", Granted: true, Scope: identity.ScopeOwn},
				}}}
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), want).Return(int64(5), nil)
			},
			assert: func(t *testing.T, version int64, err error) {
				require.NoError(t, err)
				assert.Equal(t, int64(5), version)
			},
		},
		{
			name: "names reach the store as the catalogue declares them", version: 4,
			resources: []admin.ResourceGrants{{Group: "CRM", Resource: " Lead ", Grants: []admin.Grant{
				{Privilege: "VIEW ", Granted: true},
				{Group: "Crm", Resource: "LEAD", Privilege: " Update", Granted: true, Scope: identity.ScopeOwn},
			}}},
			setup: func(store *MockGrantStore) {
				want := []admin.ResourceGrants{{Group: "crm", Resource: "lead", Grants: []admin.Grant{
					{Group: "crm", Resource: "lead", Privilege: "view", Granted: true},
					{Group: "crm", Resource: "lead", Privilege: "update", Granted: true, Scope: identity.ScopeOwn},
				}}}
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), want).Return(int64(5), nil)
			},
			assert: func(t *testing.T, _ int64, err error) { require.NoError(t, err) },
		},
		{
			name: "clearing an unlisted resource trims its names", version: 4,
			resources: []admin.ResourceGrants{{Group: " crm", Resource: "ghost "}},
			setup: func(store *MockGrantStore) {
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4),
					[]admin.ResourceGrants{{Group: "crm", Resource: "ghost", Grants: []admin.Grant{}}}).Return(int64(5), nil)
			},
			assert: func(t *testing.T, _ int64, err error) { require.NoError(t, err) },
		},
		{
			name: "an empty scope reads as all", version: 4,
			resources: []admin.ResourceGrants{lead(grant("create", ""))},
			setup: func(store *MockGrantStore) {
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), gomock.Any()).Return(int64(5), nil)
			},
			assert: func(t *testing.T, _ int64, err error) { require.NoError(t, err) },
		},
		{
			name: "unlisted privilege", version: 4, setup: noCall, assert: unknownNoCall,
			resources: []admin.ResourceGrants{lead(grant("view", identity.ScopeAll), grant("purge", identity.ScopeAll))},
		},
		{
			name: "scope the catalogue does not allow", version: 4, setup: noCall, assert: unknownNoCall,
			resources: []admin.ResourceGrants{lead(grant("create", identity.ScopeOwn))},
		},
		{
			name: "undefined scope", version: 4, setup: noCall, assert: unknownNoCall,
			resources: []admin.ResourceGrants{lead(grant("view", "team"))},
		},
		{
			name: "unlisted resource", version: 4, setup: noCall, assert: unknownNoCall,
			resources: []admin.ResourceGrants{{Group: "crm", Resource: "ghost", Grants: []admin.Grant{grant("view", "")}}},
		},
		{
			name: "clearing a resource the catalogue no longer lists is allowed", version: 4,
			resources: []admin.ResourceGrants{{Group: "crm", Resource: "ghost"}},
			setup: func(store *MockGrantStore) {
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4),
					[]admin.ResourceGrants{{Group: "crm", Resource: "ghost", Grants: []admin.Grant{}}}).Return(int64(5), nil)
			},
			assert: func(t *testing.T, _ int64, err error) { require.NoError(t, err) },
		},
		{
			name: "an unknown privilege in a later resource writes nothing", version: 4, setup: noCall,
			assert: unknownNoCall,
			resources: []admin.ResourceGrants{
				lead(grant("view", "")),
				{Group: "crm", Resource: "deal", Grants: []admin.Grant{grant("update", "")}},
			},
		},
		{
			name: "a grant naming another resource", version: 4, setup: noCall, assert: invalidNoCall,
			resources: []admin.ResourceGrants{lead(admin.Grant{Group: "crm", Resource: "deal", Privilege: "view"})},
		},
		{
			name: "a resource named twice", version: 4, setup: noCall, assert: invalidNoCall,
			resources: []admin.ResourceGrants{lead(grant("view", "")), {Group: "CRM", Resource: " lead"}},
		},
		{
			name: "a privilege named twice", version: 4, setup: noCall, assert: invalidNoCall,
			resources: []admin.ResourceGrants{lead(grant("view", identity.ScopeAll), grant("VIEW", identity.ScopeOwn))},
		},
		{
			name: "no resources", version: 4, setup: noCall, assert: invalidNoCall,
		},
		{
			name: "version zero", version: 0, setup: noCall, assert: invalidNoCall,
			resources: []admin.ResourceGrants{lead(grant("view", ""))},
		},
		{
			name: "stale update passes through", version: 4,
			resources: []admin.ResourceGrants{lead(grant("view", ""))},
			setup: func(store *MockGrantStore) {
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), gomock.Any()).Return(int64(0), admin.ErrStaleUpdate)
			},
			assert: func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrStaleUpdate) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockGrantStore(gomock.NewController(t))
			tc.setup(store)

			g, err := admin.NewGrants(store, crmCatalogue(t))
			require.NoError(t, err)

			version, err := g.Replace(actorCtx(t), "sales", tc.version, tc.resources...)
			tc.assert(t, version, err)
		})
	}
}

// TestGrants_RefusesWithoutActor pins that a replacement with no actor reaches
// no store.
func TestGrants_RefusesWithoutActor(t *testing.T) {
	t.Parallel()

	g, err := admin.NewGrants(NewMockGrantStore(gomock.NewController(t)), crmCatalogue(t))
	require.NoError(t, err)

	_, err = g.Replace(context.WithoutCancel(t.Context()), "sales", 4,
		admin.ResourceGrants{Group: "crm", Resource: "lead"})
	require.ErrorIs(t, err, admin.ErrNoActor)
}
