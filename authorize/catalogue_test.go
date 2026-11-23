package authorize_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// lead declares crm/lead with the six privileges an application typically
// grants on it; create allows only all.
func lead() authorize.CatalogueResource {
	return authorize.CatalogueResource{
		Group: "crm", Name: "lead", DisplayName: "Lead",
		Privileges: []authorize.CataloguePrivilege{
			{Name: "view", DisplayName: "View"},
			{Name: "create", DisplayName: "Create", Scopes: []identity.Scope{identity.ScopeAll}},
			{Name: "update", DisplayName: "Update"},
			{Name: "delete", DisplayName: "Delete"},
			{Name: "print", DisplayName: "Print"},
			{Name: "assign", DisplayName: "Assign"},
		},
	}
}

func TestNewCatalogue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		resources func() []authorize.CatalogueResource
		assert    func(t *testing.T, catalogue *authorize.Catalogue, err error)
	}

	refused := func(t *testing.T, catalogue *authorize.Catalogue, err error) {
		require.ErrorIs(t, err, authorize.ErrConfig)
		assert.Nil(t, catalogue)
	}

	// with returns lead() changed by change.
	with := func(change func(r *authorize.CatalogueResource)) func() []authorize.CatalogueResource {
		return func() []authorize.CatalogueResource {
			r := lead()
			change(&r)

			return []authorize.CatalogueResource{r}
		}
	}

	cases := []testCase{
		{
			name:      "a declared resource is read back in the declared order, defaults filled in",
			resources: func() []authorize.CatalogueResource { return []authorize.CatalogueResource{lead()} },
			assert: func(t *testing.T, catalogue *authorize.Catalogue, err error) {
				require.NoError(t, err)

				got := catalogue.Resources()
				require.Len(t, got, 1)
				assert.Equal(t, "crm", got[0].Group)
				assert.Equal(t, "lead", got[0].Name)
				assert.Equal(t, "Lead", got[0].DisplayName)

				names := make([]string, 0, len(got[0].Privileges))
				for _, p := range got[0].Privileges {
					names = append(names, p.Name)
				}

				assert.Equal(t, []string{"view", "create", "update", "delete", "print", "assign"}, names)
				assert.Equal(t, []identity.Scope{identity.ScopeAll, identity.ScopeOwn}, got[0].Privileges[0].Scopes,
					"a privilege declared without scopes does not allow both")
				assert.Equal(t, []identity.Scope{identity.ScopeAll}, got[0].Privileges[1].Scopes)
			},
		},
		{
			name:      "no resources is a configuration error",
			resources: func() []authorize.CatalogueResource { return nil },
			assert:    refused,
		},
		{name: "a blank group", resources: with(func(r *authorize.CatalogueResource) { r.Group = " " }), assert: refused},
		{name: "a blank resource name", resources: with(func(r *authorize.CatalogueResource) { r.Name = "" }), assert: refused},
		{
			name:      "a blank privilege name",
			resources: with(func(r *authorize.CatalogueResource) { r.Privileges[2].Name = "\t" }),
			assert:    refused,
		},
		{
			name:      "a resource with no privileges",
			resources: with(func(r *authorize.CatalogueResource) { r.Privileges = nil }),
			assert:    refused,
		},
		{
			name: "a privilege declared twice under the default comparison",
			resources: with(func(r *authorize.CatalogueResource) {
				r.Privileges = append(r.Privileges, authorize.CataloguePrivilege{Name: "VIEW"})
			}),
			assert: refused,
		},
		{
			name: "a resource declared twice under the default comparison",
			resources: func() []authorize.CatalogueResource {
				again := lead()
				again.Group, again.Name = " CRM", "Lead "

				return []authorize.CatalogueResource{lead(), again}
			},
			assert: refused,
		},
		{
			name: "the same privilege name on two resources is fine",
			resources: func() []authorize.CatalogueResource {
				deal := lead()
				deal.Name = "deal"

				return []authorize.CatalogueResource{lead(), deal}
			},
			assert: func(t *testing.T, catalogue *authorize.Catalogue, err error) {
				require.NoError(t, err)
				assert.Len(t, catalogue.Resources(), 2)
			},
		},
		{
			name: "an undefined scope",
			resources: with(func(r *authorize.CatalogueResource) {
				r.Privileges[0].Scopes = []identity.Scope{"team"}
			}),
			assert: refused,
		},
		{
			name: "a blank scope",
			resources: with(func(r *authorize.CatalogueResource) {
				r.Privileges[0].Scopes = []identity.Scope{identity.ScopeAll, ""}
			}),
			assert: refused,
		},
		{
			name: "a scope listed twice",
			resources: with(func(r *authorize.CatalogueResource) {
				r.Privileges[0].Scopes = []identity.Scope{identity.ScopeOwn, identity.ScopeOwn}
			}),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			catalogue, err := authorize.NewCatalogue(tc.resources()...)
			tc.assert(t, catalogue, err)
		})
	}
}

func TestCatalogue_Allows(t *testing.T) {
	t.Parallel()

	catalogue, err := authorize.NewCatalogue(lead())
	require.NoError(t, err)

	type testCase struct {
		name                       string
		group, resource, privilege string
		scope                      identity.Scope
		allowed                    bool
	}

	cases := []testCase{
		{name: "own on a privilege allowing both", group: "crm", resource: "lead", privilege: "view", scope: identity.ScopeOwn, allowed: true},
		{name: "names compared as the authorizer does", group: "CRM", resource: " Lead", privilege: "VIEW", scope: identity.ScopeOwn, allowed: true},
		{name: "all on a privilege restricted to all", group: "crm", resource: "lead", privilege: "create", scope: identity.ScopeAll, allowed: true},
		{name: "own on a privilege restricted to all", group: "crm", resource: "lead", privilege: "create", scope: identity.ScopeOwn},
		{name: "the empty scope reads as all", group: "crm", resource: "lead", privilege: "create", scope: "", allowed: true},
		{name: "an undefined scope", group: "crm", resource: "lead", privilege: "view", scope: "team"},
		{name: "an unknown resource", group: "crm", resource: "ghost", privilege: "view", scope: identity.ScopeAll},
		{name: "an unknown privilege", group: "crm", resource: "lead", privilege: "export", scope: identity.ScopeAll},
		{name: "a Unicode look-alike name", group: "crm", resource: "lead", privilege: "aſsign", scope: identity.ScopeAll},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.allowed, catalogue.Allows(tc.group, tc.resource, tc.privilege, tc.scope))
		})
	}
}

func TestCatalogue_IsImmutable(t *testing.T) {
	t.Parallel()

	declared := []authorize.CatalogueResource{lead()}

	catalogue, err := authorize.NewCatalogue(declared...)
	require.NoError(t, err)

	// The caller changes what it declared, at every level.
	declared[0].Name = "deal"
	declared[0].Privileges[0].Name = "export"
	declared[0].Privileges[1].Scopes[0] = identity.ScopeOwn

	// And a reader changes what it was handed.
	read := catalogue.Resources()
	read[0].Group = "hr"
	read[0].Privileges[2].Name = "erase"
	read[0].Privileges[0].Scopes[0] = "team"

	again := catalogue.Resources()
	assert.Equal(t, "crm", again[0].Group)
	assert.Equal(t, "lead", again[0].Name)
	assert.Equal(t, "view", again[0].Privileges[0].Name)
	assert.Equal(t, "update", again[0].Privileges[2].Name)
	assert.Equal(t, []identity.Scope{identity.ScopeAll, identity.ScopeOwn}, again[0].Privileges[0].Scopes)
	assert.Equal(t, []identity.Scope{identity.ScopeAll}, again[0].Privileges[1].Scopes)
	assert.False(t, catalogue.Allows("crm", "lead", "create", identity.ScopeOwn))
}

func TestCatalogue_Absent(t *testing.T) {
	t.Parallel()

	var absent *authorize.Catalogue

	assert.False(t, absent.Allows("crm", "lead", "view", identity.ScopeAll))
	assert.Nil(t, absent.Resources())
}
