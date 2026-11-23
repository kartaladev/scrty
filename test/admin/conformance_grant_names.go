package admintest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// runGrantNameCases checks how a grant replacement names resources and
// privileges: an existing row of a resource is matched by group and resource
// as the authorizer reads them (surrounding ASCII space trimmed, ASCII case
// ignored), the rows it inserts carry the names as given, and an empty
// resource or privilege name is invalid input that writes nothing.
func runGrantNameCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		rgs  []admin.ResourceGrants
		// assert receives the grants and version seeded for the role (crm/lead
		// and crm/deal), the grants and version read after the call, and the
		// call's version and error.
		assert func(t *testing.T, seeded []admin.Grant, before int64, after []admin.Grant, afterVersion, returned int64, err error)
	}

	view := admin.Grant{Privilege: "view", Granted: true, Scope: identity.ScopeAll}
	onlyDeal := func(seeded []admin.Grant) []admin.Grant {
		var out []admin.Grant
		for _, g := range seeded {
			if g.Resource == deal {
				out = append(out, g)
			}
		}

		return out
	}
	untouched := func(t *testing.T, seeded []admin.Grant, before int64, after []admin.Grant, afterVersion int64) {
		t.Helper()

		assert.ElementsMatch(t, normalGrants(seeded), normalGrants(after), "nothing is written")
		assert.Equal(t, before, afterVersion, "the version does not move")
	}

	cases := []testCase{
		{
			name: "an empty list for another spelling of a resource removes its grants",
			rgs:  []admin.ResourceGrants{{Group: "CRM", Resource: "Lead"}},
			assert: func(t *testing.T, seeded []admin.Grant, _ int64, after []admin.Grant, _, _ int64, err error) {
				require.NoError(t, err)
				assert.ElementsMatch(t, normalGrants(onlyDeal(seeded)), normalGrants(after),
					"no grant of crm/lead is left and crm/deal is unchanged")
			},
		},
		{
			name: "surrounding space and case are ignored when matching",
			rgs:  []admin.ResourceGrants{{Group: " CRM\t", Resource: "\nLEAD "}},
			assert: func(t *testing.T, seeded []admin.Grant, _ int64, after []admin.Grant, _, _ int64, err error) {
				require.NoError(t, err)
				assert.ElementsMatch(t, normalGrants(onlyDeal(seeded)), normalGrants(after))
			},
		},
		{
			name: "the rows it inserts carry the names as given",
			rgs:  []admin.ResourceGrants{grantsFor("CRM", "Lead", view)},
			assert: func(t *testing.T, seeded []admin.Grant, _ int64, after []admin.Grant, _, _ int64, err error) {
				require.NoError(t, err)

				want := append(normalGrants(onlyDeal(seeded)), normalGrants([]admin.Grant{
					{Group: "CRM", Resource: "Lead", Privilege: "view", Granted: true, Scope: identity.ScopeAll},
				})...)
				assert.ElementsMatch(t, want, normalGrants(after), "the old crm/lead rows are replaced by the given spelling")
			},
		},
		{
			name: "an empty resource name is invalid input",
			rgs:  []admin.ResourceGrants{grantsFor(crm, "", view)},
			assert: func(t *testing.T, seeded []admin.Grant, before int64, after []admin.Grant, v, _ int64, err error) {
				assert.ErrorIs(t, err, admin.ErrInvalidInput, "reason matched: %s", reasonOf(err))
				untouched(t, seeded, before, after, v)
			},
		},
		{
			name: "an empty privilege name is invalid input",
			rgs:  []admin.ResourceGrants{grantsFor(crm, lead, admin.Grant{Privilege: "", Granted: true})},
			assert: func(t *testing.T, seeded []admin.Grant, before int64, after []admin.Grant, v, _ int64, err error) {
				assert.ErrorIs(t, err, admin.ErrInvalidInput, "reason matched: %s", reasonOf(err))
				untouched(t, seeded, before, after, v)
			},
		},
		{
			name: "an invalid resource after a valid one writes nothing of either",
			rgs: []admin.ResourceGrants{
				grantsFor(crm, deal, view),
				grantsFor(crm, lead, admin.Grant{Privilege: "", Granted: true}),
			},
			assert: func(t *testing.T, seeded []admin.Grant, before int64, after []admin.Grant, v, _ int64, err error) {
				assert.ErrorIs(t, err, admin.ErrInvalidInput, "reason matched: %s", reasonOf(err))
				untouched(t, seeded, before, after, v)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			role := roleName(t, "names")
			seeded, v := seedGrants(ctx, t, f, role)

			returned, err := f.Grants().ReplaceGrants(ctx, role, v, tc.rgs)

			after, av, gerr := readGrants(ctx, f, role)
			require.NoError(t, gerr)
			tc.assert(t, seeded, v, after, av, returned, err)
		})
	}
}

// readGrants reads a role's grants and version.
func readGrants(ctx context.Context, f Fixture, role string) ([]admin.Grant, int64, error) {
	return f.Grants().GetGrants(ctx, role)
}
