package admintest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// The store rules decided while implementing the stores, beyond the ones the
// suite was first written with.

// runSuperRoleReachesHoldersCase checks that a role update changing the
// super-role flag copies it onto every holder's grant, as the loader returns
// it, and increases each holder's version; an update that leaves the flag as
// it is touches no holder. The authorizer reads the flag from the grant, so a
// store that changes only the catalogue row keeps the bypass with every
// holder after it was turned off.
func runSuperRoleReachesHoldersCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	admins, audit := roleName(t, "admins"), roleName(t, "audit")

	created, err := f.Roles().CreateRole(ctx, admin.Role{Name: admins, DisplayName: "Admins", SuperRole: true})
	require.NoError(t, err)
	mustCreateRole(ctx, t, f, audit)

	// ada: admins only, primary.
	ada := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
	mustAssign(ctx, t, f, ada.ID, ada.Version, admin.Assignment{Role: admins, Primary: true})

	// bob: audit (primary), then admins.
	bob := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1)})
	v := mustAssign(ctx, t, f, bob.ID, bob.Version, admin.Assignment{Role: audit, Primary: true})
	mustAssign(ctx, t, f, bob.ID, v, admin.Assignment{Role: admins})

	// carol: audit only, never touched by an update of admins.
	carol := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 2)})
	mustAssign(ctx, t, f, carol.ID, carol.Version, admin.Assignment{Role: audit, Primary: true})

	holders := []identity.UserID{ada.ID, bob.ID}
	requireHolderFlag(ctx, t, f, holders, admins, true, "a grant copies the role's flag when it is assigned")

	carolBefore := readGrantState(ctx, t, f, carol.ID)
	before := holderStates(ctx, t, f, holders)

	off := false
	r, err := f.Roles().UpdateRole(ctx, admins, created.Version, admin.RoleChange{SuperRole: &off})
	require.NoError(t, err)
	assert.False(t, r.SuperRole, "the role carries the new flag")

	requireHolderFlag(ctx, t, f, holders, admins, false,
		"turning the flag off reaches every holder's grant, so the bypass goes with it")
	afterOff := holderStates(ctx, t, f, holders)
	for i := range holders {
		assert.Greater(t, afterOff[i].User.Version, before[i].User.Version,
			"a flag change increases the version of holder %d", i)
		assert.Equal(t, grantOf(t, roleRefs(before[i].Roles), admins).ID,
			grantOf(t, roleRefs(afterOff[i].Roles), admins).ID, "holder %d keeps the grant it held", i)
		assert.Equal(t, primaries(roleRefs(before[i].Roles)), primaries(roleRefs(afterOff[i].Roles)),
			"a flag change keeps holder %d's primary grant", i)
	}

	audited := grantOf(t, roleRefs(readGrantState(ctx, t, f, bob.ID).Roles), audit)
	assert.False(t, audited.SuperRole, "a grant of another role is untouched")
	assert.Equal(t, carolBefore, readGrantState(ctx, t, f, carol.ID),
		"a user holding no grant of the role is unchanged, version included")

	name := "Administrators"
	r, err = f.Roles().UpdateRole(ctx, admins, r.Version, admin.RoleChange{DisplayName: &name, SuperRole: &off})
	require.NoError(t, err)
	assert.Equal(t, afterOff, holderStates(ctx, t, f, holders),
		"an update that leaves the flag as it is touches no holder, version included")

	on := true
	_, err = f.Roles().UpdateRole(ctx, admins, r.Version, admin.RoleChange{SuperRole: &on})
	require.NoError(t, err)

	requireHolderFlag(ctx, t, f, holders, admins, true, "turning the flag on reaches every holder's grant")
	afterOn := holderStates(ctx, t, f, holders)
	for i := range holders {
		assert.Greater(t, afterOn[i].User.Version, afterOff[i].User.Version,
			"a flag change increases the version of holder %d", i)
	}

	assert.Equal(t, carolBefore, readGrantState(ctx, t, f, carol.ID),
		"a user holding no grant of the role is unchanged, version included")
}

// requireHolderFlag asserts that every user in ids holds a grant of role
// carrying the super-role flag want, as the loader returns it.
func requireHolderFlag(ctx context.Context, t *testing.T, f Fixture, ids []identity.UserID, role string, want bool,
	msg string,
) {
	t.Helper()

	for i, id := range ids {
		d, err := f.Loader().LoadByUserID(ctx, id)
		require.NoError(t, err)

		g := grantOf(t, d.Roles, role)
		assert.Equal(t, want, g.SuperRole, "holder %d: %s", i, msg)
	}
}

func holderStates(ctx context.Context, t *testing.T, f Fixture, ids []identity.UserID) []grantState {
	t.Helper()

	out := make([]grantState, len(ids))
	for i, id := range ids {
		out[i] = readGrantState(ctx, t, f, id)
	}

	return out
}
