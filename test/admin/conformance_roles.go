package admintest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// runRoleSuite runs the role, grant and assignment cases, and the cases of
// the user and import ports that concern role grants.
func runRoleSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("RoleLifecycle", func(t *testing.T) { runRoleLifecycleCase(t, newFixture) })
	t.Run("StaleRoleUpdate", func(t *testing.T) { runStaleRoleUpdateCases(t, newFixture) })
	t.Run("ReplaceGrantsPerResource", func(t *testing.T) { runReplaceGrantsPerResourceCase(t, newFixture) })
	t.Run("GrantNames", func(t *testing.T) { runGrantNameCases(t, newFixture) })
	t.Run("ConcurrentGrantReplace", func(t *testing.T) { runConcurrentGrantReplaceCase(t, newFixture) })
	t.Run("ReplaceGrantsAtomic", func(t *testing.T) { runReplaceGrantsAtomicCases(t, newFixture) })
	t.Run("ForcedRoleDelete", func(t *testing.T) { runForcedRoleDeleteCase(t, newFixture) })
	t.Run("SuperRoleReachesHolders", func(t *testing.T) { runSuperRoleReachesHoldersCase(t, newFixture) })
	t.Run("RoleHeldOnlyByDeletedUsers", func(t *testing.T) { runRoleHeldOnlyByDeletedUsersCase(t, newFixture) })
	t.Run("ConcurrentAssignment", func(t *testing.T) { runConcurrentAssignmentCase(t, newFixture) })
	t.Run("RemovePrimaryHandsOver", func(t *testing.T) { runRemovePrimaryHandsOverCase(t, newFixture) })
	t.Run("AssignUnknownRole", func(t *testing.T) { runAssignUnknownRoleCase(t, newFixture) })
	t.Run("StaleAssignment", func(t *testing.T) { runStaleAssignmentCases(t, newFixture) })
	t.Run("UnknownUserAssignments", func(t *testing.T) { runUnknownUserAssignmentCases(t, newFixture) })
	t.Run("DeletedUserAssignments", func(t *testing.T) { runDeletedUserAssignmentCases(t, newFixture) })
	t.Run("UserWritesKeepGrants", func(t *testing.T) { runUserWritesKeepGrantsCase(t, newFixture) })
	t.Run("ListByRole", func(t *testing.T) { runListByRoleCases(t, newFixture) })
	t.Run("ListFiltersExcludeDeleted", func(t *testing.T) { runListFiltersExcludeDeletedCase(t, newFixture) })
	t.Run("RenameKeepsGrantsAndAssignments", func(t *testing.T) { runRenameKeepsGrantsCase(t, newFixture) })
	t.Run("ImportRoles", func(t *testing.T) { runImportChangeCases(t, newFixture, importRoleChanges, true) })
	t.Run("ImportUnknownRole", func(t *testing.T) { runImportUnknownRoleCase(t, newFixture) })
}

// The resources the grant cases write.
const (
	crm  = "crm"
	lead = "lead"
	deal = "deal"
)

// normalGrants returns grants with the resource filled in and an empty scope
// read as identity.ScopeAll, so stored and given grants compare by meaning.
func normalGrants(gs []admin.Grant) []admin.Grant {
	out := make([]admin.Grant, 0, len(gs))

	for _, g := range gs {
		if g.Scope == "" {
			g.Scope = identity.ScopeAll
		}

		out = append(out, g)
	}

	return out
}

func grantsFor(group, resource string, gs ...admin.Grant) admin.ResourceGrants {
	for i := range gs {
		gs[i].Group, gs[i].Resource = group, resource
	}

	return admin.ResourceGrants{Group: group, Resource: resource, Grants: gs}
}

func allGrants(rgs ...admin.ResourceGrants) []admin.Grant {
	var out []admin.Grant
	for _, rg := range rgs {
		out = append(out, rg.Grants...)
	}

	return out
}

// seedGrants creates role with grants on crm/lead and crm/deal and returns the
// grants and the role's version.
func seedGrants(ctx context.Context, t *testing.T, f Fixture, role string) ([]admin.Grant, int64) {
	t.Helper()

	r := mustCreateRole(ctx, t, f, role)
	rgs := []admin.ResourceGrants{
		grantsFor(crm, lead,
			admin.Grant{Privilege: "view", Granted: true, Scope: identity.ScopeAll},
			admin.Grant{Privilege: "delete", Granted: false, Scope: identity.ScopeAll}),
		grantsFor(crm, deal, admin.Grant{Privilege: "view", Granted: true, Scope: identity.ScopeOwn}),
	}

	v, err := f.Grants().ReplaceGrants(ctx, role, r.Version, rgs)
	require.NoError(t, err, "the case could not seed the grants it needs")
	require.Greater(t, v, r.Version, "replacing grants increases the role's version")

	return allGrants(rgs...), v
}

// runRoleLifecycleCase checks create, read, list with its label filter and
// assignment count, update and delete of a role.
func runRoleLifecycleCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	name, label := roleName(t, "sales"), "Partner-"+tag(t)

	created, err := f.Roles().CreateRole(ctx, admin.Role{
		Name: name, DisplayName: "Sales", Description: "Sells things", Labels: []string{label}, SuperRole: true,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), created.Version, "a role is created at version one")

	_, err = f.Roles().CreateRole(ctx, admin.Role{Name: name, DisplayName: "Again"})
	requireAlreadyExists(t, err, admin.FieldRole, "a duplicate role")

	plain := roleName(t, "plain")
	mustCreateRole(ctx, t, f, plain)

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
	gone := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1)})
	mustAssign(ctx, t, f, u.ID, u.Version, admin.Assignment{Role: name, Primary: true})
	gv := mustAssign(ctx, t, f, gone.ID, gone.Version, admin.Assignment{Role: name, Primary: true})
	require.NoError(t, f.Users().DeleteUser(ctx, gone.ID, gv))

	got, err := f.Roles().GetRole(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "Sales", got.DisplayName)
	assert.Equal(t, "Sells things", got.Description)
	assert.Equal(t, []string{label}, got.Labels)
	assert.True(t, got.SuperRole)
	assert.Equal(t, 1, got.Assigned, "a role counts the live users holding it, not deleted ones")

	listed, err := f.Roles().ListRoles(ctx, label)
	require.NoError(t, err)
	require.Len(t, listed, 1, "the label filter keeps only roles carrying the label")
	assert.Equal(t, name, listed[0].Name)
	assert.Equal(t, 1, listed[0].Assigned)

	display, labels := "Sales (Partner)", []string{}
	upd, err := f.Roles().UpdateRole(ctx, name, got.Version, admin.RoleChange{DisplayName: &display, Labels: &labels})
	require.NoError(t, err)
	assert.Equal(t, name, upd.Name, "the name never changes")
	assert.Equal(t, display, upd.DisplayName)
	assert.Empty(t, upd.Labels, "a pointer to an empty slice removes every label")
	assert.Equal(t, "Sells things", upd.Description, "an unnamed field is kept")
	assert.Greater(t, upd.Version, got.Version)

	listed, err = f.Roles().ListRoles(ctx, label)
	require.NoError(t, err)
	assert.Empty(t, listed, "a role whose label was removed is not listed under it")

	_, err = f.Roles().GetRole(ctx, roleName(t, "ghost"))
	assert.ErrorIs(t, err, admin.ErrNotFound, "an unknown role is not found (reason matched: %s)", reasonOf(err))

	pr, err := f.Roles().GetRole(ctx, plain)
	require.NoError(t, err)
	require.NoError(t, f.Roles().DeleteRole(ctx, plain, pr.Version, false), "an unassigned role deletes without force")

	_, err = f.Roles().GetRole(ctx, plain)
	assert.ErrorIs(t, err, admin.ErrNotFound)
}

// runStaleRoleUpdateCases checks that every versioned role write, grant
// replacement included, refuses a version another write moved past (F1).
func runStaleRoleUpdateCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, f Fixture, role string, stale int64) error
	}

	cases := []testCase{
		{"UpdateRole", func(ctx context.Context, f Fixture, role string, stale int64) error {
			d := "Lost"
			_, err := f.Roles().UpdateRole(ctx, role, stale, admin.RoleChange{DisplayName: &d})

			return err
		}},
		{"DeleteRole", func(ctx context.Context, f Fixture, role string, stale int64) error {
			return f.Roles().DeleteRole(ctx, role, stale, false)
		}},
		{"DeleteRole forced", func(ctx context.Context, f Fixture, role string, stale int64) error {
			return f.Roles().DeleteRole(ctx, role, stale, true)
		}},
		{"ReplaceGrants", func(ctx context.Context, f Fixture, role string, stale int64) error {
			_, err := f.Grants().ReplaceGrants(ctx, role, stale, []admin.ResourceGrants{grantsFor(crm, lead)})

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			role := roleName(t, "a")
			_, stale := seedGrants(ctx, t, f, role)

			d := "Renamed by a colleague"
			moved, err := f.Roles().UpdateRole(ctx, role, stale, admin.RoleChange{DisplayName: &d})
			require.NoError(t, err)
			require.Greater(t, moved.Version, stale)

			before, err := f.Roles().GetRole(ctx, role)
			require.NoError(t, err)
			assert.Equal(t, moved.Version, before.Version, "UpdateRole returns the stored version")

			beforeGrants, beforeVersion, err := f.Grants().GetGrants(ctx, role)
			require.NoError(t, err)
			assert.Equal(t, moved.Version, beforeVersion, "a role's grants share the role's version")

			err = tc.op(ctx, f, role, stale)
			require.ErrorIs(t, err, admin.ErrStaleUpdate, "reason matched: %s", reasonOf(err))

			after, err := f.Roles().GetRole(ctx, role)
			require.NoError(t, err, "a stale delete must not delete")
			assert.Equal(t, before, after, "a stale write must change nothing")

			afterGrants, _, err := f.Grants().GetGrants(ctx, role)
			require.NoError(t, err)
			assert.ElementsMatch(t, normalGrants(beforeGrants), normalGrants(afterGrants))
		})
	}
}

// runReplaceGrantsPerResourceCase checks that a replacement writes exactly
// the named resources, keeps the others, and stores scopes.
func runReplaceGrantsPerResourceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := roleName(t, "sales")
	seeded, v := seedGrants(ctx, t, f, role)

	got, gv, err := f.Grants().GetGrants(ctx, role)
	require.NoError(t, err)
	assert.Equal(t, v, gv)
	assert.ElementsMatch(t, normalGrants(seeded), normalGrants(got), "grants come back with their scope and flag")

	newLead := grantsFor(crm, lead,
		admin.Grant{Privilege: "view", Granted: true, Scope: identity.ScopeAll},
		admin.Grant{Privilege: "update", Granted: true, Scope: identity.ScopeOwn})

	v2, err := f.Grants().ReplaceGrants(ctx, role, v, []admin.ResourceGrants{newLead})
	require.NoError(t, err)
	assert.Greater(t, v2, v)

	got, gv, err = f.Grants().GetGrants(ctx, role)
	require.NoError(t, err)
	assert.Equal(t, v2, gv)

	var keptDeal []admin.Grant

	for _, g := range seeded {
		if g.Resource == deal {
			keptDeal = append(keptDeal, g)
		}
	}

	assert.ElementsMatch(t, normalGrants(append(newLead.Grants, keptDeal...)), normalGrants(got),
		"crm/lead holds exactly the new grants and crm/deal is unchanged")

	v3, err := f.Grants().ReplaceGrants(ctx, role, v2, []admin.ResourceGrants{{Group: crm, Resource: deal}})
	require.NoError(t, err)

	got, _, err = f.Grants().GetGrants(ctx, role)
	require.NoError(t, err)
	assert.ElementsMatch(t, normalGrants(newLead.Grants), normalGrants(got), "an empty list removes the resource's grants")

	r, err := f.Roles().GetRole(ctx, role)
	require.NoError(t, err)
	assert.Equal(t, v3, r.Version, "ReplaceGrants returns the role's new version")

	_, _, err = f.Grants().GetGrants(ctx, roleName(t, "ghost"))
	assert.ErrorIs(t, err, admin.ErrNotFound, "an unknown role's grants are not found (reason matched: %s)",
		reasonOf(err))

	_, err = f.Grants().ReplaceGrants(ctx, roleName(t, "ghost"), 1, []admin.ResourceGrants{newLead})
	assert.ErrorIs(t, err, admin.ErrNotFound, "replacing an unknown role's grants is not found (reason matched: %s)",
		reasonOf(err))
}

// runConcurrentGrantReplaceCase checks that concurrent replacements naming one
// version apply one after another: one succeeds, the rest are stale, and the
// stored grants are the winner's (F2). The race repeats over a fresh role each
// round.
func runConcurrentGrantReplaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const writers = 4

	ctx := t.Context()
	f := newFixture(t)

	for round := range raceRounds {
		role := roleName(t, "sales-"+strconv.Itoa(round))
		_, v := seedGrants(ctx, t, f, role)

		payloads := make([]admin.ResourceGrants, writers)
		versions := make([]int64, writers)

		for i := range payloads {
			payloads[i] = grantsFor(crm, lead,
				admin.Grant{Privilege: "p" + strconv.Itoa(i), Granted: true, Scope: identity.ScopeAll})
		}

		errs := together(t, writers, func(i int) error {
			nv, err := f.Grants().ReplaceGrants(ctx, role, v, []admin.ResourceGrants{payloads[i]})
			versions[i] = nv

			return err
		})

		winner := -1

		for i, err := range errs {
			if err == nil {
				require.Equal(t, -1, winner, "round %d: two replacements naming one version both succeeded", round)
				winner = i

				continue
			}

			assert.ErrorIs(t, err, admin.ErrStaleUpdate, "round %d: a losing replacement is stale (reason matched: %s)",
				round, reasonOf(err))
		}

		require.NotEqual(t, -1, winner, "round %d: one of the concurrent replacements must succeed", round)

		got, gv, err := f.Grants().GetGrants(ctx, role)
		require.NoError(t, err)
		assert.Equal(t, versions[winner], gv, "round %d: the role's version is the winner's", round)

		var leadGrants []admin.Grant

		for _, g := range got {
			if g.Resource == lead {
				leadGrants = append(leadGrants, g)
			}
		}

		assert.ElementsMatch(t, normalGrants(payloads[winner].Grants), normalGrants(leadGrants),
			"round %d: the stored grants are the winner's, not a mix", round)
	}
}

// runReplaceGrantsAtomicCases checks that a replacement interrupted between
// resources, by a storage failure or a cancelled context, leaves the role's
// grants and version exactly as before (F3, F33).
func runReplaceGrantsAtomicCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		run    func(t *testing.T, ctx context.Context, f Fixture, role string, version int64, rgs []admin.ResourceGrants) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "storage fails writing the second resource",
			run: func(t *testing.T, ctx context.Context, f Fixture, role string, v int64, rgs []admin.ResourceGrants) error {
				require.NoError(t, f.FailGrantWrite(ctx, role, crm, deal))

				_, err := f.Grants().ReplaceGrants(ctx, role, v, rgs)

				return err
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err, "the injected failure must reach the caller")
				assert.Equal(t, "none", reasonOf(err), "a storage failure matches no administration reason")
			},
		},
		{
			name: "context cancelled while writing the second resource",
			run: func(t *testing.T, ctx context.Context, f Fixture, role string, v int64, rgs []admin.ResourceGrants) error {
				stalled, err := f.StallGrantWrite(ctx, role, crm, deal)
				require.NoError(t, err)

				cctx, cancel := context.WithCancel(ctx)
				defer cancel()

				done := make(chan error, 1)

				go func() {
					_, err := f.Grants().ReplaceGrants(cctx, role, v, rgs)
					done <- err
				}()

				waitFor(t, stalled, "the replacement to reach the stalled resource")
				cancel()

				select {
				case err := <-done:
					return err
				case <-time.After(30 * time.Second):
					require.FailNow(t, "a cancelled replacement did not return")

					return nil
				}
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, context.Canceled, "the context's error is returned")
				assert.Equal(t, "none", reasonOf(err), "a cancellation matches no administration reason")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			role := roleName(t, "sales")
			seeded, v := seedGrants(ctx, t, f, role)

			rgs := []admin.ResourceGrants{
				grantsFor(crm, lead, admin.Grant{Privilege: "update", Granted: true, Scope: identity.ScopeOwn}),
				grantsFor(crm, deal, admin.Grant{Privilege: "close", Granted: true, Scope: identity.ScopeAll}),
			}

			tc.assert(t, tc.run(t, ctx, f, role, v, rgs))

			got, gv, err := f.Grants().GetGrants(ctx, role)
			require.NoError(t, err)
			assert.Equal(t, v, gv, "an interrupted replacement must not move the version")
			assert.ElementsMatch(t, normalGrants(seeded), normalGrants(got),
				"an interrupted replacement must leave every grant as it was, the first resource included")
		})
	}
}

// grantState is a user's version and grants, everything an assignment write
// changes.
type grantState struct {
	User  admin.User
	Roles []identity.AssignedRole
}

func readGrantState(ctx context.Context, t *testing.T, f Fixture, id identity.UserID) grantState {
	t.Helper()

	u := mustGetUser(ctx, t, f, id)

	roles, version, err := f.Assignments().ListAssignments(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, u.Version, version, "ListAssignments must report the user's version")

	return grantState{User: u, Roles: roleValues(roles)}
}

func roleValues(roles []*identity.AssignedRole) []identity.AssignedRole {
	vals := make([]identity.AssignedRole, 0, len(roles))

	for _, r := range roles {
		if r != nil {
			vals = append(vals, *r)
		}
	}

	return vals
}

// runForcedRoleDeleteCase checks that deleting an assigned role is refused
// without force, and with force removes the role, its grants and assignments,
// increases the version of every user whose grant it removed, and hands each
// affected user's primary mark to the remaining grant with the lowest
// position, the one assigned first (F28). Ada holds three grants, so a store
// handing the mark to any remaining grant but the first is caught.
func runForcedRoleDeleteCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	sales, audit, ops := roleName(t, "sales"), roleName(t, "audit"), roleName(t, "ops")
	_, sv := seedGrants(ctx, t, f, sales)
	mustCreateRole(ctx, t, f, audit)
	mustCreateRole(ctx, t, f, ops)

	// ada: sales (primary), then audit, then ops.
	ada := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
	v := mustAssign(ctx, t, f, ada.ID, ada.Version, admin.Assignment{Role: sales, Primary: true})
	v = mustAssign(ctx, t, f, ada.ID, v, admin.Assignment{Role: audit})
	mustAssign(ctx, t, f, ada.ID, v, admin.Assignment{Role: ops})

	// bob: sales only.
	bob := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1)})
	mustAssign(ctx, t, f, bob.ID, bob.Version, admin.Assignment{Role: sales, Primary: true})

	// carol: audit only, untouched by the delete.
	carol := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 2)})
	mustAssign(ctx, t, f, carol.ID, carol.Version, admin.Assignment{Role: audit, Primary: true})

	// dave: audit (primary), then sales, which is not his primary grant.
	dave := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 3)})
	v = mustAssign(ctx, t, f, dave.ID, dave.Version, admin.Assignment{Role: audit, Primary: true})
	mustAssign(ctx, t, f, dave.ID, v, admin.Assignment{Role: sales})

	adaBefore := readGrantState(ctx, t, f, ada.ID)
	bobBefore := readGrantState(ctx, t, f, bob.ID)
	carolBefore := readGrantState(ctx, t, f, carol.ID)
	daveBefore := readGrantState(ctx, t, f, dave.ID)
	adaAudit := grantOf(t, roleRefs(adaBefore.Roles), audit).ID

	err := f.Roles().DeleteRole(ctx, sales, sv, false)
	require.ErrorIs(t, err, admin.ErrStillAssigned, "reason matched: %s", reasonOf(err))

	_, err = f.Roles().GetRole(ctx, sales)
	require.NoError(t, err, "a refused delete keeps the role")
	assert.Equal(t, adaBefore, readGrantState(ctx, t, f, ada.ID), "a refused delete keeps the assignments")

	require.NoError(t, f.Roles().DeleteRole(ctx, sales, sv, true))

	_, err = f.Roles().GetRole(ctx, sales)
	assert.ErrorIs(t, err, admin.ErrNotFound, "a forced delete removes the role")

	_, _, err = f.Grants().GetGrants(ctx, sales)
	assert.ErrorIs(t, err, admin.ErrNotFound, "a forced delete removes the role's grants")

	adaAfter := readGrantState(ctx, t, f, ada.ID)
	require.Len(t, adaAfter.Roles, 2, "ada keeps her two remaining grants")
	assert.Equal(t, []string{audit}, primaries(roleRefs(adaAfter.Roles)),
		"the remaining grant assigned first (audit) becomes primary, not a later one")
	assert.Equal(t, adaAudit, grantOf(t, roleRefs(adaAfter.Roles), audit).ID,
		"the handed-over grant is the one ada held, not a new one")
	assert.Greater(t, adaAfter.User.Version, adaBefore.User.Version,
		"a forced delete that removes a user's grant increases the user's version")

	d, err := f.Loader().LoadByUserID(ctx, ada.ID)
	require.NoError(t, err)
	require.NotEmpty(t, d.Roles)
	assert.Equal(t, audit, d.Roles[0].Name, "the loader's active role is the handed-over grant")
	assert.True(t, d.Roles[0].Primary)

	bobAfter := readGrantState(ctx, t, f, bob.ID)
	assert.Empty(t, bobAfter.Roles, "a user whose only grant was removed holds none")
	assert.Greater(t, bobAfter.User.Version, bobBefore.User.Version,
		"a forced delete that removes a user's only grant increases the user's version")

	d, err = f.Loader().LoadByUserID(ctx, bob.ID)
	require.NoError(t, err, "a user left with no grant still loads")
	assert.Empty(t, d.Roles)

	daveAfter := readGrantState(ctx, t, f, dave.ID)
	assert.Equal(t, []string{audit}, primaries(roleRefs(daveAfter.Roles)),
		"a user whose removed grant was not primary keeps his primary grant")
	assert.Len(t, daveAfter.Roles, 1)
	assert.Greater(t, daveAfter.User.Version, daveBefore.User.Version,
		"a forced delete that removes a user's non-primary grant increases the user's version")

	assert.Equal(t, carolBefore, readGrantState(ctx, t, f, carol.ID),
		"a user holding no grant of the role is unchanged, version included")
}

func roleRefs(vals []identity.AssignedRole) []*identity.AssignedRole {
	out := make([]*identity.AssignedRole, len(vals))
	for i := range vals {
		out[i] = &vals[i]
	}

	return out
}

// runRoleHeldOnlyByDeletedUsersCase checks that a role whose only holders are
// soft-deleted users is deleted without force: deleted users do not hold a
// role (the store rules fixed with the suite).
func runRoleHeldOnlyByDeletedUsersCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := roleName(t, "sales")
	mustCreateRole(ctx, t, f, role)

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
	v := mustAssign(ctx, t, f, u.ID, u.Version, admin.Assignment{Role: role, Primary: true})
	require.NoError(t, f.Users().DeleteUser(ctx, u.ID, v))

	r, err := f.Roles().GetRole(ctx, role)
	require.NoError(t, err)
	assert.Zero(t, r.Assigned, "a role held only by deleted users counts no holder")

	err = f.Roles().DeleteRole(ctx, role, r.Version, false)
	require.NoError(t, err, "a role held only by deleted users deletes without force (reason matched: %s)",
		reasonOf(err))

	_, err = f.Roles().GetRole(ctx, role)
	assert.ErrorIs(t, err, admin.ErrNotFound, "the role is gone")
}

// runConcurrentAssignmentCase checks that concurrent assignment writes naming
// one user version apply one after another: one succeeds, the rest are stale.
// The race repeats over a fresh user each round.
func runConcurrentAssignmentCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const writers = 4

	ctx := t.Context()
	f := newFixture(t)

	roles := make([]string, writers)
	for i := range roles {
		roles[i] = roleName(t, strconv.Itoa(i))
		mustCreateRole(ctx, t, f, roles[i])
	}

	for round := range raceRounds {
		u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, round)})

		errs := together(t, writers, func(i int) error {
			_, err := f.Assignments().AddAssignment(ctx, u.ID, u.Version, admin.Assignment{Role: roles[i], Primary: true})

			return err
		})

		winner := -1

		for i, err := range errs {
			if err == nil {
				require.Equal(t, -1, winner, "round %d: two assignment writes naming one version both succeeded", round)
				winner = i

				continue
			}

			assert.ErrorIs(t, err, admin.ErrStaleUpdate, "round %d: a losing write is stale (reason matched: %s)",
				round, reasonOf(err))
		}

		require.NotEqual(t, -1, winner, "round %d: one of the concurrent assignment writes must succeed", round)

		held, _, err := f.Assignments().ListAssignments(ctx, u.ID)
		require.NoError(t, err)
		require.Len(t, held, 1, "round %d: only the winner's grant is stored", round)
		assert.Equal(t, roles[winner], held[0].Name)
	}
}

// runRemovePrimaryHandsOverCase checks primary handling across add, mark and
// remove: removing the primary grant hands the mark to the remaining grant
// with the lowest position, the one assigned first, and increases the
// version (F28). It also checks that assignment dates round-trip through
// ListAssignments and GetUser.
func runRemovePrimaryHandsOverCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	sales, audit, ops := roleName(t, "sales"), roleName(t, "audit"), roleName(t, "ops")
	mustCreateRole(ctx, t, f, sales)
	mustCreateRole(ctx, t, f, audit)
	mustCreateRole(ctx, t, f, ops)

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	ada := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
	v := mustAssign(ctx, t, f, ada.ID, ada.Version, admin.Assignment{Role: sales, Primary: true})
	v = mustAssign(ctx, t, f, ada.ID, v, admin.Assignment{Role: audit, Start: start, End: end})

	roles, lv, err := f.Assignments().ListAssignments(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, v, lv)
	assert.Equal(t, []string{sales}, primaries(roles))

	s, a := grantOf(t, roles, sales), grantOf(t, roles, audit)
	assert.True(t, s.StartDate.IsZero() && s.ValidUntil.IsZero(), "a grant with no dates is stored with none")
	assert.True(t, start.Equal(a.StartDate), "the start date round-trips, got %v", a.StartDate)
	assert.True(t, end.Equal(a.ValidUntil), "the end date round-trips, got %v", a.ValidUntil)

	got := mustGetUser(ctx, t, f, ada.ID)
	ga := grantOf(t, got.Roles, audit)
	assert.True(t, start.Equal(ga.StartDate), "GetUser returns the grant's start date, got %v", ga.StartDate)
	assert.True(t, end.Equal(ga.ValidUntil), "GetUser returns the grant's end date, got %v", ga.ValidUntil)
	assert.True(t, grantOf(t, got.Roles, sales).Primary, "GetUser returns the primary mark")

	v, err = f.Assignments().SetPrimary(ctx, ada.ID, v, a.ID)
	require.NoError(t, err)

	roles, _, err = f.Assignments().ListAssignments(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{audit}, primaries(roles), "the marked grant is the only primary one")

	d, err := f.Loader().LoadByUserID(ctx, ada.ID)
	require.NoError(t, err)
	require.NotEmpty(t, d.Roles)
	assert.Equal(t, audit, d.Roles[0].Name, "the primary role is the marked grant")

	v, err = f.Assignments().AddAssignment(ctx, ada.ID, v, admin.Assignment{Role: ops, Primary: true})
	require.NoError(t, err)

	roles, _, err = f.Assignments().ListAssignments(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{ops}, primaries(roles), "a primary assignment replaces the previous primary")

	o := grantOf(t, roles, ops)
	before := v

	v, err = f.Assignments().RemoveAssignment(ctx, ada.ID, v, o.ID)
	require.NoError(t, err)
	assert.Greater(t, v, before, "removing a grant increases the user's version")

	roles, lv, err = f.Assignments().ListAssignments(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, v, lv)
	require.Len(t, roles, 2)
	assert.Equal(t, []string{sales}, primaries(roles),
		"removing the primary grant hands the mark to the remaining grant assigned first (sales), "+
			"not to the last one or the previous primary")

	_, err = f.Assignments().RemoveAssignment(ctx, ada.ID, v, string(newUserID(t)))
	assert.ErrorIs(t, err, admin.ErrNotFound, "an unknown grant is not found (reason matched: %s)", reasonOf(err))

	_, err = f.Assignments().SetPrimary(ctx, ada.ID, v, string(newUserID(t)))
	assert.ErrorIs(t, err, admin.ErrNotFound, "an unknown grant is not found (reason matched: %s)", reasonOf(err))

	_, lv, err = f.Assignments().ListAssignments(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, v, lv, "a refused assignment write leaves the version alone")
}

// runAssignUnknownRoleCase checks that assigning a role the store does not
// hold is not found and writes nothing. An empty role name is a role no
// catalogue holds, so it is not found too, as the port documents, rather than
// invalid input.
func runAssignUnknownRoleCase(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		role func(t *testing.T) string
	}

	cases := []testCase{
		{"a role not in the catalogue", func(t *testing.T) string { return roleName(t, "ghost") }},
		{"an empty role name", func(*testing.T) string { return "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})

			_, err := f.Assignments().AddAssignment(ctx, u.ID, u.Version, admin.Assignment{Role: tc.role(t), Primary: true})
			require.ErrorIs(t, err, admin.ErrNotFound, "an unknown role is not found (reason matched: %s)", reasonOf(err))

			roles, v, err := f.Assignments().ListAssignments(ctx, u.ID)
			require.NoError(t, err)
			assert.Empty(t, roles, "a refused assignment writes no grant")
			assert.Equal(t, u.Version, v, "a refused assignment leaves the version alone")
		})
	}
}

// staleGrantFixture is a user with two role grants, the primary one first,
// and a third role it does not hold, read at Stale and since moved past it.
type staleGrantFixture struct {
	ID        identity.UserID
	Stale     int64
	Secondary string // the identifier of the non-primary grant
	Unheld    string // a role the user does not hold
}

func arrangeStaleGrants(ctx context.Context, t *testing.T, f Fixture) staleGrantFixture {
	t.Helper()

	primary, second, unheld := roleName(t, "a"), roleName(t, "b"), roleName(t, "c")
	mustCreateRole(ctx, t, f, primary)
	mustCreateRole(ctx, t, f, second)
	mustCreateRole(ctx, t, f, unheld)

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada"})

	v := mustAssign(ctx, t, f, u.ID, u.Version, admin.Assignment{Role: primary, Primary: true})
	v = mustAssign(ctx, t, f, u.ID, v, admin.Assignment{Role: second})

	roles, _, err := f.Assignments().ListAssignments(ctx, u.ID)
	require.NoError(t, err)

	gid := grantOf(t, roles, second).ID

	// A colleague's write moves the version past the one this caller read.
	name := "Renamed by a colleague"
	moved, _, err := f.Users().UpdateUser(ctx, u.ID, v, admin.UserChange{Name: &name})
	require.NoError(t, err, "an update naming the current version must succeed")
	require.Greater(t, moved.Version, v, "a successful update must increase the version")

	return staleGrantFixture{ID: u.ID, Stale: v, Secondary: gid, Unheld: unheld}
}

// runStaleAssignmentCases checks that every assignment write refuses a user
// version another write, of the user port, has moved past, and writes
// nothing: a user's grants share the user's version (F1, Review Focus 3).
func runStaleAssignmentCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, f Fixture, s staleGrantFixture) error
	}

	cases := []testCase{
		{"AddAssignment", func(ctx context.Context, f Fixture, s staleGrantFixture) error {
			_, err := f.Assignments().AddAssignment(ctx, s.ID, s.Stale, admin.Assignment{Role: s.Unheld})

			return err
		}},
		{"RemoveAssignment", func(ctx context.Context, f Fixture, s staleGrantFixture) error {
			_, err := f.Assignments().RemoveAssignment(ctx, s.ID, s.Stale, s.Secondary)

			return err
		}},
		{"SetPrimary", func(ctx context.Context, f Fixture, s staleGrantFixture) error {
			_, err := f.Assignments().SetPrimary(ctx, s.ID, s.Stale, s.Secondary)

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			s := arrangeStaleGrants(ctx, t, f)
			before := readGrantState(ctx, t, f, s.ID)

			err := tc.op(ctx, f, s)
			require.ErrorIs(t, err, admin.ErrStaleUpdate,
				"a write naming a version another write moved past must be refused as stale, not "+
					"applied over the colleague's change (reason matched: %s)", reasonOf(err))

			assert.Equal(t, before, readGrantState(ctx, t, f, s.ID), "a stale write must change nothing")
		})
	}
}

// runUnknownUserAssignmentCases checks that every call of the assignment
// port answers ErrNotFound, not a storage failure, for an identifier no live
// user has, including one the store cannot represent.
func runUnknownUserAssignmentCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, t *testing.T, f Fixture, id identity.UserID, role string) error
	}

	cases := []testCase{
		{"ListAssignments", func(ctx context.Context, _ *testing.T, f Fixture, id identity.UserID, _ string) error {
			_, _, err := f.Assignments().ListAssignments(ctx, id)

			return err
		}},
		{"AddAssignment", func(ctx context.Context, _ *testing.T, f Fixture, id identity.UserID, role string) error {
			_, err := f.Assignments().AddAssignment(ctx, id, 1, admin.Assignment{Role: role})

			return err
		}},
		{"RemoveAssignment", func(ctx context.Context, t *testing.T, f Fixture, id identity.UserID, _ string) error {
			_, err := f.Assignments().RemoveAssignment(ctx, id, 1, string(newUserID(t)))

			return err
		}},
		{"SetPrimary", func(ctx context.Context, t *testing.T, f Fixture, id identity.UserID, _ string) error {
			_, err := f.Assignments().SetPrimary(ctx, id, 1, string(newUserID(t)))

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			role := roleName(t, "a")
			mustCreateRole(ctx, t, f, role)

			for what, id := range unknownUserIDs(t) {
				err := tc.op(ctx, t, f, id, role)
				assert.ErrorIs(t, err, admin.ErrNotFound,
					"%s must be not found, not a storage failure (reason matched: %s)", what, reasonOf(err))
			}
		})
	}
}

// runDeletedUserAssignmentCases checks that every call of the assignment port
// on a soft-deleted user answers ErrNotFound, at the version the user had when
// it was deleted and at the next one (D13).
func runDeletedUserAssignmentCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, f Fixture, id identity.UserID, version int64, grant, role string) error
	}

	cases := []testCase{
		{"ListAssignments", func(ctx context.Context, f Fixture, id identity.UserID, _ int64, _, _ string) error {
			_, _, err := f.Assignments().ListAssignments(ctx, id)

			return err
		}},
		{"AddAssignment", func(ctx context.Context, f Fixture, id identity.UserID, v int64, _, role string) error {
			_, err := f.Assignments().AddAssignment(ctx, id, v, admin.Assignment{Role: role})

			return err
		}},
		{"RemoveAssignment", func(ctx context.Context, f Fixture, id identity.UserID, v int64, grant, _ string) error {
			_, err := f.Assignments().RemoveAssignment(ctx, id, v, grant)

			return err
		}},
		{"SetPrimary", func(ctx context.Context, f Fixture, id identity.UserID, v int64, grant, _ string) error {
			_, err := f.Assignments().SetPrimary(ctx, id, v, grant)

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			held, other := roleName(t, "a"), roleName(t, "b")
			mustCreateRole(ctx, t, f, held)
			mustCreateRole(ctx, t, f, other)

			u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
			v := mustAssign(ctx, t, f, u.ID, u.Version, admin.Assignment{Role: held, Primary: true})

			roles, _, err := f.Assignments().ListAssignments(ctx, u.ID)
			require.NoError(t, err)

			grant := grantOf(t, roles, held).ID

			require.NoError(t, f.Users().DeleteUser(ctx, u.ID, v))

			for _, version := range []int64{v, v + 1} {
				err := tc.op(ctx, f, u.ID, version, grant, other)
				assert.ErrorIs(t, err, admin.ErrNotFound,
					"an assignment call on a deleted user must be not found at version %d (reason matched: %s)",
					version, reasonOf(err))
			}

			_, err = f.Users().GetUser(ctx, u.ID)
			assert.ErrorIs(t, err, admin.ErrNotFound, "the user stays deleted")
		})
	}
}

// runUserWritesKeepGrantsCase checks that the user port's writes leave the
// user's grants as they were: a store that rewrites the user row must not
// drop or re-mint its grants.
func runUserWritesKeepGrantsCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	a, b := roleName(t, "a"), roleName(t, "b")
	mustCreateRole(ctx, t, f, a)
	mustCreateRole(ctx, t, f, b)

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada"})
	v := mustAssign(ctx, t, f, u.ID, u.Version, admin.Assignment{Role: a, Primary: true})
	mustAssign(ctx, t, f, u.ID, v, admin.Assignment{Role: b, End: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)})

	before := readGrantState(ctx, t, f, u.ID)

	type write struct {
		name string
		op   func(version int64) (int64, error)
	}

	writes := []write{
		{"UpdateUser", func(version int64) (int64, error) {
			name := "Ada Lovelace"
			got, _, err := f.Users().UpdateUser(ctx, u.ID, version, admin.UserChange{Name: &name})

			return got.Version, err
		}},
		{"SetPassword", func(version int64) (int64, error) {
			got, err := f.Users().SetPassword(ctx, u.ID, version, []byte("hash-1"), passwordSetAt)

			return got.Version, err
		}},
		{"SetActive", func(version int64) (int64, error) {
			got, _, err := f.Users().SetActive(ctx, u.ID, version, false)

			return got.Version, err
		}},
	}

	version := before.User.Version

	for _, w := range writes {
		nv, err := w.op(version)
		require.NoError(t, err, "%s naming the current version must succeed", w.name)
		require.Greater(t, nv, version, "%s increases the version", w.name)
		version = nv

		assert.Equal(t, before.Roles, readGrantState(ctx, t, f, u.ID).Roles, "%s must keep the user's grants", w.name)
	}
}

// runListByRoleCases checks the role filter of ListUsers, alone and with the
// attribute and active filters.
func runListByRoleCases(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	attr := "job_title-" + tag(t)
	role := roleName(t, "sales")
	mustCreateRole(ctx, t, f, role)

	ids := seedListUsers(ctx, t, f, role, []listSeed{
		{attrs: map[string]string{attr: "Manager"}, role: true, active: true},        // 0
		{attrs: map[string]string{attr: "Manager"}, active: true},                    // 1
		{attrs: map[string]string{attr: "manager"}, role: true, active: true},        // 2: case differs
		{attrs: map[string]string{attr + "x": "Manager"}, active: true},              // 3: name differs
		{attrs: map[string]string{attr: "Manager"}, role: true},                      // 4: inactive
		{attrs: map[string]string{attr: "Manager Senior"}, role: true, active: true}, // 5: value is longer
	})

	yes, no := true, false

	runListCases(ctx, t, f, ids, []listCase{
		{"role", admin.UserQuery{Role: role}, []int{0, 2, 4, 5}},
		{"attribute and role", admin.UserQuery{Role: role, Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}}, []int{0, 4}},
		{"attribute, role and active", admin.UserQuery{Role: role, Active: &yes, Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}}, []int{0}},
		{"inactive with the role", admin.UserQuery{Role: role, Active: &no}, []int{4}},
	})
}

// runListFiltersExcludeDeletedCase checks that the role filter and the
// attribute filter, alone and together, leave out a soft-deleted user who
// held the role and the attribute before it was deleted.
func runListFiltersExcludeDeletedCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	attr := "job_title-" + tag(t)
	role := roleName(t, "sales")
	mustCreateRole(ctx, t, f, role)

	ids := seedListUsers(ctx, t, f, role, []listSeed{
		{attrs: map[string]string{attr: "Manager"}, role: true, active: true}, // 0: live, matches both
		{attrs: map[string]string{attr: "Manager"}, role: true, active: true}, // 1: deleted below, matched both
	})

	gone, err := f.Users().GetUser(ctx, ids[1])
	require.NoError(t, err)
	require.NoError(t, f.Users().DeleteUser(ctx, gone.ID, gone.Version))

	yes := true

	runListCases(ctx, t, f, ids, []listCase{
		{"role", admin.UserQuery{Role: role}, []int{0}},
		{"role and attribute", admin.UserQuery{Role: role, Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}}, []int{0}},
		{"attribute", admin.UserQuery{Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}}, []int{0}},
		{"role and active", admin.UserQuery{Role: role, Active: &yes}, []int{0}},
	})
}

// runRenameKeepsGrantsCase checks that changing a role's display name leaves
// its name, its grants and the assignments that hold it as they were, and that
// the listing shows the new display name.
func runRenameKeepsGrantsCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := roleName(t, "sales")
	seeded, v := seedGrants(ctx, t, f, role)

	ada := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})
	mustAssign(ctx, t, f, ada.ID, ada.Version, admin.Assignment{Role: role, Primary: true})

	before := readGrantState(ctx, t, f, ada.ID)
	require.Equal(t, role, grantOf(t, roleRefs(before.Roles), role).Name)

	display := "Sales (Partner)"
	upd, err := f.Roles().UpdateRole(ctx, role, v, admin.RoleChange{DisplayName: &display})
	require.NoError(t, err)
	assert.Equal(t, role, upd.Name, "the name never changes")

	got, _, err := f.Grants().GetGrants(ctx, role)
	require.NoError(t, err)
	assert.ElementsMatch(t, normalGrants(seeded), normalGrants(got), "a rename keeps every grant of the role")

	after := readGrantState(ctx, t, f, ada.ID)
	assert.Equal(t, grantOf(t, roleRefs(before.Roles), role).ID, grantOf(t, roleRefs(after.Roles), role).ID,
		"a rename keeps the holder's assignment")
	assert.Equal(t, []string{role}, primaries(roleRefs(after.Roles)), "a rename keeps the primary grant")

	d, err := f.Loader().LoadByUserID(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, role, grantOf(t, d.Roles, role).Name, "the loader still returns the grant under the role's name")

	listed, err := f.Roles().ListRoles(ctx, "")
	require.NoError(t, err)

	var found bool

	for _, r := range listed {
		if r.Name != role {
			continue
		}

		found = true

		assert.Equal(t, display, r.DisplayName, "the listing shows the new display name")
		assert.Equal(t, 1, r.Assigned, "the listing still counts the holder")
	}

	assert.True(t, found, "the renamed role is listed")
}
