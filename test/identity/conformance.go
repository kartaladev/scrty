package identitytest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// passwordChangedAt is the instant the suite seeds before checking that neither
// verb moves a user's password-changed time.
var passwordChangedAt = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// The validity window the suite seeds on a role grant. No identity port sets
// these, which is why a rebuild must carry them across rather than mint them.
var (
	grantStart      = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	grantValidUntil = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
)

// Fixture is what an implementation offers the conformance suite: the four
// identity ports, plus the seeding the suite needs to arrange each case.
//
// The seeding methods are the suite's requirement, not scrty's. A consumer's
// implementation satisfies them however its own storage allows — an insert, a
// fixture file, a migration — so long as a later read through the ports sees the
// seeded state.
type Fixture interface {
	identity.UserProvisioner
	identity.UserLoader
	identity.RoleLoader
	identity.MFARequirementLookup

	// SeedRole records the privileges a role grants.
	SeedRole(ctx context.Context, role string, p []*identity.ResourcePrivileges) error

	// SeedMFARequired records whether a user must use a second factor.
	SeedMFARequired(ctx context.Context, id identity.UserID, required bool) error

	// SeedPasswordChangedAt records when a user's password was last changed.
	//
	// The suite needs it to check that neither verb moves that time: comparing a
	// value the store never set would compare zero with zero and hold however the
	// implementation behaved.
	SeedPasswordChangedAt(ctx context.Context, username string, at time.Time) error

	// SeedRoleGrants replaces a user's role grants outright.
	//
	// A grant's identifier, super-role flag and validity window are set by the
	// consumer's own administration, never by an identity port: Provision creates
	// grants carrying only a name, an order and the primary flag. The suite seeds
	// them so that "the rebuild kept this grant's attributes" compares real
	// values rather than two zero values.
	SeedRoleGrants(ctx context.Context, username string, grants []*identity.AssignedRole) error

	// FailUserLoads makes every user load fail with err, so the suite can check
	// that a backend failure is distinguishable from "no such user". An
	// implementation that cannot inject a fault may skip the test.
	FailUserLoads(err error)

	// FailMFALookups makes every MFA requirement lookup fail with err, so the
	// suite can check that a lookup failure is reported as an error rather than
	// as "not required".
	FailMFALookups(err error)
}

// Factory returns a fresh, empty Fixture for one test.
//
// The suite calls it per case rather than once per run, so no case can see state
// another case left behind.
type Factory func(t *testing.T) Fixture

// RunConformanceSuite checks an implementation of scrty's identity ports against
// every contract the library relies on.
//
// A consumer implementing the ports over their own user tables calls it from
// their own test:
//
//	func TestMyStoreConformance(t *testing.T) {
//	    identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
//	        return newMyStore(t)
//	    })
//	}
func RunConformanceSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)

	t.Run("UserLoader", func(t *testing.T) { RunUserLoaderSuite(t, newFixture) })
	t.Run("RoleLoader", func(t *testing.T) { RunRoleLoaderSuite(t, newFixture) })
	t.Run("Provisioner", func(t *testing.T) { RunProvisionerSuite(t, newFixture) })
	t.Run("MFALookup", func(t *testing.T) { RunMFALookupSuite(t, newFixture) })
}

// requireUsableFixture fails the whole suite rather than each sub-suite when the
// factory cannot produce a fixture, so the reason is reported once and clearly.
func requireUsableFixture(t *testing.T, newFixture Factory) {
	t.Helper()

	require.NotNil(t, newFixture, "the suite needs a factory to build the implementation under test")

	f := newFixture(t)
	require.NotNil(t, f, "the factory returned no fixture, so no contract can be checked")
}

// errBackendUnreachable stands in for a fault that is not a lookup miss.
var errBackendUnreachable = errors.New("identitytest: backend unreachable")

// RunUserLoaderSuite checks the user loader contract.
func RunUserLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("Lookup", func(t *testing.T) { runUserLoaderCases(t, newFixture) })
	t.Run("Ownership", func(t *testing.T) { runLoadOwnershipCase(t, newFixture) })
}

// runLoadOwnershipCase checks that a loaded record belongs to the caller.
//
// The library hands a loaded record onward — to the principal mapper, to a
// password check, to application code — and those callers treat it as a value
// of their own: they rewrite a field, wipe the password buffer once it has been
// verified, or keep the record in a cache. An implementation that returns a
// handle on its own state turns each of those into a write to the store, so
// verifying a password can destroy the stored hash and reading a record can
// move its user into another organization.
//
// The check is therefore a round trip: mutate everything the returned record
// reaches, then read the user again through the port and require the stored
// state to be exactly as it was.
func runLoadOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	_, err := f.Provision(ctx, "alice",
		identity.WithUserName("Alice"),
		identity.WithUserPassword([]byte("H1")),
		identity.WithUserRoles("admin"),
		identity.WithUserOrganization(&identity.Organization{
			ID:    "o-1",
			Name:  "acme",
			Group: &identity.Group{ID: "g-1", Name: "external"},
		}),
	)
	require.NoError(t, err)

	loaded, err := f.LoadByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	require.Len(t, loaded.Roles, 1)
	require.NotEmpty(t, loaded.Password)
	require.NotNil(t, loaded.Organization)
	require.NotNil(t, loaded.Organization.Group,
		"the suite needs a group to write through, so the record must carry the one provisioned")

	// A caller does with the record what a caller may: rewrite it, and wipe the
	// password buffer it has finished verifying.
	loaded.Name = "Rewritten"
	loaded.Roles[0].SuperRole = true
	loaded.Organization.ID = "o-victim"
	loaded.Organization.Group.Internal = true
	clear(loaded.Password)

	again, err := f.LoadByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, again)

	assert.Equal(t, "Alice", again.Name,
		"a caller rewriting the record it was handed rewrote the stored user")
	assert.Equal(t, []byte("H1"), again.Password,
		"wiping the password buffer after verifying it destroyed the stored hash, so the user "+
			"can never sign in again")

	require.Len(t, again.Roles, 1)
	assert.False(t, again.Roles[0].SuperRole,
		"a caller made its own grant a super role by writing through the record it was handed")

	require.NotNil(t, again.Organization)
	assert.Equal(t, "o-1", again.Organization.ID,
		"a caller moved the stored user into another organization")

	require.NotNil(t, again.Organization.Group)
	assert.False(t, again.Organization.Group.Internal,
		"and marked the stored group internal")
}

func runUserLoaderCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture)
		lookup string
		assert func(t *testing.T, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name: "the username reaches the loader exactly as presented",
			seed: func(t *testing.T, ctx context.Context, f Fixture) {
				_, err := f.Provision(ctx, " Alice@Example.COM")
				require.NoError(t, err)
			},
			lookup: " Alice@Example.COM",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Equal(t, " Alice@Example.COM", d.Username,
					"the username is never trimmed or case-folded on the way in or out")
			},
		},
		{
			name: "a username differing only in case is a different user",
			seed: func(t *testing.T, ctx context.Context, f Fixture) {
				_, err := f.Provision(ctx, "abc")
				require.NoError(t, err)
			},
			lookup: "ABC",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"case-folding the lookup would let one user sign in as another")
				assert.Nil(t, d)
			},
		},
		{
			name:   "an unknown username is identifiable as a miss",
			lookup: "nobody",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)
			},
		},
		{
			name: "a backend failure is not reported as a miss",
			seed: func(_ *testing.T, _ context.Context, f Fixture) {
				f.FailUserLoads(errBackendUnreachable)
			},
			lookup: "alice",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"a store that is down must not read as 'no such user': the caller would "+
						"treat an outage as a failed login and count it against the user")
				assert.Nil(t, d)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			if tc.seed != nil {
				tc.seed(t, ctx, f)
			}

			d, err := f.LoadByUsername(ctx, tc.lookup)
			tc.assert(t, d, err)
		})
	}
}

// RunRoleLoaderSuite checks the role loader contract.
func RunRoleLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("Privileges", func(t *testing.T) { runRoleLoaderCases(t, newFixture) })
	t.Run("Ownership", func(t *testing.T) { runPrivilegesOwnershipCase(t, newFixture) })
}

// runPrivilegesOwnershipCase checks that loaded privileges belong to the caller.
//
// Privileges are read on the request path and cached, so a reader that is
// handed the store's own rows can grant itself a privilege the role was refused,
// or repoint a row at another resource, for every later request in the process.
func runPrivilegesOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	require.NoError(t, f.SeedRole(ctx, "clerk", []*identity.ResourcePrivileges{{
		Group:    "billing",
		Resource: "invoice",
		Privileges: []identity.Privilege{
			{Name: "read", Granted: true},
			{Name: "delete", Granted: false},
		},
	}}))

	got, err := f.LoadPrivileges(ctx, "clerk")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Privileges, 2,
		"the suite needs the refused privilege to write through, so it must be carried")

	got[0].Resource = "payment"
	got[0].Privileges[0].Name = "write"
	got[0].Privileges[1].Granted = true

	again, err := f.LoadPrivileges(ctx, "clerk")
	require.NoError(t, err)
	require.Len(t, again, 1)

	assert.Equal(t, "invoice", again[0].Resource,
		"a reader rewrote which resource the stored row is about")

	require.Len(t, again[0].Privileges, 2)
	assert.Equal(t, "read", again[0].Privileges[0].Name,
		"a reader renamed a privilege on the stored row")
	assert.False(t, again[0].Privileges[1].Granted,
		"a reader granted itself a privilege the role is refused")
}

func runRoleLoaderCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture)
		role   string
		assert func(t *testing.T, p []*identity.ResourcePrivileges, err error)
	}

	cases := []testCase{
		{
			name: "a role returns the privileges it grants, including the ones it is refused",
			seed: func(t *testing.T, ctx context.Context, f Fixture) {
				require.NoError(t, f.SeedRole(ctx, "clerk", []*identity.ResourcePrivileges{{
					Group:    "billing",
					Resource: "invoice",
					Privileges: []identity.Privilege{
						{Name: "read", Granted: true},
						{Name: "delete", Granted: false},
					},
				}}))
			},
			role: "clerk",
			assert: func(t *testing.T, p []*identity.ResourcePrivileges, err error) {
				require.NoError(t, err)
				require.Len(t, p, 1)
				assert.Equal(t, "billing", p[0].Group)
				assert.Equal(t, "invoice", p[0].Resource)
				assert.Equal(t, []identity.Privilege{
					{Name: "read", Granted: true},
					{Name: "delete", Granted: false},
				}, p[0].Privileges,
					"a privilege that is not granted is carried as refused rather than filtered "+
						"away, so a caller can tell 'refused' apart from 'not mentioned'; a loader "+
						"that drops it makes the two indistinguishable")
			},
		},
		{
			name: "a role granting nothing is identifiable as such",
			role: "ghost",
			assert: func(t *testing.T, p []*identity.ResourcePrivileges, err error) {
				require.ErrorIs(t, err, identity.ErrPrivilegesNotFound)
				assert.Empty(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			if tc.seed != nil {
				tc.seed(t, ctx, f)
			}

			p, err := f.LoadPrivileges(ctx, tc.role)
			tc.assert(t, p, err)
		})
	}
}

// RunProvisionerSuite checks the create-only and amend contracts.
func RunProvisionerSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("Provision", func(t *testing.T) { runProvisionCases(t, newFixture) })
	t.Run("Concurrent", func(t *testing.T) { runProvisionRaceCase(t, newFixture) })
	t.Run("Update", func(t *testing.T) { runUpdateCases(t, newFixture) })
	t.Run("Roles", func(t *testing.T) { runRoleRebuildCases(t, newFixture) })
	t.Run("ConcurrentRoles", func(t *testing.T) { runRoleRebuildRaceCase(t, newFixture) })
	t.Run("ProvisionOwnership", func(t *testing.T) { runProvisionOwnershipCase(t, newFixture) })
	t.Run("UpdateOwnership", func(t *testing.T) { runUpdateOwnershipCase(t, newFixture) })
}

// runProvisionOwnershipCase checks that a created user is the store's own copy
// in both directions.
//
// A caller hands Provision a password hash and an organization it built, and
// goes on using both: it wipes the hash buffer once the credential has been
// used, and reuses the organization value for the next user. A store that keeps
// those pointers is rewritten by every such use — a routine wipe destroys the
// stored hash, so the user can never sign in. In the other direction, the
// record Provision returns is the caller's to amend before handing it on.
func runProvisionOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	hash := []byte("argon2id$hash")
	org := &identity.Organization{
		ID:    "o-1",
		Name:  "acme",
		Group: &identity.Group{ID: "g-1", Name: "external"},
	}

	created, err := f.Provision(ctx, "alice",
		identity.WithUserPassword(hash),
		identity.WithUserOrganization(org),
		identity.WithUserRoles("admin"),
	)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Len(t, created.Roles, 1)

	// The caller wipes the buffer it owns, as credential hygiene requires, and
	// reuses the organization value it built.
	clear(hash)
	org.ID = "o-victim"
	org.Group.Internal = true

	// And amends the record it was handed.
	created.Name = "Rewritten"
	created.Roles[0].SuperRole = true

	if created.Organization != nil {
		created.Organization.ID = "o-rewritten"
	}

	stored, err := f.LoadByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, []byte("argon2id$hash"), stored.Password,
		"the caller wiping its own buffer wiped the stored hash, so the user can never sign in")
	assert.Empty(t, stored.Name,
		"amending the returned record rewrote the stored user; the record a write returns is "+
			"the caller's, not a handle on the store")

	require.Len(t, stored.Roles, 1)
	assert.False(t, stored.Roles[0].SuperRole,
		"and made the stored grant a super role")

	require.NotNil(t, stored.Organization)
	assert.Equal(t, "o-1", stored.Organization.ID,
		"the caller reusing the organization value it built moved the stored user")

	require.NotNil(t, stored.Organization.Group)
	assert.False(t, stored.Organization.Group.Internal,
		"and marked the stored group internal")
}

// runUpdateOwnershipCase checks the same ownership rule for an amendment: the
// values the caller named stay the caller's, and the record returned is a copy.
func runUpdateOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	_, err := f.Provision(ctx, "alice", identity.WithUserRoles("admin"))
	require.NoError(t, err)

	hash := []byte("argon2id$new")
	org := &identity.Organization{
		ID:    "o-1",
		Name:  "acme",
		Group: &identity.Group{ID: "g-1", Name: "external"},
	}

	updated, err := f.Update(ctx, "alice",
		identity.WithUserName("Alice"),
		identity.WithUserPassword(hash),
		identity.WithUserOrganization(org),
	)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.Len(t, updated.Roles, 1,
		"the update named no roles, so the record returned carries the stored grant")

	clear(hash)
	org.ID = "o-victim"
	org.Group.Internal = true

	updated.Name = "Rewritten"
	updated.Roles[0].SuperRole = true

	if updated.Organization != nil {
		updated.Organization.ID = "o-rewritten"
	}

	stored, err := f.LoadByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, []byte("argon2id$new"), stored.Password,
		"the caller wiping its own buffer wiped the stored hash")
	assert.Equal(t, "Alice", stored.Name,
		"amending the returned record rewrote the stored user")

	require.Len(t, stored.Roles, 1)
	assert.False(t, stored.Roles[0].SuperRole,
		"and made the stored grant a super role")

	require.NotNil(t, stored.Organization)
	assert.Equal(t, "o-1", stored.Organization.ID,
		"the caller reusing the organization value it named moved the stored user")

	require.NotNil(t, stored.Organization.Group)
	assert.False(t, stored.Organization.Group.Internal,
		"and marked the stored group internal")
}

// runRoleRebuildRaceCase checks that concurrent updates of one user are
// serialized.
//
// Rebuilding grants is a read-modify-write: read the stored grants, work out
// which survive, write the new set. Two callers doing that at once against the
// same user can interleave so that each decides from the state it read, and the
// loser's decision is computed from grants that no longer exist. The visible
// result is a merge that neither caller asked for — both roles present, or
// neither — which is a privilege change nobody requested.
//
// One update revokes admin in favour of viewer while another re-asserts admin.
// Either outcome is correct, because either caller may win; a blend of the two
// is not.
//
// Counting the surviving grants cannot tell the two apart: each caller asks for
// exactly one role, so every interleaving leaves exactly one grant. What
// distinguishes them is the surviving grant's own attributes. Under any
// serialized ordering the second write rebuilds from the first write's result,
// which holds only the other caller's role, so the surviving grant is minted
// fresh: it carries neither the seeded identifier, nor the seeded validity
// window, nor the super-role flag. A grant that comes back still carrying them
// was rebuilt from a state the other caller had already replaced — a lost
// update, or a revoked super role restored — and no serialized ordering can
// produce it.
//
// The race is run several times over a fresh user, so a window that opens only
// sometimes is still found; run the suite with -race -count=10 to widen it
// further.
func runRoleRebuildRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	// The attributes seeded on each grant, so that "the survivor was minted
	// fresh" compares real values rather than two zero values.
	seeded := map[string]string{"admin": "r-admin", "viewer": "r-viewer"}

	const rounds = 4

	for round := range rounds {
		ctx := t.Context()
		f := newFixture(t)

		_, err := f.Provision(ctx, "alice")
		require.NoError(t, err, "round %d", round)
		require.NoError(t, f.SeedRoleGrants(ctx, "alice", []*identity.AssignedRole{
			{
				ID:         seeded["admin"],
				Name:       "admin",
				Primary:    true,
				SuperRole:  true,
				StartDate:  grantStart,
				ValidUntil: grantValidUntil,
			},
			{
				ID:         seeded["viewer"],
				Name:       "viewer",
				StartDate:  grantStart,
				ValidUntil: grantValidUntil,
			},
		}), "round %d", round)

		var wg sync.WaitGroup

		start := make(chan struct{})

		wg.Add(2)

		go func() {
			defer wg.Done()

			<-start

			_, _ = f.Update(ctx, "alice", identity.WithUserRoles("viewer"))
		}()

		go func() {
			defer wg.Done()

			<-start

			_, _ = f.Update(ctx, "alice", identity.WithUserRoles("admin"))
		}()

		close(start)
		wg.Wait()

		final, err := f.LoadByUsername(ctx, "alice")
		require.NoError(t, err, "round %d", round)
		require.Len(t, final.Roles, 1,
			"round %d: each caller asked for exactly one role, so the final grants must be one "+
				"caller's set and not a blend", round)

		got := final.Roles[0]

		require.Contains(t, seeded, got.Name,
			"round %d: the surviving grant must be one of the two that were requested", round)
		assert.True(t, got.Primary,
			"round %d: the surviving grant is the first of its caller's list, so it carries the "+
				"primary flag", round)

		assert.NotEqual(t, seeded[got.Name], got.ID,
			"round %d: %q survived carrying the identifier it held before either caller wrote, so "+
				"its rebuild read grants the other caller had already replaced: a serialized "+
				"second write finds no grant of that name and mints a new one",
			round, got.Name)
		assert.False(t, got.SuperRole,
			"round %d: %q survived as a super role although the other caller had revoked it; no "+
				"serialized ordering restores a revoked grant's privileges",
			round, got.Name)
		assert.True(t, got.StartDate.IsZero(),
			"round %d: %q survived carrying the validity window seeded before either caller "+
				"wrote, so the losing caller's decision was computed from grants that no longer "+
				"existed", round, got.Name)
		assert.True(t, got.ValidUntil.IsZero(),
			"round %d: %q survived carrying the valid-until date seeded before either caller "+
				"wrote", round, got.Name)
	}
}

func runRoleRebuildCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture)
		roles  []string
		assert func(t *testing.T, d *identity.Details, err error)
	}

	// seedGranted gives alice a super-role admin with a validity window, and a
	// plain viewer. Neither the identifier, the super-role flag nor the dates can
	// be set through an identity port, which is exactly why a rebuild must carry
	// them across instead of minting fresh grants.
	seedGranted := func(t *testing.T, ctx context.Context, f Fixture) {
		t.Helper()

		_, err := f.Provision(ctx, "alice")
		require.NoError(t, err)
		require.NoError(t, f.SeedRoleGrants(ctx, "alice", []*identity.AssignedRole{
			{
				ID:         "r-admin",
				Name:       "admin",
				Primary:    true,
				SuperRole:  true,
				StartDate:  grantStart,
				ValidUntil: grantValidUntil,
			},
			{ID: "r-viewer", Name: "viewer"},
		}))
	}

	assertUntouched := func(t *testing.T, d *identity.Details, err error) {
		require.NoError(t, err)
		require.Len(t, d.Roles, 2,
			"nothing can strip every grant through Update: a caller that named no usable role "+
				"asked for no change, not for the user to lose all access")
		assert.Equal(t, "admin", d.Roles[0].Name)
		assert.True(t, d.Roles[0].SuperRole)
	}

	cases := []testCase{
		{
			name:   "an empty role list leaves the stored grants untouched",
			seed:   seedGranted,
			roles:  []string{},
			assert: assertUntouched,
		},
		{
			name:   "a list of only empty names leaves the stored grants untouched",
			seed:   seedGranted,
			roles:  []string{"", ""},
			assert: assertUntouched,
		},
		{
			name:  "surviving names rebuild in the order given, with the first primary",
			seed:  seedGranted,
			roles: []string{"viewer", "admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				assert.Equal(t, "viewer", d.Roles[0].Name)
				assert.True(t, d.Roles[0].Primary, "the first name given becomes the primary role")
				assert.Equal(t, "admin", d.Roles[1].Name)
				assert.False(t, d.Roles[1].Primary,
					"the previous primary loses the flag, or two grants claim it")
			},
		},
		{
			name:  "a repeated name collapses to its first occurrence",
			seed:  seedGranted,
			roles: []string{"viewer", "viewer", "admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2, "Update deduplicates; Provision records each occurrence")
				assert.Equal(t, "viewer", d.Roles[0].Name)
				assert.Equal(t, "admin", d.Roles[1].Name)
			},
		},
		{
			name:  "a surviving name keeps the stored grant's identifier, flag and dates",
			seed:  seedGranted,
			roles: []string{"viewer", "admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				admin := d.Roles[1]
				assert.Equal(t, "r-admin", admin.ID,
					"a rebuilt grant that mints a new identifier breaks every reference to the old one")
				assert.True(t, admin.SuperRole,
					"re-asserting a role by name must not silently demote it")
				assert.Equal(t, grantStart, admin.StartDate)
				assert.Equal(t, grantValidUntil, admin.ValidUntil,
					"nor silently extend a grant that was due to expire")
			},
		},
		{
			name: "where the stored grants repeat a name, the first stored grant is kept",
			seed: func(t *testing.T, ctx context.Context, f Fixture) {
				t.Helper()

				_, err := f.Provision(ctx, "alice")
				require.NoError(t, err)
				require.NoError(t, f.SeedRoleGrants(ctx, "alice", []*identity.AssignedRole{
					{ID: "r-first", Name: "viewer", Primary: true},
					{ID: "r-second", Name: "viewer"},
				}))
			},
			roles: []string{"viewer"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 1)
				assert.Equal(t, "r-first", d.Roles[0].ID,
					"the choice is defined rather than left to map order, so two stores agree")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			if tc.seed != nil {
				tc.seed(t, ctx, f)
			}

			d, err := f.Update(ctx, "alice", identity.WithUserRoles(tc.roles...))
			tc.assert(t, d, err)
		})
	}
}

func runUpdateCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture)
		user   string
		opts   []identity.UserOption
		assert func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error)
	}

	// seedAlice gives every case a user with something in each field, so an
	// assertion that a field survived is meaningful rather than comparing two
	// zero values.
	seedAlice := func(t *testing.T, ctx context.Context, f Fixture) {
		t.Helper()

		_, err := f.Provision(ctx, "alice",
			identity.WithUserName("First"),
			identity.WithUserPassword([]byte("H1")),
			identity.WithUserRoles("viewer"),
			identity.WithUserOrganization(&identity.Organization{ID: "o-1", Name: "acme"}),
		)
		require.NoError(t, err)
		require.NoError(t, f.SeedPasswordChangedAt(ctx, "alice", passwordChangedAt))
	}

	cases := []testCase{
		{
			name: "a field the caller did not name is left as the store holds it",
			seed: seedAlice,
			user: "alice",
			opts: []identity.UserOption{identity.WithUserPassword([]byte("H2"))},
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("H2"), d.Password)

				require.NotNil(t, d.Organization,
					"an unnamed organization must survive a password-only update")
				assert.Equal(t, "acme", d.Organization.Name)
				assert.Equal(t, "First", d.Name)
			},
		},
		{
			name: "naming a field with an empty value clears it",
			seed: seedAlice,
			user: "alice",
			opts: []identity.UserOption{identity.WithUserName("")},
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Empty(t, d.Name,
					"the write follows IsSet, so naming a field with an empty value clears it; "+
						"an implementation keyed on the value being non-empty could never clear one")

				require.NotNil(t, d.Organization, "and only the named field is touched")
				assert.Equal(t, "acme", d.Organization.Name)
			},
		},
		{
			name: "an unknown username is refused and creates nothing",
			user: "nobody",
			opts: []identity.UserOption{identity.WithUserName("Nobody")},
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)

				_, loadErr := f.LoadByUsername(ctx, "nobody")
				assert.ErrorIs(t, loadErr, identity.ErrUserNotFound,
					"Update never creates: that is what makes Provision the only way in")
			},
		},
		{
			name: "the complete stored record is returned, not only the amended fields",
			seed: seedAlice,
			user: "alice",
			opts: []identity.UserOption{identity.WithUserName("Alice A.")},
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, "Alice A.", d.Name)
				assert.Len(t, d.Roles, 1, "the returned record carries the roles it did not touch")
				assert.NotNil(t, d.Organization)
				assert.Equal(t, []byte("H1"), d.Password)
			},
		},
		{
			name: "the password-changed time survives a password change",
			seed: seedAlice,
			user: "alice",
			opts: []identity.UserOption{identity.WithUserPassword([]byte("H2"))},
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, passwordChangedAt, d.PasswordChangedAt,
					"the store records the hash; when the password last changed is the caller's "+
						"to decide, so neither verb may move it")

				loaded, loadErr := f.LoadByUsername(ctx, "alice")
				require.NoError(t, loadErr)
				assert.Equal(t, passwordChangedAt, loaded.PasswordChangedAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			if tc.seed != nil {
				tc.seed(t, ctx, f)
			}

			d, err := f.Update(ctx, tc.user, tc.opts...)
			tc.assert(t, ctx, f, d, err)
		})
	}
}

// runProvisionRaceCase checks that the username collision is decided by the write
// itself.
//
// This is the case a pre-flight read cannot pass. An implementation that asks
// "does this username exist?" and then inserts has a window between the two in
// which another caller does the same, so both see no user and both create one —
// leaving two accounts on one username, or one account silently overwritten. The
// check has to be the write: a unique constraint, an INSERT ... ON CONFLICT DO
// NOTHING that reports zero rows, or an insert under the same lock that answered
// the question.
//
// Concurrency is what makes it visible, so this runs several callers at once and
// releases them together. Run the suite with -race -count=10 to give the window
// a chance to open.
func runProvisionRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const attempts = 8

	ctx := t.Context()
	f := newFixture(t)

	var (
		mu      sync.Mutex
		created int
		refused int
		other   []error
		wg      sync.WaitGroup
	)

	start := make(chan struct{})

	wg.Add(attempts)

	for range attempts {
		go func() {
			defer wg.Done()

			<-start

			_, err := f.Provision(ctx, "bob")

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				created++
			case errors.Is(err, identity.ErrUserExists):
				refused++
			default:
				other = append(other, err)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Empty(t, other,
		"a losing caller must be refused with ErrUserExists, not with an incidental failure")
	assert.Equal(t, 1, created,
		"exactly one concurrent Provision may create the user: more than one means the collision "+
			"was decided by a read that another caller raced")
	assert.Equal(t, attempts-1, refused,
		"every caller that did not create the user is refused")
}

func runProvisionCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture)
		user   string
		opts   []identity.UserOption
		assert func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name: "a created user is active",
			user: "alice",
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.True(t, d.Active,
					"a user created through provisioning can sign in without a second step")
			},
		},
		{
			name: "a created user is readable through the loader",
			user: "alice",
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.NoError(t, err)

				loaded, loadErr := f.LoadByUsername(ctx, "alice")
				require.NoError(t, loadErr, "a provisioned user must be visible to the loader")
				assert.Equal(t, d.ID, loaded.ID)
			},
		},
		{
			name: "an empty username is refused",
			user: "",
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.Error(t, err, "a user with no username could never be loaded again")
				assert.Nil(t, d)
			},
		},
		{
			name: "the first role name is primary and the rest are not",
			user: "carol",
			opts: []identity.UserOption{identity.WithUserRoles("editor", "viewer")},
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				assert.Equal(t, "editor", d.Roles[0].Name)
				assert.True(t, d.Roles[0].Primary)
				assert.Equal(t, "viewer", d.Roles[1].Name)
				assert.False(t, d.Roles[1].Primary,
					"exactly one grant is primary, or the active role is ambiguous")
			},
		},
		{
			name: "a repeated role name creates one grant per occurrence",
			user: "carol",
			opts: []identity.UserOption{identity.WithUserRoles("viewer", "viewer")},
			assert: func(t *testing.T, _ context.Context, _ Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Len(t, d.Roles, 2,
					"Provision records what the caller asked for; deduplication is Update's rule")
			},
		},
		{
			name: "the password hash is stored exactly as given",
			user: "carol",
			opts: []identity.UserOption{identity.WithUserPassword([]byte("H"))},
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("H"), d.Password)

				loaded, loadErr := f.LoadByUsername(ctx, "carol")
				require.NoError(t, loadErr)
				assert.Equal(t, []byte("H"), loaded.Password,
					"a store that re-hashed here would make every stored credential unverifiable")
			},
		},
		{
			name: "creation does not stamp the password-changed time",
			user: "carol",
			opts: []identity.UserOption{identity.WithUserPassword([]byte("H"))},
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.True(t, d.PasswordChangedAt.IsZero(),
					"the store records the hash; when the password last changed is the consumer's "+
						"to decide, so creation leaves it unset rather than stamping now — a "+
						"password-age policy reading a stamp nobody set refuses a fresh credential")

				loaded, loadErr := f.LoadByUsername(ctx, "carol")
				require.NoError(t, loadErr)
				assert.True(t, loaded.PasswordChangedAt.IsZero(),
					"and the stored record carries no stamp either")
			},
		},
		{
			name: "a username that is only whitespace is opaque and creates a user",
			user: "   ",
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.NoError(t, err,
					"only an empty username is refused: the username is opaque, so an "+
						"implementation that trims before deciding refuses one the contract allows")
				require.NotNil(t, d)

				loaded, loadErr := f.LoadByUsername(ctx, "   ")
				require.NoError(t, loadErr, "and the user it created is loadable by that username")
				assert.Equal(t, d.ID, loaded.ID)
			},
		},
		{
			name: "the email is never a lookup key",
			user: "erin",
			opts: []identity.UserOption{identity.WithUserEmail("erin@example.com")},
			assert: func(t *testing.T, ctx context.Context, f Fixture, _ *identity.Details, err error) {
				require.NoError(t, err)

				_, loadErr := f.LoadByUsername(ctx, "erin@example.com")
				require.ErrorIs(t, loadErr, identity.ErrUserNotFound,
					"matching on email would let a caller claim an address and take over the account")
			},
		},
		{
			name: "a taken username is refused and the existing user is untouched",
			seed: func(t *testing.T, ctx context.Context, f Fixture) {
				_, err := f.Provision(ctx, "alice", identity.WithUserName("First"))
				require.NoError(t, err)
			},
			user: "alice",
			opts: []identity.UserOption{identity.WithUserName("Second")},
			assert: func(t *testing.T, ctx context.Context, f Fixture, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserExists)
				assert.Nil(t, d)

				stored, loadErr := f.LoadByUsername(ctx, "alice")
				require.NoError(t, loadErr)
				assert.Equal(t, "First", stored.Name,
					"the existing account is never adopted or overwritten by a second create")
			},
		},
		{
			name: "the collision error does not quote the username",
			seed: func(t *testing.T, ctx context.Context, f Fixture) {
				_, err := f.Provision(ctx, "dave@example.com")
				require.NoError(t, err)
			},
			user: "dave@example.com",
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserExists)
				assert.NotContains(t, err.Error(), "dave@example.com",
					"on just-in-time provisioning the username is an email address, and the error "+
						"reaches logs and sometimes the caller")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			if tc.seed != nil {
				tc.seed(t, ctx, f)
			}

			d, err := f.Provision(ctx, tc.user, tc.opts...)
			tc.assert(t, ctx, f, d, err)
		})
	}
}

// RunMFALookupSuite checks the multi-factor requirement contract.
func RunMFALookupSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		setup  func(t *testing.T, ctx context.Context, f Fixture) identity.UserID
		assert func(t *testing.T, required bool, err error)
	}

	provisionRequired := func(t *testing.T, ctx context.Context, f Fixture) identity.UserID {
		t.Helper()

		d, err := f.Provision(ctx, "alice")
		require.NoError(t, err)
		require.NoError(t, f.SeedMFARequired(ctx, d.ID, true))

		return d.ID
	}

	cases := []testCase{
		{
			name: "an unknown user is answered rather than refused",
			setup: func(_ *testing.T, _ context.Context, _ Fixture) identity.UserID {
				return "u-unknown"
			},
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err,
					"an unknown user is a legitimate answer of false, not a lookup failure")
				assert.False(t, required)
			},
		},
		{
			name:  "a user marked as requiring a second factor is reported as required",
			setup: provisionRequired,
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err)
				assert.True(t, required)
			},
		},
		{
			name: "the requirement is answered by user reference",
			setup: func(t *testing.T, ctx context.Context, f Fixture) identity.UserID {
				t.Helper()

				provisionRequired(t, ctx, f)

				other, err := f.Provision(ctx, "bob")
				require.NoError(t, err)

				return other.ID
			},
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err)
				assert.False(t, required,
					"the answer is keyed on the reference asked about, not on whichever user "+
						"happens to be marked: otherwise one user's requirement challenges another")
			},
		},
		{
			name: "the requirement survives a change to the user",
			setup: func(t *testing.T, ctx context.Context, f Fixture) identity.UserID {
				t.Helper()

				id := provisionRequired(t, ctx, f)

				// Stands in for losing an enrolment: the requirement lives with the
				// user, so rewriting the user's own record must not clear it.
				_, err := f.Update(ctx, "alice",
					identity.WithUserRoles("viewer"),
					identity.WithUserPassword([]byte("H2")),
				)
				require.NoError(t, err)

				return id
			},
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err)
				assert.True(t, required,
					"a requirement held inside the user record would be rebuilt away by an "+
						"update, silently dropping a user's second factor")
			},
		},
		{
			name: "a lookup failure is an error, not 'not required'",
			setup: func(t *testing.T, ctx context.Context, f Fixture) identity.UserID {
				t.Helper()

				id := provisionRequired(t, ctx, f)
				f.FailMFALookups(errBackendUnreachable)

				return id
			},
			assert: func(t *testing.T, required bool, err error) {
				require.Error(t, err,
					"a lookup that cannot answer must say so: reported as 'not required', an "+
						"outage would wave every user past their second factor")
				assert.False(t, required, "and it fails closed rather than guessing true")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			id := tc.setup(t, ctx, f)

			required, err := f.Required(ctx, id)
			tc.assert(t, required, err)
		})
	}
}
