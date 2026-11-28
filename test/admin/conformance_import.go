package admintest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
)

// runImportSuite runs the import cases that need no role. The import cases
// that name roles run in runRoleSuite.
func runImportSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("ImportIdempotent", func(t *testing.T) { runImportChangeCases(t, newFixture, importFieldChanges, false) })
	t.Run("ImportRace", func(t *testing.T) { runImportRaceCase(t, newFixture) })
	t.Run("ImportTakeoverRefused", func(t *testing.T) { runImportTakeoverRefusedCases(t, newFixture) })
	t.Run("ImportDeletedUserRefused", func(t *testing.T) { runImportDeletedUserRefusedCase(t, newFixture) })
	t.Run("ImportIdentifierAsGiven", func(t *testing.T) { runImportIdentifierAsGivenCases(t, newFixture) })
	t.Run("ImportAfterRename", func(t *testing.T) { runImportAfterRenameCase(t, newFixture) })
}

// importHashes are two password hashes an import stores as given.
var importHashes = [2][]byte{
	[]byte("$2a$10$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0"),
	[]byte("$2a$10$0ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvuutsrqponmlkjihgfedcba"),
}

// importedUser returns a complete import payload unique to the case.
func importedUser(t *testing.T, i int, roles ...string) admin.ImportedUser {
	t.Helper()

	return admin.ImportedUser{
		ID:              newUserID(t),
		Username:        username(t, i),
		Name:            "Imported " + username(t, i),
		Email:           email(t, i),
		EmailVerifiedAt: verifiedAt,
		PasswordHash:    slices.Clone(importHashes[0]),
		Active:          true,
		CreatedAt:       importCreatedAt,
		UpdatedAt:       importUpdatedAt,
		Roles:           roles,
		Attributes:      map[string]string{"source": "directory", "department": "sales"},
	}
}

// cloneImport returns a copy of in that shares no slice or map with it.
func cloneImport(in admin.ImportedUser) admin.ImportedUser {
	in.PasswordHash = slices.Clone(in.PasswordHash)
	in.Roles = slices.Clone(in.Roles)
	in.Attributes = cloneMap(in.Attributes)

	return in
}

// requireImported requires the stored user to carry exactly the payload's
// values, including the identifier, hash and both times.
func requireImported(ctx context.Context, t *testing.T, f Fixture, in admin.ImportedUser) admin.User {
	t.Helper()

	got := mustGetUser(ctx, t, f, in.ID)
	assert.Equal(t, in.Username, got.Username)
	assert.Equal(t, in.Name, got.Name)
	assert.Equal(t, in.Email, got.Email)
	assert.True(t, in.EmailVerifiedAt.Equal(got.EmailVerifiedAt),
		"email verification time is stored as given, got %v", got.EmailVerifiedAt)
	assert.Equal(t, in.Active, got.Active)
	assert.True(t, in.CreatedAt.Equal(got.CreatedAt), "creation time is stored as given, got %v", got.CreatedAt)
	assert.True(t, in.UpdatedAt.Equal(got.UpdatedAt), "update time is stored as given, got %v", got.UpdatedAt)

	if len(in.Attributes) == 0 {
		assert.Empty(t, got.Attributes, "the user holds no attribute")
	} else {
		assert.Equal(t, in.Attributes, got.Attributes)
	}

	held := make([]string, 0, len(got.Roles))
	for _, r := range got.Roles {
		if r != nil {
			held = append(held, r.Name)
		}
	}

	assert.ElementsMatch(t, in.Roles, held, "the user holds each imported role exactly once")

	hash, err := f.Users().CurrentPasswordHash(ctx, in.ID)
	require.NoError(t, err)
	assert.Equal(t, in.PasswordHash, hash, "the hash is stored unchanged")

	return got
}

// importChange is one row of the import-change table: a payload already
// imported, and a change to exactly one of its fields.
type importChange struct {
	name string
	// change returns the payload with one field changed. roles are the roles
	// the case created, a and b held by the first import and c not.
	change func(t *testing.T, in admin.ImportedUser, roles [3]string) admin.ImportedUser
}

// importFieldChanges change one field each, every field of ImportedUser but
// the identifier and the roles. A store that compares fewer fields than it
// stores reports a changed payload unchanged and writes nothing.
var importFieldChanges = []importChange{
	{"display name", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Name = "Renamed upstream"

		return in
	}},
	{"username", func(t *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Username = username(t, 50)

		return in
	}},
	{"email", func(t *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Email = email(t, 50)

		return in
	}},
	{"email verification time", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.EmailVerifiedAt = verifiedAt.Add(time.Hour)

		return in
	}},
	{"email verification cleared", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.EmailVerifiedAt = time.Time{}

		return in
	}},
	{"password hash", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.PasswordHash = slices.Clone(importHashes[1])

		return in
	}},
	{"deactivated", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Active = false

		return in
	}},
	{"attribute value changed", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Attributes["source"] = "ldap"

		return in
	}},
	{"attribute added", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Attributes["phone"] = "+62 21 555"

		return in
	}},
	{"attribute removed", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		delete(in.Attributes, "department")

		return in
	}},
	{"every attribute removed", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Attributes = map[string]string{}

		return in
	}},
	{"creation time", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.CreatedAt = importCreatedAt.Add(-24 * time.Hour)

		return in
	}},
	{"update time", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.UpdatedAt = importUpdatedAt.Add(48 * time.Hour)

		return in
	}},
}

// importRoleChanges change the roles the payload names. They run in the role
// part, which creates the roles.
var importRoleChanges = []importChange{
	{"role added", func(_ *testing.T, in admin.ImportedUser, r [3]string) admin.ImportedUser {
		in.Roles = []string{r[0], r[1], r[2]}

		return in
	}},
	{"role removed", func(_ *testing.T, in admin.ImportedUser, r [3]string) admin.ImportedUser {
		in.Roles = []string{r[0]}

		return in
	}},
	{"role swapped for another", func(_ *testing.T, in admin.ImportedUser, r [3]string) admin.ImportedUser {
		in.Roles = []string{r[0], r[2]}

		return in
	}},
	{"every role removed", func(_ *testing.T, in admin.ImportedUser, _ [3]string) admin.ImportedUser {
		in.Roles = nil

		return in
	}},
}

// runImportChangeCases checks the three outcomes over one changed field per
// row: the first import of an identifier creates the user, re-importing equal
// values is unchanged and writes nothing, an import differing in the row's
// field updates the user to exactly the new values and moves its version, and
// re-importing that is unchanged again. With withRoles, each row runs with
// three roles created, the first two held by the first import.
func runImportChangeCases(t *testing.T, newFixture Factory, rows []importChange, withRoles bool) {
	t.Helper()

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			var (
				roles [3]string
				held  []string
			)

			if withRoles {
				for i, label := range []string{"a", "b", "c"} {
					roles[i] = roleName(t, label)
					mustCreateRole(ctx, t, f, roles[i])
				}

				held = []string{roles[0], roles[1]}
			}

			in := importedUser(t, 0, held...)

			out, err := f.Importer().ImportUser(ctx, cloneImport(in))
			require.NoError(t, err)
			require.Equal(t, admin.ImportCreated, out, "the first import of an identifier creates the user")

			created := requireImported(ctx, t, f, in)

			out, err = f.Importer().ImportUser(ctx, cloneImport(in))
			require.NoError(t, err)
			assert.Equal(t, admin.ImportUnchanged, out, "re-importing equal values changes nothing")

			same := mustGetUser(ctx, t, f, in.ID)
			assert.Equal(t, created.Version, same.Version, "an unchanged import must not write: the version moved")
			assert.True(t, created.UpdatedAt.Equal(same.UpdatedAt),
				"an unchanged import must not write: the update time moved")

			changed := row.change(t, cloneImport(in), roles)

			// Every row must end updated to exactly the changed payload, with a
			// higher version, and unchanged when imported again.
			out, err = f.Importer().ImportUser(ctx, cloneImport(changed))
			require.NoError(t, err)
			assert.Equal(t, admin.ImportUpdated, out,
				"an import whose %s differs from the stored one must update the user", row.name)

			updated := requireImported(ctx, t, f, changed)
			assert.Greater(t, updated.Version, created.Version, "an updating import increases the version")

			out, err = f.Importer().ImportUser(ctx, cloneImport(changed))
			require.NoError(t, err)
			assert.Equal(t, admin.ImportUnchanged, out, "re-importing the updated values changes nothing")
			assert.Equal(t, updated.Version, mustGetUser(ctx, t, f, in.ID).Version,
				"an unchanged import must not write: the version moved")
		})
	}
}

// runImportUnknownRoleCase checks that an import naming a role the store does
// not hold is not found and writes nothing.
func runImportUnknownRoleCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := roleName(t, "a")
	mustCreateRole(ctx, t, f, role)

	// The store imports a user naming a role it holds, so the refusal below
	// is about the role and not about a store that imports nothing.
	known := importedUser(t, 0, role)
	out, err := f.Importer().ImportUser(ctx, known)
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, out)

	in := importedUser(t, 1, role, roleName(t, "ghost"))

	_, err = f.Importer().ImportUser(ctx, in)
	require.ErrorIs(t, err, admin.ErrNotFound, "an unknown role is not found (reason matched: %s)", reasonOf(err))

	_, err = f.Users().GetUser(ctx, in.ID)
	assert.ErrorIs(t, err, admin.ErrNotFound, "a refused import creates nothing")
}

// runImportRaceCase checks that concurrent imports of one new identifier with
// identical payloads create one user, and every other import reports
// unchanged, never updated and never a constraint error (Review Focus 4, and
// the store rules fixed with the suite). The race repeats over a fresh
// identifier each round.
func runImportRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const importers = 4

	ctx := t.Context()
	f := newFixture(t)

	for round := range raceRounds {
		in := importedUser(t, round)
		outcomes := make([]admin.ImportOutcome, importers)

		errs := together(t, importers, func(i int) error {
			out, err := f.Importer().ImportUser(ctx, cloneImport(in))
			outcomes[i] = out

			return err
		})

		created := 0

		for i, err := range errs {
			require.NoError(t, err, "round %d: a concurrent import of the same user must not fail "+
				"(reason matched: %s)", round, reasonOf(err))

			switch outcomes[i] {
			case admin.ImportCreated:
				created++
			case admin.ImportUnchanged:
			default:
				t.Errorf("round %d: import %d of an identical payload reported %v, want created or unchanged",
					round, i, outcomes[i])
			}
		}

		require.Equal(t, 1, created, "round %d: exactly one concurrent import creates the user", round)
		requireImported(ctx, t, f, in)
	}
}

// runImportTakeoverRefusedCases checks that import matches by identifier only:
// a username or email held by another identifier is refused and both users
// are unchanged (F9).
func runImportTakeoverRefusedCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name  string
		field string
		// payload builds the import from the victim and a fresh payload; an
		// existing payload is imported first when existing is true.
		existing bool
		payload  func(victim admin.User, in admin.ImportedUser) admin.ImportedUser
	}

	cases := []testCase{
		{
			name: "a new identifier with another user's username", field: admin.FieldUsername,
			payload: func(v admin.User, in admin.ImportedUser) admin.ImportedUser {
				in.Username = v.Username

				return in
			},
		},
		{
			name: "a new identifier with another user's email in different case", field: admin.FieldEmail,
			payload: func(v admin.User, in admin.ImportedUser) admin.ImportedUser {
				in.Email = strings.ToUpper(v.Email)

				return in
			},
		},
		{
			name: "a new identifier whose username is another user's email", field: admin.FieldUsername,
			payload: func(v admin.User, in admin.ImportedUser) admin.ImportedUser {
				in.Username = v.Email

				return in
			},
		},
		{
			name: "an existing identifier renamed to another user's username", field: admin.FieldUsername,
			existing: true,
			payload: func(v admin.User, in admin.ImportedUser) admin.ImportedUser {
				in.Username = v.Username

				return in
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			victim := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Email: email(t, 0)})
			victimBefore := mustGetUser(ctx, t, f, victim.ID)

			in := importedUser(t, 1)

			var importedBefore *admin.User

			if tc.existing {
				_, err := f.Importer().ImportUser(ctx, cloneImport(in))
				require.NoError(t, err)

				u := mustGetUser(ctx, t, f, in.ID)
				importedBefore = &u
			}

			_, err := f.Importer().ImportUser(ctx, tc.payload(victim, cloneImport(in)))
			requireAlreadyExists(t, err, tc.field, "an import naming another identifier's "+tc.field)

			assert.Equal(t, victimBefore, mustGetUser(ctx, t, f, victim.ID), "the other user must be unchanged")

			if importedBefore != nil {
				assert.Equal(t, *importedBefore, mustGetUser(ctx, t, f, in.ID), "the imported user must be unchanged")
			} else {
				_, err := f.Users().GetUser(ctx, in.ID)
				assert.ErrorIs(t, err, admin.ErrNotFound, "a refused import creates nothing")
			}

			_, err = f.Loader().LoadByUserID(ctx, victim.ID)
			require.NoError(t, err)

			if importedBefore == nil {
				_, err = f.Loader().LoadByUserID(ctx, in.ID)
				assert.ErrorIs(t, err, identity.ErrUserNotFound)
			}
		})
	}
}

// runImportDeletedUserRefusedCase checks that an import naming the identifier
// of a soft-deleted user is refused as an AlreadyExistsError naming the field
// "id", and neither restores nor changes the deleted record (D13, and the
// store rules fixed with the suite). The payload's username and email are
// fresh, so the identifier is the only thing that collides.
func runImportDeletedUserRefusedCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	in := importedUser(t, 0)

	out, err := f.Importer().ImportUser(ctx, cloneImport(in))
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, out)

	u := mustGetUser(ctx, t, f, in.ID)
	require.NoError(t, f.Users().DeleteUser(ctx, u.ID, u.Version))

	again := importedUser(t, 1)
	again.ID = in.ID

	_, err = f.Importer().ImportUser(ctx, again)
	requireAlreadyExists(t, err, admin.FieldID,
		fmt.Sprintf("an import naming a deleted user's identifier (reason matched: %s)", reasonOf(err)))

	_, err = f.Users().GetUser(ctx, in.ID)
	assert.ErrorIs(t, err, admin.ErrNotFound, "a deleted user is never restored by an import")

	residue, err := f.UserResidue(ctx, in.ID)
	require.NoError(t, err)
	assert.True(t, residue.Deleted, "the record stays deleted")
	assert.False(t, residue.Active, "the record stays inactive")
	assert.Equal(t, in.Username, residue.Username, "the record keeps its own username")
	assert.Empty(t, residue.Email, "the record holds no email")

	_, err = f.Loader().LoadByUsername(ctx, again.Username)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, "the refused payload's username names no user")
}

// runImportIdentifierAsGivenCases checks that an imported identifier is stored
// exactly as given or refused (D14). The identifier's form is the store's to
// judge: a store whose identifiers are UUIDs, as scrty's are, refuses any text
// that is not a canonical lower-case UUID other than the nil UUID with
// ErrInvalidInput and writes nothing; a store that holds any text accepts it
// and must then return the user under exactly that identifier. Accepting it and
// storing another spelling (a lower-cased or reparsed UUID) is the defect this
// case exists for: the source system's identifier would then name no user.
func runImportIdentifierAsGivenCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		// id derives the identifier from a fresh canonical one.
		id func(canonical identity.UserID) identity.UserID
	}

	cases := []testCase{
		{"an upper-case UUID", func(c identity.UserID) identity.UserID {
			return identity.UserID(strings.ToUpper(string(c)))
		}},
		{"text that is not a UUID", func(c identity.UserID) identity.UserID {
			return identity.UserID("not-a-uuid-" + string(c))
		}},
		{"the nil UUID", func(identity.UserID) identity.UserID {
			return "00000000-0000-0000-0000-000000000000"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			in := importedUser(t, 0)
			canonical := in.ID
			in.ID = tc.id(canonical)

			out, err := f.Importer().ImportUser(ctx, cloneImport(in))
			if err != nil {
				require.ErrorIs(t, err, admin.ErrInvalidInput,
					"an identifier the store cannot hold is refused as invalid input (reason matched: %s)",
					reasonOf(err))

				for _, ref := range []identity.UserID{in.ID, canonical} {
					residue, err := f.UserResidue(ctx, ref)
					require.NoError(t, err)
					assert.False(t, residue.Exists, "a refused import writes no record under %q", ref)
				}

				_, err = f.Loader().LoadByUsername(ctx, in.Username)
				assert.ErrorIs(t, err, identity.ErrUserNotFound, "a refused import's username names no user")

				return
			}

			require.Equal(t, admin.ImportCreated, out)
			got := mustGetUser(ctx, t, f, in.ID)
			assert.Equal(t, in.ID, got.ID, "an accepted identifier is returned exactly as given")

			if folded := identity.UserID(strings.ToLower(string(in.ID))); folded != in.ID {
				residue, err := f.UserResidue(ctx, folded)
				require.NoError(t, err)
				assert.False(t, residue.Exists, "the store kept another spelling of the identifier")
			}
		})
	}
}

// eventRecorder collects the events a service reports. The sink may be called
// concurrently, so the slice is guarded.
type eventRecorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *eventRecorder) sink(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
}

func (r *eventRecorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	names := make([]string, 0, len(r.events))
	for _, e := range r.events {
		names = append(names, e.Name)
	}

	return names
}

// runImportAfterRenameCase checks that a rename through an update leaves
// import matching by identifier as before: ada is imported, renamed through
// the administration service, and her identifier then imported with the new
// username and every other value as stored. The import reports unchanged,
// emits no event and writes nothing.
func runImportAfterRenameCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := admin.WithSystemActor(t.Context(), "admintest")
	f := newFixture(t)

	in := importedUser(t, 0)
	out, err := f.Importer().ImportUser(ctx, cloneImport(in))
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, out)

	users, err := admin.NewUsers(f.Users())
	require.NoError(t, err)

	ada := mustGetUser(ctx, t, f, in.ID)
	newName := username(t, 5)
	_, err = users.Update(ctx, ada.ID, ada.Version, admin.UserChange{Username: &newName})
	require.NoError(t, err, "the rename must succeed (reason matched: %s)", reasonOf(err))

	renamed := mustGetUser(ctx, t, f, in.ID)
	assert.Equal(t, newName, renamed.Username, "the rename must be stored before the import")

	recognizer, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	var rec eventRecorder
	importer, err := admin.NewImporter(f.Importer(), recognizer, admin.WithEventSink(rec.sink))
	require.NoError(t, err)

	again := cloneImport(in)
	again.Username = newName
	again.UpdatedAt = renamed.UpdatedAt

	out, err = importer.Import(ctx, again)
	require.NoError(t, err, "the import after a rename must succeed (reason matched: %s)", reasonOf(err))
	assert.Equal(t, admin.ImportUnchanged, out,
		"an import equal to the renamed user, the new username included, changes nothing")
	assert.Empty(t, rec.names(), "an unchanged import emits no event")

	after := mustGetUser(ctx, t, f, in.ID)
	assert.Equal(t, renamed, after, "an unchanged import writes nothing")
}
