package admintest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// runUserSuite runs the cases of the user port that need no role. The cases
// of the user port that concern role grants run in runRoleSuite.
func runUserSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("StaleUpdate", func(t *testing.T) { runStaleUpdateCases(t, newFixture) })
	t.Run("StaleAfterLoginUpdate", func(t *testing.T) { runStaleAfterLoginUpdateCase(t, newFixture) })
	t.Run("UnknownUser", func(t *testing.T) { runUnknownUserCases(t, newFixture) })
	t.Run("UpdateKeepsUnnamedFields", func(t *testing.T) { runUpdateKeepsUnnamedFieldsCase(t, newFixture) })
	t.Run("SetActive", func(t *testing.T) { runSetActiveCase(t, newFixture) })
	t.Run("CreateRace", func(t *testing.T) { runCreateRaceCases(t, newFixture) })
	t.Run("UsernameEmailCollision", func(t *testing.T) { runUsernameEmailCollisionCases(t, newFixture) })
	t.Run("UsernameEmailRace", func(t *testing.T) { runUsernameEmailRaceCase(t, newFixture) })
	t.Run("SoftDelete", func(t *testing.T) { runSoftDeleteCase(t, newFixture) })
	t.Run("DeletedUserWrites", func(t *testing.T) { runDeletedUserWriteCases(t, newFixture) })
	t.Run("AttributesRoundTrip", func(t *testing.T) { runAttributesRoundTripCase(t, newFixture) })
	t.Run("OrganizationRoundTrip", func(t *testing.T) { runOrganizationRoundTripCase(t, newFixture) })
	t.Run("AttributeSearch", func(t *testing.T) { runAttributeSearchCases(t, newFixture) })
	t.Run("ListPagingStable", func(t *testing.T) { runListPagingStableCase(t, newFixture) })
	t.Run("ListPagingOrder", func(t *testing.T) { runListPagingOrderCase(t, newFixture) })
	t.Run("SearchLiteral", func(t *testing.T) { runSearchLiteralCases(t, newFixture) })
	t.Run("ForgedIdentifiers", func(t *testing.T) { runForgedIdentifierCases(t, newFixture) })
	t.Run("CurrentPasswordHash", func(t *testing.T) { runCurrentPasswordHashCase(t, newFixture) })
	t.Run("SetPasswordRecordsChange", func(t *testing.T) { runSetPasswordRecordsChangeCase(t, newFixture) })
}

// userState is everything a refused user write must leave as it was.
type userState struct {
	User admin.User
	Hash []byte
}

func readUserState(ctx context.Context, t *testing.T, f Fixture, id identity.UserID) userState {
	t.Helper()

	u := mustGetUser(ctx, t, f, id)

	hash, err := f.Users().CurrentPasswordHash(ctx, id)
	require.NoError(t, err)

	return userState{User: u, Hash: hash}
}

// staleFixture is a user with a password, read at Stale and since moved past
// it by a colleague's write.
type staleFixture struct {
	ID    identity.UserID
	Stale int64
}

func arrangeStaleUser(ctx context.Context, t *testing.T, f Fixture) staleFixture {
	t.Helper()

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada"})
	require.Positive(t, u.Version, "a created user carries a version")

	set, err := f.Users().SetPassword(ctx, u.ID, u.Version, []byte("hash-0"), passwordSetAt)
	require.NoError(t, err, "a password change naming the current version must succeed")
	require.Greater(t, set.Version, u.Version, "a password change must increase the version")

	// A colleague's write moves the version past the one this caller read.
	name := "Renamed by a colleague"
	moved, err := f.Users().UpdateUser(ctx, u.ID, set.Version, admin.UserChange{Name: &name})
	require.NoError(t, err, "an update naming the current version must succeed")
	require.Greater(t, moved.Version, set.Version, "a successful update must increase the version")
	assert.Equal(t, name, moved.Name, "UpdateUser must return the updated record")

	return staleFixture{ID: u.ID, Stale: set.Version}
}

// runStaleUpdateCases checks that every versioned user write refuses a version
// another write has moved past and writes nothing (F1, Review Focus 3),
// including a write that would change nothing. The assignment writes, which
// share the user's version, are checked by runStaleAssignmentCases.
func runStaleUpdateCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, f Fixture, s staleFixture) error
	}

	cases := []testCase{
		{"UpdateUser", func(ctx context.Context, f Fixture, s staleFixture) error {
			name := "Lost update"
			_, err := f.Users().UpdateUser(ctx, s.ID, s.Stale, admin.UserChange{Name: &name})

			return err
		}},
		{"SetActive", func(ctx context.Context, f Fixture, s staleFixture) error {
			_, _, err := f.Users().SetActive(ctx, s.ID, s.Stale, false)

			return err
		}},
		// The user is active, so this write would change nothing. A store
		// that short-circuits a no-op before comparing the version tells the
		// caller its stale form was applied.
		{"SetActive to the flag it already has", func(ctx context.Context, f Fixture, s staleFixture) error {
			_, _, err := f.Users().SetActive(ctx, s.ID, s.Stale, true)

			return err
		}},
		{"DeleteUser", func(ctx context.Context, f Fixture, s staleFixture) error {
			return f.Users().DeleteUser(ctx, s.ID, s.Stale)
		}},
		{"SetPassword", func(ctx context.Context, f Fixture, s staleFixture) error {
			_, err := f.Users().SetPassword(ctx, s.ID, s.Stale, []byte("lost-hash"), passwordSetAt)

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			s := arrangeStaleUser(ctx, t, f)
			before := readUserState(ctx, t, f, s.ID)

			err := tc.op(ctx, f, s)
			require.ErrorIs(t, err, admin.ErrStaleUpdate,
				"a write naming a version another write moved past must be refused as stale, not "+
					"applied over the colleague's change (reason matched: %s)", reasonOf(err))

			assert.Equal(t, before, readUserState(ctx, t, f, s.ID), "a stale write must change nothing")
		})
	}
}

// runStaleAfterLoginUpdateCase checks that a login-time identity Update moves
// the version, so an administrator's form read before it is stale (D11,
// Review Focus 3).
func runStaleAfterLoginUpdateCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	name := username(t, 0)

	read := mustCreateUser(ctx, t, f, admin.NewUser{Username: name, Name: "Ada"})

	_, err := f.Provisioner().Update(ctx, name, identity.WithUserName("Ada from the login"))
	require.NoError(t, err, "the login-time update must succeed")

	now := mustGetUser(ctx, t, f, read.ID)
	require.Greater(t, now.Version, read.Version,
		"a login-time Update must increase the version, or an administrator's form left open "+
			"across it overwrites what the login wrote")

	edited := "Ada from the form"
	_, err = f.Users().UpdateUser(ctx, read.ID, read.Version, admin.UserChange{Name: &edited})
	require.ErrorIs(t, err, admin.ErrStaleUpdate,
		"an update naming the version read before a login-time update must be stale (reason matched: %s)",
		reasonOf(err))

	assert.Equal(t, "Ada from the login", mustGetUser(ctx, t, f, read.ID).Name,
		"the stale update must not overwrite the login's write")
}

// unknownUserIDs are identifiers no live user has: one the store can hold and
// one it may not.
func unknownUserIDs(t *testing.T) map[string]identity.UserID {
	t.Helper()

	return map[string]identity.UserID{
		"an identifier no user has":            newUserID(t),
		"an identifier the store may not hold": "not-a-uuid",
	}
}

// runUnknownUserCases checks that every user-keyed call of the user port
// answers ErrNotFound, not a storage failure, for an identifier no live user
// has, including one the store cannot represent. runUnknownUserAssignmentCases
// checks the assignment port.
func runUnknownUserCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, f Fixture, id identity.UserID) error
	}

	cases := []testCase{
		{"GetUser", func(ctx context.Context, f Fixture, id identity.UserID) error {
			_, err := f.Users().GetUser(ctx, id)

			return err
		}},
		{"UpdateUser", func(ctx context.Context, f Fixture, id identity.UserID) error {
			name := "x"
			_, err := f.Users().UpdateUser(ctx, id, 1, admin.UserChange{Name: &name})

			return err
		}},
		{"SetActive", func(ctx context.Context, f Fixture, id identity.UserID) error {
			_, _, err := f.Users().SetActive(ctx, id, 1, false)

			return err
		}},
		{"DeleteUser", func(ctx context.Context, f Fixture, id identity.UserID) error {
			return f.Users().DeleteUser(ctx, id, 1)
		}},
		{"CurrentPasswordHash", func(ctx context.Context, f Fixture, id identity.UserID) error {
			_, err := f.Users().CurrentPasswordHash(ctx, id)

			return err
		}},
		{"SetPassword", func(ctx context.Context, f Fixture, id identity.UserID) error {
			_, err := f.Users().SetPassword(ctx, id, 1, []byte("h"), passwordSetAt)

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			for what, id := range unknownUserIDs(t) {
				err := tc.op(ctx, f, id)
				assert.ErrorIs(t, err, admin.ErrNotFound,
					"%s must be not found, not a storage failure (reason matched: %s)", what, reasonOf(err))
			}
		})
	}
}

// runUpdateKeepsUnnamedFieldsCase checks that an update changes only the
// fields it names.
func runUpdateKeepsUnnamedFieldsCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	u := mustCreateUser(ctx, t, f, admin.NewUser{
		Username:        username(t, 0),
		Name:            "Ada",
		Email:           email(t, 0),
		EmailVerifiedAt: verifiedAt,
		Attributes:      map[string]string{"phone": "+62 21 555"},
	})

	_, err := f.Users().SetPassword(ctx, u.ID, u.Version, []byte("hash-1"), passwordSetAt)
	require.NoError(t, err)

	before := readUserState(ctx, t, f, u.ID)

	name := "Ada Lovelace"
	updated, err := f.Users().UpdateUser(ctx, u.ID, before.User.Version, admin.UserChange{Name: &name})
	require.NoError(t, err)

	after := readUserState(ctx, t, f, u.ID)
	assert.Equal(t, name, after.User.Name)
	assert.Equal(t, updated.Version, after.User.Version, "UpdateUser returns the stored version")
	assert.Greater(t, after.User.Version, before.User.Version)
	assert.Equal(t, before.User.Email, after.User.Email, "an update naming only the name kept the email")
	assert.True(t, before.User.EmailVerifiedAt.Equal(after.User.EmailVerifiedAt),
		"an update naming only the name kept the email verification")
	assert.Equal(t, before.User.Attributes, after.User.Attributes, "an update naming only the name kept the attributes")
	assert.Equal(t, before.Hash, after.Hash, "an update naming only the name kept the password")

	// A pointer to the zero time clears the verification and nothing else.
	var zero time.Time
	_, err = f.Users().UpdateUser(ctx, u.ID, after.User.Version, admin.UserChange{EmailVerifiedAt: &zero})
	require.NoError(t, err)

	cleared := mustGetUser(ctx, t, f, u.ID)
	assert.True(t, cleared.EmailVerifiedAt.IsZero(), "a pointer to the zero time clears the verification")
	assert.Equal(t, before.User.Email, cleared.Email, "clearing the verification kept the email")
	assert.Equal(t, name, cleared.Name)
}

// runSetActiveCase checks that SetActive changes only the active flag, and
// that a flag already at the requested value writes nothing.
func runSetActiveCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada"})
	require.True(t, u.Active, "a created user is active")

	off, changed, err := f.Users().SetActive(ctx, u.ID, u.Version, false)
	require.NoError(t, err)
	assert.True(t, changed, "deactivating an active user is a change")
	assert.False(t, off.Active)
	assert.Greater(t, off.Version, u.Version, "a deactivation increases the version")
	assert.Equal(t, u.Name, off.Name)

	again, changed, err := f.Users().SetActive(ctx, u.ID, off.Version, false)
	require.NoError(t, err, "deactivating an inactive user succeeds")
	assert.False(t, changed, "deactivating an inactive user is no change")
	assert.Equal(t, off.Version, again.Version, "a no-op SetActive must leave the version alone")

	on, changed, err := f.Users().SetActive(ctx, u.ID, again.Version, true)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.True(t, on.Active)
	assert.True(t, mustGetUser(ctx, t, f, u.ID).Active)
}

// runCreateRaceCases checks that concurrent creations of one username, or of
// one email, create exactly one user, the rest refused as already existing
// (F4). The collision is decided by the write, not by a preceding read, so
// the race repeats over fresh names each round.
func runCreateRaceCases(t *testing.T, newFixture Factory) {
	t.Helper()

	const creators = 8

	type testCase struct {
		name  string
		user  func(t *testing.T, round, i int) admin.NewUser
		field string
	}

	cases := []testCase{
		{
			name: "one username",
			user: func(t *testing.T, round, i int) admin.NewUser {
				return admin.NewUser{
					Username: username(t, round*100), Name: "Racer", Email: email(t, round*100+i),
				}
			},
			field: admin.FieldUsername,
		},
		{
			name: "one email in different case",
			user: func(t *testing.T, round, i int) admin.NewUser {
				addr := email(t, round*100)
				if i%2 == 1 {
					addr = strings.ToUpper(addr)
				}

				return admin.NewUser{Username: username(t, round*100+i), Name: "Racer", Email: addr}
			},
			field: admin.FieldEmail,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			for round := range raceRounds {
				users := make([]admin.NewUser, creators)
				for i := range users {
					users[i] = tc.user(t, round, i)
					users[i].ID = newUserID(t)
				}

				errs := together(t, creators, func(i int) error {
					_, err := f.Users().CreateUser(ctx, users[i])

					return err
				})

				won := 0

				for i, err := range errs {
					if err == nil {
						won++

						continue
					}

					requireAlreadyExists(t, err, tc.field, fmt.Sprintf("round %d: a losing concurrent creation", round))

					_, err := f.Users().GetUser(ctx, users[i].ID)
					assert.ErrorIs(t, err, admin.ErrNotFound, "round %d: a refused creation must create nothing", round)
				}

				require.Equal(t, 1, won, "round %d: exactly one of the concurrent creations must succeed", round)
			}
		})
	}
}

// runUsernameEmailCollisionCases checks that a username never equals another
// live user's email, nor an email another user's username, ignoring case, in
// both directions and on create and update.
func runUsernameEmailCollisionCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		act    func(ctx context.Context, t *testing.T, f Fixture, bob, other admin.User) (identity.UserID, error)
		assert func(t *testing.T, err error)
	}

	refused := func(field string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			requireAlreadyExists(t, err, field, "the colliding write")
		}
	}

	cases := []testCase{
		{
			name: "create with a username equal to another user's email",
			act: func(ctx context.Context, t *testing.T, f Fixture, bob, _ admin.User) (identity.UserID, error) {
				id := newUserID(t)
				_, err := f.Users().CreateUser(ctx, admin.NewUser{ID: id, Username: strings.ToUpper(bob.Email)})

				return id, err
			},
			assert: refused(admin.FieldUsername),
		},
		{
			name: "create with an email equal to another user's username",
			act: func(ctx context.Context, t *testing.T, f Fixture, bob, _ admin.User) (identity.UserID, error) {
				id := newUserID(t)
				_, err := f.Users().CreateUser(ctx, admin.NewUser{
					ID: id, Username: username(t, 7), Email: strings.ToUpper(bob.Username),
				})

				return id, err
			},
			assert: refused(admin.FieldEmail),
		},
		{
			name: "update to an email equal to another user's username",
			act: func(ctx context.Context, t *testing.T, f Fixture, bob, other admin.User) (identity.UserID, error) {
				addr := strings.ToUpper(bob.Username)
				_, err := f.Users().UpdateUser(ctx, other.ID, other.Version, admin.UserChange{Email: &addr})

				return other.ID, err
			},
			assert: refused(admin.FieldEmail),
		},
		{
			name: "update to an email equal to another user's email",
			act: func(ctx context.Context, t *testing.T, f Fixture, bob, other admin.User) (identity.UserID, error) {
				addr := strings.ToUpper(bob.Email)
				_, err := f.Users().UpdateUser(ctx, other.ID, other.Version, admin.UserChange{Email: &addr})

				return other.ID, err
			},
			assert: refused(admin.FieldEmail),
		},
		{
			name: "a user's own username may be its own email",
			act: func(ctx context.Context, t *testing.T, f Fixture, _, _ admin.User) (identity.UserID, error) {
				id := newUserID(t)
				addr := email(t, 8)
				_, err := f.Users().CreateUser(ctx, admin.NewUser{ID: id, Username: addr, Email: addr})

				return id, err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err, "the rule is about another user's email, not the user's own")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			bob := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Email: email(t, 0)})
			other := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1), Email: email(t, 1)})
			bobBefore := mustGetUser(ctx, t, f, bob.ID)
			otherBefore := mustGetUser(ctx, t, f, other.ID)

			id, err := tc.act(ctx, t, f, bob, other)
			tc.assert(t, err)

			assert.Equal(t, bobBefore, mustGetUser(ctx, t, f, bob.ID), "the existing user must be unchanged")

			if err == nil {
				return
			}

			if id == other.ID {
				assert.Equal(t, otherBefore, mustGetUser(ctx, t, f, other.ID), "a refused update must change nothing")
			} else {
				_, gerr := f.Users().GetUser(ctx, id)
				assert.ErrorIs(t, gerr, admin.ErrNotFound, "a refused creation must create nothing")
			}
		})
	}
}

// runUsernameEmailRaceCase checks that a creation of username x and an update
// setting email x on another user, racing, never both succeed (F5).
func runUsernameEmailRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	for round := range raceRounds {
		addr := email(t, 100+round)
		other := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, round)})
		creator := newUserID(t)

		errs := together(t, 2, func(i int) error {
			if i == 0 {
				_, err := f.Users().CreateUser(ctx, admin.NewUser{ID: creator, Username: addr})

				return err
			}

			_, err := f.Users().UpdateUser(ctx, other.ID, other.Version, admin.UserChange{Email: &addr})

			return err
		})

		won := 0

		for _, err := range errs {
			if err == nil {
				won++

				continue
			}

			assert.ErrorIs(t, err, admin.ErrAlreadyExists,
				"round %d: the losing write must be refused as already existing, not fail as storage "+
					"(reason matched: %s)", round, reasonOf(err))
		}

		assert.LessOrEqual(t, won, 1, "round %d: a username and another user's email were both set to one value", round)
	}
}

// runSoftDeleteCase checks what deletion keeps and removes (D13).
func runSoftDeleteCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	name, addr := username(t, 0), email(t, 0)

	u := mustCreateUser(ctx, t, f, admin.NewUser{
		Username: name, Name: "Ada", Email: addr, EmailVerifiedAt: verifiedAt,
		Attributes: map[string]string{"phone": "+62 21 555", "job_title": "Manager"},
	})

	set, err := f.Users().SetPassword(ctx, u.ID, u.Version, []byte("hash-1"), passwordSetAt)
	require.NoError(t, err)

	// Password history is written by the password policy's reuse rule, not by
	// SetPassword (design D16b), so the case seeds it.
	seed := historySeeder(f)
	require.NotNil(t, seed, "the preflight requires a way to seed password history")
	require.NoError(t, seed(ctx, u.ID, []byte("hash-0")), "the case could not seed the password history it needs")

	residue, err := f.UserResidue(ctx, u.ID)
	require.NoError(t, err)
	require.NotEmpty(t, residue.PasswordHistory,
		"the case needs password history to check that deletion removes it")

	el, emailLoader := f.Loader().(identity.EmailLoader)
	if emailLoader {
		// The email check below proves something only if the loader finds the
		// live user by the same address first.
		d, err := el.LoadByEmail(ctx, addr)
		require.NoError(t, err, "a live user with a verified email must load by it before deletion")
		require.Equal(t, u.ID, d.ID, "the email loads the user that holds it")
	} else {
		t.Log("admintest: the loader implements no identity.EmailLoader, so the check that a deleted " +
			"user does not load by email did not run")
	}

	require.NoError(t, f.Users().DeleteUser(ctx, u.ID, set.Version))

	_, err = f.Users().GetUser(ctx, u.ID)
	assert.ErrorIs(t, err, admin.ErrNotFound, "a deleted user is not found")

	_, err = f.Loader().LoadByUsername(ctx, name)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, "a deleted user loads by username as not found")

	_, err = f.Loader().LoadByUserID(ctx, u.ID)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, "a deleted user loads by identifier as not found")

	if emailLoader {
		_, err = el.LoadByEmail(ctx, addr)
		assert.ErrorIs(t, err, identity.ErrUserNotFound, "a deleted user loads by email as not found")
	}

	residue, err = f.UserResidue(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, residue.Exists, "deletion keeps the record")
	assert.True(t, residue.Deleted, "deletion marks the record deleted")
	assert.False(t, residue.Active, "deletion clears the active flag")
	assert.Equal(t, name, residue.Username, "deletion keeps the username")
	assert.Empty(t, residue.Email, "deletion releases the email")
	assert.Zero(t, residue.Attributes, "deletion removes the profile attributes")
	assert.Empty(t, residue.PasswordHistory, "deletion removes the password history")

	page, err := f.Users().ListUsers(ctx, admin.UserQuery{Search: tag(t), Limit: 500})
	require.NoError(t, err)
	assert.Empty(t, page, "a deleted user is not listed")

	_, err = f.Users().CreateUser(ctx, admin.NewUser{ID: newUserID(t), Username: name})
	requireAlreadyExists(t, err, admin.FieldUsername, "a deleted user's username is never reused")

	reused := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1), Email: strings.ToUpper(addr)})
	assert.NotEqual(t, u.ID, reused.ID, "a deleted user's email is released for a new user")
}

// runDeletedUserWriteCases checks that every call of the user port on a
// soft-deleted user answers ErrNotFound, at the version the user had when it
// was deleted and at the next one, and leaves the record deleted (D13): a
// deleted user is never updated, reactivated, given a password or deleted
// again. runDeletedUserAssignmentCases checks the assignment port.
func runDeletedUserWriteCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		op   func(ctx context.Context, f Fixture, id identity.UserID, version int64) error
	}

	cases := []testCase{
		{"UpdateUser", func(ctx context.Context, f Fixture, id identity.UserID, v int64) error {
			name := "Renamed after deletion"
			_, err := f.Users().UpdateUser(ctx, id, v, admin.UserChange{Name: &name})

			return err
		}},
		{"SetActive", func(ctx context.Context, f Fixture, id identity.UserID, v int64) error {
			_, _, err := f.Users().SetActive(ctx, id, v, true)

			return err
		}},
		{"SetPassword", func(ctx context.Context, f Fixture, id identity.UserID, v int64) error {
			_, err := f.Users().SetPassword(ctx, id, v, []byte("after-deletion"), passwordSetAt)

			return err
		}},
		{"CurrentPasswordHash", func(ctx context.Context, f Fixture, id identity.UserID, _ int64) error {
			_, err := f.Users().CurrentPasswordHash(ctx, id)

			return err
		}},
		{"DeleteUser", func(ctx context.Context, f Fixture, id identity.UserID, v int64) error {
			return f.Users().DeleteUser(ctx, id, v)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			name := username(t, 0)
			u := mustCreateUser(ctx, t, f, admin.NewUser{Username: name, Name: "Ada"})

			set, err := f.Users().SetPassword(ctx, u.ID, u.Version, []byte("hash-1"), passwordSetAt)
			require.NoError(t, err)
			require.NoError(t, f.Users().DeleteUser(ctx, u.ID, set.Version))

			for _, version := range []int64{set.Version, set.Version + 1} {
				err := tc.op(ctx, f, u.ID, version)
				assert.ErrorIs(t, err, admin.ErrNotFound,
					"a call on a deleted user must be not found at version %d (reason matched: %s)",
					version, reasonOf(err))
			}

			_, err = f.Users().GetUser(ctx, u.ID)
			assert.ErrorIs(t, err, admin.ErrNotFound, "the user stays deleted")

			residue, err := f.UserResidue(ctx, u.ID)
			require.NoError(t, err)
			assert.True(t, residue.Deleted, "the record stays deleted")
			assert.False(t, residue.Active, "the record stays inactive")
			assert.Equal(t, name, residue.Username, "the record keeps its username")
		})
	}
}

// runAttributesRoundTripCase checks that attributes are stored and returned
// unchanged, replaced as a set, and owned by neither side's later writes.
func runAttributesRoundTripCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	attrs := map[string]string{
		"phone":                 "+62 21 555",
		"job_title":             "Manager",
		"note":                  "ünïcödé \"quoted\" 'single' %_\\ <tag>",
		"empty":                 "",
		strings.Repeat("n", 64): strings.Repeat("v", 1024),
	}
	given := cloneMap(attrs)

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Attributes: given})

	// The caller reuses the map it handed over.
	given["phone"] = "rewritten"

	got := mustGetUser(ctx, t, f, u.ID)
	assert.Equal(t, attrs, got.Attributes, "every attribute must come back exactly as stored")

	got.Attributes["job_title"] = "rewritten"
	assert.Equal(t, attrs, mustGetUser(ctx, t, f, u.ID).Attributes,
		"rewriting a returned record's attributes must not write to the store")

	replaced := map[string]string{"phone": "+62 21 777"}

	updated, err := f.Users().UpdateUser(ctx, u.ID, got.Version, admin.UserChange{Attributes: replaced})
	require.NoError(t, err)
	assert.Equal(t, replaced, mustGetUser(ctx, t, f, u.ID).Attributes, "named attributes replace the whole set")

	name := "Renamed"
	updated, err = f.Users().UpdateUser(ctx, u.ID, updated.Version, admin.UserChange{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, replaced, mustGetUser(ctx, t, f, u.ID).Attributes, "nil attributes leave the set unchanged")

	_, err = f.Users().UpdateUser(ctx, u.ID, updated.Version, admin.UserChange{Attributes: map[string]string{}})
	require.NoError(t, err)
	assert.Empty(t, mustGetUser(ctx, t, f, u.ID).Attributes, "an empty non-nil map removes every attribute")
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}

	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}

	return out
}

// requireOrganization requires the user to refer to want, read back whole,
// or to none when want is nil.
func requireOrganization(t *testing.T, want *identity.Organization, got admin.User, msg string) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got.Organization, "%s: the user must refer to no organization", msg)

		return
	}

	require.NotNil(t, got.Organization, "%s: the user must refer to the organization", msg)
	assert.Equal(t, want.ID, got.Organization.ID, "%s: the organization's identifier", msg)
	assert.Equal(t, want.Name, got.Organization.Name, "%s: the organization reads back whole", msg)
}

// runOrganizationRoundTripCase checks that the organization a user refers to
// is stored on create, replaced and removed by an update that names it, and
// kept by one that does not.
func runOrganizationRoundTripCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	first := &identity.Organization{ID: string(newUserID(t)), Name: "First " + tag(t)}
	second := &identity.Organization{ID: string(newUserID(t)), Name: "Second " + tag(t)}
	require.NoError(t, f.SeedOrganization(ctx, first), "the case could not seed the organization it needs")
	require.NoError(t, f.SeedOrganization(ctx, second), "the case could not seed the organization it needs")

	u := mustCreateUser(ctx, t, f, admin.NewUser{
		Username: username(t, 0), Organization: &identity.Organization{ID: first.ID},
	})
	got := mustGetUser(ctx, t, f, u.ID)
	requireOrganization(t, first, got, "after create")

	ref := &identity.Organization{ID: second.ID}
	upd, err := f.Users().UpdateUser(ctx, u.ID, got.Version, admin.UserChange{Organization: &ref})
	require.NoError(t, err)
	got = mustGetUser(ctx, t, f, u.ID)
	requireOrganization(t, second, got, "after an update naming another organization")
	assert.Greater(t, got.Version, u.Version)

	name := "Renamed"
	upd, err = f.Users().UpdateUser(ctx, u.ID, upd.Version, admin.UserChange{Name: &name})
	require.NoError(t, err)
	requireOrganization(t, second, mustGetUser(ctx, t, f, u.ID), "after an update not naming the organization")

	var none *identity.Organization
	_, err = f.Users().UpdateUser(ctx, u.ID, upd.Version, admin.UserChange{Organization: &none})
	require.NoError(t, err)
	requireOrganization(t, nil, mustGetUser(ctx, t, f, u.ID), "after an update naming no organization")

	plain := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1)})
	requireOrganization(t, nil, mustGetUser(ctx, t, f, plain.ID), "a user created with none")
}

// listSeed is one user of a list-filter case.
type listSeed struct {
	attrs  map[string]string
	role   bool
	active bool
}

// seedListUsers creates one user per seed, grants role to those that ask for
// it, and deactivates the inactive ones. It returns the users' identifiers.
func seedListUsers(ctx context.Context, t *testing.T, f Fixture, role string, seeds []listSeed) []identity.UserID {
	t.Helper()

	ids := make([]identity.UserID, len(seeds))

	for i, s := range seeds {
		u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, i), Attributes: s.attrs})
		v := u.Version

		if s.role {
			v = mustAssign(ctx, t, f, u.ID, v, admin.Assignment{Role: role, Primary: true})
		}

		if !s.active {
			_, _, err := f.Users().SetActive(ctx, u.ID, v, false)
			require.NoError(t, err)
		}

		ids[i] = u.ID
	}

	return ids
}

// listCase is one query of a list-filter case and the seeds it must find.
type listCase struct {
	name  string
	query admin.UserQuery
	want  []int
}

func runListCases(ctx context.Context, t *testing.T, f Fixture, ids []identity.UserID, cases []listCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := tc.query
			q.Limit = 500

			got, err := f.Users().ListUsers(ctx, q)
			require.NoError(t, err)

			want := make([]identity.UserID, 0, len(tc.want))
			for _, i := range tc.want {
				want = append(want, ids[i])
			}

			assert.ElementsMatch(t, want, userIDs(got))
		})
	}
}

// runAttributeSearchCases checks the attribute and active filters, alone and
// together. runListByRoleCases checks the role filter.
func runAttributeSearchCases(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	attr := "job_title-" + tag(t)

	ids := seedListUsers(ctx, t, f, "", []listSeed{
		{attrs: map[string]string{attr: "Manager"}, active: true},        // 0
		{attrs: map[string]string{attr: "manager"}, active: true},        // 1: case differs
		{attrs: map[string]string{attr + "x": "Manager"}, active: true},  // 2: name differs
		{attrs: map[string]string{attr: "Manager"}},                      // 3: inactive
		{attrs: map[string]string{attr: "Manager Senior"}, active: true}, // 4: value is longer
	})

	yes, no := true, false

	runListCases(ctx, t, f, ids, []listCase{
		{"attribute matches name and value exactly", admin.UserQuery{Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}}, []int{0, 3}},
		{"attribute and active", admin.UserQuery{Active: &yes, Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}}, []int{0}},
		{"inactive", admin.UserQuery{Search: tag(t), Active: &no}, []int{3}},
	})
}

func userIDs(users []admin.User) []identity.UserID {
	out := make([]identity.UserID, 0, len(users))
	for _, u := range users {
		out = append(out, u.ID)
	}

	return out
}

// pageAll lists every user matching q, q.Limit at a time, following the
// cursor of each page, and returns the users and the size of each page. It
// stops after maxPages so a cursor that never advances cannot loop forever.
func pageAll(ctx context.Context, t *testing.T, f Fixture, q admin.UserQuery, maxPages int) ([]admin.User, []int) {
	t.Helper()

	var (
		paged []admin.User
		sizes []int
	)

	for range maxPages {
		page, err := f.Users().ListUsers(ctx, q)
		require.NoError(t, err)

		sizes = append(sizes, len(page))
		paged = append(paged, page...)

		if len(page) < q.Limit {
			break
		}

		last := page[len(page)-1]
		q.AfterUsername, q.AfterID = last.Username, last.ID
	}

	return paged, sizes
}

// runListPagingStableCase checks keyset paging over (lower(username), id):
// 120 users in pages of 50 come back as 50, 50 and 20, each exactly once, in
// the order one large page gives. The usernames mix case and scripts, so a
// store that orders by one folding and compares by another skips or repeats
// users across a page boundary.
func runListPagingStableCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)
	stems := []string{"Émile", "éclair", "Zed", "alpha", "ÖSTER", "beta", "Ärger", "zulu", "ÉTÉ", "Mañana"}

	const total = 120

	for i := range total {
		k := key
		if i%5 == 0 {
			k = strings.ToUpper(key) // the search must fold case too
		}

		name := stems[i%len(stems)] + "-" + k + "-" + itoa3(i)
		mustCreateUser(ctx, t, f, admin.NewUser{Username: name})
	}

	all, err := f.Users().ListUsers(ctx, admin.UserQuery{Search: key, Limit: 500})
	require.NoError(t, err)
	require.Len(t, all, total, "one large page lists every matching user")

	paged, sizes := pageAll(ctx, t, f, admin.UserQuery{Search: key, Limit: 50}, 4)

	assert.Equal(t, []int{50, 50, 20}, sizes, "120 users in pages of 50")
	assert.Equal(t, userIDs(all), userIDs(paged),
		"paging must give every user exactly once, in the order of one large page")
}

func itoa3(i int) string { return fmt.Sprintf("%03d", i) }

// runListPagingOrderCase checks the order itself: users whose names are
// letters only, so every collation sorts them alike, come back across pages
// in exactly (lower(username), id) order. The stems put upper-case names
// where a byte comparison would sort them before every lower-case one.
func runListPagingOrderCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := letterTag(t)
	stems := []string{"Bravo", "alpha", "Charlie", "delta", "Echo", "foxtrot", "Golf"}

	created := make([]admin.User, 0, len(stems))
	for _, s := range stems {
		created = append(created, mustCreateUser(ctx, t, f, admin.NewUser{Username: s + key}))
	}

	want := slices.Clone(created)
	slices.SortFunc(want, func(a, b admin.User) int {
		if c := strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username)); c != 0 {
			return c
		}

		return strings.Compare(string(a.ID), string(b.ID))
	})

	paged, sizes := pageAll(ctx, t, f, admin.UserQuery{Search: key, Limit: 3}, 5)

	assert.Equal(t, []int{3, 3, 1}, sizes, "seven users in pages of three")
	assert.ElementsMatch(t, userIDs(created), userIDs(paged), "paging must give every user exactly once")
	assert.Equal(t, userIDs(want), userIDs(paged), "the pages must follow (lower(username), id)")
}

// runSearchLiteralCases checks that the search is literal for %, _ and \, and
// matches username, display name and email ignoring case.
func runSearchLiteralCases(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)

	seeds := []admin.NewUser{
		{Username: key + "a_b"},  // 0
		{Username: key + "axb"},  // 1
		{Username: key + "a%b"},  // 2
		{Username: key + "azzb"}, // 3
		{Username: key + `a\b`},  // 4
		{Username: key + "ab"},   // 5
		{Username: "n-" + key + "-6", Name: "Display " + strings.ToUpper(key) + " Person"},    // 6
		{Username: "n-" + key + "-7", Email: "Mail." + strings.ToUpper(key) + "@Example.com"}, // 7
	}

	ids := make([]identity.UserID, len(seeds))
	for i, s := range seeds {
		ids[i] = mustCreateUser(ctx, t, f, s).ID
	}

	type testCase struct {
		search string
		want   []int
	}

	cases := []testCase{
		{key + "a_b", []int{0}},
		{key + "a%b", []int{2}},
		{key + `a\b`, []int{4}},
		{"display " + key, []int{6}},
		{"mail." + key + "@example", []int{7}},
		{strings.ToUpper(key) + "AXB", []int{1}},
	}

	for _, tc := range cases {
		t.Run(tc.search, func(t *testing.T) {
			got, err := f.Users().ListUsers(ctx, admin.UserQuery{Search: tc.search, Limit: 500})
			require.NoError(t, err)

			want := make([]identity.UserID, 0, len(tc.want))
			for _, i := range tc.want {
				want = append(want, ids[i])
			}

			assert.ElementsMatch(t, want, userIDs(got), "the search text is literal and ignores case")
		})
	}
}

// forgedID is an identifier scrty's stores cannot hold.
const forgedID = "not-a-uuid"

// runForgedIdentifierCases checks that an identifier forged into a cursor or
// an organization reference is either refused as invalid input or honoured:
// a store that cannot hold it answers ErrInvalidInput, and a store that
// accepts it must act on it. Accepting it and then ignoring it is the defect
// this case exists for: a cursor that silently restarts the listing, or an
// organization that silently is not stored.
func runForgedIdentifierCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		// op calls the port with the forged identifier and, when the store
		// accepted it, checks that the store honoured it.
		op func(ctx context.Context, t *testing.T, f Fixture) error
	}

	// seedForgedOrganization records an organization under the forged
	// identifier. A store that cannot hold the identifier cannot seed it
	// either; that error is the expected outcome, not a failure, and the port
	// is then expected to refuse the identifier as invalid input.
	seedForgedOrganization := func(ctx context.Context, t *testing.T, f Fixture) *identity.Organization {
		t.Helper()

		org := &identity.Organization{ID: forgedID, Name: "Forged " + tag(t)}
		if err := f.SeedOrganization(ctx, org); err != nil {
			t.Logf("the fixture could not seed an organization under a forged identifier (%v); "+
				"the port is expected to refuse it", err)
		}

		return org
	}

	cases := []testCase{
		{"a cursor's identifier", func(ctx context.Context, t *testing.T, f Fixture) error {
			key := letterTag(t)

			var created []admin.User
			for _, stem := range []string{"a", "b", "c", "d"} {
				created = append(created, mustCreateUser(ctx, t, f, admin.NewUser{Username: stem + key}))
			}

			// The cursor's username sorts between b<key> and c<key> and is no
			// user's, so a store honouring the cursor returns c and d whatever
			// it makes of the forged identifier.
			page, err := f.Users().ListUsers(ctx, admin.UserQuery{
				Search: key, AfterUsername: "b" + key + "z", AfterID: forgedID, Limit: 10,
			})
			if err == nil {
				assert.Equal(t, userIDs(created[2:]), userIDs(page),
					"a store that accepts the cursor must page after it, not restart the listing")
			}

			return err
		}},
		{"an organization on create", func(ctx context.Context, t *testing.T, f Fixture) error {
			org := seedForgedOrganization(ctx, t, f)
			id := newUserID(t)

			_, err := f.Users().CreateUser(ctx, admin.NewUser{
				ID: id, Username: username(t, 0), Organization: &identity.Organization{ID: forgedID},
			})
			if err == nil {
				requireOrganization(t, org, mustGetUser(ctx, t, f, id),
					"a store that accepts the organization must store it")
			}

			return err
		}},
		{"an organization on update", func(ctx context.Context, t *testing.T, f Fixture) error {
			org := seedForgedOrganization(ctx, t, f)
			u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1)})
			ref := &identity.Organization{ID: forgedID}

			_, err := f.Users().UpdateUser(ctx, u.ID, u.Version, admin.UserChange{Organization: &ref})
			if err == nil {
				requireOrganization(t, org, mustGetUser(ctx, t, f, u.ID),
					"a store that accepts the organization must store it")
			}

			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.op(t.Context(), t, newFixture(t))
			if err != nil {
				assert.ErrorIs(t, err, admin.ErrInvalidInput,
					"input the store cannot represent is invalid input, not a storage failure "+
						"(reason matched: %s)", reasonOf(err))
			}
		})
	}
}

// runCurrentPasswordHashCase checks that the current hash is the stored one,
// empty for a user with none, and the caller's own copy.
func runCurrentPasswordHashCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})

	hash, err := f.Users().CurrentPasswordHash(ctx, u.ID)
	require.NoError(t, err, "a user with no password has an empty hash, not an error")
	assert.Empty(t, hash)

	_, err = f.Users().SetPassword(ctx, u.ID, u.Version, []byte("hash-1"), passwordSetAt)
	require.NoError(t, err)

	hash, err = f.Users().CurrentPasswordHash(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("hash-1"), hash)

	clear(hash)

	again, err := f.Users().CurrentPasswordHash(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("hash-1"), again, "wiping the returned hash must not wipe the stored one")
}

// runSetPasswordRecordsChangeCase checks that SetPassword stores the hash and
// the change time, keeps no handle on the caller's buffer, and records no
// password history of its own: history belongs to the password policy's
// reuse rule, which retires the replaced hash through password.History
// (design D16b), so a store that also recorded it would count one password
// twice.
func runSetPasswordRecordsChangeCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0)})

	first := []byte("hash-1")

	set, err := f.Users().SetPassword(ctx, u.ID, u.Version, first, passwordSetAt)
	require.NoError(t, err)
	assert.Greater(t, set.Version, u.Version, "a password change increases the version")

	clear(first)

	hash, err := f.Users().CurrentPasswordHash(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("hash-1"), hash, "wiping the caller's buffer must not wipe the stored hash")

	d, err := f.Loader().LoadByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.True(t, passwordSetAt.Equal(d.PasswordChangedAt), "the change time is the one given, got %v", d.PasswordChangedAt)

	later := passwordSetAt.Add(24 * time.Hour)

	set2, err := f.Users().SetPassword(ctx, u.ID, set.Version, []byte("hash-2"), later)
	require.NoError(t, err)
	assert.Greater(t, set2.Version, set.Version)

	d, err = f.Loader().LoadByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.Equal(t, []byte("hash-2"), d.Password, "the new hash is stored")
	assert.True(t, later.Equal(d.PasswordChangedAt), "the change time is the one given, got %v", d.PasswordChangedAt)

	residue, err := f.UserResidue(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, residue.PasswordHistory,
		"SetPassword must record no password history; the password policy's reuse rule does")
}
