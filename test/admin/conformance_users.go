package admintest

import (
	"context"
	"fmt"
	"slices"
	"strconv"
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
	t.Run("UpdateEmailVerification", func(t *testing.T) { runUpdateEmailVerificationCases(t, newFixture) })
	t.Run("SetActive", func(t *testing.T) { runSetActiveCase(t, newFixture) })
	t.Run("InactiveUserLoads", func(t *testing.T) { runInactiveUserLoadsCase(t, newFixture) })
	t.Run("CreateRace", func(t *testing.T) { runCreateRaceCases(t, newFixture) })
	t.Run("UsernameEmailCollision", func(t *testing.T) { runUsernameEmailCollisionCases(t, newFixture) })
	t.Run("UsernameEmailRace", func(t *testing.T) { runUsernameEmailRaceCase(t, newFixture) })
	t.Run("SoftDelete", func(t *testing.T) { runSoftDeleteCase(t, newFixture) })
	t.Run("RetireAfterDeletion", func(t *testing.T) { runRetireAfterDeletionCase(t, newFixture) })
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
	t.Run("Rename", func(t *testing.T) { runRenameCases(t, newFixture) })
	t.Run("RenameThroughService", func(t *testing.T) { runRenameThroughServiceCase(t, newFixture) })
	t.Run("OffsetAndCount", func(t *testing.T) { runPagerCases(t, newFixture) })
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

// runUpdateEmailVerificationCases checks how an update that names the email
// treats the stored verification time: an address equal to the stored one,
// ignoring case, keeps it, since it is the address that was verified; a
// different or cleared address never inherits it. It also checks that a
// verification time is refused, changing nothing, when the user has no email
// to verify.
func runUpdateEmailVerificationCases(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	type testCase struct {
		name string
		// stored is the email the user is created with, verified at
		// verifiedAt when not empty.
		stored func(t *testing.T) string
		// change builds the update from the stored email.
		change func(t *testing.T, stored string) admin.UserChange
		assert func(t *testing.T, before userState, after admin.User, err error)
	}

	given := func(t *testing.T) string { t.Helper(); return email(t, 0) }
	none := func(*testing.T) string { return "" }

	kept := func(want func(stored string) string) func(t *testing.T, before userState, after admin.User, err error) {
		return func(t *testing.T, before userState, after admin.User, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want(before.User.Email), after.Email)
			assert.True(t, after.EmailVerifiedAt.Equal(verifiedAt),
				"the address that was verified is unchanged, ignoring case, so its verification stays; got %v",
				after.EmailVerifiedAt)
			assert.Greater(t, after.Version, before.User.Version)
		}
	}

	cases := []testCase{
		{
			name:   "the stored email re-sent keeps the verification",
			stored: given,
			change: func(_ *testing.T, stored string) admin.UserChange { return admin.UserChange{Email: &stored} },
			assert: kept(func(stored string) string { return stored }),
		},
		{
			name:   "the stored email in another case keeps the verification and stores the new spelling",
			stored: given,
			change: func(_ *testing.T, stored string) admin.UserChange {
				upper := strings.ToUpper(stored)
				return admin.UserChange{Email: &upper}
			},
			assert: kept(strings.ToUpper),
		},
		{
			name:   "a different email clears the verification",
			stored: given,
			change: func(t *testing.T, _ string) admin.UserChange {
				t.Helper()
				other := email(t, 1)
				return admin.UserChange{Email: &other}
			},
			assert: func(t *testing.T, _ userState, after admin.User, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, email(t, 1), after.Email)
				assert.True(t, after.EmailVerifiedAt.IsZero(),
					"a new address never inherits the old one's verification; got %v", after.EmailVerifiedAt)
			},
		},
		{
			name:   "a cleared email clears the verification",
			stored: given,
			change: func(*testing.T, string) admin.UserChange {
				empty := ""
				return admin.UserChange{Email: &empty}
			},
			assert: func(t *testing.T, _ userState, after admin.User, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, after.Email)
				assert.True(t, after.EmailVerifiedAt.IsZero(), "no email keeps no verification; got %v",
					after.EmailVerifiedAt)
			},
		},
		{
			name:   "a verification time for a user with no email is refused",
			stored: none,
			change: func(*testing.T, string) admin.UserChange {
				at := verifiedAt
				return admin.UserChange{EmailVerifiedAt: &at}
			},
			assert: func(t *testing.T, before userState, after admin.User, err error) {
				t.Helper()
				require.ErrorIs(t, err, admin.ErrInvalidInput,
					"a verification time with no email to verify is invalid input; got %s", reasonOf(err))
				assert.True(t, after.EmailVerifiedAt.IsZero(), "the refused update stored a verification time")
				assert.Equal(t, before.User.Version, after.Version, "the refused update changed the version")
			},
		},
		{
			name:   "a verification time with the email named empty is refused",
			stored: given,
			change: func(*testing.T, string) admin.UserChange {
				empty, at := "", verifiedAt.Add(time.Hour)
				return admin.UserChange{Email: &empty, EmailVerifiedAt: &at}
			},
			assert: func(t *testing.T, before userState, after admin.User, err error) {
				t.Helper()
				require.ErrorIs(t, err, admin.ErrInvalidInput,
					"a verification time while the email is cleared is invalid input; got %s", reasonOf(err))
				assert.Equal(t, before.User.Version, after.Version, "the refused update changed the version")
				assert.Equal(t, before.User.Email, after.Email, "the refused update changed the email")
				assert.True(t, after.EmailVerifiedAt.Equal(verifiedAt),
					"the refused update changed the verification time; got %v", after.EmailVerifiedAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			nu := admin.NewUser{Username: username(t, 0), Name: "Ada", Email: tc.stored(t)}
			if nu.Email != "" {
				nu.EmailVerifiedAt = verifiedAt
			}
			u := mustCreateUser(ctx, t, f, nu)
			before := readUserState(ctx, t, f, u.ID)

			_, err := f.Users().UpdateUser(ctx, u.ID, before.User.Version, tc.change(t, before.User.Email))

			tc.assert(t, before, mustGetUser(ctx, t, f, u.ID), err)
		})
	}
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
			act: func(ctx context.Context, _ *testing.T, f Fixture, bob, other admin.User) (identity.UserID, error) {
				addr := strings.ToUpper(bob.Username)
				_, err := f.Users().UpdateUser(ctx, other.ID, other.Version, admin.UserChange{Email: &addr})

				return other.ID, err
			},
			assert: refused(admin.FieldEmail),
		},
		{
			name: "update to an email equal to another user's email",
			act: func(ctx context.Context, _ *testing.T, f Fixture, bob, other admin.User) (identity.UserID, error) {
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

// runRetireAfterDeletionCase checks that password history cannot be written
// back for a deleted user (D13, F76). A password change reads the user, the
// policy retires the replaced hash, and only then does the store write the new
// one; a deletion that commits between the read and the retire must not leave
// a history entry behind, so retiring a hash for a deleted user is refused and
// records nothing. The retire goes through the same seeding path as the rest
// of the part (see HistorySeeder), and the case requires only an error: what
// that error matches is the history implementation's to choose.
func runRetireAfterDeletionCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada"})
	set, err := f.Users().SetPassword(ctx, u.ID, u.Version, []byte("hash-1"), passwordSetAt)
	require.NoError(t, err)

	seed := historySeeder(f)
	require.NotNil(t, seed, "the preflight requires a way to seed password history")
	require.NoError(t, seed(ctx, u.ID, []byte("hash-0")), "the case could not seed the password history it needs")

	require.NoError(t, f.Users().DeleteUser(ctx, u.ID, set.Version))

	err = seed(ctx, u.ID, []byte("hash-1"))
	require.Error(t, err, "retiring a hash for a deleted user must be refused, not recorded")

	residue, err := f.UserResidue(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, residue.Deleted, "the record stays deleted")
	assert.Empty(t, residue.PasswordHistory, "a deleted user keeps no password history, even after a late retire")
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

// runInactiveUserLoadsCase checks that a deactivated user is returned by the
// identity loaders, by username and by identifier, with the active flag false
// and no error: the loader reports the flag and the authenticator decides.
func runInactiveUserLoadsCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	u := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada"})

	d, err := f.Loader().LoadByUsername(ctx, u.Username)
	require.NoError(t, err)
	require.True(t, d.Active, "the loader marks a live user active before it is deactivated")

	_, _, err = f.Users().SetActive(ctx, u.ID, u.Version, false)
	require.NoError(t, err)

	byName, err := f.Loader().LoadByUsername(ctx, u.Username)
	require.NoError(t, err, "an inactive user is returned, not hidden (reason matched: %s)", reasonOf(err))
	assert.Equal(t, u.ID, byName.ID)
	assert.False(t, byName.Active, "loaded by username")

	byID, err := f.Loader().LoadByUserID(ctx, u.ID)
	require.NoError(t, err, "an inactive user is returned, not hidden (reason matched: %s)", reasonOf(err))
	assert.Equal(t, u.ID, byID.ID)
	assert.False(t, byID.Active, "loaded by identifier")
}

// renameSkip is the message the rename cases skip with on a store that does
// not implement admin.UsernameUpdater (D8).
const renameSkip = "admintest: the store does not implement admin.UsernameUpdater; rename cases skipped"

// renameEnv is what a rename case starts from: ada, the user it renames, and
// carol, another live user whose username and email ada must not take.
type renameEnv struct {
	f       Fixture
	renamer admin.UsernameUpdater
	ada     admin.User
	carol   admin.User
}

// rename calls UpdateUserRenaming on ada at version with change.
func (e renameEnv) rename(ctx context.Context, version int64, change admin.UserChange) (admin.User, bool, error) {
	return e.renamer.UpdateUserRenaming(ctx, e.ada.ID, version, change)
}

// runRenameCases checks UpdateUserRenaming against the rules of creation: a
// username another user holds, deleted or not, compared exactly, or equal to
// another live user's email ignoring case, is refused naming the username;
// the user's own username and email never clash; a username and an email
// named together are written both or neither; and renamed reports whether the
// stored username differed, byte for byte. A store that does not implement
// admin.UsernameUpdater skips these cases (D8).
func runRenameCases(t *testing.T, newFixture Factory) {
	t.Helper()

	if _, ok := newFixture(t).Users().(admin.UsernameUpdater); !ok {
		t.Skip(renameSkip)
	}

	type testCase struct {
		name string
		// ada is the user the case creates and renames; nil creates her with
		// username 0 and email 0, the email verified.
		ada func(t *testing.T) admin.NewUser
		// act runs the write under test, after any setup of its own.
		act    func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error)
		assert func(ctx context.Context, t *testing.T, e renameEnv, before userState, got admin.User, renamed bool, err error)
	}

	str := func(s string) *string { return &s }

	// unchanged asserts a refusal naming field that wrote nothing. The error
	// text must contain none of ada's old username and the values the change
	// asked for, which asked lists.
	unchanged := func(field string, asked ...func(t *testing.T, e renameEnv) string,
	) func(context.Context, *testing.T, renameEnv, userState, admin.User, bool, error) {
		return func(ctx context.Context, t *testing.T, e renameEnv, before userState, _ admin.User, renamed bool, err error) {
			t.Helper()
			requireAlreadyExists(t, err, field, "the clashing rename")
			assert.False(t, renamed, "a refused rename reports no rename")
			assert.NotContains(t, err.Error(), e.ada.Username, "error text never contains a username")

			for _, a := range asked {
				assert.NotContains(t, err.Error(), a(t, e), "error text never contains a requested value")
			}

			assert.Equal(t, before, readUserState(ctx, t, e.f, e.ada.ID), "a refused rename must change nothing")
			assert.Equal(t, e.carol, mustGetUser(ctx, t, e.f, e.carol.ID), "the other user must be unchanged")
		}
	}

	// applied asserts a successful write storing username and email exactly as
	// given, reporting renamed, and increasing the version.
	applied := func(username, email func(t *testing.T, e renameEnv) string, renamed bool,
	) func(context.Context, *testing.T, renameEnv, userState, admin.User, bool, error) {
		return func(ctx context.Context, t *testing.T, e renameEnv, before userState, got admin.User, gotRenamed bool, err error) {
			t.Helper()
			require.NoError(t, err, "the rename must succeed (reason matched: %s)", reasonOf(err))
			assert.Equal(t, renamed, gotRenamed, "renamed must report whether the stored username differed")
			assert.Greater(t, got.Version, before.User.Version, "every successful update increases the version")

			stored := mustGetUser(ctx, t, e.f, e.ada.ID)
			assert.Equal(t, got, stored, "UpdateUserRenaming must return the record as stored")
			assert.Equal(t, []byte(username(t, e)), []byte(stored.Username), "the username is stored byte for byte as given")
			assert.Equal(t, email(t, e), stored.Email)
		}
	}

	same := func(t *testing.T, e renameEnv) string { t.Helper(); return e.ada.Email }
	newName := func(t *testing.T, _ renameEnv) string { t.Helper(); return username(t, 5) }
	carolEmailUpper := func(t *testing.T, e renameEnv) string { t.Helper(); return strings.ToUpper(e.carol.Email) }
	carolNameUpper := func(t *testing.T, e renameEnv) string { t.Helper(); return strings.ToUpper(e.carol.Username) }

	cases := []testCase{
		{
			name: "Rename",
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(username(t, 5))})
			},
			assert: func(ctx context.Context, t *testing.T, e renameEnv, before userState, got admin.User, renamed bool, err error) {
				t.Helper()
				applied(func(t *testing.T, _ renameEnv) string { return username(t, 5) }, same, true)(
					ctx, t, e, before, got, renamed, err)

				_, lerr := e.f.Loader().LoadByUsername(ctx, e.ada.Username)
				assert.ErrorIs(t, lerr, identity.ErrUserNotFound, "the old username must name no live user")

				d, lerr := e.f.Loader().LoadByUsername(ctx, username(t, 5))
				require.NoError(t, lerr, "the renamed user must load by the new username")
				assert.Equal(t, e.ada.ID, d.ID)
			},
		},
		{
			name: "Username held by a deleted user",
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				bob := mustCreateUser(ctx, t, e.f, admin.NewUser{Username: username(t, 2)})
				require.NoError(t, e.f.Users().DeleteUser(ctx, bob.ID, bob.Version))

				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(bob.Username)})
			},
			assert: unchanged(admin.FieldUsername, func(t *testing.T, _ renameEnv) string { t.Helper(); return username(t, 2) }),
		},
		{
			name: "Username held by a live user",
			act: func(ctx context.Context, _ *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(e.carol.Username)})
			},
			assert: unchanged(admin.FieldUsername, func(_ *testing.T, e renameEnv) string { return e.carol.Username }),
		},
		{
			name: "Case variant of another user's username",
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				upper := strings.ToUpper(e.carol.Username)
				require.NotEqual(t, e.carol.Username, upper, "the variant must differ from the held username")
				require.NotEqual(t, e.ada.Username, upper, "the variant must differ from the renamed user's own username")
				require.False(t, strings.EqualFold(upper, e.carol.Email) || strings.EqualFold(upper, e.ada.Email),
					"the variant must not equal any user's email")

				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: &upper})
			},
			assert: applied(carolNameUpper, same, true),
		},
		{
			name: "Username equal to another user's email",
			act: func(ctx context.Context, _ *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(strings.ToUpper(e.carol.Email))})
			},
			assert: unchanged(admin.FieldUsername, carolEmailUpper),
		},
		{
			name: "Only the case changes",
			act: func(ctx context.Context, _ *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(strings.ToUpper(e.ada.Username))})
			},
			assert: applied(func(_ *testing.T, e renameEnv) string { return strings.ToUpper(e.ada.Username) }, same, true),
		},
		{
			name: "Stale rename",
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				_, _, err := e.f.Users().SetActive(ctx, e.ada.ID, e.ada.Version, false)
				require.NoError(t, err)

				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(username(t, 5))})
			},
			assert: func(ctx context.Context, t *testing.T, e renameEnv, _ userState, _ admin.User, renamed bool, err error) {
				t.Helper()
				require.ErrorIs(t, err, admin.ErrStaleUpdate,
					"a rename at a version a deactivation moved past must be stale (reason matched: %s)", reasonOf(err))
				assert.False(t, renamed)

				stored := mustGetUser(ctx, t, e.f, e.ada.ID)
				assert.False(t, stored.Active, "the deactivation must stay")
				assert.Equal(t, e.ada.Username, stored.Username, "a stale rename must not write the username")
			},
		},
		{
			name: "Username follows a new email",
			ada: func(t *testing.T) admin.NewUser {
				t.Helper()
				return admin.NewUser{Username: email(t, 0), Email: email(t, 0), EmailVerifiedAt: verifiedAt}
			},
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				addr := email(t, 5)
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: &addr, Email: &addr})
			},
			assert: func(ctx context.Context, t *testing.T, e renameEnv, before userState, got admin.User, renamed bool, err error) {
				t.Helper()
				addr := func(t *testing.T, _ renameEnv) string { return email(t, 5) }
				applied(addr, addr, true)(ctx, t, e, before, got, renamed, err)
				assert.True(t, got.EmailVerifiedAt.IsZero(),
					"a new address never inherits the old one's verification; got %v", got.EmailVerifiedAt)
				assert.Equal(t, before.User.Version+1, got.Version, "one change is one write: the version increases once")
			},
		},
		{
			name: "One field clashes",
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{
					Username: str(username(t, 5)), Email: str(strings.ToUpper(e.carol.Email)),
				})
			},
			assert: func(ctx context.Context, t *testing.T, e renameEnv, before userState, got admin.User, renamed bool, err error) {
				t.Helper()
				unchanged(admin.FieldEmail, newName, carolEmailUpper)(ctx, t, e, before, got, renamed, err)

				_, lerr := e.f.Loader().LoadByUsername(ctx, username(t, 5))
				assert.ErrorIs(t, lerr, identity.ErrUserNotFound, "the free username must not have been written")
			},
		},
		{
			name: "Rename to one's own email in the same change",
			act: func(ctx context.Context, _ *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{
					Username: str(strings.ToUpper(e.ada.Email)), Email: str(e.ada.Email),
				})
			},
			assert: func(ctx context.Context, t *testing.T, e renameEnv, before userState, got admin.User, renamed bool, err error) {
				t.Helper()
				applied(func(_ *testing.T, e renameEnv) string { return strings.ToUpper(e.ada.Email) }, same, true)(
					ctx, t, e, before, got, renamed, err)
				assert.True(t, got.EmailVerifiedAt.Equal(verifiedAt),
					"the stored address re-sent keeps its verification; got %v", got.EmailVerifiedAt)
			},
		},
		{
			name: "Username and email equal ignoring case in the same change",
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{
					Username: str(strings.ToUpper(email(t, 5))), Email: str(email(t, 5)),
				})
			},
			assert: applied(func(t *testing.T, _ renameEnv) string { return strings.ToUpper(email(t, 5)) },
				func(t *testing.T, _ renameEnv) string { return email(t, 5) }, true),
		},
		{
			name: "Same username again",
			act: func(ctx context.Context, _ *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(e.ada.Username)})
			},
			assert: applied(func(_ *testing.T, e renameEnv) string { return e.ada.Username }, same, false),
		},
		{
			name: "Normalisation differs",
			ada: func(t *testing.T) admin.NewUser {
				t.Helper()
				return admin.NewUser{Username: username(t, 0) + "-caf\u00e9", Email: email(t, 0), EmailVerifiedAt: verifiedAt}
			},
			act: func(ctx context.Context, t *testing.T, e renameEnv) (admin.User, bool, error) {
				return e.rename(ctx, e.ada.Version, admin.UserChange{Username: str(username(t, 0) + "-cafe\u0301")})
			},
			assert: applied(func(t *testing.T, _ renameEnv) string { return username(t, 0) + "-cafe\u0301" }, same, true),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			renamer, ok := f.Users().(admin.UsernameUpdater)
			require.True(t, ok, "the fixture's user store must implement admin.UsernameUpdater in every case")

			nu := admin.NewUser{Username: username(t, 0), Name: "Ada", Email: email(t, 0), EmailVerifiedAt: verifiedAt}
			if tc.ada != nil {
				nu = tc.ada(t)
			}

			e := renameEnv{f: f, renamer: renamer}
			e.ada = mustCreateUser(ctx, t, f, nu)
			e.carol = mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 1), Email: email(t, 1)})
			e.carol = mustGetUser(ctx, t, f, e.carol.ID)
			e.ada = mustGetUser(ctx, t, f, e.ada.ID)
			before := readUserState(ctx, t, f, e.ada.ID)

			got, renamed, err := tc.act(ctx, t, e)
			tc.assert(ctx, t, e, before, got, renamed, err)
		})
	}
}

// runRenameThroughServiceCase checks that a rename asked of the
// administration service reaches the store and is applied: the service over
// the fixture's user store renames ada, returns her under the new username at
// a higher version, and the store then holds and loads her by that username
// alone. A store that does not implement admin.UsernameUpdater skips the case
// (D8), as the service would refuse the rename with admin.ErrConfig.
func runRenameThroughServiceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := admin.WithSystemActor(t.Context(), "admintest")
	f := newFixture(t)

	if _, ok := f.Users().(admin.UsernameUpdater); !ok {
		t.Skip(renameSkip)
	}

	users, err := admin.NewUsers(f.Users())
	require.NoError(t, err, "the service must accept the fixture's user store")

	ada := mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, 0), Name: "Ada", Email: email(t, 0)})
	newName := username(t, 5)

	got, err := users.Update(ctx, ada.ID, ada.Version, admin.UserChange{Username: &newName})
	require.NoError(t, err, "the service must rename through the store (reason matched: %s)", reasonOf(err))
	assert.Equal(t, newName, got.Username, "Update must return the renamed user")
	assert.Greater(t, got.Version, ada.Version, "a rename increases the version")

	stored := mustGetUser(ctx, t, f, ada.ID)
	assert.Equal(t, newName, stored.Username, "the store must hold the new username")
	assert.Equal(t, ada.Email, stored.Email, "a rename leaves the email as it was")

	_, err = f.Loader().LoadByUsername(ctx, ada.Username)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, "the old username must name no live user")

	d, err := f.Loader().LoadByUsername(ctx, newName)
	require.NoError(t, err, "the renamed user must load by the new username")
	assert.Equal(t, ada.ID, d.ID)
}

// pagerSkip is the message the offset and count cases skip with on a store
// that does not implement admin.UserPager (D14).
const pagerSkip = "admintest: the store does not implement admin.UserPager; offset and count cases skipped"

// runPagerCases checks admin.UserPager: an offset listing gives the users of
// the cursor listing, in its order, from the offset on, and a count gives how
// many live users the same filters match. A store that does not implement
// admin.UserPager skips these cases (D14).
func runPagerCases(t *testing.T, newFixture Factory) {
	t.Helper()

	if _, ok := newFixture(t).Users().(admin.UserPager); !ok {
		t.Skip(pagerSkip)
	}

	t.Run("Jump to a page", func(t *testing.T) { runJumpToPageCase(t, newFixture) })
	t.Run("Consecutive offsets cover every user once, in order", func(t *testing.T) {
		runConsecutiveOffsetsCase(t, newFixture)
	})
	t.Run("Offset past the end", func(t *testing.T) { runOffsetPastEndCase(t, newFixture) })
	t.Run("Offset and count honour the filters", func(t *testing.T) { runPagerFilterCases(t, newFixture) })
	t.Run("Count beside a page", func(t *testing.T) { runCountBesidePageCase(t, newFixture) })
	t.Run("Deleted users are not counted", func(t *testing.T) { runDeletedNotCountedCase(t, newFixture) })
	t.Run("Library stores", func(t *testing.T) { runPagerThroughServiceCase(t, newFixture) })
}

// pagerOf returns the fixture's user store as an admin.UserPager.
func pagerOf(t *testing.T, f Fixture) admin.UserPager {
	t.Helper()

	p, ok := f.Users().(admin.UserPager)
	require.True(t, ok, "the fixture's user store stopped implementing admin.UserPager between fixtures")

	return p
}

// seedPagerUsers creates n users whose usernames hold key and mix case and
// scripts, so a store whose offset order differs from its cursor order
// (lower(username), id) lists them differently.
func seedPagerUsers(ctx context.Context, t *testing.T, f Fixture, key string, n int) {
	t.Helper()

	stems := []string{"Émile", "éclair", "Zed", "alpha", "ÖSTER", "beta", "Ärger", "zulu", "ÉTÉ", "Mañana"}
	for i := range n {
		mustCreateUser(ctx, t, f, admin.NewUser{Username: stems[i%len(stems)] + "-" + key + "-" + itoa3(i)})
	}
}

// listAll lists every user matching q in one page of 500, by cursor listing.
func listAll(ctx context.Context, t *testing.T, f Fixture, q admin.UserQuery) []admin.User {
	t.Helper()

	q.Limit = 500
	all, err := f.Users().ListUsers(ctx, q)
	require.NoError(t, err)

	return all
}

// runJumpToPageCase checks that offset 100 at page size 50 over 120 users
// gives exactly the third cursor page, in order.
func runJumpToPageCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)
	seedPagerUsers(ctx, t, f, key, 120)

	paged, sizes := pageAll(ctx, t, f, admin.UserQuery{Search: key, Limit: 50}, 4)
	require.Equal(t, []int{50, 50, 20}, sizes, "the cursor listing pages 120 users as 50, 50 and 20")

	got, err := pagerOf(t, f).ListUsersFrom(ctx, admin.UserQuery{Search: key, Limit: 50}, 100)
	require.NoError(t, err)
	assert.Equal(t, userIDs(paged[100:]), userIDs(got), "offset 100 must give the third cursor page, in order")
}

// runConsecutiveOffsetsCase checks that offsets 0, 7, 57 and 107 at page size
// 50, one of them not a multiple of the page size, give 7, 50, 50 and 13
// users that together are the cursor listing, each once, in its order.
func runConsecutiveOffsetsCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)
	seedPagerUsers(ctx, t, f, key, 120)

	all := listAll(ctx, t, f, admin.UserQuery{Search: key})
	require.Len(t, all, 120, "one large page lists every matching user")

	pager := pagerOf(t, f)
	spans := []struct{ offset, limit int }{{0, 7}, {7, 50}, {57, 50}, {107, 50}}

	var (
		joined []admin.User
		sizes  []int
	)

	for _, s := range spans {
		page, err := pager.ListUsersFrom(ctx, admin.UserQuery{Search: key, Limit: s.limit}, s.offset)
		require.NoError(t, err, "offset %d", s.offset)

		sizes = append(sizes, len(page))
		joined = append(joined, page...)
	}

	assert.Equal(t, []int{7, 50, 50, 13}, sizes, "120 users from offsets 0, 7, 57 and 107")
	assert.Equal(t, userIDs(all), userIDs(joined),
		"consecutive offsets must give every user exactly once, in the order of the cursor listing")
}

// runOffsetPastEndCase checks that an offset at or past the last match is an
// empty result and no error.
func runOffsetPastEndCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)
	seedPagerUsers(ctx, t, f, key, 3)

	for _, offset := range []int{3, 500} {
		got, err := pagerOf(t, f).ListUsersFrom(ctx, admin.UserQuery{Search: key, Limit: 50}, offset)
		require.NoError(t, err, "offset %d past the end is not an error", offset)
		assert.Empty(t, got, "offset %d past the end lists no user", offset)
	}
}

// runPagerFilterCases checks that the offset listing and the count apply the
// search, active, role and attribute filters as the cursor listing does. The
// role filter needs the role ports, so it is skipped when the fixture has
// none (RunUserSuite alone).
func runPagerFilterCases(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)
	attr := "job_title-" + key
	withRoles := f.Roles() != nil && f.Assignments() != nil

	role := ""
	if withRoles {
		role = roleName(t, "sales")
		mustCreateRole(ctx, t, f, role)
	}

	ids := seedListUsers(ctx, t, f, role, []listSeed{
		{attrs: map[string]string{attr: "Manager"}, active: true, role: withRoles}, // 0
		{attrs: map[string]string{attr: "Manager"}},                                // 1: inactive
		{attrs: map[string]string{attr: "Other"}, active: true},                    // 2
		{active: true, role: withRoles},                                            // 3
		{attrs: map[string]string{attr: "Manager"}, active: true},                  // 4
	})

	// Users 0 and 2 also carry a display name the search case looks for.
	needle := "Zebra-" + key
	for _, i := range []int{0, 2} {
		u := mustGetUser(ctx, t, f, ids[i])
		_, err := f.Users().UpdateUser(ctx, u.ID, u.Version, admin.UserChange{Name: &needle})
		require.NoError(t, err)
	}

	yes, no := true, false

	type testCase struct {
		name      string
		query     admin.UserQuery
		needRoles bool
		assert    func(t *testing.T, all, fromOne []admin.User, count int64)
	}

	matches := func(want ...int) func(t *testing.T, all, fromOne []admin.User, count int64) {
		return func(t *testing.T, all, fromOne []admin.User, count int64) {
			t.Helper()

			wantIDs := make([]identity.UserID, 0, len(want))
			for _, i := range want {
				wantIDs = append(wantIDs, ids[i])
			}

			require.ElementsMatch(t, wantIDs, userIDs(all), "the cursor listing applies the filter")
			assert.Equal(t, userIDs(all[1:]), userIDs(fromOne),
				"offset 1 must give the cursor listing's users after the first, in its order")
			assert.Equal(t, int64(len(want)), count, "the count must match the filtered users")
		}
	}

	cases := []testCase{
		{name: "search", query: admin.UserQuery{Search: strings.ToUpper(needle)}, assert: matches(0, 2)},
		{name: "active", query: admin.UserQuery{Search: key, Active: &no}, assert: matches(1)},
		{name: "role", query: admin.UserQuery{Role: role}, needRoles: true, assert: matches(0, 3)},
		{
			name:   "attribute",
			query:  admin.UserQuery{Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}},
			assert: matches(0, 1, 4),
		},
		{
			name:   "attribute and active",
			query:  admin.UserQuery{Active: &yes, Attribute: &admin.AttributeMatch{Name: attr, Value: "Manager"}},
			assert: matches(0, 4),
		},
	}

	pager := pagerOf(t, f)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needRoles && !withRoles {
				t.Skip("admintest: the fixture has no role ports; the role filter is checked by RunRoleSuite's fixtures")
			}

			all := listAll(ctx, t, f, tc.query)

			q := tc.query
			q.Limit = 500
			fromOne, err := pager.ListUsersFrom(ctx, q, 1)
			require.NoError(t, err)

			// The count gets the filters only, as admin.Users.Count sends them.
			count, err := pager.CountUsers(ctx, tc.query)
			require.NoError(t, err)

			tc.assert(t, all, fromOne, count)
		})
	}
}

// runCountBesidePageCase checks that 999 matching users count 999, whether
// the query names a page size or not: CountUsers ignores the limit.
func runCountBesidePageCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)

	for i := range 999 {
		mustCreateUser(ctx, t, f, admin.NewUser{Username: "c-" + key + "-" + strconv.Itoa(i)})
	}

	pager := pagerOf(t, f)

	for _, limit := range []int{0, 50} {
		n, err := pager.CountUsers(ctx, admin.UserQuery{Search: key, Limit: limit})
		require.NoError(t, err)
		assert.Equal(t, int64(999), n, "999 matching users count 999 (limit %d)", limit)
	}
}

// runDeletedNotCountedCase checks that a soft-deleted user is neither counted
// nor listed from an offset. The users are matched by a username search,
// because deletion releases the email but keeps the username.
func runDeletedNotCountedCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)

	var users []admin.User
	for i := range 3 {
		users = append(users, mustCreateUser(ctx, t, f, admin.NewUser{Username: username(t, i)}))
	}

	require.NoError(t, f.Users().DeleteUser(ctx, users[1].ID, users[1].Version))

	pager := pagerOf(t, f)
	q := admin.UserQuery{Search: "u-" + tag(t) + "-"}

	n, err := pager.CountUsers(ctx, q)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "a deleted user is not counted")

	q.Limit = 50
	got, err := pager.ListUsersFrom(ctx, q, 0)
	require.NoError(t, err)
	assert.ElementsMatch(t, []identity.UserID{users[0].ID, users[2].ID}, userIDs(got),
		"a deleted user is not listed from an offset")
}

// runPagerThroughServiceCase checks that the administration service lists
// from an offset and counts through the fixture's store: with 120 users,
// List from offset 50 gives 50 users, those of the cursor listing from the
// 51st, and Count gives 120.
func runPagerThroughServiceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	key := tag(t)
	seedPagerUsers(ctx, t, f, key, 120)

	all := listAll(ctx, t, f, admin.UserQuery{Search: key})
	require.Len(t, all, 120, "one large page lists every matching user")

	users, err := admin.NewUsers(f.Users())
	require.NoError(t, err, "the service must accept the fixture's user store")

	page, err := users.List(ctx, admin.UserFilter{Search: key, Offset: 50, PageSize: 50})
	require.NoError(t, err, "the service must list from an offset (reason matched: %s)", reasonOf(err))
	assert.Equal(t, userIDs(all[50:100]), userIDs(page.Users), "offset 50 gives the users from the 51st, in order")
	assert.Empty(t, page.Next, "a page from a non-zero offset carries no cursor")

	n, err := users.Count(ctx, admin.UserFilter{Search: key, Offset: 50, PageSize: 50})
	require.NoError(t, err, "the service must count (reason matched: %s)", reasonOf(err))
	assert.Equal(t, int64(120), n, "the service counts every matching user")
}
