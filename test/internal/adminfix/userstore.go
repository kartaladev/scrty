// Package adminfix holds the store-level tests the SQL adapters share for the
// user and import administration ports: the cases only a real database shows
// (row locks, advisory locks, unique indexes, literal ILIKE, the list order),
// run against each adapter over one migrated database.
package adminfix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// Harness is one adapter's user and import stores over DB, a database with the
// identity set applied. DB is used for seeding and inspecting rows only.
type Harness struct {
	Users   admin.UserStore
	Imports admin.ImportStore
	// Assignments is the assignment port over the same tables. The
	// assignment cases run only when it is set.
	Assignments admin.AssignmentStore
	// Grants is the grant port over the same tables. The grant cases run
	// only when it is set.
	Grants admin.GrantStore
	// Ambient opens a caller's transaction the stores join. The cases that
	// need one run only when it is set.
	Ambient Ambient
	DB      *sql.DB
}

var (
	gen     = id.NewV7Generator()
	counter atomic.Uint64
)

// uniq is a name no other case of the test binary uses.
func uniq(prefix string) string {
	return fmt.Sprintf("%s%d-%d", prefix, time.Now().UnixNano(), counter.Add(1))
}

func newID(t *testing.T) identity.UserID {
	t.Helper()
	v, err := gen.NewID()
	require.NoError(t, err)

	return identity.UserID(v.String())
}

// seedRole stores a role in the catalogue.
func seedRole(t *testing.T, db *sql.DB, name string, super bool) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `INSERT INTO scrty_roles (id, name, super_role, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())`, string(newID(t)), name, super)
	require.NoError(t, err)
}

// seedGrant gives user a grant of role.
func seedGrant(t *testing.T, db *sql.DB, user identity.UserID, role string, primary bool) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `INSERT INTO scrty_assigned_roles (id, user_id, role_name, position,
  is_primary, created_at, updated_at) VALUES ($1, $2, $3, 0, $4, now(), now())`, string(newID(t)), string(user), role, primary)
	require.NoError(t, err)
}

func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), query, args...).Scan(&n))

	return n
}

func create(t *testing.T, h Harness, u admin.NewUser) admin.User {
	t.Helper()
	if u.ID == "" {
		u.ID = newID(t)
	}
	got, err := h.Users.CreateUser(t.Context(), u)
	require.NoError(t, err)

	return got
}

// requireExists asserts err is an AlreadyExistsError naming field.
func requireExists(t *testing.T, err error, field string) {
	t.Helper()
	require.ErrorIs(t, err, admin.ErrAlreadyExists)
	var ae admin.AlreadyExistsError
	require.True(t, errors.As(err, &ae), "error %v is not an AlreadyExistsError", err)
	assert.Equal(t, field, ae.Field)
}

// noValues asserts that err's text carries none of values.
func noValues(t *testing.T, err error, values ...string) {
	t.Helper()
	for _, v := range values {
		if v != "" {
			assert.NotContains(t, err.Error(), v)
		}
	}
}

// Run runs every case against h.
func Run(t *testing.T, h Harness) {
	t.Run("Users", func(t *testing.T) { runUsers(t, h) })
	t.Run("List", func(t *testing.T) { runList(t, h) })
	t.Run("Import", func(t *testing.T) { runImport(t, h) })
	if h.Assignments != nil {
		t.Run("Assignments", func(t *testing.T) { runAssignments(t, h) })
	}
	if h.Grants != nil {
		t.Run("Grants", func(t *testing.T) { runGrants(t, h) })
	}
	if h.Ambient != nil {
		t.Run("RetireRacesDelete", func(t *testing.T) { runRetireRacesDelete(t, h) })
	}
}

// seedPrivilege stores one granted privilege of role on group/resource,
// spelled exactly as given.
func seedPrivilege(t *testing.T, db *sql.DB, role, group, resource, privilege string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `INSERT INTO scrty_resource_privileges (id, role_name, resource_group,
  resource, privilege, granted, scope, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, true, 'all', now(), now())`,
		string(newID(t)), role, group, resource, privilege)
	require.NoError(t, err)
}

func runGrants(t *testing.T, h Harness) {
	t.Run("ReplaceMatchesResourceAsTheAuthorizerDoes", func(t *testing.T) {
		t.Parallel()

		// The authorizer compares group and resource names with surrounding
		// ASCII whitespace trimmed and ASCII case ignored, nothing wider; a
		// replacement removes exactly the stored rows it would read as the
		// named resource.
		const kelvin = "\u212a" // KELVIN SIGN, which a Unicode fold reads as k

		type testCase struct {
			name            string
			group, resource string // the replacement names this resource, with no grant
			assert          func(t *testing.T, left []admin.Grant)
		}

		cases := []testCase{
			{
				name: "case and surrounding space differ", group: "CRM", resource: " Lead\t",
				assert: func(t *testing.T, left []admin.Grant) {
					require.Len(t, left, 1, "the resource's stored grants are removed")
					assert.Equal(t, kelvin+"ind", left[0].Resource, "another resource is kept")
				},
			},
			{
				name: "a Unicode fold is not an ASCII one", group: "crm", resource: "kind",
				assert: func(t *testing.T, left []admin.Grant) {
					assert.Len(t, left, 2, "a name equal only under a Unicode fold names another resource")
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				ctx := t.Context()

				role := uniq("grants")
				seedRole(t, h.DB, role, false)
				seedPrivilege(t, h.DB, role, "crm", "lead", "view")
				seedPrivilege(t, h.DB, role, "crm", kelvin+"ind", "view")

				_, v, err := h.Grants.GetGrants(ctx, role)
				require.NoError(t, err)
				_, err = h.Grants.ReplaceGrants(ctx, role, v,
					[]admin.ResourceGrants{{Group: tc.group, Resource: tc.resource}})
				require.NoError(t, err)

				left, _, err := h.Grants.GetGrants(ctx, role)
				require.NoError(t, err)
				tc.assert(t, left)
			})
		}
	})
}

func runAssignments(t *testing.T, h Harness) {
	t.Run("FirstAssignmentIsPrimary", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			adds   []bool // Assignment.Primary of each grant, in order
			assert func(t *testing.T, roles []string, held []*identity.AssignedRole, stored string)
		}

		cases := []testCase{
			{
				name: "a first grant not asked to be primary is primary",
				adds: []bool{false},
				assert: func(t *testing.T, roles []string, held []*identity.AssignedRole, stored string) {
					require.Len(t, held, 1)
					assert.True(t, held[0].Primary, "a user with grants always has a primary one")
					assert.Equal(t, roles[0], stored, "scrty_users.role follows the primary grant")
				},
			},
			{
				name: "a later grant not asked to be primary is not",
				adds: []bool{false, false},
				assert: func(t *testing.T, roles []string, held []*identity.AssignedRole, stored string) {
					require.Len(t, held, 2)
					assert.Equal(t, roles[0], held[0].Name)
					assert.True(t, held[0].Primary)
					assert.False(t, held[1].Primary)
					assert.Equal(t, roles[0], stored)
				},
			},
			{
				name: "a later grant asked to be primary replaces the first",
				adds: []bool{false, true},
				assert: func(t *testing.T, roles []string, held []*identity.AssignedRole, stored string) {
					require.Len(t, held, 2)
					assert.Equal(t, roles[1], held[0].Name, "the primary grant reads first")
					assert.True(t, held[0].Primary)
					assert.False(t, held[1].Primary)
					assert.Equal(t, roles[1], stored)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				ctx := t.Context()

				u := create(t, h, admin.NewUser{Username: uniq("asg")})
				version := u.Version
				roles := make([]string, len(tc.adds))
				for i, primary := range tc.adds {
					roles[i] = uniq("role")
					seedRole(t, h.DB, roles[i], false)
					v, err := h.Assignments.AddAssignment(ctx, u.ID, version, admin.Assignment{Role: roles[i], Primary: primary})
					require.NoError(t, err)
					require.Greater(t, v, version)
					version = v
				}

				held, v, err := h.Assignments.ListAssignments(ctx, u.ID)
				require.NoError(t, err)
				assert.Equal(t, version, v)

				var stored string
				require.NoError(t, h.DB.QueryRowContext(ctx, `SELECT role FROM scrty_users WHERE id = $1`,
					string(u.ID)).Scan(&stored))
				tc.assert(t, roles, held, stored)
			})
		}
	})
}

func runUsers(t *testing.T, h Harness) {
	t.Run("CreateAndGetRoundTrip", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		orgID := string(newID(t))
		_, err := h.DB.ExecContext(ctx, `INSERT INTO scrty_organizations (id, name, created_at, updated_at)
VALUES ($1, 'Org', now(), now())`, orgID)
		require.NoError(t, err)

		verified := time.Date(2026, 1, 2, 3, 4, 5, 678000, time.UTC)
		in := admin.NewUser{
			ID: newID(t), Username: uniq("Ada"), Name: "Ada L", Email: uniq("ada") + "@Example.com",
			EmailVerifiedAt: verified, Attributes: map[string]string{"phone": "+62 21 555", "job_title": "Manager"},
			Organization: &identity.Organization{ID: orgID},
		}
		created, err := h.Users.CreateUser(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, in.ID, created.ID)
		assert.Equal(t, int64(1), created.Version)
		assert.True(t, created.Active)

		got, err := h.Users.GetUser(ctx, in.ID)
		require.NoError(t, err)
		assert.Equal(t, in.Username, got.Username)
		assert.Equal(t, in.Name, got.Name)
		assert.Equal(t, in.Email, got.Email)
		assert.True(t, verified.Equal(got.EmailVerifiedAt))
		assert.Equal(t, in.Attributes, got.Attributes)
		require.NotNil(t, got.Organization)
		assert.Equal(t, "Org", got.Organization.Name)
		assert.Empty(t, got.Roles)
		assert.Equal(t, created, got)

		hash, err := h.Users.CurrentPasswordHash(ctx, in.ID)
		require.NoError(t, err)
		assert.Empty(t, hash)
	})

	t.Run("CreateRefusals", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			setup  func(t *testing.T) admin.NewUser
			assert func(t *testing.T, in admin.NewUser, err error)
		}

		taken := func(field string) func(t *testing.T, in admin.NewUser, err error) {
			return func(t *testing.T, in admin.NewUser, err error) {
				requireExists(t, err, field)
				noValues(t, err, in.Username, in.Email)
				assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_users WHERE id = $1`, string(in.ID)))
			}
		}

		cases := []testCase{
			{
				name: "username taken",
				setup: func(t *testing.T) admin.NewUser {
					u := create(t, h, admin.NewUser{Username: uniq("dup")})
					return admin.NewUser{Username: u.Username}
				},
				assert: taken(admin.FieldUsername),
			},
			{
				name: "username of a deleted user",
				setup: func(t *testing.T) admin.NewUser {
					u := create(t, h, admin.NewUser{Username: uniq("gone")})
					require.NoError(t, h.Users.DeleteUser(t.Context(), u.ID, u.Version))
					return admin.NewUser{Username: u.Username}
				},
				assert: taken(admin.FieldUsername),
			},
			{
				name: "email taken ignoring case",
				setup: func(t *testing.T) admin.NewUser {
					e := uniq("mail") + "@example.com"
					create(t, h, admin.NewUser{Username: uniq("m"), Email: e})
					return admin.NewUser{Username: uniq("m"), Email: strings.ToUpper(e)}
				},
				assert: taken(admin.FieldEmail),
			},
			{
				name: "username is another user's email",
				setup: func(t *testing.T) admin.NewUser {
					e := uniq("carol") + "@example.com"
					create(t, h, admin.NewUser{Username: uniq("bob"), Email: e})
					return admin.NewUser{Username: strings.ToUpper(e)}
				},
				assert: taken(admin.FieldUsername),
			},
			{
				name: "email is another user's username",
				setup: func(t *testing.T) admin.NewUser {
					u := create(t, h, admin.NewUser{Username: uniq("x") + "@example.com"})
					return admin.NewUser{Username: uniq("y"), Email: u.Username}
				},
				assert: taken(admin.FieldEmail),
			},
			{
				name: "deleted user's email is free",
				setup: func(t *testing.T) admin.NewUser {
					e := uniq("free") + "@example.com"
					u := create(t, h, admin.NewUser{Username: uniq("f"), Email: e})
					require.NoError(t, h.Users.DeleteUser(t.Context(), u.ID, u.Version))
					return admin.NewUser{Username: uniq("f"), Email: strings.ToUpper(e)}
				},
				assert: func(t *testing.T, _ admin.NewUser, err error) {
					require.NoError(t, err)
				},
			},
			{
				name: "organization that is not a UUID",
				setup: func(_ *testing.T) admin.NewUser {
					return admin.NewUser{Username: uniq("o"), Organization: &identity.Organization{ID: "not-a-uuid"}}
				},
				assert: func(t *testing.T, _ admin.NewUser, err error) {
					require.ErrorIs(t, err, admin.ErrInvalidInput)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				in := tc.setup(t)
				in.ID = newID(t)
				_, err := h.Users.CreateUser(t.Context(), in)
				tc.assert(t, in, err)
			})
		}
	})

	t.Run("ConcurrentCreatesOneEmail", func(t *testing.T) {
		t.Parallel()
		email := uniq("race") + "@example.com"
		errs := race(8, func(_ int) error {
			_, err := h.Users.CreateUser(t.Context(), admin.NewUser{
				ID: newID(t), Username: uniq("racer"), Email: email,
			})
			return err
		})
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
				continue
			}
			requireExists(t, err, admin.FieldEmail)
		}
		assert.Equal(t, 1, ok)
	})

	t.Run("RacingUsernameAndEmail", func(t *testing.T) {
		t.Parallel()
		for round := 0; round < 4; round++ {
			value := uniq("pair") + "@example.com"
			other := create(t, h, admin.NewUser{Username: uniq("holder")})
			errs := race(2, func(i int) error {
				if i == 0 {
					_, err := h.Users.CreateUser(t.Context(), admin.NewUser{ID: newID(t), Username: value})
					return err
				}
				_, err := h.Users.UpdateUser(t.Context(), other.ID, other.Version, admin.UserChange{Email: &value})
				return err
			})
			ok := 0
			for _, err := range errs {
				if err == nil {
					ok++
				} else {
					require.ErrorIs(t, err, admin.ErrAlreadyExists)
				}
			}
			assert.Equal(t, 1, ok)
		}
	})

	t.Run("Update", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			change func(t *testing.T, u admin.User) (int64, admin.UserChange)
			assert func(t *testing.T, before, after admin.User, err error)
		}

		name := "Renamed"
		cases := []testCase{
			{
				name: "only the named field changes and the version increases",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					return u.Version, admin.UserChange{Name: &name}
				},
				assert: func(t *testing.T, before, after admin.User, err error) {
					require.NoError(t, err)
					assert.Equal(t, "Renamed", after.Name)
					assert.Equal(t, before.Email, after.Email)
					assert.Equal(t, before.Attributes, after.Attributes)
					assert.Equal(t, before.Version+1, after.Version)
				},
			},
			{
				name: "stale version changes nothing",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					return u.Version + 1, admin.UserChange{Name: &name}
				},
				assert: func(t *testing.T, before, after admin.User, err error) {
					require.ErrorIs(t, err, admin.ErrStaleUpdate)
					assert.Equal(t, before, after)
				},
			},
			{
				name: "attributes are replaced as a set",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					return u.Version, admin.UserChange{Attributes: map[string]string{"team": "a"}}
				},
				assert: func(t *testing.T, _, after admin.User, err error) {
					require.NoError(t, err)
					assert.Equal(t, map[string]string{"team": "a"}, after.Attributes)
				},
			},
			{
				name: "an empty attribute map removes them all",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					return u.Version, admin.UserChange{Attributes: map[string]string{}}
				},
				assert: func(t *testing.T, _, after admin.User, err error) {
					require.NoError(t, err)
					assert.Empty(t, after.Attributes)
				},
			},
			{
				name: "email cleared and verification cleared",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					empty, zero := "", time.Time{}
					return u.Version, admin.UserChange{Email: &empty, EmailVerifiedAt: &zero}
				},
				assert: func(t *testing.T, _, after admin.User, err error) {
					require.NoError(t, err)
					assert.Empty(t, after.Email)
					assert.True(t, after.EmailVerifiedAt.IsZero())
				},
			},
			{
				name: "email changed with an explicit cleared verification is unverified",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					fresh, zero := uniq("new")+"@example.com", time.Time{}
					return u.Version, admin.UserChange{Email: &fresh, EmailVerifiedAt: &zero}
				},
				assert: func(t *testing.T, before, after admin.User, err error) {
					require.NoError(t, err)
					assert.NotEqual(t, before.Email, after.Email)
					assert.False(t, before.EmailVerifiedAt.IsZero())
					assert.True(t, after.EmailVerifiedAt.IsZero(), "a new address never inherits the old verification")
				},
			},
			{
				name: "email taken by another user",
				change: func(t *testing.T, u admin.User) (int64, admin.UserChange) {
					e := uniq("other") + "@example.com"
					create(t, h, admin.NewUser{Username: uniq("o"), Email: e})
					upper := strings.ToUpper(e)
					return u.Version, admin.UserChange{Email: &upper}
				},
				assert: func(t *testing.T, before, after admin.User, err error) {
					requireExists(t, err, admin.FieldEmail)
					assert.Equal(t, before, after)
				},
			},
			{
				name: "organization removed",
				change: func(_ *testing.T, u admin.User) (int64, admin.UserChange) {
					var none *identity.Organization
					return u.Version, admin.UserChange{Organization: &none}
				},
				assert: func(t *testing.T, _, after admin.User, err error) {
					require.NoError(t, err)
					assert.Nil(t, after.Organization)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				before := create(t, h, admin.NewUser{
					Username: uniq("upd"), Name: "Before", Email: uniq("upd") + "@example.com",
					EmailVerifiedAt: time.Now().UTC().Truncate(time.Second), Attributes: map[string]string{"k": "v"},
				})
				version, change := tc.change(t, before)
				_, err := h.Users.UpdateUser(t.Context(), before.ID, version, change)
				after, gerr := h.Users.GetUser(t.Context(), before.ID)
				require.NoError(t, gerr)
				tc.assert(t, before, after, err)
			})
		}
	})

	t.Run("UnknownUser", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		for _, ref := range []identity.UserID{newID(t), "not-a-uuid"} {
			_, err := h.Users.GetUser(ctx, ref)
			require.ErrorIs(t, err, admin.ErrNotFound)
			_, err = h.Users.UpdateUser(ctx, ref, 1, admin.UserChange{})
			require.ErrorIs(t, err, admin.ErrNotFound)
			_, _, err = h.Users.SetActive(ctx, ref, 1, false)
			require.ErrorIs(t, err, admin.ErrNotFound)
			require.ErrorIs(t, h.Users.DeleteUser(ctx, ref, 1), admin.ErrNotFound)
			_, err = h.Users.CurrentPasswordHash(ctx, ref)
			require.ErrorIs(t, err, admin.ErrNotFound)
			_, err = h.Users.SetPassword(ctx, ref, 1, []byte("h"), time.Now())
			require.ErrorIs(t, err, admin.ErrNotFound)
		}
	})

	t.Run("SetActive", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		u := create(t, h, admin.NewUser{Username: uniq("act")})

		same, changed, err := h.Users.SetActive(ctx, u.ID, u.Version, true)
		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, u.Version, same.Version)

		off, changed, err := h.Users.SetActive(ctx, u.ID, u.Version, false)
		require.NoError(t, err)
		assert.True(t, changed)
		assert.False(t, off.Active)
		assert.Equal(t, u.Version+1, off.Version)

		_, _, err = h.Users.SetActive(ctx, u.ID, u.Version, true)
		require.ErrorIs(t, err, admin.ErrStaleUpdate)

		// A stale call that would change nothing is still stale.
		_, _, err = h.Users.SetActive(ctx, u.ID, u.Version, false)
		require.ErrorIs(t, err, admin.ErrStaleUpdate)
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		u := create(t, h, admin.NewUser{
			Username: uniq("del"), Email: uniq("del") + "@example.com", Attributes: map[string]string{"a": "b"},
		})
		u, err := h.Users.SetPassword(ctx, u.ID, u.Version, []byte("hash-1"), time.Now())
		require.NoError(t, err)
		// History is the password policy's to record; seed one entry as its
		// reuse rule would.
		_, err = h.DB.ExecContext(ctx, `INSERT INTO scrty_password_history (id, user_id, password, retired_at)
VALUES ($1, $2, 'hash-0', now())`, string(newID(t)), string(u.ID))
		require.NoError(t, err)
		require.Equal(t, 1, count(t, h.DB, `SELECT count(*) FROM scrty_password_history WHERE user_id = $1`, string(u.ID)))

		require.ErrorIs(t, h.Users.DeleteUser(ctx, u.ID, u.Version-1), admin.ErrStaleUpdate)
		require.NoError(t, h.Users.DeleteUser(ctx, u.ID, u.Version))

		_, err = h.Users.GetUser(ctx, u.ID)
		require.ErrorIs(t, err, admin.ErrNotFound)
		require.ErrorIs(t, h.Users.DeleteUser(ctx, u.ID, u.Version+1), admin.ErrNotFound)

		// Every write at the deleted user's current version is not found.
		current := u.Version + 1
		name := "x"
		_, err = h.Users.UpdateUser(ctx, u.ID, current, admin.UserChange{Name: &name})
		require.ErrorIs(t, err, admin.ErrNotFound)
		_, _, err = h.Users.SetActive(ctx, u.ID, current, true)
		require.ErrorIs(t, err, admin.ErrNotFound)
		_, err = h.Users.SetPassword(ctx, u.ID, current, []byte("h"), time.Now())
		require.ErrorIs(t, err, admin.ErrNotFound)
		_, err = h.Users.CurrentPasswordHash(ctx, u.ID)
		require.ErrorIs(t, err, admin.ErrNotFound)

		var (
			username string
			active   bool
			email    sql.NullString
			deleted  sql.NullTime
		)
		require.NoError(t, h.DB.QueryRowContext(ctx,
			`SELECT username, active, email, deleted_at FROM scrty_users WHERE id = $1`, string(u.ID)).
			Scan(&username, &active, &email, &deleted))
		assert.Equal(t, u.Username, username)
		assert.False(t, active)
		assert.False(t, email.Valid)
		assert.True(t, deleted.Valid)
		assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_user_attributes WHERE user_id = $1`, string(u.ID)))
		assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_password_history WHERE user_id = $1`, string(u.ID)))
	})

	t.Run("SetPassword", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		u := create(t, h, admin.NewUser{Username: uniq("pw")})
		at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

		u1, err := h.Users.SetPassword(ctx, u.ID, u.Version, []byte("first"), at)
		require.NoError(t, err)
		assert.Equal(t, u.Version+1, u1.Version)
		assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_password_history WHERE user_id = $1`, string(u.ID)),
			"SetPassword records no history")

		_, err = h.Users.SetPassword(ctx, u.ID, u.Version, []byte("stale"), at)
		require.ErrorIs(t, err, admin.ErrStaleUpdate)

		later := at.Add(time.Hour)
		_, err = h.Users.SetPassword(ctx, u.ID, u1.Version, []byte("second"), later)
		require.NoError(t, err)

		cur, err := h.Users.CurrentPasswordHash(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, []byte("second"), cur)

		assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_password_history WHERE user_id = $1`, string(u.ID)),
			"SetPassword writes only the hash and the change time: history is the password policy's to record")

		var changed time.Time
		require.NoError(t, h.DB.QueryRowContext(ctx,
			`SELECT password_changed_at FROM scrty_users WHERE id = $1`, string(u.ID)).Scan(&changed))
		assert.True(t, later.Equal(changed))
	})

	t.Run("UnknownOrganization", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name  string
			write func(t *testing.T, org *identity.Organization) (admin.User, error)
		}

		cases := []testCase{
			{
				name: "CreateUser",
				write: func(t *testing.T, org *identity.Organization) (admin.User, error) {
					in := admin.NewUser{ID: newID(t), Username: uniq("org"), Organization: org}
					_, err := h.Users.CreateUser(t.Context(), in)
					assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_users WHERE id = $1`, string(in.ID)),
						"a refused create stores no user")

					return admin.User{}, err
				},
			},
			{
				name: "UpdateUser",
				write: func(t *testing.T, org *identity.Organization) (admin.User, error) {
					u := create(t, h, admin.NewUser{Username: uniq("org")})
					_, err := h.Users.UpdateUser(t.Context(), u.ID, u.Version, admin.UserChange{Organization: &org})
					after, gerr := h.Users.GetUser(t.Context(), u.ID)
					require.NoError(t, gerr)
					assert.Equal(t, u, after, "a refused update changes nothing")

					return after, err
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				// A canonical UUID that names no stored organization.
				_, err := tc.write(t, &identity.Organization{ID: string(newID(t))})
				require.ErrorIs(t, err, admin.ErrInvalidInput,
					"an organization reference naming no organization is invalid input, not a storage failure")
			})
		}
	})

	t.Run("CancelledWriteChangesNothing", func(t *testing.T) {
		t.Parallel()
		u := create(t, h, admin.NewUser{Username: uniq("cx")})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		name := "never"
		_, err := h.Users.UpdateUser(ctx, u.ID, u.Version, admin.UserChange{Name: &name})
		require.Error(t, err)
		got, err := h.Users.GetUser(t.Context(), u.ID)
		require.NoError(t, err)
		assert.Equal(t, u, got)
	})
}

func runList(t *testing.T, h Harness) {
	t.Run("LiteralSearch", func(t *testing.T) {
		t.Parallel()
		tag := uniq("lit")
		create(t, h, admin.NewUser{Username: tag + "a_b"})
		create(t, h, admin.NewUser{Username: tag + "axb"})
		create(t, h, admin.NewUser{Username: uniq("pct"), Name: tag + `100%\`})

		got, err := h.Users.ListUsers(t.Context(), admin.UserQuery{Search: strings.ToUpper(tag) + "A_B", Limit: 10})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, tag+"a_b", got[0].Username)

		got, err = h.Users.ListUsers(t.Context(), admin.UserQuery{Search: tag + `100%\`, Limit: 10})
		require.NoError(t, err)
		require.Len(t, got, 1)
	})

	t.Run("PagesFoldCase", func(t *testing.T) {
		t.Parallel()
		tag := uniq("page")
		names := []string{tag + "c", tag + "B", tag + "a", tag + "D", tag + "e"}
		for _, n := range names {
			create(t, h, admin.NewUser{Username: n})
		}
		gone := create(t, h, admin.NewUser{Username: tag + "bb"})
		require.NoError(t, h.Users.DeleteUser(t.Context(), gone.ID, gone.Version))

		var seen []string
		q := admin.UserQuery{Search: tag, Limit: 2}
		for page := 0; page < 5; page++ {
			got, err := h.Users.ListUsers(t.Context(), q)
			require.NoError(t, err)
			for _, u := range got {
				seen = append(seen, u.Username)
			}
			if len(got) < q.Limit {
				break
			}
			q.AfterUsername, q.AfterID = got[len(got)-1].Username, got[len(got)-1].ID
		}
		assert.Equal(t, []string{tag + "a", tag + "B", tag + "c", tag + "D", tag + "e"}, seen)
	})

	t.Run("Filters", func(t *testing.T) {
		t.Parallel()
		tag := uniq("flt")
		role := uniq("sales")
		seedRole(t, h.DB, role, false)
		match := create(t, h, admin.NewUser{Username: tag + "1", Attributes: map[string]string{"job_title": "Manager"}})
		seedGrant(t, h.DB, match.ID, role, true)
		other := create(t, h, admin.NewUser{Username: tag + "2", Attributes: map[string]string{"job_title": "Clerk"}})
		seedGrant(t, h.DB, other.ID, role, true)
		inactive := create(t, h, admin.NewUser{Username: tag + "3"})
		_, _, err := h.Users.SetActive(t.Context(), inactive.ID, inactive.Version, false)
		require.NoError(t, err)

		got, err := h.Users.ListUsers(t.Context(), admin.UserQuery{
			Search: tag, Role: role, Attribute: &admin.AttributeMatch{Name: "job_title", Value: "Manager"}, Limit: 10,
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, match.ID, got[0].ID)
		require.Len(t, got[0].Roles, 1)
		assert.Equal(t, role, got[0].Roles[0].Name)
		assert.Equal(t, map[string]string{"job_title": "Manager"}, got[0].Attributes)

		no := false
		got, err = h.Users.ListUsers(t.Context(), admin.UserQuery{Search: tag, Active: &no, Limit: 10})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, inactive.ID, got[0].ID)
	})

	t.Run("ForgedCursor", func(t *testing.T) {
		t.Parallel()
		for _, q := range []admin.UserQuery{
			{AfterUsername: "a", AfterID: "not-a-uuid", Limit: 1},
			{AfterUsername: "a", AfterID: "", Limit: 1},
			{Search: "a\x00", Limit: 1},
			{Limit: 0},
		} {
			_, err := h.Users.ListUsers(t.Context(), q)
			require.ErrorIs(t, err, admin.ErrInvalidInput)
		}
	})
}

func runImport(t *testing.T, h Harness) {
	newImported := func(t *testing.T, roles ...string) admin.ImportedUser {
		return admin.ImportedUser{
			ID: newID(t), Username: uniq("imp"), Name: "Imported", Email: uniq("imp") + "@example.com",
			EmailVerifiedAt: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
			PasswordHash:    []byte("$2a$10$abcdefghijklmnopqrstuuJ7xg0h9d1j3o5W7m9E1t2nZbQd4iV5S"),
			Active:          true,
			CreatedAt:       time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC),
			UpdatedAt:       time.Date(2021, 3, 5, 5, 6, 7, 0, time.UTC),
			Roles:           roles,
			Attributes:      map[string]string{"dept": "ops"},
		}
	}

	t.Run("CreateUnchangedUpdated", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		role, second := uniq("r"), uniq("r")
		seedRole(t, h.DB, role, false)
		seedRole(t, h.DB, second, true)
		in := newImported(t, role)

		out, err := h.Imports.ImportUser(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, admin.ImportCreated, out)

		got, err := h.Users.GetUser(ctx, in.ID)
		require.NoError(t, err)
		assert.True(t, in.CreatedAt.Equal(got.CreatedAt))
		assert.True(t, in.UpdatedAt.Equal(got.UpdatedAt))
		assert.Equal(t, in.Attributes, got.Attributes)
		require.Len(t, got.Roles, 1)
		assert.True(t, got.Roles[0].Primary)
		hash, err := h.Users.CurrentPasswordHash(ctx, in.ID)
		require.NoError(t, err)
		assert.Equal(t, in.PasswordHash, hash)

		out, err = h.Imports.ImportUser(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, admin.ImportUnchanged, out)
		again, err := h.Users.GetUser(ctx, in.ID)
		require.NoError(t, err)
		assert.Equal(t, got, again)

		in.Name = "Changed"
		in.Roles = []string{second, role}
		in.UpdatedAt = in.UpdatedAt.Add(time.Hour)
		out, err = h.Imports.ImportUser(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, admin.ImportUpdated, out)
		updated, err := h.Users.GetUser(ctx, in.ID)
		require.NoError(t, err)
		assert.Equal(t, "Changed", updated.Name)
		assert.Equal(t, got.Version+1, updated.Version)
		require.Len(t, updated.Roles, 2)
		assert.Equal(t, second, updated.Roles[0].Name)
		assert.True(t, updated.Roles[0].Primary)
		assert.True(t, updated.Roles[0].SuperRole)
	})

	t.Run("TimesNotGiven", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		// Created without times: the store fills both with the time of the
		// import.
		bare := newImported(t)
		bare.CreatedAt, bare.UpdatedAt = time.Time{}, time.Time{}
		lower := time.Now().Add(-time.Minute)
		out, err := h.Imports.ImportUser(ctx, bare)
		require.NoError(t, err)
		require.Equal(t, admin.ImportCreated, out)
		got, err := h.Users.GetUser(ctx, bare.ID)
		require.NoError(t, err)
		assert.True(t, got.CreatedAt.After(lower), "a creation time not given is the time of the import, got %v", got.CreatedAt)
		assert.True(t, got.UpdatedAt.After(lower), "an update time not given is the time of the import, got %v", got.UpdatedAt)

		// Reimported without times: nothing to compare or write, so unchanged.
		out, err = h.Imports.ImportUser(ctx, bare)
		require.NoError(t, err)
		assert.Equal(t, admin.ImportUnchanged, out, "times not given are not compared")

		// An existing user with stored times, reimported without them and
		// with a changed name: updated, and the stored times are kept.
		timed := newImported(t)
		_, err = h.Imports.ImportUser(ctx, timed)
		require.NoError(t, err)
		timed.CreatedAt, timed.UpdatedAt = time.Time{}, time.Time{}
		out, err = h.Imports.ImportUser(ctx, timed)
		require.NoError(t, err)
		assert.Equal(t, admin.ImportUnchanged, out, "times not given are not compared with the stored ones")

		timed.Name = "Renamed"
		out, err = h.Imports.ImportUser(ctx, timed)
		require.NoError(t, err)
		assert.Equal(t, admin.ImportUpdated, out)
		kept, err := h.Users.GetUser(ctx, timed.ID)
		require.NoError(t, err)
		assert.True(t, time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC).Equal(kept.CreatedAt), "got %v", kept.CreatedAt)
		assert.True(t, time.Date(2021, 3, 5, 5, 6, 7, 0, time.UTC).Equal(kept.UpdatedAt), "got %v", kept.UpdatedAt)
	})

	t.Run("Refusals", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			setup  func(t *testing.T) admin.ImportedUser
			assert func(t *testing.T, in admin.ImportedUser, err error)
		}

		cases := []testCase{
			{
				name: "username held by another identifier",
				setup: func(t *testing.T) admin.ImportedUser {
					u := create(t, h, admin.NewUser{Username: uniq("held")})
					in := newImported(t)
					in.Username = u.Username
					return in
				},
				assert: func(t *testing.T, in admin.ImportedUser, err error) {
					requireExists(t, err, admin.FieldUsername)
					noValues(t, err, in.Username, in.Email, string(in.PasswordHash))
				},
			},
			{
				name: "email held by another identifier",
				setup: func(t *testing.T) admin.ImportedUser {
					e := uniq("heldmail") + "@example.com"
					create(t, h, admin.NewUser{Username: uniq("hm"), Email: e})
					in := newImported(t)
					in.Email = strings.ToUpper(e)
					return in
				},
				assert: func(t *testing.T, _ admin.ImportedUser, err error) {
					requireExists(t, err, admin.FieldEmail)
				},
			},
			{
				name: "unknown role",
				setup: func(t *testing.T) admin.ImportedUser {
					return newImported(t, uniq("nosuchrole"))
				},
				assert: func(t *testing.T, _ admin.ImportedUser, err error) {
					require.ErrorIs(t, err, admin.ErrNotFound)
				},
			},
			// The identifier's form is the store's to judge (D14): scrty's
			// stores hold canonical lower-case UUIDs other than the nil UUID,
			// and refuse any other text rather than store another spelling.
			{
				name: "upper-case identifier",
				setup: func(t *testing.T) admin.ImportedUser {
					in := newImported(t)
					in.ID = identity.UserID(strings.ToUpper(string(in.ID)))
					return in
				},
				assert: func(t *testing.T, in admin.ImportedUser, err error) {
					require.ErrorIs(t, err, admin.ErrInvalidInput)
					assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_users WHERE id::text = $1`,
						strings.ToLower(string(in.ID))), "no record under the lower-cased spelling")
				},
			},
			{
				name: "identifier that is not a UUID",
				setup: func(t *testing.T) admin.ImportedUser {
					in := newImported(t)
					in.ID = "not-a-uuid"
					return in
				},
				assert: func(t *testing.T, _ admin.ImportedUser, err error) {
					require.ErrorIs(t, err, admin.ErrInvalidInput)
				},
			},
			{
				name: "nil UUID identifier",
				setup: func(t *testing.T) admin.ImportedUser {
					in := newImported(t)
					in.ID = "00000000-0000-0000-0000-000000000000"
					return in
				},
				assert: func(t *testing.T, in admin.ImportedUser, err error) {
					require.ErrorIs(t, err, admin.ErrInvalidInput)
					noValues(t, err, string(in.ID), in.Username)
				},
			},
			{
				name: "identifier of a deleted user",
				setup: func(t *testing.T) admin.ImportedUser {
					u := create(t, h, admin.NewUser{Username: uniq("delimp")})
					require.NoError(t, h.Users.DeleteUser(t.Context(), u.ID, u.Version))
					in := newImported(t)
					in.ID = u.ID
					return in
				},
				assert: func(t *testing.T, _ admin.ImportedUser, err error) {
					requireExists(t, err, "id")
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				in := tc.setup(t)
				_, err := h.Imports.ImportUser(t.Context(), in)
				tc.assert(t, in, err)
				assert.Equal(t, 0, count(t, h.DB,
					`SELECT count(*) FROM scrty_users WHERE id::text = $1 AND deleted_at IS NULL`, string(in.ID)))
			})
		}
	})

	if h.Ambient != nil {
		t.Run("QueuesBehindCallerTx", func(t *testing.T) { runImportQueue(t, h, newImported) })
	}

	t.Run("CollisionNamesTheField", func(t *testing.T) { runImportCollisionField(t, h, newImported) })

	t.Run("Race", func(t *testing.T) {
		t.Parallel()
		role := uniq("rr")
		seedRole(t, h.DB, role, false)
		in := newImported(t, role)
		outs := make([]admin.ImportOutcome, 8)
		errs := race(8, func(i int) error {
			var err error
			outs[i], err = h.Imports.ImportUser(t.Context(), in)
			return err
		})
		created := 0
		for i, err := range errs {
			require.NoError(t, err)
			if outs[i] == admin.ImportCreated {
				created++
			} else {
				assert.Contains(t, []admin.ImportOutcome{admin.ImportUnchanged, admin.ImportUpdated}, outs[i])
			}
		}
		assert.Equal(t, 1, created)
	})
}

// race runs n calls of f at once, released together, and returns each error.
func race(n int, f func(i int) error) []error {
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, n)
	)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = f(i)
		}()
	}
	close(start)
	wg.Wait()

	return errs
}
