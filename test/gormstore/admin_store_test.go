package gormstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/store/gormstore"
)

// newAdminUser creates a live user with a unique username and the email.
func newAdminUser(ctx context.Context, t *testing.T, s *gormstore.IdentityStore, email string) admin.User {
	t.Helper()

	uid, err := seedIDs.NewID()
	require.NoError(t, err)
	u, err := s.CreateUser(ctx, admin.NewUser{
		ID: identity.UserID(uid.String()), Username: "u-" + uid.String(), Email: email,
	})
	require.NoError(t, err)

	return u
}

// waitForLockWait blocks until a backend is waiting on a lock, the point a
// blocked write has reached.
func waitForLockWait(t *testing.T, d database) {
	t.Helper()

	require.Eventually(t, func() bool {
		var n int
		err := d.conn.DB.QueryRowContext(t.Context(),
			`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`).Scan(&n)

		return err == nil && n > 0
	}, 10*time.Second, 20*time.Millisecond, "the write never blocked on the lock")
}

// TestAdminUnknownOrganization checks that an organization identifier that is
// a valid UUID but names no organization is invalid input, naming no value.
func TestAdminUnknownOrganization(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	store := newIdentityStore(t, d.db)

	type testCase struct {
		name   string
		write  func(ctx context.Context, org *identity.Organization) error
		assert func(t *testing.T, err error)
	}

	ghost := func() *identity.Organization {
		v, err := seedIDs.NewID()
		require.NoError(t, err)

		return &identity.Organization{ID: v.String()}
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		assert.ErrorIs(t, err, admin.ErrInvalidInput)
	}

	cases := []testCase{
		{
			name: "create",
			write: func(ctx context.Context, org *identity.Organization) error {
				uid, err := seedIDs.NewID()
				require.NoError(t, err)
				_, err = store.CreateUser(ctx, admin.NewUser{
					ID: identity.UserID(uid.String()), Username: "u-" + uid.String(), Organization: org,
				})

				return err
			},
			assert: refused,
		},
		{
			name: "update",
			write: func(ctx context.Context, org *identity.Organization) error {
				u := newAdminUser(ctx, t, store, "")
				ref := org
				_, err := store.UpdateUser(ctx, u.ID, u.Version, admin.UserChange{Organization: &ref})

				return err
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			org := ghost()
			err := tc.write(t.Context(), org)
			tc.assert(t, err)
			assert.NotContains(t, errText(err), org.ID, "the error names no identifier")
		})
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

// TestAdminAmbientTransaction checks the user port inside a caller's
// transaction, attached with WithTx and through a resolver: a refused write
// leaves the transaction usable, and the caller's rollback undoes the rest.
func TestAdminAmbientTransaction(t *testing.T) {
	t.Parallel()

	for _, resolver := range []bool{false, true} {
		name := "WithTx"
		if resolver {
			name = "resolver"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := migratedIdentityDB(t)
			opts := []gormstore.Option(nil)
			if resolver {
				opts = append(opts, gormstore.WithTxResolver(func(ctx context.Context) (*gormdb.DB, bool) {
					tx, ok := ctx.Value(consumerTxKey{}).(*gormdb.DB)

					return tx, ok
				}))
			}
			store := newIdentityStore(t, d.db, opts...)

			tx := d.db.WithContext(t.Context()).Begin()
			require.NoError(t, tx.Error)
			t.Cleanup(func() { tx.Rollback() })

			ctx := gormstore.WithTx(t.Context(), tx)
			if resolver {
				ctx = context.WithValue(t.Context(), consumerTxKey{}, tx)
			}

			first := newAdminUser(ctx, t, store, "dup-"+t.Name()+"@example.com")

			uid, err := seedIDs.NewID()
			require.NoError(t, err)
			_, err = store.CreateUser(ctx, admin.NewUser{
				ID: identity.UserID(uid.String()), Username: "u-" + uid.String(), Email: first.Email,
			})
			var exists admin.AlreadyExistsError
			require.ErrorAs(t, err, &exists)
			assert.Equal(t, admin.FieldEmail, exists.Field)
			assert.NotContains(t, err.Error(), first.Email)

			// The transaction is still usable and holds the first user.
			got, err := store.GetUser(ctx, first.ID)
			require.NoError(t, err, "the refusal left the caller's transaction aborted")
			assert.Equal(t, first.ID, got.ID)

			// A statement the database itself rejects inside the transaction, an
			// email a lock-free writer commits between the check and the update,
			// aborts nothing of the caller's.
			email := "raced-" + t.Name() + "@example.com"
			raw, err := d.conn.DB.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Rollback() })
			rival, err := seedIDs.NewID()
			require.NoError(t, err)
			_, err = raw.ExecContext(t.Context(), `INSERT INTO scrty_users (id, username, name, email, password, active,
  role, version, created_at, updated_at) VALUES ($1, $2, '', $3, ''::bytea, true, '', 1, now(), now())`,
				rival, "rival-"+rival.String(), email)
			require.NoError(t, err)

			done := make(chan error, 1)
			go func() {
				_, err := store.UpdateUser(ctx, first.ID, first.Version, admin.UserChange{Email: &email})
				done <- err
			}()
			waitForLockWait(t, d)
			require.NoError(t, raw.Commit())
			require.ErrorAs(t, <-done, &exists)
			assert.Equal(t, admin.FieldEmail, exists.Field)

			got, err = store.GetUser(ctx, first.ID)
			require.NoError(t, err, "a rejected statement left the caller's transaction aborted")
			assert.Equal(t, first.Version, got.Version, "the refused update is undone, the earlier write is kept")

			require.NoError(t, tx.Rollback().Error)

			_, err = store.GetUser(t.Context(), first.ID)
			assert.ErrorIs(t, err, admin.ErrNotFound, "the caller's rollback undoes the user")
		})
	}
}

// TestAdminRacedUniqueViolation checks that an email another writer took
// between the store's check and its update, a writer that takes no lock, is
// reported as AlreadyExistsError naming the email field, with no value.
func TestAdminRacedUniqueViolation(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	store := newIdentityStore(t, d.db)
	ctx := t.Context()

	victim := newAdminUser(ctx, t, store, "")
	email := "raced-" + string(victim.ID) + "@example.com"

	// An uncommitted insert of the email, from a writer that takes no lock:
	// the store's check cannot see it, and its update waits on the index.
	raw, err := d.conn.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Rollback() })
	rival, err := seedIDs.NewID()
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `INSERT INTO scrty_users (id, username, name, email, password, active, role, version,
  created_at, updated_at) VALUES ($1, $2, '', $3, ''::bytea, true, '', 1, now(), now())`,
		rival, "rival-"+rival.String(), email)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := store.UpdateUser(ctx, victim.ID, victim.Version, admin.UserChange{Email: &email})
		done <- err
	}()
	waitForLockWait(t, d)
	require.NoError(t, raw.Commit())

	err = <-done
	var exists admin.AlreadyExistsError
	require.ErrorAs(t, err, &exists)
	assert.Equal(t, admin.FieldEmail, exists.Field)
	assert.NotContains(t, err.Error(), email, "the error carries no value")

	got, err := store.GetUser(ctx, victim.ID)
	require.NoError(t, err)
	assert.Equal(t, victim.Version, got.Version, "nothing of the refused update is written")
}

// TestAdminCancelledMidWrite checks that a write whose context is cancelled
// while it waits for the user's row lock returns the context error and
// writes nothing.
func TestAdminCancelledMidWrite(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	store := newIdentityStore(t, d.db)
	ctx := t.Context()

	u := newAdminUser(ctx, t, store, "")

	raw, err := d.conn.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Rollback() })
	_, err = raw.ExecContext(ctx, `SELECT 1 FROM scrty_users WHERE id = $1 FOR UPDATE`, u.ID)
	require.NoError(t, err)

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	name := "changed"
	done := make(chan error, 1)
	go func() {
		_, err := store.UpdateUser(cctx, u.ID, u.Version, admin.UserChange{Name: &name})
		done <- err
	}()
	waitForLockWait(t, d)
	cancel()

	err = <-done
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
	require.NoError(t, raw.Rollback())

	got, err := store.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.Version, got.Version)
	assert.Equal(t, u.Name, got.Name, "nothing is written")
}

// TestAdminRoleWriteStampsTimeAfterLock checks that a role write that waits
// for the role's lock stamps the time it wrote, not the time it started.
func TestAdminRoleWriteStampsTimeAfterLock(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

	type testCase struct {
		name  string
		write func(ctx context.Context, s *gormstore.IdentityStore, role admin.Role) error
	}

	cases := []testCase{
		{
			name: "update role",
			write: func(ctx context.Context, s *gormstore.IdentityStore, r admin.Role) error {
				d := "changed"
				_, err := s.UpdateRole(ctx, r.Name, r.Version, admin.RoleChange{DisplayName: &d})

				return err
			},
		},
		{
			name: "replace grants",
			write: func(ctx context.Context, s *gormstore.IdentityStore, r admin.Role) error {
				_, err := s.ReplaceGrants(ctx, r.Name, r.Version, []admin.ResourceGrants{{Group: "g", Resource: "r"}})

				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := migratedIdentityDB(t)
			clk := clockwork.NewFakeClockAt(start)
			store := newIdentityStore(t, d.db, gormstore.WithClock(clk))
			ctx := t.Context()

			role, err := store.CreateRole(ctx, admin.Role{Name: "r-" + t.Name()})
			require.NoError(t, err)

			raw, err := d.conn.DB.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Rollback() })
			_, err = raw.ExecContext(ctx, `SELECT 1 FROM scrty_roles WHERE name = $1 FOR UPDATE`, role.Name)
			require.NoError(t, err)

			var wg sync.WaitGroup
			var werr error
			wg.Add(1)
			go func() {
				defer wg.Done()
				werr = tc.write(ctx, store, role)
			}()
			waitForLockWait(t, d)

			later := start.Add(time.Hour)
			clk.Advance(time.Hour)
			require.NoError(t, raw.Commit())
			wg.Wait()
			require.NoError(t, werr)

			var updated time.Time
			require.NoError(t, d.conn.DB.QueryRowContext(ctx, `SELECT updated_at FROM scrty_roles WHERE name = $1`,
				role.Name).Scan(&updated))
			assert.True(t, updated.Equal(later), "updated_at %v, want the time after the lock %v", updated, later)
		})
	}
}
