package gormstore_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	identitytest "github.com/kartaladev/scrty/test/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestIdentityStore runs the identity ports' conformance suite and its
// ambient-transaction part against the gorm store, every case over one shared
// database: the suite's names are unique to each case and run. The ambient
// part runs twice, with the transaction attached through gormstore.WithTx and
// through a consumer's WithTxResolver.
func TestIdentityStore(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	taken := prepareAmbient(t, d.conn.DB)
	store := newIdentityStore(t, d.db)

	t.Run("conformance", func(t *testing.T) {
		t.Parallel()

		identitytest.RunConformanceSuite(t, func(*testing.T) identitytest.Fixture {
			return newIdentityFixture(store, d.db)
		})
	})

	t.Run("ambient/WithTx", func(t *testing.T) {
		t.Parallel()

		identitytest.RunAmbientTx(t, func(t *testing.T) identitytest.AmbientHarness {
			return newIdentityAmbient(t, d, taken, false)
		})
	})

	t.Run("ambient/WithTxResolver", func(t *testing.T) {
		t.Parallel()

		identitytest.RunAmbientTx(t, func(t *testing.T) identitytest.AmbientHarness {
			return newIdentityAmbient(t, d, taken, true)
		})
	})
}

func TestNewIdentityStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		noDB   bool
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.IdentityStore, err error)
	}

	refused := refusedConfig[*gormstore.IdentityStore]
	accepted := storefix.AcceptedConfig[*gormstore.IdentityStore]

	cases := []testCase{
		{name: "a handle is all it needs", assert: accepted},
		{
			name: "it honours a generator, a clock and a resolver",
			opts: []gormstore.Option{
				gormstore.WithIDGenerator(id.NewV7Generator()),
				gormstore.WithClock(time.Now),
				gormstore.WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return nil, false }),
			},
			assert: accepted,
		},
		{name: "a missing handle is refused", noDB: true, assert: refused("the database handle is nil")},
		{
			name:   "re-sealing does not apply to identity records",
			opts:   []gormstore.Option{gormstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
		{
			name:   "a nil generator is refused",
			opts:   []gormstore.Option{gormstore.WithIDGenerator(nil)},
			assert: refused("the id generator is nil"),
		},
		{
			name:   "a nil clock is refused",
			opts:   []gormstore.Option{gormstore.WithClock(nil)},
			assert: refused("the clock is nil"),
		},
		{
			name:   "a nil resolver is refused",
			opts:   []gormstore.Option{gormstore.WithTxResolver(nil)},
			assert: refused("the transaction resolver is nil"),
		},
		{
			name:   "a nil option is refused",
			opts:   []gormstore.Option{nil},
			assert: refused("an option is nil"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := db
			if tc.noDB {
				h = nil
			}

			s, err := gormstore.NewIdentityStore(h, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// withGoneTable runs fn with a context carrying a fresh transaction of d in
// which table has been renamed away, rolled back afterwards. Each call gets
// its own transaction: in a shared one the first failure would abort it
// (SQLSTATE 25P02) and mask the missing table (42P01) on every call after.
func withGoneTable(ctx context.Context, t *testing.T, d database, table string, fn func(txCtx context.Context)) {
	t.Helper()

	tx := d.db.WithContext(ctx).Begin()
	require.NoError(t, tx.Error)
	defer tx.Rollback()
	// table is always one of the tests' own literals, never input.
	require.NoError(t, tx.Exec(`ALTER TABLE `+table+` RENAME TO `+table+`_gone`).Error)

	fn(gormstore.WithTx(ctx, tx))
}

// TestIdentityStore_Scenarios pins what only this adapter can show: its
// clock, its generator, its handling of references it cannot parse, and its
// behaviour when a table it reads is missing.
func TestIdentityStore_Scenarios(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}

	cases := []testCase{
		{
			name: "a reference that is not a UUID is an unknown user to the lookup and the loader",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)

				required, err := s.Required(ctx, "not-a-uuid")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.False(t, required)

				_, err = s.LoadByUserID(ctx, "not-a-uuid")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "an upper-case reference to a stored user is an unknown user",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(newDescendingIDs(0xff)))

				created, err := s.Provision(ctx, "upper-case-ref")
				require.NoError(t, err)
				require.Equal(t, identity.UserID("ffffffff-ffff-ffff-ffff-ffffffffffff"), created.ID)

				_, err = s.LoadByUserID(ctx, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
				require.ErrorIs(t, err, identity.ErrUserNotFound)

				_, err = s.Required(ctx, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "an inactive user loads with the active flag false",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)

				created, err := s.Provision(ctx, "inactive-user")
				require.NoError(t, err)
				_, err = d.conn.DB.ExecContext(ctx, `UPDATE users SET active = false WHERE id = $1`, string(created.ID))
				require.NoError(t, err)

				got, err := s.LoadByUsername(ctx, "inactive-user")
				require.NoError(t, err)
				assert.False(t, got.Active, "the store returns the flag; authentication interprets it")
			},
		},
		{
			name: "a missing users table is a failure, not an unknown user or 'not required'",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)
				created, err := s.Provision(ctx, "missing-table-user")
				require.NoError(t, err)

				withGoneTable(ctx, t, d, "users", func(txCtx context.Context) {
					got, err := s.LoadByUsername(txCtx, "missing-table-user")
					require.Error(t, err)
					assert.NotErrorIs(t, err, identity.ErrUserNotFound)
					assert.Contains(t, err.Error(), "42P01", "the load reached the missing table")
					assert.Nil(t, got)
				})

				withGoneTable(ctx, t, d, "users", func(txCtx context.Context) {
					required, err := s.Required(txCtx, created.ID)
					require.Error(t, err)
					assert.NotErrorIs(t, err, identity.ErrUserNotFound)
					assert.Contains(t, err.Error(), "42P01", "the lookup reached the missing table")
					assert.False(t, required)
				})
			},
		},
		{
			name: "a missing grants, organization or group table fails the load with no partial record",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)
				f := newIdentityFixture(s, d.db)

				org := &identity.Organization{
					ID:    storefix.NewID(t).String(),
					Name:  "acme",
					Group: &identity.Group{ID: storefix.NewID(t).String(), Name: "partners"},
				}
				require.NoError(t, f.SeedOrganization(ctx, org))
				_, err := s.Provision(ctx, "partial-user",
					identity.WithUserRoles("admin"), identity.WithUserOrganization(&identity.Organization{ID: org.ID}))
				require.NoError(t, err)

				for _, table := range []string{"assigned_roles", "organizations", "groups"} {
					withGoneTable(ctx, t, d, table, func(txCtx context.Context) {
						got, err := s.LoadByUsername(txCtx, "partial-user")
						require.Error(t, err, table)
						assert.NotErrorIs(t, err, identity.ErrUserNotFound, table)
						assert.Contains(t, err.Error(), "42P01", table)
						assert.Nil(t, got, table)
					})
				}
			},
		},
		{
			name: "the clock binds every created and updated time the store writes",
			assert: func(t *testing.T, ctx context.Context, d database) {
				t1 := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
				t2 := t1.Add(48 * time.Hour)

				s1 := newIdentityStore(t, d.db, gormstore.WithClock(func() time.Time { return t1 }))
				created, err := s1.Provision(ctx, "clocked-user", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				userTimes := func() (c, u time.Time) {
					require.NoError(t, d.conn.DB.QueryRowContext(ctx,
						`SELECT created_at, updated_at FROM users WHERE id = $1`, string(created.ID)).Scan(&c, &u))
					return c, u
				}
				grantTimes := func(role string) (c, u time.Time) {
					require.NoError(t, d.conn.DB.QueryRowContext(ctx,
						`SELECT created_at, updated_at FROM assigned_roles WHERE user_id = $1 AND role_name = $2`,
						string(created.ID), role).Scan(&c, &u))
					return c, u
				}

				c, u := userTimes()
				assert.True(t, t1.Equal(c), "user created_at: want %v, got %v", t1, c)
				assert.True(t, t1.Equal(u), "user updated_at: want %v, got %v", t1, u)
				c, u = grantTimes("admin")
				assert.True(t, t1.Equal(c), "grant created_at: want %v, got %v", t1, c)
				assert.True(t, t1.Equal(u), "grant updated_at: want %v, got %v", t1, u)

				s2 := newIdentityStore(t, d.db, gormstore.WithClock(func() time.Time { return t2 }))
				_, err = s2.Update(ctx, "clocked-user", identity.WithUserName("Renamed"), identity.WithUserRoles("admin", "viewer"))
				require.NoError(t, err)

				c, u = userTimes()
				assert.True(t, t1.Equal(c), "an update keeps the user's created_at: want %v, got %v", t1, c)
				assert.True(t, t2.Equal(u), "an update moves the user's updated_at: want %v, got %v", t2, u)
				c, u = grantTimes("admin")
				assert.True(t, t1.Equal(c), "a kept grant keeps its created_at: want %v, got %v", t1, c)
				assert.True(t, t2.Equal(u), "a kept grant's updated_at moves: want %v, got %v", t2, u)
				c, u = grantTimes("viewer")
				assert.True(t, t2.Equal(c), "a new grant's created_at: want %v, got %v", t2, c)
				assert.True(t, t2.Equal(u), "a new grant's updated_at: want %v, got %v", t2, u)
			},
		},
		{
			name: "an update naming a zero time and an empty name writes NULL and ''",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)
				recorded := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

				_, err := s.Provision(ctx, "zero-values-user", identity.WithUserName("Named"),
					identity.WithUserPasswordChangedAt(recorded))
				require.NoError(t, err)

				_, err = s.Update(ctx, "zero-values-user",
					identity.WithUserName(""), identity.WithUserPasswordChangedAt(time.Time{}))
				require.NoError(t, err)

				var (
					name    string
					changed *time.Time
				)
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT name, password_changed_at FROM users WHERE username = $1`, "zero-values-user").
					Scan(&name, &changed))
				assert.Empty(t, name, "a named empty name is written")
				assert.Nil(t, changed, "a named zero time is written as NULL")
			},
		},
		{
			name: "grants load in the given order under a descending generator",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(newDescendingIDs(0xfe)))

				_, err := s.Provision(ctx, "descending-order", identity.WithUserRoles("admin", "auditor", "viewer"))
				require.NoError(t, err)

				got, err := s.LoadByUsername(ctx, "descending-order")
				require.NoError(t, err)
				require.Len(t, got.Roles, 3)
				assert.Equal(t, "admin", got.Roles[0].Name)
				assert.Equal(t, "auditor", got.Roles[1].Name)
				assert.Equal(t, "viewer", got.Roles[2].Name)
			},
		},
		{
			name: "the first stored duplicate keeps its super role under a descending generator",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(newDescendingIDs(0xfd)))

				created, err := s.Provision(ctx, "descending-dup", identity.WithUserRoles("admin", "admin"))
				require.NoError(t, err)
				require.Len(t, created.Roles, 2)
				first := created.Roles[0].ID

				// The consumer's administration makes the first admin grant a
				// super role; the second, whose identifier sorts first, is not.
				_, err = d.conn.DB.ExecContext(ctx,
					`UPDATE assigned_roles SET super_role = true WHERE id = $1`, first)
				require.NoError(t, err)

				got, err := s.Update(ctx, "descending-dup", identity.WithUserRoles("admin"))
				require.NoError(t, err)
				require.Len(t, got.Roles, 1)
				assert.Equal(t, first, got.Roles[0].ID, "the first given grant survives, not the lowest identifier")
				assert.True(t, got.Roles[0].SuperRole, "the surviving grant carries the first grant's super role")
			},
		},
		{
			name: "a generator failing on the second grant writes nothing",
			assert: func(t *testing.T, ctx context.Context, d database) {
				genErr := errors.New("generator exhausted")
				// Call 1 is the user, call 2 the first grant, call 3 the second.
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(&failingIDs{failOn: 3, err: genErr}))

				_, err := s.Provision(ctx, "generator-fails", identity.WithUserRoles("admin", "viewer"))
				require.ErrorIs(t, err, genErr)

				_, err = s.LoadByUsername(ctx, "generator-fails")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "a grant insert failing after the user row, outside a caller's transaction, leaves no user",
			assert: func(t *testing.T, ctx context.Context, d database) {
				plain := newIdentityStore(t, d.db)
				_, err := plain.Provision(ctx, "atomic-grant-owner", identity.WithUserRoles("admin"))
				require.NoError(t, err)
				owner, err := plain.LoadByUsername(ctx, "atomic-grant-owner")
				require.NoError(t, err)
				require.Len(t, owner.Roles, 1)
				taken := id.MustParse(owner.Roles[0].ID)

				// Call 1 is the new user, fresh; call 2 its grant, re-issuing
				// the owner's grant identifier, so PostgreSQL rejects the grant
				// insert after the user row is written.
				var calls atomic.Int32
				reissuing := newIdentityStore(t, d.db, gormstore.WithIDGenerator(storefix.GeneratorFunc(
					func() (id.ID, error) {
						if calls.Add(1) == 2 {
							return taken, nil
						}
						return seedIDs.NewID()
					})))

				_, err = reissuing.Provision(ctx, "atomic-grant-collides", identity.WithUserRoles("viewer"))
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserExists)
				assert.Contains(t, err.Error(), "23505", "the grant insert hit the primary key")

				_, err = plain.LoadByUsername(ctx, "atomic-grant-collides")
				require.ErrorIs(t, err, identity.ErrUserNotFound, "the user row outlived its failed grant insert")
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "atomic-grant-collides"))
			},
		},
		{
			name: "with no generator configured, a user's identifier is canonical UUIDv7 text",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)

				got, err := s.Provision(ctx, "default-generator-user")
				require.NoError(t, err)
				assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, string(got.ID),
					"the default generator mints lowercase RFC 9562 version 7 identifiers")
			},
		},
		{
			name: "the collision error does not carry the username",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db)

				_, err := s.Provision(ctx, "ada@example.test")
				require.NoError(t, err)
				_, err = s.Provision(ctx, "ada@example.test")
				require.ErrorIs(t, err, identity.ErrUserExists)

				for _, text := range storefix.ErrorTexts(err) {
					assert.NotContains(t, text, "ada@example.test")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), d)
		})
	}
}
