package pgxstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	identitytest "github.com/kartaladev/scrty/test/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestIdentityStore runs the identity ports' conformance suite and its
// ambient-transaction part against the pgx store, every case over one shared
// database: the suite's names are unique to each case and run. The ambient
// part runs twice, once with the transaction attached through pgxstore.WithTx
// and once through a consumer resolver.
func TestIdentityStore(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)
	taken := prepareAmbient(t, db)
	store := newIdentityStore(t, db.Pool)

	t.Run("conformance", func(t *testing.T) {
		t.Parallel()

		identitytest.RunConformanceSuite(t, func(*testing.T) identitytest.Fixture {
			return newIdentityFixture(store, db.Pool)
		})
	})

	t.Run("ambient/WithTx", func(t *testing.T) {
		t.Parallel()

		identitytest.RunAmbientTx(t, func(t *testing.T) identitytest.AmbientHarness {
			return newIdentityAmbient(t, db, taken, false)
		})
	})

	t.Run("ambient/WithTxResolver", func(t *testing.T) {
		t.Parallel()

		identitytest.RunAmbientTx(t, func(t *testing.T) identitytest.AmbientHarness {
			return newIdentityAmbient(t, db, taken, true)
		})
	})
}

func TestIdentityStore_Construction(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)

	type testCase struct {
		name   string
		noPool bool
		opts   []pgxstore.Option
		assert func(t *testing.T, s *pgxstore.IdentityStore, err error)
	}

	refused := refusedConfig[*pgxstore.IdentityStore]
	accepted := storefix.AcceptedConfig[*pgxstore.IdentityStore]

	cases := []testCase{
		{name: "a pool is all it needs", assert: accepted},
		{
			name: "it honours a generator, a clock and a resolver",
			opts: []pgxstore.Option{
				pgxstore.WithIDGenerator(id.NewV7Generator()),
				pgxstore.WithClock(time.Now),
				pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) { return nil, false }),
			},
			assert: accepted,
		},
		{name: "a missing pool is refused", noPool: true, assert: refused("the pool is nil")},
		{
			name:   "re-sealing does not apply to identity records",
			opts:   []pgxstore.Option{pgxstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
		{
			name:   "a nil generator is refused",
			opts:   []pgxstore.Option{pgxstore.WithIDGenerator(nil)},
			assert: refused("the id generator is nil"),
		},
		{
			name:   "a typed-nil generator is refused",
			opts:   []pgxstore.Option{pgxstore.WithIDGenerator((*descendingIDs)(nil))},
			assert: refused("the id generator is nil"),
		},
		{
			name:   "a nil clock is refused",
			opts:   []pgxstore.Option{pgxstore.WithClock(nil)},
			assert: refused("the clock is nil"),
		},
		{
			name:   "a nil resolver is refused",
			opts:   []pgxstore.Option{pgxstore.WithTxResolver(nil)},
			assert: refused("the transaction resolver is nil"),
		},
		{
			name:   "a nil option is refused",
			opts:   []pgxstore.Option{nil},
			assert: refused("an option is nil"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := pool
			if tc.noPool {
				p = nil
			}

			s, err := pgxstore.NewIdentityStore(p, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// TestIdentityStore_Scenarios pins what only this adapter can show: its
// clock, its generator, its handling of references it cannot parse, and its
// behaviour when a table it reads is missing.
func TestIdentityStore_Scenarios(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, pool *pgxpool.Pool)
	}

	cases := []testCase{
		{
			name: "a reference that is not a UUID is an unknown user to the lookup and the loader",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				required, err := s.Required(ctx, "not-a-uuid")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.False(t, required)

				_, err = s.LoadByUserID(ctx, "not-a-uuid")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "an upper-case reference to a stored user is an unknown user",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(newDescendingIDs(0xff)))

				d, err := s.Provision(ctx, "upper-case-ref")
				require.NoError(t, err)
				require.Equal(t, identity.UserID("ffffffff-ffff-ffff-ffff-ffffffffffff"), d.ID)

				_, err = s.LoadByUserID(ctx, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
				require.ErrorIs(t, err, identity.ErrUserNotFound)

				_, err = s.Required(ctx, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "an inactive user loads with the active flag false",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				d, err := s.Provision(ctx, "inactive-user")
				require.NoError(t, err)
				_, err = pool.Exec(ctx, `UPDATE users SET active = false WHERE id = $1`, string(d.ID))
				require.NoError(t, err)

				got, err := s.LoadByUsername(ctx, "inactive-user")
				require.NoError(t, err)
				assert.False(t, got.Active, "the store returns the flag; authentication interprets it")
			},
		},
		{
			name: "a missing users table is a failure, not an unknown user or 'not required'",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				d, err := s.Provision(ctx, "missing-table-user")
				require.NoError(t, err)

				for _, probe := range []string{"load", "lookup"} {
					tx := beginTx(ctx, t, pool)
					_, err = tx.Exec(ctx, `ALTER TABLE users RENAME TO users_gone`)
					require.NoError(t, err)
					txCtx := pgxstore.WithTx(ctx, tx)

					switch probe {
					case "load":
						got, err := s.LoadByUsername(txCtx, "missing-table-user")
						require.Error(t, err)
						assert.NotErrorIs(t, err, identity.ErrUserNotFound)
						assert.Nil(t, got)
					case "lookup":
						required, err := s.Required(txCtx, d.ID)
						require.Error(t, err)
						assert.NotErrorIs(t, err, identity.ErrUserNotFound)
						assert.False(t, required)
					}

					require.NoError(t, tx.Rollback(ctx))
				}
			},
		},
		{
			name: "a missing grants, organization or group table fails the load with no partial record",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				f := newIdentityFixture(s, pool)

				o, err := seedIDs.NewID()
				require.NoError(t, err)
				g, err := seedIDs.NewID()
				require.NoError(t, err)
				org := &identity.Organization{ID: o.String(), Name: "acme", Group: &identity.Group{ID: g.String(), Name: "partners"}}
				require.NoError(t, f.SeedOrganization(ctx, org))
				_, err = s.Provision(ctx, "partial-user",
					identity.WithUserRoles("admin"), identity.WithUserOrganization(&identity.Organization{ID: org.ID}))
				require.NoError(t, err)

				for _, table := range []string{"assigned_roles", "organizations", "groups"} {
					tx := beginTx(ctx, t, pool)
					// table is one of the three literals above, never input.
					_, err = tx.Exec(ctx, `ALTER TABLE `+table+` RENAME TO `+table+`_gone`)
					require.NoError(t, err)

					got, err := s.LoadByUsername(pgxstore.WithTx(ctx, tx), "partial-user")
					require.Error(t, err, table)
					assert.NotErrorIs(t, err, identity.ErrUserNotFound, table)
					assert.Nil(t, got, table)

					require.NoError(t, tx.Rollback(ctx))
				}
			},
		},
		{
			name: "the clock binds every created and updated time the store writes",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				t1 := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
				t2 := t1.Add(48 * time.Hour)

				s1 := newIdentityStore(t, pool, pgxstore.WithClock(func() time.Time { return t1 }))
				d, err := s1.Provision(ctx, "clocked-user", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				userTimes := func() (created, updated time.Time) {
					require.NoError(t, pool.QueryRow(ctx,
						`SELECT created_at, updated_at FROM users WHERE id = $1`, string(d.ID)).Scan(&created, &updated))
					return created, updated
				}
				grantTimes := func(role string) (created, updated time.Time) {
					require.NoError(t, pool.QueryRow(ctx,
						`SELECT created_at, updated_at FROM assigned_roles WHERE user_id = $1 AND role_name = $2`,
						string(d.ID), role).Scan(&created, &updated))
					return created, updated
				}

				c, u := userTimes()
				assert.True(t, t1.Equal(c), "user created_at: want %v, got %v", t1, c)
				assert.True(t, t1.Equal(u), "user updated_at: want %v, got %v", t1, u)
				c, u = grantTimes("admin")
				assert.True(t, t1.Equal(c), "grant created_at: want %v, got %v", t1, c)
				assert.True(t, t1.Equal(u), "grant updated_at: want %v, got %v", t1, u)

				s2 := newIdentityStore(t, pool, pgxstore.WithClock(func() time.Time { return t2 }))
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
			name: "grants load in the given order under a descending generator",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(newDescendingIDs(0xfe)))

				_, err := s.Provision(ctx, "descending-order", identity.WithUserRoles("admin", "auditor", "viewer"))
				require.NoError(t, err)

				d, err := s.LoadByUsername(ctx, "descending-order")
				require.NoError(t, err)
				require.Len(t, d.Roles, 3)
				assert.Equal(t, "admin", d.Roles[0].Name)
				assert.Equal(t, "auditor", d.Roles[1].Name)
				assert.Equal(t, "viewer", d.Roles[2].Name)
			},
		},
		{
			name: "the first stored duplicate keeps its super role under a descending generator",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(newDescendingIDs(0xfd)))

				created, err := s.Provision(ctx, "descending-dup", identity.WithUserRoles("admin", "admin"))
				require.NoError(t, err)
				require.Len(t, created.Roles, 2)
				first := created.Roles[0].ID

				// The consumer's administration makes the first admin grant a
				// super role; the second, whose identifier sorts first, is not.
				_, err = pool.Exec(ctx, `UPDATE assigned_roles SET super_role = true WHERE id = $1`, first)
				require.NoError(t, err)

				d, err := s.Update(ctx, "descending-dup", identity.WithUserRoles("admin"))
				require.NoError(t, err)
				require.Len(t, d.Roles, 1)
				assert.Equal(t, first, d.Roles[0].ID, "the first given grant survives, not the lowest identifier")
				assert.True(t, d.Roles[0].SuperRole, "the surviving grant carries the first grant's super role")
			},
		},
		{
			name: "a generator failing on the second grant writes nothing",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				genErr := errors.New("generator exhausted")
				// Call 1 is the user, call 2 the first grant, call 3 the second.
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(&failingIDs{failOn: 3, err: genErr}))

				_, err := s.Provision(ctx, "generator-fails", identity.WithUserRoles("admin", "viewer"))
				require.ErrorIs(t, err, genErr)

				_, err = s.LoadByUsername(ctx, "generator-fails")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "a provision failing after its user row, outside a caller's transaction, stores nothing",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				// The generator mints fresh identifiers, except that the
				// second provision's grant re-issues the first one's, so
				// PostgreSQL rejects that grant after the user row is in.
				var (
					mu     sync.Mutex
					minted []id.ID
				)
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
					mu.Lock()
					defer mu.Unlock()

					if len(minted) == 3 {
						return minted[1], nil
					}
					fresh, err := seedIDs.NewID()
					minted = append(minted, fresh)

					return fresh, err
				})))

				_, err := s.Provision(ctx, "grant-reissued-first", identity.WithUserRoles("admin"))
				require.NoError(t, err)
				_, err = s.Provision(ctx, "grant-reissued-second", identity.WithUserRoles("admin"))
				require.Error(t, err)
				assert.Contains(t, err.Error(), "23505", "the grant insert hit the primary key")

				_, err = s.LoadByUsername(ctx, "grant-reissued-second")
				require.ErrorIs(t, err, identity.ErrUserNotFound, "the user row rolled back with the grant")
			},
		},
		{
			name: "a store with no generator configured mints version 7 user identifiers",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				d, err := s.Provision(ctx, "default-generator-user")
				require.NoError(t, err)
				assert.Regexp(t,
					`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, string(d.ID),
					"canonical lowercase UUID text, version nibble 7")
			},
		},
		{
			name: "the collision error does not carry the username",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

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

			tc.assert(t, t.Context(), db.Pool)
		})
	}
}
