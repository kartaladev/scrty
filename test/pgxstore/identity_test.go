package pgxstore_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test"
	identitytest "github.com/kartaladev/scrty/test/identity"
	"github.com/kartaladev/scrty/test/internal/idgenmock"
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
			return conformanceFixture{newIdentityFixture(store, db.Pool)}
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
				pgxstore.WithClock(clock.System()),
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
			name: "an empty email is not found before any query runs",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				// A cancelled context fails any query, so a not-found
				// result proves the store never reached the database.
				got, err := s.LoadByEmail(cctx, "")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.NotErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)
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
				_, err = pool.Exec(ctx, `UPDATE scrty_users SET active = false WHERE id = $1`, string(d.ID))
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
					_, err = tx.Exec(ctx, `ALTER TABLE scrty_users RENAME TO users_gone`)
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

				for _, table := range []string{"scrty_assigned_roles", "scrty_organizations", "scrty_groups"} {
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

				s1 := newIdentityStore(t, pool, pgxstore.WithClock(storefix.NewClock(t1)))
				d, err := s1.Provision(ctx, "clocked-user", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				userTimes := func() (created, updated time.Time) {
					require.NoError(t, pool.QueryRow(ctx,
						`SELECT created_at, updated_at FROM scrty_users WHERE id = $1`, string(d.ID)).Scan(&created, &updated))
					return created, updated
				}
				grantTimes := func(role string) (created, updated time.Time) {
					require.NoError(t, pool.QueryRow(ctx,
						`SELECT created_at, updated_at FROM scrty_assigned_roles WHERE user_id = $1 AND role_name = $2`,
						string(d.ID), role).Scan(&created, &updated))
					return created, updated
				}

				c, u := userTimes()
				assert.True(t, t1.Equal(c), "user created_at: want %v, got %v", t1, c)
				assert.True(t, t1.Equal(u), "user updated_at: want %v, got %v", t1, u)
				c, u = grantTimes("admin")
				assert.True(t, t1.Equal(c), "grant created_at: want %v, got %v", t1, c)
				assert.True(t, t1.Equal(u), "grant updated_at: want %v, got %v", t1, u)

				s2 := newIdentityStore(t, pool, pgxstore.WithClock(storefix.NewClock(t2)))
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
				_, err = pool.Exec(ctx, `UPDATE scrty_assigned_roles SET super_role = true WHERE id = $1`, first)
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
			name: "a generator answering the nil id for the user writes nothing",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				// Call 1 is the user.
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(nilOnCall(t, 1)))

				_, err := s.Provision(ctx, "nil-user-id", identity.WithUserRoles("admin"))
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Zero(t, userRowCount(ctx, t, pool, "nil-user-id"), "a user was stored under the nil id")
			},
		},
		{
			name: "a generator answering the nil id for a grant writes nothing",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				// Call 1 is the user, call 2 the first grant.
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(nilOnCall(t, 2)))

				_, err := s.Provision(ctx, "nil-grant-id", identity.WithUserRoles("admin", "viewer"))
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Zero(t, userRowCount(ctx, t, pool, "nil-grant-id"), "a user was stored")

				var n int
				require.NoError(t, pool.QueryRow(ctx,
					`SELECT count(*) FROM scrty_assigned_roles WHERE id = $1`, id.Nil.String()).Scan(&n))
				assert.Zero(t, n, "a grant was stored under the nil id")
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
		{
			name: "UpdateBumpsVersion: every update that writes moves the version, and nothing else does",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				d, err := s.Provision(ctx, "versioned-user", identity.WithUserPassword([]byte("H1")))
				require.NoError(t, err)

				version := func() int64 {
					var v int64
					require.NoError(t, pool.QueryRow(ctx,
						`SELECT version FROM scrty_users WHERE id = $1`, string(d.ID)).Scan(&v))
					return v
				}
				require.Equal(t, int64(1), version(), "a new user starts at the column's default")

				_, err = s.Update(ctx, "versioned-user", identity.WithUserName("Ada"))
				require.NoError(t, err)
				assert.Equal(t, int64(2), version(),
					"a login-time update moves the version, so an administrator's earlier read is stale")

				_, err = s.Update(ctx, "versioned-user", identity.WithUserRoles("viewer"))
				require.NoError(t, err)
				assert.Equal(t, int64(3), version(), "a grant rebuild is a write to the user")

				_, err = s.Update(ctx, "versioned-user")
				require.NoError(t, err)
				assert.Equal(t, int64(3), version(), "an update naming nothing writes nothing")

				_, err = s.Update(ctx, "versioned-user",
					identity.WithUserPasswordIf([]byte("not-the-hash")), identity.WithUserPassword([]byte("H2")))
				require.ErrorIs(t, err, identity.ErrNotUpdated)
				assert.Equal(t, int64(3), version(), "a refused conditional update writes nothing")
			},
		},
		{
			name: "the refusal of a username that is another user's email carries neither",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				f := newIdentityFixture(s, pool)
				_, err := s.Provision(ctx, "bob")
				require.NoError(t, err)
				require.NoError(t, f.SeedEmail(ctx, "bob", "carol@example.com", time.Time{}))

				_, err = s.Provision(ctx, "Carol@Example.com")
				require.ErrorIs(t, err, identity.ErrUserExists)
				for _, text := range storefix.ErrorTexts(err) {
					assert.NotContains(t, strings.ToLower(text), "carol@example.com")
					assert.NotContains(t, text, "bob")
				}
			},
		},
		{
			name: "a missing users table fails the email load, never as an unknown address",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				tx, err := pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
				_, err = tx.Exec(ctx, `ALTER TABLE scrty_users RENAME TO users_gone`)
				require.NoError(t, err)

				got, err := s.LoadByEmail(pgxstore.WithTx(ctx, tx), "ada@example.com")
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name: "a cancelled context fails the email load and the provision, never as a refusal or a miss",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				got, err := s.LoadByEmail(cctx, "ada@example.com")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, got)

				_, err = s.Provision(cctx, "ada@example.com")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, identity.ErrUserExists)

				_, err = s.LoadByUsername(ctx, "ada@example.com")
				require.ErrorIs(t, err, identity.ErrUserNotFound, "nothing was written")
			},
		},
		{
			name: "a soft-deleted user that keeps its verified email is unknown to the email load and frees the address as a username",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				_, err := s.Provision(ctx, "kept-email-user")
				require.NoError(t, err)
				// Unlike the administration's delete, which clears the email, only
				// deleted_at is set here, so each predicate on it is what decides.
				_, err = pool.Exec(ctx, `UPDATE scrty_users
SET email = 'kept@example.com', email_verified_at = now(), deleted_at = now()
WHERE username = 'kept-email-user'`)
				require.NoError(t, err)

				got, err := s.LoadByEmail(ctx, "kept@example.com")
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, got)

				_, err = s.Provision(ctx, "kept@example.com")
				require.NoError(t, err, "a deleted user's email does not hold the address")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A database of its own: cases rename tables, which locks them for the
			// transaction and must not reach a sibling case.
			db := migratedIdentity(t)

			tc.assert(t, t.Context(), db.Pool)
		})
	}
}

// TestIdentityStore_InputTheDatabaseCannotEncode loads from a LATIN1 database
// through a handle that sends UTF-8, so a username with no LATIN1 form is
// refused by the server (SQLSTATE 22P05). The refusal means no user can hold
// that name, so it is a miss; every other failure stays a failure.
func TestIdentityStore_InputTheDatabaseCannotEncode(t *testing.T) {
	t.Parallel()

	admin := test.RunTestPostgres(t)
	store := newIdentityStore(t, openPool(t, storefix.Latin1DSN(t, admin.DB, admin.DSN)))

	type testCase struct {
		name     string
		username string
		byEmail  bool                                      // load by email rather than by username
		ctx      func(ctx context.Context) context.Context // nil means identity
		assert   func(t *testing.T, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name:     "an email the database cannot encode is not found",
			username: "ada\u20ac@example.com",
			byEmail:  true,
			assert: func(t *testing.T, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name:     "a failure of an email load that is not the input stays a failure",
			username: "ada\u20ac@example.com",
			byEmail:  true,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *identity.Details, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name:     "a username the database cannot encode is not found",
			username: "ada\u20ac",
			assert: func(t *testing.T, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name:     "a username the database can encode is not found when nobody has it",
			username: "ad\u00e1",
			assert: func(t *testing.T, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name:     "a failure that is not the input stays a failure",
			username: "ada\u20ac",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *identity.Details, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound)
				assert.ErrorIs(t, err, context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			load := store.LoadByUsername
			if tc.byEmail {
				load = store.LoadByEmail
			}

			d, err := load(ctx, tc.username)
			tc.assert(t, d, err)
		})
	}
}

// TestIdentityStore_StoredRowTheConnectionCannotEncode loads an existing user
// from a UTF8 database through a handle that asks for the LATIN1 client
// encoding. The user's stored name has no LATIN1 form, so the server fails
// the row's output (SQLSTATE 22P05). The input did not cause that failure, so
// it is a failure and no lookup reports the user as not found.
//
// Its setup differs from the table above, which reads a LATIN1 database, so
// it is a table of its own.
func TestIdentityStore_StoredRowTheConnectionCannotEncode(t *testing.T) {
	t.Parallel()

	admin := test.RunTestPostgres(t)
	writeDSN, readDSN := storefix.UTF8ReadAsLatin1DSN(t, admin.DB, admin.DSN)

	ada, err := newIdentityStore(t, openPool(t, writeDSN)).Provision(t.Context(), "ada",
		identity.WithUserName("Ada \u20ac"), identity.WithUserRoles("user"))
	require.NoError(t, err)
	store := newIdentityStore(t, openPool(t, readDSN))

	type testCase struct {
		name   string
		load   func(ctx context.Context) (*identity.Details, error)
		assert func(t *testing.T, d *identity.Details, err error)
	}

	failure := func(t *testing.T, _ *identity.Details, err error) {
		require.Error(t, err)
		assert.NotErrorIs(t, err, identity.ErrUserNotFound)
	}

	cases := []testCase{
		{
			name: "a stored name the connection cannot encode is a failure, not a miss, by reference",
			load: func(ctx context.Context) (*identity.Details, error) {
				return store.LoadByUserID(ctx, ada.ID)
			},
			assert: failure,
		},
		{
			name: "a stored name the connection cannot encode is a failure, not a miss, by username",
			load: func(ctx context.Context) (*identity.Details, error) {
				return store.LoadByUsername(ctx, "ada")
			},
			assert: failure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d, err := tc.load(t.Context())
			tc.assert(t, d, err)
		})
	}
}

// nilOnCall is a generator that mints from the default generator and answers
// the nil identifier, with no error, on its n-th call (1-based).
func nilOnCall(t *testing.T, n int) *idgenmock.MockGenerator {
	t.Helper()

	var (
		mu    sync.Mutex
		calls int
	)
	g := idgenmock.NewMockGenerator(gomock.NewController(t))
	g.EXPECT().NewID().DoAndReturn(func() (id.ID, error) {
		mu.Lock()
		defer mu.Unlock()

		calls++
		if calls == n {
			return id.Nil, nil
		}

		return seedIDs.NewID()
	}).AnyTimes()

	return g
}

// conformanceFixture is the identity fixture the conformance suite runs on. It
// differs from identityFixture only in SeedRole, which also records each
// privilege's scope: a privilege seeded with none keeps the column's default,
// as a row written before scopes existed does.
type conformanceFixture struct{ *identityFixture }

func (f conformanceFixture) SeedRole(ctx context.Context, role string, p []*identity.ResourcePrivileges) error {
	if err := f.identityFixture.SeedRole(ctx, role, p); err != nil {
		return err
	}

	for _, rp := range p {
		if rp == nil {
			continue
		}
		for _, priv := range rp.Privileges {
			if priv.Scope == "" {
				continue
			}
			if _, err := f.q(ctx).Exec(ctx, `UPDATE scrty_resource_privileges SET scope = $5
WHERE role_name = $1 AND resource_group = $2 AND resource = $3 AND privilege = $4`,
				role, rp.Group, rp.Resource, priv.Name, string(priv.Scope)); err != nil {
				return err
			}
		}
	}

	return nil
}

// LoadByEmail is the store's, failing as FailUserLoads asks.
func (f *identityFixture) LoadByEmail(ctx context.Context, email string) (*identity.Details, error) {
	// An empty address is answered by the store before any query, so an
	// injected backend fault has nothing to reach.
	if email == "" {
		return f.IdentityStore.LoadByEmail(ctx, email)
	}
	if err := f.fault(&f.loadErr); err != nil {
		return nil, err
	}

	return f.IdentityStore.LoadByEmail(ctx, email)
}

// SeedEmail sets the user's email as the administration does: under the
// advisory lock of the address, the lock Provision takes, it refuses an address
// another live user holds as its email or username.
func (f *identityFixture) SeedEmail(ctx context.Context, username, email string, verifiedAt time.Time) error {
	return f.seedAtomically(ctx, func(q pgxstore.DBTX) error {
		rows, err := q.Query(ctx, pgschema.IdentifierLockKeys, []string{email})
		if err != nil {
			return err
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		for _, k := range keys {
			if _, err := q.Exec(ctx, pgschema.LockIdentifierKey, k); err != nil {
				return err
			}
		}

		var userID string
		err = q.QueryRow(ctx,
			`SELECT id::text FROM scrty_users WHERE username = $1 AND deleted_at IS NULL FOR UPDATE`, username).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ErrUserNotFound
		}
		if err != nil {
			return err
		}

		for _, check := range []string{pgschema.EmailHeldByLiveUser, pgschema.UsernameHeldByLiveUser} {
			var held bool
			if err := q.QueryRow(ctx, check, email, userID).Scan(&held); err != nil {
				return err
			}
			if held {
				return identity.ErrUserExists
			}
		}

		_, err = q.Exec(ctx, `UPDATE scrty_users SET email = $2, email_verified_at = $3 WHERE id = $1`,
			userID, email, nullTime(verifiedAt))
		if isUniqueViolation(err) {
			return identity.ErrUserExists
		}

		return err
	})
}

// SoftDelete deletes the user as the administration does: the row and its
// username stay, the email is cleared and the user is inactive.
func (f *identityFixture) SoftDelete(ctx context.Context, username string) error {
	tag, err := f.q(ctx).Exec(ctx, `UPDATE scrty_users
SET deleted_at = now(), active = false, email = NULL, email_verified_at = NULL
WHERE username = $1 AND deleted_at IS NULL`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}

	return nil
}

// seedAtomically runs fn in the test's transaction when ctx carries one,
// otherwise in a READ COMMITTED transaction of its own on the pool.
func (f *identityFixture) seedAtomically(ctx context.Context, fn func(q pgxstore.DBTX) error) error {
	if tx, ok := ctx.Value(seedTxKey{}).(pgx.Tx); ok {
		return fn(tx)
	}

	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// isUniqueViolation reports whether err is PostgreSQL's unique_violation.
func isUniqueViolation(err error) bool {
	var st interface{ SQLState() string }

	return errors.As(err, &st) && st.SQLState() == "23505"
}

var (
	_ identitytest.Fixture = conformanceFixture{}
	_ identity.EmailLoader = (*identityFixture)(nil)
)
