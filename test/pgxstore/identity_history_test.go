package pgxstore_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	pgxstore "github.com/kartaladev/scrty/pgx"
	identitytest "github.com/kartaladev/scrty/test/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestIdentityStore_PasswordHistory runs the password-history part of the
// identity suite against the pgx store, its transaction attached with
// pgxstore.WithTx.
func TestIdentityStore_PasswordHistory(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)
	store := newIdentityStore(t, db.Pool)

	identitytest.RunPasswordHistory(t, func(*testing.T) identitytest.HistoryHarness {
		return &identityHistory{IdentityStore: store, pool: db.Pool}
	})
}

// identityHistory is the password-history harness over the identity store:
// Begin opens a transaction on the store's pool and attaches it with
// pgxstore.WithTx.
type identityHistory struct {
	*pgxstore.IdentityStore

	pool *pgxpool.Pool
}

func (h *identityHistory) Begin(ctx context.Context) (context.Context, func() error, func() error, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	// The suite rolls back once a case ends, when ctx may already be done.
	end := context.WithoutCancel(ctx)

	return pgxstore.WithTx(ctx, tx), func() error { return tx.Commit(end) }, func() error { return tx.Rollback(end) }, nil
}

var _ identitytest.HistoryHarness = (*identityHistory)(nil)

// TestIdentityStore_HistoryScenarios pins what only this adapter can show of
// password history: its order under a consumer generator, its clock, its
// handling of references it cannot parse, its errors, its savepoint inside a
// caller's transaction, and that no identity port call records history.
func TestIdentityStore_HistoryScenarios(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, pool *pgxpool.Pool)
	}

	h1, h2 := []byte("h1"), []byte("h2")

	cases := []testCase{
		{
			name: "entries read newest first under a descending generator",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(newDescendingIDs(0xfc)))
				user := newHistoryUser(t)

				require.NoError(t, s.RetirePassword(ctx, user, h1, 3))
				require.NoError(t, s.RetirePassword(ctx, user, h2, 3))

				got, err := s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h2, h1}, got, "order is the order of retiring, not of identifiers")
			},
		},
		{
			name: "retired_at comes from the store's clock",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				at := time.Date(2032, 3, 4, 5, 6, 7, 891011000, time.UTC)
				s := newIdentityStore(t, pool, pgxstore.WithClock(storefix.NewClock(at)))
				user := newHistoryUser(t)

				require.NoError(t, s.RetirePassword(ctx, user, h1, 3))

				var got time.Time
				require.NoError(t, pool.QueryRow(ctx,
					`SELECT retired_at FROM password_history WHERE user_id = $1`, string(user)).Scan(&got))
				assert.True(t, at.Truncate(time.Microsecond).Equal(got), "want %v, got %v", at, got)
			},
		},
		{
			name: "five updates naming a password record no history",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				d, err := s.Provision(ctx, "mirrored-password-user", identity.WithUserPassword([]byte("m0")))
				require.NoError(t, err)
				for _, hash := range []string{"m1", "m2", "m3", "m4", "m5"} {
					_, err := s.Update(ctx, "mirrored-password-user", identity.WithUserPassword([]byte(hash)))
					require.NoError(t, err)
				}

				assert.Zero(t, historyRows(ctx, t, pool, d.ID), "only the history port writes history")
				got, err := s.RecentPasswords(ctx, d.ID, 10)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name: "keeping fewer prunes to the new bound, and keeping more never restores",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				user := newHistoryUser(t)

				for _, hash := range []string{"k1", "k2", "k3", "k4"} {
					require.NoError(t, s.RetirePassword(ctx, user, []byte(hash), 3))
				}
				require.Equal(t, 3, historyRows(ctx, t, pool, user))

				require.NoError(t, s.RetirePassword(ctx, user, []byte("k5"), 1))
				assert.Equal(t, 1, historyRows(ctx, t, pool, user), "a smaller keep prunes on the next retire")

				require.NoError(t, s.RetirePassword(ctx, user, []byte("k6"), 5))
				got, err := s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("k6"), []byte("k5")}, got, "a larger keep never brings pruned rows back")
			},
		},
		{
			name: "a reference that is not canonical UUID text fails every call with fixed text",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				upper := identity.UserID("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
				refused := []byte("refused-reference-hash")

				for _, ref := range []identity.UserID{"not-a-uuid", upper, ""} {
					got, err := s.RecentPasswords(ctx, ref, 10)
					require.Error(t, err, "read %q", ref)
					assert.Nil(t, got, "a malformed reference is never an empty history")

					errs := []error{
						err,
						s.RetirePassword(ctx, ref, refused, 3),
						s.ForgetPasswords(ctx, ref),
					}
					for _, err := range errs {
						require.Error(t, err, "%q", ref)
						if ref != "" {
							assertNoneContains(t, err, string(ref))
						}
					}
				}

				var n int
				require.NoError(t, pool.QueryRow(ctx,
					`SELECT count(*) FROM password_history WHERE password = $1`, refused).Scan(&n))
				assert.Zero(t, n, "a refused retire writes nothing")
			},
		},
		{
			name: "a negative count or keep is refused, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				user := newHistoryUser(t)
				require.NoError(t, s.RetirePassword(ctx, user, h1, 3))

				got, err := s.RecentPasswords(ctx, user, -1)
				require.Error(t, err)
				assert.Nil(t, got)

				err = s.RetirePassword(ctx, user, h2, -1)
				require.Error(t, err)
				assertNoneContains(t, err, string(user), "h2")

				got, err = s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got, "a refused retire neither records nor prunes")
			},
		},
		{
			name: "reading zero entries returns none and no error",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				user := newHistoryUser(t)
				require.NoError(t, s.RetirePassword(ctx, user, h1, 3))

				got, err := s.RecentPasswords(ctx, user, 0)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name: "an unavailable table fails every call with no hash, no reference and no driver error",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				user := newHistoryUser(t)
				hash := []byte("$argon2id$v=19$history-secret-hash")

				// Each call gets its own transaction in which the table is
				// renamed: a shared transaction would abort on the first
				// failure (SQLSTATE 25P02), masking the missing-table error
				// (42P01) on every call after it.
				withGoneTable := func(fn func(txCtx context.Context)) {
					t.Helper()

					tx := beginTx(ctx, t, pool)
					defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
					_, err := tx.Exec(ctx, `ALTER TABLE password_history RENAME TO password_history_gone`)
					require.NoError(t, err)

					fn(pgxstore.WithTx(ctx, tx))
				}

				withGoneTable(func(txCtx context.Context) {
					got, err := s.RecentPasswords(txCtx, user, 10)
					assertHistoryCut(t, err, user, hash)
					assert.Contains(t, err.Error(), "42P01", "the text keeps the driver's SQLSTATE")
					assert.Nil(t, got, "a failed read is never an empty history")
				})

				withGoneTable(func(txCtx context.Context) {
					err := s.RetirePassword(txCtx, user, hash, 3)
					assertHistoryCut(t, err, user, hash)
					assert.Contains(t, err.Error(), "42P01", "the text keeps the driver's SQLSTATE")
				})

				withGoneTable(func(txCtx context.Context) {
					err := s.RetirePassword(txCtx, user, hash, 0)
					assertHistoryCut(t, err, user, hash)
					assert.Contains(t, err.Error(), "42P01", "the text keeps the driver's SQLSTATE")
				})

				withGoneTable(func(txCtx context.Context) {
					err := s.ForgetPasswords(txCtx, user)
					assertHistoryCut(t, err, user, hash)
					assert.Contains(t, err.Error(), "42P01", "the text keeps the driver's SQLSTATE")
				})
			},
		},
		{
			name: "a failed retire inside a caller's transaction leaves it usable",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				taken, err := seedIDs.NewID()
				require.NoError(t, err)
				colliding := newIdentityStore(t, pool, pgxstore.WithIDGenerator(fixedIDs{taken}))
				s := newIdentityStore(t, pool)
				owner, failing, other := newHistoryUser(t), newHistoryUser(t), newHistoryUser(t)
				hash := []byte("$argon2id$v=19$colliding-secret-hash")

				// The first retire takes the identifier; the one inside the
				// transaction reuses it, so PostgreSQL itself rejects the insert.
				require.NoError(t, colliding.RetirePassword(ctx, owner, h1, 3))

				tx := beginTx(ctx, t, pool)
				txCtx := pgxstore.WithTx(ctx, tx)

				require.NoError(t, s.RetirePassword(txCtx, failing, []byte("before"), 3))
				err = colliding.RetirePassword(txCtx, failing, hash, 3)
				assertHistoryCut(t, err, failing, hash)
				assert.Contains(t, err.Error(), "23505", "the text keeps the driver's SQLSTATE")

				require.NoError(t, s.RetirePassword(txCtx, other, h2, 3), "the caller's transaction stays usable")
				require.NoError(t, tx.Commit(ctx))

				got, err := s.RecentPasswords(ctx, failing, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("before")}, got, "the failed retire undid only its own writes")
				got, err = s.RecentPasswords(ctx, other, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h2}, got)
			},
		},
		{
			name: "a retire whose prune fails, outside a caller's transaction, keeps no new entry",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				user := newHistoryUser(t)
				require.NoError(t, s.RetirePassword(ctx, user, h1, 3))
				refuseHistoryDeletes(ctx, t, pool, user)

				require.Error(t, s.RetirePassword(ctx, user, h2, 1), "the prune is refused")

				got, err := s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got, "the insert rolled back with the refused prune")
			},
		},
		{
			name: "a retire whose prune fails, inside a caller's transaction, keeps no new entry and leaves it usable",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)
				user, other := newHistoryUser(t), newHistoryUser(t)
				require.NoError(t, s.RetirePassword(ctx, user, h1, 3))
				refuseHistoryDeletes(ctx, t, pool, user)

				tx := beginTx(ctx, t, pool)
				txCtx := pgxstore.WithTx(ctx, tx)
				require.Error(t, s.RetirePassword(txCtx, user, h2, 1), "the prune is refused")
				require.NoError(t, s.RetirePassword(txCtx, other, h2, 3), "the caller's transaction stays usable")
				require.NoError(t, tx.Commit(ctx))

				got, err := s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got, "the insert rolled back with the refused prune")
				got, err = s.RecentPasswords(ctx, other, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h2}, got, "the later write committed")
			},
		},
		{
			name: "history is forgotten with the user, and another user's is unchanged",
			assert: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				s := newIdentityStore(t, pool)

				gone, err := s.Provision(ctx, "history-deleted-user", identity.WithUserRoles("admin"))
				require.NoError(t, err)
				kept, err := s.Provision(ctx, "history-kept-user")
				require.NoError(t, err)
				for _, hash := range []string{"d1", "d2", "d3"} {
					require.NoError(t, s.RetirePassword(ctx, gone.ID, []byte(hash), 5))
				}
				for _, hash := range []string{"o1", "o2"} {
					require.NoError(t, s.RetirePassword(ctx, kept.ID, []byte(hash), 5))
				}

				// The consumer's user deletion: the user, the grants and the
				// history, in one transaction.
				tx := beginTx(ctx, t, pool)
				_, err = tx.Exec(ctx, `DELETE FROM assigned_roles WHERE user_id = $1`, string(gone.ID))
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, string(gone.ID))
				require.NoError(t, err)
				require.NoError(t, s.ForgetPasswords(pgxstore.WithTx(ctx, tx), gone.ID))
				require.NoError(t, tx.Commit(ctx))

				got, err := s.RecentPasswords(ctx, gone.ID, 10)
				require.NoError(t, err)
				assert.Empty(t, got)
				assert.Zero(t, historyRows(ctx, t, pool, gone.ID))

				got, err = s.RecentPasswords(ctx, kept.ID, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("o2"), []byte("o1")}, got)
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

// newHistoryUser is a user reference unique to the calling case. History
// needs no stored user: the tables declare no foreign keys.
func newHistoryUser(t *testing.T) identity.UserID {
	t.Helper()

	raw, err := seedIDs.NewID()
	require.NoError(t, err)

	return identity.UserID(raw.String())
}

// refuseHistoryDeletes installs, until t ends, a trigger that refuses to
// delete any password_history row of user, and only of user, so cases
// sharing the database are untouched.
func refuseHistoryDeletes(ctx context.Context, t *testing.T, pool *pgxpool.Pool, user identity.UserID) {
	t.Helper()

	name := "refuse_history_delete_" + strings.ReplaceAll(string(user), "-", "_")
	_, err := pool.Exec(ctx, `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.user_id = '`+string(user)+`' THEN
    RAISE EXCEPTION 'password history delete refused';
  END IF;
  RETURN OLD;
END $$`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CREATE TRIGGER `+name+` BEFORE DELETE ON password_history
FOR EACH ROW EXECUTE FUNCTION `+name+`()`)
	require.NoError(t, err)

	t.Cleanup(func() {
		end := context.WithoutCancel(ctx)
		_, err := pool.Exec(end, `DROP TRIGGER `+name+` ON password_history`)
		assert.NoError(t, err)
		_, err = pool.Exec(end, `DROP FUNCTION `+name+`()`)
		assert.NoError(t, err)
	})
}

// historyRows counts the stored history rows of user.
func historyRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, user identity.UserID) int {
	t.Helper()

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM password_history WHERE user_id = $1`, string(user)).Scan(&n))

	return n
}

// assertHistoryCut asserts err is a failure cut from the driver's error: the
// driver's value is not reachable, and no text in the chain carries the user
// reference or the hash, raw or as the hex PostgreSQL shows bytea in.
func assertHistoryCut(t *testing.T, err error, user identity.UserID, hash []byte) {
	t.Helper()
	require.Error(t, err)

	var pgErr *pgconn.PgError
	assert.False(t, errors.As(err, &pgErr), "the driver's error is reachable, detail %q", detailOf(pgErr))
	assertNoneContains(t, err, string(user), string(hash), hex.EncodeToString(hash))
}
