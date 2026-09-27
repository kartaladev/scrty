package pgxstore_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newSessionStore builds the session store over pool, failing t on a refusal.
func newSessionStore(t *testing.T, pool *pgxpool.Pool, c seal.Cipher, opts ...pgxstore.Option) session.Store {
	t.Helper()

	s, err := pgxstore.NewSessionStore(pool, c, opts...)
	require.NoError(t, err)

	return s
}

func TestSessionStore(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	c := storefix.TestCipher(t)

	t.Run("pgx", func(t *testing.T) {
		storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
			return newSessionStore(t, emptied(t, db, "sessions"), c, pgxstore.WithClock(now))
		})
	})
}

func TestNewSessionStore(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		pool   *pgxpool.Pool
		cipher seal.Cipher
		opts   []pgxstore.Option
		assert func(t *testing.T, s session.Store, err error)
	}

	refused := refusedConfig[session.Store]
	accepted := storefix.AcceptedConfig[session.Store]

	cases := []testCase{
		{name: "a pool and a cipher are all it needs", pool: pool, cipher: c, assert: accepted},
		{
			name:   "it honours a clock and an id generator",
			pool:   pool,
			cipher: c,
			opts:   []pgxstore.Option{pgxstore.WithClock(time.Now), pgxstore.WithIDGenerator(id.NewV7Generator())},
			assert: accepted,
		},
		{name: "a missing cipher is refused", pool: pool, assert: refused("the cipher is nil")},
		{
			name:   "a typed-nil cipher is refused",
			pool:   pool,
			cipher: (*storefix.CountingCipher)(nil),
			assert: refused("the cipher is nil"),
		},
		{name: "a missing pool is refused", cipher: c, assert: refused("the pool is nil")},
		{
			name:   "a nil option is refused",
			pool:   pool,
			cipher: c,
			opts:   []pgxstore.Option{nil},
			assert: refused("an option is nil"),
		},
		{
			name:   "re-sealing on read does not apply to sessions",
			pool:   pool,
			cipher: c,
			opts:   []pgxstore.Option{pgxstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := pgxstore.NewSessionStore(tc.pool, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestSessionStore_SealedColumns(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	c := storefix.TestCipher(t)
	h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
		return newSessionStore(t, pool, c, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, storefix.SealedSessions(db.Pool,
			func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) session.Store {
				return newSessionStore(t, pool, c)
			}))
	})
}

func TestSessionStore_Durable(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	db, pool := conn.DB, conn.Pool
	keys := storefix.NewKeys(t)
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	at := func(clock time.Time) pgxstore.Option { return pgxstore.WithClock(func() time.Time { return clock }) }

	// store seals under both keys, k2 active, and reads the clock at now.
	store := newSessionStore(t, pool, keys.Rotated(t), at(now))

	// enrolmentMarked is sid's session, with the enrolment-origin marker set.
	enrolmentMarked := func(sid string) *session.Session {
		s := storefix.DurableSession(sid, now)
		s.EnrolmentOriginDeadline = now.Add(12 * time.Hour)
		return s
	}
	// enrolmentGenerated is sid's session, having begun an enrolment.
	generation := id.MustParse("01926a4e-0000-7000-8000-00000000abcd")
	enrolmentGenerated := func(sid string) *session.Session {
		s := storefix.DurableSession(sid, now)
		s.EnrolmentGeneration = generation
		return s
	}
	const markerField, generationField = "enrolment-origin marker", "enrolment generation"
	markerValue := now.Add(12 * time.Hour).Format(time.RFC3339)

	// refusedCreate creates sess, which the store must refuse, naming field,
	// and write nothing.
	refusedCreate := func(sess *session.Session, field string, values ...string) func(t *testing.T, ctx context.Context) {
		return func(t *testing.T, ctx context.Context) {
			err := store.Create(ctx, sess)
			require.Error(t, err)
			storefix.AssertNamesOnly(t, err, field, append(values, sess.ID)...)
			assert.Empty(t, storefix.SessionRow(ctx, t, db, sess.ID), "a refused create wrote a row")
		}
	}
	// refusedSave creates a clean session sid, then saves marked over it,
	// which the store must refuse, naming field, and leave the row unchanged.
	refusedSave := func(marked *session.Session, field string, values ...string) func(t *testing.T, ctx context.Context) {
		return func(t *testing.T, ctx context.Context) {
			require.NoError(t, store.Create(ctx, storefix.DurableSession(marked.ID, now)))
			before := storefix.SessionRow(ctx, t, db, marked.ID)

			marked.LastAccessedAt = now.Add(time.Minute)
			err := store.Save(ctx, marked)
			require.Error(t, err)
			storefix.AssertNamesOnly(t, err, field, append(values, marked.ID)...)
			assert.Equal(t, before, storefix.SessionRow(ctx, t, db, marked.ID), "a refused save changed the row")
		}
	}

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context)
	}

	cases := []testCase{
		{
			name: "session identifiers are never stored",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "SESSION-SENTINEL"
				sess := storefix.DurableSession(sid, now)
				// Only the identifier carries the sentinel.
				sess.UserID, sess.ExternalSessionID, sess.ExternalIDToken = "u-sentinel", "sid-sentinel", "token"
				require.NoError(t, store.Create(ctx, sess))

				var table string
				require.NoError(t, db.QueryRowContext(ctx,
					`SELECT string_agg(row_to_json(s)::text, ',') FROM sessions s`).Scan(&table))
				assert.NotContains(t, table, sid, "a column holds the session identifier")

				got, err := store.Load(ctx, sid)
				require.NoError(t, err)
				assert.Equal(t, sid, got.ID)
				assert.Equal(t, "token", got.ExternalIDToken)
			},
		},
		{
			name: "a session with an unreadable ID token is unreadable, not missing",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-tampered"
				require.NoError(t, store.Create(ctx, storefix.DurableSession(sid, now)))

				garbage := make([]byte, 64)
				_, err := rand.Read(garbage)
				require.NoError(t, err)
				_, err = db.ExecContext(ctx, `UPDATE sessions SET external_id_token = $2 WHERE id_digest = $1`,
					storefix.Digest(sid), base64.RawURLEncoding.EncodeToString(garbage))
				require.NoError(t, err)

				got, err := store.Load(ctx, sid)
				require.ErrorIs(t, err, session.ErrSessionUnreadable)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name: "sessions are not rewritten on read, and stay deleted",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-retired-key"
				require.NoError(t, newSessionStore(t, pool, keys.UnderK1(t), at(now)).Create(ctx, storefix.DurableSession(sid, now)))
				before := storefix.SessionRow(ctx, t, db, sid)

				got, err := store.Load(ctx, sid)
				require.NoError(t, err)
				assert.Equal(t, "ID-TOKEN-"+sid, got.ExternalIDToken)
				assert.Equal(t, before, storefix.SessionRow(ctx, t, db, sid), "the load rewrote the row")

				require.NoError(t, store.Delete(ctx, sid))
				_, err = store.Load(ctx, sid)
				require.ErrorIs(t, err, session.ErrSessionNotFound)
				assert.Empty(t, storefix.SessionRow(ctx, t, db, sid))
			},
		},
		{
			name: "the consumer's cipher seals and opens with the session's additional data",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-counted"
				counting := &storefix.CountingCipher{Cipher: keys.Rotated(t)}
				s := newSessionStore(t, pool, counting, at(now))

				require.NoError(t, s.Create(ctx, storefix.DurableSession(sid, now)))
				_, err := s.Load(ctx, sid)
				require.NoError(t, err)

				assert.Equal(t, []string{storefix.SessionAAD + sid}, counting.Seals())
				assert.Equal(t, []string{storefix.SessionAAD + sid}, counting.Opens())
			},
		},
		{
			name: "the consumer's clock drives expiry",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-clock"
				require.NoError(t, store.Create(ctx, storefix.DurableSession(sid, now)))

				_, err := store.Load(ctx, sid)
				require.NoError(t, err, "at 12:00 a session idle until 12:05 loads")

				later := newSessionStore(t, pool, keys.Rotated(t), at(now.Add(6*time.Minute)))
				_, err = later.Load(ctx, sid)
				require.ErrorIs(t, err, session.ErrSessionExpired, "at 12:06 it is expired")
			},
		},
		{
			name: "a load under a cancelled context fails with the cancellation, never as not found",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context) {
				_, err := store.Load(ctx, "sess-never")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
			},
		},
		{
			name: "a session whose MFA satisfaction time is infinite is an error, never unsatisfied",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-infinite-mfa"
				require.NoError(t, store.Create(ctx, storefix.DurableSession(sid, now)))
				_, err := db.ExecContext(ctx,
					`UPDATE sessions SET mfa_satisfied_at = 'infinity' WHERE id_digest = $1`, storefix.Digest(sid))
				require.NoError(t, err)

				got, err := store.Load(ctx, sid)
				require.Error(t, err, "an infinite satisfaction time loaded as %v", got)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name:   "a create carrying the enrolment-origin marker is refused and writes nothing",
			assert: refusedCreate(enrolmentMarked("sess-create-marker"), markerField, markerValue),
		},
		{
			name:   "a create carrying an enrolment generation is refused and writes nothing",
			assert: refusedCreate(enrolmentGenerated("sess-create-generation"), generationField, generation.String()),
		},
		{
			name:   "a save carrying the enrolment-origin marker is refused and leaves the row unchanged",
			assert: refusedSave(enrolmentMarked("sess-save-marker"), markerField, markerValue),
		},
		{
			name:   "a save carrying an enrolment generation is refused and leaves the row unchanged",
			assert: refusedSave(enrolmentGenerated("sess-save-generation"), generationField, generation.String()),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx)
		})
	}
}
