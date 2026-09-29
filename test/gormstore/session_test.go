package gormstore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newSessionStore builds the session store over db, failing t on a refusal.
func newSessionStore(t *testing.T, db *gormdb.DB, c seal.Cipher, opts ...gormstore.Option) session.Store {
	t.Helper()

	s, err := gormstore.NewSessionStore(db, c, opts...)
	require.NoError(t, err)

	return s
}

func TestSessionStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
			return newSessionStore(t, emptied(t, d, "sessions"), c, gormstore.WithClock(clk))
		})
	})
}

func TestNewSessionStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		cipher seal.Cipher
		opts   []gormstore.Option
		assert func(t *testing.T, s session.Store, err error)
	}

	refused := refusedConfig[session.Store]
	accepted := storefix.AcceptedConfig[session.Store]

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name:   "it honours a clock and an id generator",
			db:     db,
			cipher: c,
			opts:   []gormstore.Option{gormstore.WithClock(clock.System()), gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: accepted,
		},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{
			name:   "a typed-nil cipher is refused",
			db:     db,
			cipher: (*storefix.CountingCipher)(nil),
			assert: refused("the cipher is nil"),
		},
		{name: "a missing handle is refused", cipher: c, assert: refused("the database handle is nil")},
		{
			name:   "re-sealing on read does not apply to sessions",
			db:     db,
			cipher: c,
			opts:   []gormstore.Option{gormstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewSessionStore(tc.db, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestSessionStore_SealedColumns(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)
	h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) session.Store {
		return newSessionStore(t, db, c, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, storefix.SealedSessions(d.db,
			func(t *testing.T, db *gormdb.DB, c seal.Cipher) session.Store {
				return newSessionStore(t, db, c)
			}))
	})
}

// storedSession is the stored row of session sid as JSON, or "" when there is
// none.
func storedSession(ctx context.Context, t *testing.T, db *sql.DB, sid string) string {
	t.Helper()

	var row sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT row_to_json(s)::text FROM sessions s WHERE id_digest = $1`, storefix.Digest(sid)).Scan(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)

	return row.String
}

func TestSessionStore_Durable(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	db, raw := d.db, d.conn.DB
	keys := storefix.NewKeys(t)
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	at := func(clock time.Time) gormstore.Option { return gormstore.WithClock(storefix.NewClock(clock)) }

	// store seals under both keys, k2 active, and reads the clock at now.
	store := newSessionStore(t, db, keys.Rotated(t), at(now))

	// enrolmentMarked is sid's session, marked enrolment-only and having
	// begun an enrolment on generation.
	generation := id.MustParse("01926a4e-0000-7000-8000-00000000abcd")
	enrolmentMarked := func(sid string) *session.Session {
		s := storefix.DurableSession(sid, now)
		s.MFA = session.MFAEnrolmentPending
		s.EnrolmentOriginDeadline = now.Add(12 * time.Hour)
		s.EnrolmentGeneration = generation
		return s
	}
	// enrolmentColumns reads sid's two enrolment columns out of band.
	enrolmentColumns := func(ctx context.Context, t *testing.T, sid string) (sql.NullTime, sql.NullString) {
		t.Helper()
		var (
			deadline sql.NullTime
			gen      sql.NullString
		)
		require.NoError(t, raw.QueryRowContext(ctx,
			`SELECT enrolment_origin_deadline, enrolment_generation::text FROM sessions WHERE id_digest = $1`,
			storefix.Digest(sid)).Scan(&deadline, &gen))
		return deadline, gen
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
				require.NoError(t, raw.QueryRowContext(ctx,
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
				_, err = raw.ExecContext(ctx, `UPDATE sessions SET external_id_token = $2 WHERE id_digest = $1`,
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
				require.NoError(t, newSessionStore(t, db, keys.UnderK1(t), at(now)).Create(ctx, storefix.DurableSession(sid, now)))
				before := storedSession(ctx, t, raw, sid)

				got, err := store.Load(ctx, sid)
				require.NoError(t, err)
				assert.Equal(t, "ID-TOKEN-"+sid, got.ExternalIDToken)
				assert.Equal(t, before, storedSession(ctx, t, raw, sid), "the load rewrote the row")

				require.NoError(t, store.Delete(ctx, sid))
				_, err = store.Load(ctx, sid)
				require.ErrorIs(t, err, session.ErrSessionNotFound)
				assert.Empty(t, storedSession(ctx, t, raw, sid))
			},
		},
		{
			name: "the consumer's cipher seals and opens with the session's additional data",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-counted"
				counting := &storefix.CountingCipher{Cipher: keys.Rotated(t)}
				s := newSessionStore(t, db, counting, at(now))

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

				later := newSessionStore(t, db, keys.Rotated(t), at(now.Add(6*time.Minute)))
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
			name: "a marked session keeps its marker and generation in their columns",
			assert: func(t *testing.T, ctx context.Context) {
				require.NoError(t, store.Create(ctx, enrolmentMarked("sess-marked")))

				deadline, gen := enrolmentColumns(ctx, t, "sess-marked")
				require.True(t, deadline.Valid, "the marker was not stored")
				assert.True(t, deadline.Time.Equal(now.Add(12*time.Hour)))
				assert.Equal(t, sql.NullString{String: generation.String(), Valid: true}, gen)
			},
		},
		{
			name: "an unmarked session, or one whose marker is cleared, stores NULL in both columns",
			assert: func(t *testing.T, ctx context.Context) {
				require.NoError(t, store.Create(ctx, storefix.DurableSession("sess-unmarked", now)))
				deadline, gen := enrolmentColumns(ctx, t, "sess-unmarked")
				assert.False(t, deadline.Valid, "an unmarked session stored a marker")
				assert.False(t, gen.Valid, "a session with no enrolment stored a generation")

				marked := enrolmentMarked("sess-cleared")
				require.NoError(t, store.Create(ctx, marked))
				marked.MFA, marked.EnrolmentOriginDeadline, marked.EnrolmentGeneration = session.MFASatisfied, time.Time{}, id.Nil
				require.NoError(t, store.Save(ctx, marked))
				deadline, gen = enrolmentColumns(ctx, t, "sess-cleared")
				assert.False(t, deadline.Valid, "a cleared marker is still stored")
				assert.False(t, gen.Valid, "a cleared generation is still stored")
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
			tc.assert(t, ctx)
		})
	}
}
