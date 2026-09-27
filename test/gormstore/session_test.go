package gormstore_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/storetest"
)

// sessionAAD is the additional data package session binds a provider ID
// token to, followed by the session identifier.
const sessionAAD = "scrty/session:external-id-token:"

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
	c := testCipher(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
			return newSessionStore(t, emptied(t, d, "sessions"), c, gormstore.WithClock(now))
		})
	})
}

func TestNewSessionStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := testCipher(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		cipher seal.Cipher
		opts   []gormstore.Option
		assert func(t *testing.T, s session.Store, err error)
	}

	refused := refusedConfig[session.Store]
	accepted := acceptedConfig[session.Store]

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name:   "it honours a clock and an id generator",
			db:     db,
			cipher: c,
			opts:   []gormstore.Option{gormstore.WithClock(time.Now), gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: accepted,
		},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{
			name:   "a typed-nil cipher is refused",
			db:     db,
			cipher: (*countingCipher)(nil),
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

// durableSession returns a federated session with identifier sid, holding a
// provider ID token, valid from now for an hour.
func durableSession(sid string, now time.Time) *session.Session {
	return &session.Session{
		ID:                sid,
		UserID:            identity.UserID("u-" + sid),
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(5 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		ExternalProvider:  "corp",
		ExternalIssuer:    "https://idp.example",
		ExternalSessionID: "sid-" + sid,
		ExternalIDToken:   "ID-TOKEN-" + sid,
		Data:              map[string]string{"tenant": "t-9"},
	}
}

// digest is the key a session is stored under.
func digest(sid string) []byte {
	sum := sha256.Sum256([]byte(sid))
	return sum[:]
}

// sealedSessions is the sealed-column suite's view of the session store,
// built by newWith over a cipher on db. The owner is the session identifier,
// digested exactly as the store itself digests it.
func sealedSessions(
	db *gormdb.DB, newWith func(t *testing.T, db *gormdb.DB, c seal.Cipher) session.Store,
) storetest.Sealed[session.Store] {
	return storetest.Sealed[session.Store]{
		Encoding: storetest.SealedBase64URL,
		Rotation: storetest.UnchangedOnRead,
		NewWithKeyring: func(t *testing.T, kr seal.Keyring) session.Store {
			c, err := seal.NewAEADCipher(kr)
			require.NoError(t, err)
			return newWith(t, db, c)
		},
		Put: func(ctx context.Context, s session.Store, owner string, secret []byte) error {
			sess := durableSession(owner, time.Now())
			sess.ExternalIDToken = string(secret)
			return s.Create(ctx, sess)
		},
		Get: func(ctx context.Context, s session.Store, owner string) ([]byte, bool, error) {
			sess, err := s.Load(ctx, owner)
			if errors.Is(err, session.ErrSessionNotFound) {
				return nil, false, nil
			}
			if err != nil {
				return nil, false, err
			}
			return []byte(sess.ExternalIDToken), true, nil
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			var col sql.NullString
			require.NoError(t, raw.QueryRowContext(t.Context(),
				`SELECT external_id_token FROM sessions WHERE id_digest = $1`, digest(owner)).Scan(&col))
			return []byte(col.String)
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE sessions
SET external_id_token = (SELECT external_id_token FROM sessions WHERE id_digest = $1) WHERE id_digest = $2`,
				digest(from), digest(to))
			require.NoError(t, err)
		},
	}
}

func TestSessionStore_SealedColumns(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := testCipher(t)
	h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) session.Store {
		return newSessionStore(t, db, c, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, sealedSessions(d.db,
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
		`SELECT row_to_json(s)::text FROM sessions s WHERE id_digest = $1`, digest(sid)).Scan(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)

	return row.String
}

// errorTexts is the text of err and of every error it wraps.
func errorTexts(err error) []string {
	if err == nil {
		return nil
	}

	texts := []string{err.Error()}
	switch u := err.(type) { //nolint:errorlint // walking the tree itself
	case interface{ Unwrap() error }:
		texts = append(texts, errorTexts(u.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			texts = append(texts, errorTexts(e)...)
		}
	}

	return texts
}

// assertNamesOnly requires some error in err's tree to name field, and none to
// carry any of values.
func assertNamesOnly(t *testing.T, err error, field string, values ...string) {
	t.Helper()

	texts := errorTexts(err)
	assert.True(t, slices.ContainsFunc(texts, func(text string) bool { return strings.Contains(text, field) }),
		"no error names %q: %q", field, texts)
	for _, text := range texts {
		for _, v := range values {
			assert.NotContains(t, text, v, "an error carries a value")
		}
	}
}

// countingCipher records the additional data every Seal and Open is given,
// and delegates to the default cipher.
type countingCipher struct {
	seal.Cipher

	mu    sync.Mutex
	seals []string
	opens []string
}

func (c *countingCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	c.mu.Lock()
	c.seals = append(c.seals, string(aad))
	c.mu.Unlock()

	return c.Cipher.Seal(plaintext, aad)
}

func (c *countingCipher) Open(sealed, aad []byte) ([]byte, string, error) {
	c.mu.Lock()
	c.opens = append(c.opens, string(aad))
	c.mu.Unlock()

	return c.Cipher.Open(sealed, aad)
}

func TestSessionStore_Durable(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	db, raw := d.db, d.conn.DB
	keys := newTestKeys(t)
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	at := func(clock time.Time) gormstore.Option { return gormstore.WithClock(func() time.Time { return clock }) }

	// store seals under both keys, k2 active, and reads the clock at now.
	store := newSessionStore(t, db, keys.rotated(t), at(now))

	// enrolmentMarked is sid's session, with the enrolment-origin marker set.
	enrolmentMarked := func(sid string) *session.Session {
		s := durableSession(sid, now)
		s.EnrolmentOriginDeadline = now.Add(12 * time.Hour)
		return s
	}
	// enrolmentGenerated is sid's session, having begun an enrolment.
	generation := id.MustParse("01926a4e-0000-7000-8000-00000000abcd")
	enrolmentGenerated := func(sid string) *session.Session {
		s := durableSession(sid, now)
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
			assertNamesOnly(t, err, field, append(values, sess.ID)...)
			assert.Empty(t, storedSession(ctx, t, raw, sess.ID), "a refused create wrote a row")
		}
	}
	// refusedSave creates a clean session sid, then saves marked over it,
	// which the store must refuse, naming field, and leave the row unchanged.
	refusedSave := func(marked *session.Session, field string, values ...string) func(t *testing.T, ctx context.Context) {
		return func(t *testing.T, ctx context.Context) {
			require.NoError(t, store.Create(ctx, durableSession(marked.ID, now)))
			before := storedSession(ctx, t, raw, marked.ID)

			marked.LastAccessedAt = now.Add(time.Minute)
			err := store.Save(ctx, marked)
			require.Error(t, err)
			assertNamesOnly(t, err, field, append(values, marked.ID)...)
			assert.Equal(t, before, storedSession(ctx, t, raw, marked.ID), "a refused save changed the row")
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
				sess := durableSession(sid, now)
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
				require.NoError(t, store.Create(ctx, durableSession(sid, now)))

				garbage := make([]byte, 64)
				_, err := rand.Read(garbage)
				require.NoError(t, err)
				_, err = raw.ExecContext(ctx, `UPDATE sessions SET external_id_token = $2 WHERE id_digest = $1`,
					digest(sid), base64.RawURLEncoding.EncodeToString(garbage))
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
				require.NoError(t, newSessionStore(t, db, keys.underK1(t), at(now)).Create(ctx, durableSession(sid, now)))
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
				counting := &countingCipher{Cipher: keys.rotated(t)}
				s := newSessionStore(t, db, counting, at(now))

				require.NoError(t, s.Create(ctx, durableSession(sid, now)))
				_, err := s.Load(ctx, sid)
				require.NoError(t, err)

				assert.Equal(t, []string{sessionAAD + sid}, counting.seals)
				assert.Equal(t, []string{sessionAAD + sid}, counting.opens)
			},
		},
		{
			name: "the consumer's clock drives expiry",
			assert: func(t *testing.T, ctx context.Context) {
				const sid = "sess-clock"
				require.NoError(t, store.Create(ctx, durableSession(sid, now)))

				_, err := store.Load(ctx, sid)
				require.NoError(t, err, "at 12:00 a session idle until 12:05 loads")

				later := newSessionStore(t, db, keys.rotated(t), at(now.Add(6*time.Minute)))
				_, err = later.Load(ctx, sid)
				require.ErrorIs(t, err, session.ErrSessionExpired, "at 12:06 it is expired")
			},
		},
		{
			name: "a load under a cancelled context fails with the cancellation, never as not found",
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context) {
				_, err := store.Load(ctx, "sess-never")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
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
