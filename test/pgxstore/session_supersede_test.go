package pgxstore_test

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// supersedeAt is the instant the supersession cases run at.
var supersedeAt = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// supersessionOf is the supersession of old by a new session named
// successorID in old's family, observing observed, at supersedeAt.
func supersessionOf(old *session.Session, successorID string, observed []byte) session.Supersession {
	successor := storefix.DurableSession(successorID, supersedeAt)
	successor.UserID = old.UserID
	successor.FamilyID = old.FamilyID
	successor.FamilyCreatedAt = old.FamilyCreatedAt

	return session.Supersession{
		Old:               old.ID,
		ObservedSuccessor: observed,
		AcceptUntil:       supersedeAt.Add(30 * time.Second),
		RetainUntil:       supersedeAt.Add(time.Hour),
		Successor:         successor,
		Now:               supersedeAt,
	}
}

// successorIsNull reports whether the stored successor_digest of session sid
// is SQL NULL, and whether the row exists.
func successorIsNull(ctx context.Context, t *testing.T, db *sql.DB, sid string) (isNull, found bool) {
	t.Helper()

	err := db.QueryRowContext(ctx,
		`SELECT successor_digest IS NULL FROM sessions WHERE id_digest = $1`, storefix.Digest(sid)).Scan(&isNull)
	if err == sql.ErrNoRows {
		return false, false
	}
	require.NoError(t, err)

	return isNull, true
}

func TestSessionStore_SupersedeObservingNoSuccessor(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	db := conn.DB
	store := newSessionStore(t, conn.Pool, storefix.TestCipher(t))

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, sid string)
	}

	cases := []testCase{
		{
			name: "a live record's successor digest is NULL, and a supersession observing none succeeds",
			assert: func(t *testing.T, ctx context.Context, sid string) {
				old := storefix.DurableSession(sid, supersedeAt)
				require.NoError(t, store.Create(ctx, old))
				isNull, _ := successorIsNull(ctx, t, db, sid)
				assert.True(t, isNull, "a live record's successor_digest is not SQL NULL")

				require.NoError(t, store.Supersede(ctx, supersessionOf(old, sid+"-next", nil)))

				isNull, _ = successorIsNull(ctx, t, db, sid)
				assert.False(t, isNull, "the superseded record records its successor")
				isNull, found := successorIsNull(ctx, t, db, sid+"-next")
				require.True(t, found)
				assert.True(t, isNull, "the successor, live, has a NULL successor_digest")
			},
		},
		{
			name: "an empty observation reads as none",
			assert: func(t *testing.T, ctx context.Context, sid string) {
				old := storefix.DurableSession(sid, supersedeAt)
				require.NoError(t, store.Create(ctx, old))

				require.NoError(t, store.Supersede(ctx, supersessionOf(old, sid+"-next", []byte{})))
			},
		},
		{
			name: "a supersession observing none is refused on a record already superseded",
			assert: func(t *testing.T, ctx context.Context, sid string) {
				old := storefix.DurableSession(sid, supersedeAt)
				require.NoError(t, store.Create(ctx, old))
				require.NoError(t, store.Supersede(ctx, supersessionOf(old, sid+"-next", nil)))

				for _, observed := range [][]byte{nil, {}} {
					err := store.Supersede(ctx, supersessionOf(old, sid+"-late", observed))
					require.ErrorIs(t, err, session.ErrRenewalConflict)
				}
				_, found := successorIsNull(ctx, t, db, sid+"-late")
				assert.False(t, found, "a refused supersession wrote its successor")
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, t.Context(), "sess-nosucc-"+strconv.Itoa(i))
		})
	}
}
