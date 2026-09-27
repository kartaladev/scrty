package storefix

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// Exists reports whether query, a SELECT EXISTS over args, is true, read out
// of band.
func Exists(t *testing.T, raw *sql.DB, query string, args ...any) bool {
	t.Helper()

	return ExistsCtx(t.Context(), t, raw, query, args...)
}

// ExistsCtx is Exists under ctx.
func ExistsCtx(ctx context.Context, t *testing.T, raw *sql.DB, query string, args ...any) bool {
	t.Helper()

	var found bool
	require.NoError(t, raw.QueryRowContext(ctx, query, args...).Scan(&found))

	return found
}

// KeyRowExists selects whether the API key $1 is committed.
const KeyRowExists = `SELECT EXISTS (SELECT 1 FROM api_keys WHERE id = $1)`

// APIKeyPresent reports whether API key n (see APIKey) is committed, read out
// of band.
func APIKeyPresent(t *testing.T, raw *sql.DB, n int) bool {
	t.Helper()

	return Exists(t, raw, KeyRowExists, APIKey(n, "").ID)
}

// AttemptIDs returns the ids of username's stored failures, as text.
func AttemptIDs(ctx context.Context, t *testing.T, db *sql.DB, username string) []string {
	t.Helper()

	rows, err := db.QueryContext(ctx, `SELECT id::text FROM login_attempts WHERE username = $1`, username)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		ids = append(ids, s)
	}
	require.NoError(t, rows.Err())

	return ids
}

// SessionRow is the stored row of session sid as JSON, or "" when there is
// none.
func SessionRow(ctx context.Context, t *testing.T, db *sql.DB, sid string) string {
	t.Helper()

	var row sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT row_to_json(s)::text FROM sessions s WHERE id_digest = $1`, Digest(sid)).Scan(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)

	return row.String
}

// SecretColumn is user's MFA secret column as stored, read out of band.
func SecretColumn(ctx context.Context, t *testing.T, db *sql.DB, user identity.UserID) string {
	t.Helper()

	var s string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT secret FROM mfa_enrolments WHERE user_id = $1`, string(user)).Scan(&s))

	return s
}

// SetSecretColumn replaces user's MFA secret column out of band.
func SetSecretColumn(ctx context.Context, t *testing.T, db *sql.DB, user identity.UserID, secret string) {
	t.Helper()

	_, err := db.ExecContext(ctx, `UPDATE mfa_enrolments SET secret = $2 WHERE user_id = $1`, string(user), secret)
	require.NoError(t, err)
}

// PrivateColumn is kid's private_key column as stored, read out of band.
func PrivateColumn(ctx context.Context, t *testing.T, db *sql.DB, kid string) []byte {
	t.Helper()

	var b []byte
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT private_key FROM signing_keys WHERE kid = $1`, kid).Scan(&b))

	return b
}
