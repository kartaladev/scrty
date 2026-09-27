package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/seal"
)

// failed wraps err, from the statement of operation op, with the operation's
// name. It never maps err to a refusal or to absence.
func failed(op string, err error) error {
	return fmt.Errorf("sqlstore: %s: %w", op, err)
}

// exec runs query, one statement, on the handle ctx resolves to, and reports
// how many rows it affected.
func (c *config) exec(ctx context.Context, op, query string, args ...any) (int64, error) {
	q, _, _, err := c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}

	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, failed(op, err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, failed(op, err)
	}

	return n, nil
}

// execOrRefuse runs query like exec, and returns refusal when it affected no
// row: the single conditional write whose condition failing is the store's
// refusal.
func (c *config) execOrRefuse(ctx context.Context, op string, refusal error, query string, args ...any) error {
	n, err := c.exec(ctx, op, query, args...)
	if err != nil {
		return err
	}
	if n == 0 {
		return refusal
	}

	return nil
}

// execOutsideTx runs query like exec, but only outside a caller's transaction:
// inside one it runs nothing and returns nil. It is for the best-effort
// writes (re-sealing on read) whose error the caller discards, since a failed
// statement would abort the caller's transaction.
func (c *config) execOutsideTx(ctx context.Context, op, query string, args ...any) error {
	q, _, ambient, err := c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	if ambient {
		return nil
	}

	if _, err := q.ExecContext(ctx, query, args...); err != nil {
		return failed(op, err)
	}

	return nil
}

// queryRow runs query, one statement, on the handle ctx resolves to, and
// scans its single row into dest. It returns sql.ErrNoRows unwrapped when
// there is no row, so the caller maps absence to its own sentinel, and any
// other error wrapped with op.
func (c *config) queryRow(ctx context.Context, op, query string, args []any, dest ...any) error {
	q, _, _, err := c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	err = q.QueryRowContext(ctx, query, args...).Scan(dest...)
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return err
	}

	return failed(op, err)
}

// count runs a count(*) query and returns its result as an int.
func (c *config) count(ctx context.Context, op, query string, args ...any) (int, error) {
	var n int64
	if err := c.queryRow(ctx, op, query, args, &n); err != nil {
		return 0, err
	}

	return int(n), nil
}

// storable reports whether PostgreSQL text can hold every one of values: none
// holds a NUL byte, and each is valid UTF-8. A value that fails is refused by
// the writes, never altered; a lookup by one matches nothing, since no such
// value can have been stored.
func storable(values ...string) bool {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 || !utf8.ValidString(v) {
			return false
		}
	}

	return true
}

// textField is one text value a write stores, and the name its refusal gives
// it.
type textField struct{ name, value string }

// checkStorable refuses a write of op when one of fields holds text
// PostgreSQL cannot store, naming the first such field and never its value.
func checkStorable(op string, fields ...textField) error {
	for _, f := range fields {
		if !storable(f.value) {
			return errUnstorable(op, f.name)
		}
	}

	return nil
}

// errUnstorable is the refusal of a write handed text PostgreSQL cannot hold.
// It names the field and never the value.
func errUnstorable(op, field string) error {
	return fmt.Errorf("sqlstore: %s: the %s holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store",
		op, field)
}

// requireCipher is the construction check of a store with sealed columns: a
// nil cipher, typed nil included, is a configuration error.
func requireCipher(c seal.Cipher) error {
	if nilcheck.IsNil(c) {
		return fmt.Errorf("%w: the cipher is nil", ErrConfig)
	}

	return nil
}

// orEmpty is b, or an empty value for nil: the byte columns are NOT NULL, and
// a store persists what it is given rather than refusing an absent value.
func orEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}

	return b
}

// ts is t as stored: UTC, truncated to the microsecond PostgreSQL keeps.
// Truncating here, rather than leaving it to the driver, makes the stored
// value the same whichever way the driver sends it (PostgreSQL rounds text
// input).
func ts(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

// nullTs is t as stored in a nullable column: NULL for the zero time.
func nullTs(t time.Time) any {
	if t.IsZero() {
		return nil
	}

	return ts(t)
}

// fromNull is a nullable column's time as the contracts hold it: the zero
// time for NULL, otherwise UTC.
func fromNull(t sql.NullTime) time.Time {
	if !t.Valid {
		return time.Time{}
	}

	return t.Time.UTC()
}

// nullTsPtr is *t as stored in a nullable column: NULL for nil.
func nullTsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}

	return ts(*t)
}

// timePtr is a nullable column's time as a pointer: nil for NULL, otherwise
// UTC.
func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()

	return &u
}

// orNone is values, or an empty list for nil, so a JSON array column never
// holds null.
func orNone(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}
