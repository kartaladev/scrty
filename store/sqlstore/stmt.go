package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/internal/storekit"
)

// failed wraps err, from operation op, with the adapter prefix and the
// operation's name: a statement's failure, or a refusal internal/storekit
// judged. It never maps err to a sentinel refusal or to absence.
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

// nullTs is t as stored in a nullable column: NULL for the zero time.
func nullTs(t time.Time) any {
	if t.IsZero() {
		return nil
	}

	return storekit.Time(t)
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

	return storekit.Time(*t)
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
