package pgxstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// failed wraps err, from operation op, with the adapter prefix and the
// operation's name: a statement's failure, or a refusal internal/storekit
// judged. It never maps err to a sentinel refusal or to absence.
func failed(op string, err error) error {
	return fmt.Errorf("pgxstore: %s: %w", op, err)
}

// exec runs query, one statement, on the handle ctx resolves to, and reports
// how many rows it affected.
func (c *config) exec(ctx context.Context, op, query string, args ...any) (int64, error) {
	q, _, err := c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}

	tag, err := q.Exec(ctx, query, args...)
	if err != nil {
		return 0, failed(op, err)
	}

	return tag.RowsAffected(), nil
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
	q, ambient, err := c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	if ambient {
		return nil
	}

	if _, err := q.Exec(ctx, query, args...); err != nil {
		return failed(op, err)
	}

	return nil
}

// query runs query, one statement returning rows, on the handle ctx resolves
// to, and calls scan for each row. Any error, scan's included, is wrapped
// with op; the rows are always closed.
func (c *config) query(ctx context.Context, op, query string, args []any, scan func(pgx.Rows) error) error {
	q, _, err := c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return failed(op, err)
	}
	defer rows.Close()

	for rows.Next() {
		if err := scan(rows); err != nil {
			return failed(op, err)
		}
	}
	if err := rows.Err(); err != nil {
		return failed(op, err)
	}

	return nil
}

// queryRow runs query, one statement, on the handle ctx resolves to, and
// scans its single row into dest. It returns pgx.ErrNoRows unwrapped when
// there is no row, so the caller maps absence to its own sentinel, and any
// other error wrapped with op.
func (c *config) queryRow(ctx context.Context, op, query string, args []any, dest ...any) error {
	q, _, err := c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	err = q.QueryRow(ctx, query, args...).Scan(dest...)
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
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
func nullTs(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}

	return pgtype.Timestamptz{Time: storekit.Time(t), Valid: true}
}

// errInfiniteTime is the error of a timestamp column holding 'infinity' or
// '-infinity', which no store writes and no contract time can hold. It names
// no value.
var errInfiniteTime = errors.New("a timestamp column held an infinite value")

// fromNull is a nullable column's time as the contracts hold it: the zero
// time for NULL, otherwise UTC. An infinite value, written out of band, is
// errInfiniteTime, never the zero time a caller would read as "not yet".
func fromNull(t pgtype.Timestamptz) (time.Time, error) {
	if !t.Valid {
		return time.Time{}, nil
	}
	if t.InfinityModifier != pgtype.Finite {
		return time.Time{}, errInfiniteTime
	}

	return t.Time.UTC(), nil
}

// nullTsPtr is *t as stored in a nullable column: NULL for nil.
func nullTsPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}

	return pgtype.Timestamptz{Time: storekit.Time(*t), Valid: true}
}

// timePtr is a nullable column's time as a pointer: nil for NULL, otherwise
// UTC. An infinite value is errInfiniteTime.
func timePtr(t pgtype.Timestamptz) (*time.Time, error) {
	u, err := fromNull(t)
	if err != nil || !t.Valid {
		return nil, err
	}

	return &u, nil
}

// uuidArg is v as a statement argument for a uuid column: its canonical text,
// which pgx encodes for a uuid parameter, as the database/sql stores send it.
func uuidArg(v id.ID) any { return v.String() }

// scanID is the identifier a uuid column held, scanned through pgtype.UUID. A
// NULL is an error: every uuid column the stores read is NOT NULL, and the
// zero identifier must never stand in for a missing one.
func scanID(u pgtype.UUID) (id.ID, error) {
	if !u.Valid {
		return id.Nil, errors.New("pgxstore: a uuid column held NULL")
	}

	return id.ID(u.Bytes), nil
}

// nullableID is the identifier a nullable uuid column held: id.Nil for NULL.
func nullableID(u pgtype.UUID) id.ID {
	if !u.Valid {
		return id.Nil
	}

	return id.ID(u.Bytes)
}

// nullID is v as bound to a nullable uuid column or compared with one: NULL
// for the nil identifier, otherwise uuidArg(v). The nil identifier sent as its
// text is the all-zero UUID, which "generation = $n" would match on a row
// stored with that value; NULL matches nothing.
func nullID(v id.ID) any {
	if v.IsZero() {
		return nil
	}

	return uuidArg(v)
}
