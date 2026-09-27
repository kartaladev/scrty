package gorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/storekit"
)

// failed wraps err, from operation op, with the adapter prefix and the
// operation's name: a statement's failure, or a refusal internal/storekit
// judged. It never maps err to a sentinel refusal or to absence.
func failed(op string, err error) error {
	return fmt.Errorf("gorm: %s: %w", op, err)
}

// deleteWhere runs one DELETE of the rows of model T matching query and args,
// on the handle ctx resolves to, and reports how many it removed.
func deleteWhere[T any](ctx context.Context, c *config, op, query string, args ...any) (int, error) {
	q, _, err := c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	res := q.Where(query, args...).Delete(new(T))
	if res.Error != nil {
		return 0, failed(op, res.Error)
	}

	return int(res.RowsAffected), nil
}

// nullTs is t as stored in a nullable column: nil, NULL, for the zero time.
func nullTs(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := storekit.Time(t)

	return &u
}

// fromNull is a nullable column's time as the contracts hold it: the zero
// time for NULL, otherwise UTC.
func fromNull(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}

	return t.UTC()
}

// takeWhere runs one SELECT of the row of model T matching query and args, on
// the handle ctx resolves to. It reports false, with no error, when there is
// none: gorm.ErrRecordNotFound is the only absence, and every other failure
// is returned wrapped, never as absence.
func takeWhere[T any](ctx context.Context, c *config, op, query string, args ...any) (T, bool, error) {
	var row T
	q, _, err := c.conn(ctx)
	if err != nil {
		return row, false, failed(op, err)
	}
	err = q.Where(query, args...).Take(&row).Error
	if errors.Is(err, gormdb.ErrRecordNotFound) {
		return row, false, nil
	}
	if err != nil {
		return row, false, failed(op, err)
	}

	return row, true, nil
}

// updateWhere runs one UPDATE of the rows of model T matching query and args,
// setting values, on the handle ctx resolves to, and reports how many it
// changed. A caller whose zero is a refusal maps it; a failed statement is
// returned wrapped, never as a refusal.
func updateWhere[T any](ctx context.Context, c *config, op string, values map[string]any, query string, args ...any) (int64, error) {
	q, _, err := c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}

	return update[T](q, op, values, query, args...)
}

// updateOrRefuse is updateWhere for an operation whose zero rows affected is
// refusal.
func updateOrRefuse[T any](ctx context.Context, c *config, op string, refusal error, values map[string]any, query string, args ...any) error {
	n, err := updateWhere[T](ctx, c, op, values, query, args...)
	if err != nil {
		return err
	}
	if n == 0 {
		return refusal
	}

	return nil
}

// resealWhere is the conditional re-seal write of a sealed store: one UPDATE
// of the rows of model T matching query and args, setting values, run only
// outside a caller's transaction. Inside one it runs nothing: the re-seal is a
// best-effort write whose failure is discarded, and a failed statement would
// abort the caller's transaction.
func resealWhere[T any](ctx context.Context, c *config, op string, values map[string]any, query string, args ...any) error {
	q, ambient, err := c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	if ambient {
		return nil
	}
	_, err = update[T](q, op, values, query, args...)

	return err
}

// update runs one UPDATE of the rows of model T matching query and args,
// setting values, on q, and reports how many it changed.
func update[T any](q *gormdb.DB, op string, values map[string]any, query string, args ...any) (int64, error) {
	res := q.Model(new(T)).Where(query, args...).Updates(values)
	if res.Error != nil {
		return 0, failed(op, res.Error)
	}

	return res.RowsAffected, nil
}

// tsPtr is *t as stored in a nullable column: nil, NULL, for nil.
func tsPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := storekit.Time(*t)

	return &u
}

// utcPtr is a nullable column's time as the contracts hold it: nil for NULL,
// otherwise UTC.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()

	return &u
}
