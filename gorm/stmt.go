package gorm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/seal"
)

// failed wraps err, from the statement of operation op, with the operation's
// name. It never maps err to a refusal or to absence.
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
	return fmt.Errorf("gorm: %s: the %s holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store",
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

// nullTs is t as stored in a nullable column: nil, NULL, for the zero time.
func nullTs(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := ts(t)

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

// errZeroID is the refusal of an insert of a record whose own identifier, the
// row's primary key and the caller's to mint, is zero.
func errZeroID(op, record string) error {
	return fmt.Errorf("gorm: %s: the %s id is zero", op, record)
}

// tsPtr is *t as stored in a nullable column: nil, NULL, for nil.
func tsPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := ts(*t)

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

// orNone is values, or an empty list for nil, so a key with no scopes is
// stored as an empty JSON array rather than null.
func orNone(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}
