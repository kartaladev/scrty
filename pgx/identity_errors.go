package pgx

import (
	"context"
	"errors"
	"strconv"

	pgxv5 "github.com/jackc/pgx/v5"
)

// dbFailed wraps err, a failure of a database call the identity store made,
// like failed, but first cuts it from the driver's error value (detached).
// The identity store returns only this for a database failure: its tables
// hold usernames and password hashes, which a driver error's detail fields
// can carry. The security-state stores keep the driver error in the chain;
// their rows hold neither.
func dbFailed(op string, err error) error {
	return failed(op, detached(err))
}

// scanFailed wraps err, a failure of a Scan call the identity store made,
// like dbFailed. When err is a column-conversion failure (pgx.ScanArgError),
// its text is replaced with the column's index and name alone, dropping the
// conversion error pgx's own text would carry, which can quote the value;
// any other failure a Scan call can return (a cancelled context, a lost
// connection, a statement the server refused) is wrapped exactly as dbFailed
// would wrap it, since none of those carry a scanned value.
func scanFailed(op string, err error) error {
	var argErr pgxv5.ScanArgError
	if !errors.As(err, &argErr) {
		return dbFailed(op, err)
	}

	text := "scan error on column index " + strconv.Itoa(argErr.ColumnIndex) +
		", name " + strconv.Quote(argErr.FieldName)

	return failed(op, detachedText(err, text))
}

// detachedKept is the sentinels a detached error stays matchable against
// when the driver's error matched them. None carries a value.
var detachedKept = []error{
	context.Canceled,
	context.DeadlineExceeded,
	pgxv5.ErrTxClosed,
	pgxv5.ErrTxCommitRollback,
}

// detachedError is a database failure cut from the driver's error: fixed
// text and the sentinels of detachedKept it matched, nothing else.
type detachedError struct {
	text string
	kept []error
}

func (e *detachedError) Error() string   { return e.text }
func (e *detachedError) Unwrap() []error { return e.kept }

// sqlStater is a driver error that reports its SQLSTATE, as *pgconn.PgError
// does.
type sqlStater interface{ SQLState() string }

// detached is err with the driver's error value left out of its chain and
// its text replaced by the library's own: "database failure", and the
// SQLSTATE when err reports one through a SQLState method. It stays
// matchable against the context and pgx sentinels err matched, so a caller
// still tells a cancellation from a failure. The text of err itself, which
// for a PostgreSQL error is a primary message that can quote a value, never
// reaches it.
func detached(err error) error {
	text := "database failure"
	var st sqlStater
	if errors.As(err, &st) {
		if code := st.SQLState(); isSQLState(code) {
			text += " (SQLSTATE " + code + ")"
		}
	}

	return detachedText(err, text)
}

// isSQLState reports whether code has the shape of a SQLSTATE: five digits or
// upper-case letters. Anything else a consumer's error reports is left out.
func isSQLState(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, c := range []byte(code) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}

	return true
}

// detachedText is err with the driver's error value left out of its chain,
// like detached, but with text in place of detached's own. It still matches
// the context and pgx sentinels err matched, whatever text says.
func detachedText(err error, text string) error {
	var kept []error
	for _, s := range detachedKept {
		if errors.Is(err, s) {
			kept = append(kept, s)
		}
	}

	return &detachedError{text: text, kept: kept}
}
