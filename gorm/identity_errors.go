package gorm

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
)

// dbFailed wraps err, a failure of a database call the identity store made,
// like failed, but first cuts it from the driver's error value (detached).
// The identity store returns only this for a database failure: its tables
// hold usernames and password hashes, which a driver error's detail fields
// can carry, and gorm hands the driver's error back as it is. The
// security-state stores keep the driver error in the chain; their rows hold
// neither.
func dbFailed(op string, err error) error {
	return failed(op, detached(err))
}

// scanColumnErr matches the prefix database/sql's Rows.Scan gives a
// column-conversion failure: "sql: Scan error on column index N, name "col":
// ...". The text after that colon can quote the offending value, the only
// place a Scan call's error text can carry one. database/sql quotes the name
// with %q, so a quote inside it arrives backslash-escaped; the second group
// spans such escapes and captures the quoted name, quotes included, ready to
// reuse as it stands.
var scanColumnErr = regexp.MustCompile(`^sql: Scan error on column index (\d+), name ("(?:[^"\\]|\\.)*"):`)

// scanFailed wraps err, a failure of a Scan call the identity store made,
// like dbFailed. When err is a database/sql column-conversion failure, its
// text is replaced with the column's index and name alone, dropping the value
// database/sql's own error text would otherwise quote; any other failure a
// Scan call can return (a canceled context, a lost connection) is wrapped
// exactly as dbFailed would wrap it, since none of those carry a scanned
// value.
func scanFailed(op string, err error) error {
	// The text is parsed, never returned: database/sql writes this prefix in
	// a fixed format, and only the column index and the column name, which
	// is the library's own statement's, are taken from it.
	m := scanColumnErr.FindStringSubmatch(err.Error()) //nolint:forbidigo // fixed database/sql format; only the index and library-owned column name are kept
	if m == nil {
		return dbFailed(op, err)
	}

	text := "scan error on column index " + m[1] + ", name " + m[2]

	return failed(op, detachedText(err, text))
}

// detachedKept is the sentinels a detached error stays matchable against when
// the driver's error matched them. None carries a value.
var detachedKept = []error{context.Canceled, context.DeadlineExceeded, sql.ErrTxDone, sql.ErrConnDone}

// detachedError is a database failure cut from the driver's error: fixed
// text and the sentinels of detachedKept it matched, nothing else.
type detachedError struct {
	text string
	kept []error
}

func (e *detachedError) Error() string   { return e.text }
func (e *detachedError) Unwrap() []error { return e.kept }

// sqlStater is the method PostgreSQL drivers' errors report their SQLSTATE
// through: pgconn.PgError and lib/pq's Error both provide it.
type sqlStater interface{ SQLState() string }

// detached is err with the driver's error value left out of its chain and
// its text replaced with the library's own: "database failure", followed by
// the SQLSTATE when err is or wraps an error reporting one through a
// SQLState method. The driver's message is never kept, since a PostgreSQL
// primary message can quote a value, and neither is any other text of err's
// chain, gorm's own included. It stays matchable against the context and
// database/sql sentinels err matched, so a caller still tells a cancellation
// from a failure.
func detached(err error) error {
	text := "database failure"

	var st sqlStater
	if errors.As(err, &st) {
		if code := st.SQLState(); validSQLState(code) {
			text += " (SQLSTATE " + code + ")"
		}
	}

	return detachedText(err, text)
}

// validSQLState reports whether code has the shape of a SQLSTATE, five digits
// or upper-case letters, so a driver reporting anything else through its
// SQLState method adds no text of its own.
func validSQLState(code string) bool {
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
// like detached, but with text in place of err's own text. It still matches
// the context and database/sql sentinels err matched, whatever text says.
func detachedText(err error, text string) error {
	var kept []error
	for _, s := range detachedKept {
		if errors.Is(err, s) {
			kept = append(kept, s)
		}
	}

	return &detachedError{text: text, kept: kept}
}
