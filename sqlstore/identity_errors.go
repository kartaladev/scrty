package sqlstore

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
// can carry. The security-state stores keep the driver error in the chain;
// their rows hold neither.
func dbFailed(op string, err error) error {
	return failed(op, detached(err))
}

// scanColumnErr matches the prefix database/sql's Rows.Scan and Row.Scan give
// a column-conversion failure: "sql: Scan error on column index N, name
// "col": ...". The text after that colon can quote the offending value, the
// only place a Scan call's error text can carry one. database/sql quotes the
// name with %q, so a quote inside it arrives backslash-escaped; the second
// group spans such escapes and captures the quoted name, quotes included,
// ready to reuse as it stands.
var scanColumnErr = regexp.MustCompile(`^sql: Scan error on column index (\d+), name ("(?:[^"\\]|\\.)*"):`)

// scanFailed wraps err, a failure of a Scan call the identity store made,
// like dbFailed. When err is a database/sql column-conversion failure, its
// text is replaced with the column's index and name alone, dropping the
// value database/sql's own error text would otherwise quote; any other
// database failure a Scan call can return (a canceled context, a lost
// connection) is wrapped exactly as dbFailed would wrap it, since none of
// those carry a scanned value.
func scanFailed(op string, err error) error {
	m := scanColumnErr.FindStringSubmatch(err.Error())
	if m == nil {
		return dbFailed(op, err)
	}

	text := "scan error on column index " + m[1] + ", name " + m[2]

	return failed(op, detachedText(err, text))
}

// detachedKept is the sentinels a detached error stays matchable against
// when the driver's error matched them. None carries a value.
var detachedKept = []error{context.Canceled, context.DeadlineExceeded, sql.ErrTxDone, sql.ErrConnDone}

// detachedError is a database failure cut from the driver's error: the text
// of that error and the sentinels of detachedKept it matched, nothing else.
type detachedError struct {
	text string
	kept []error
}

func (e *detachedError) Error() string   { return e.text }
func (e *detachedError) Unwrap() []error { return e.kept }

// detached is err with the driver's error value left out of its chain. It
// keeps err's text, which for PostgreSQL drivers is the primary message and
// the SQLSTATE and never the detail fields, and stays matchable against the
// context and database/sql sentinels err matched, so a caller still tells a
// cancellation from a failure.
func detached(err error) error {
	return detachedText(err, err.Error())
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
