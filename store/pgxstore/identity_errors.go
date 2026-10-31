package pgxstore

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/kartaladev/scrty/internal/storekit"
)

// dbFailed wraps err, a failure of a database call the identity store made,
// like failed, but first cuts it from the driver's error value
// ([storekit.Detached]). The identity store returns only this for a database
// failure: its tables hold usernames and password hashes, which a driver
// error's detail fields can carry. The security-state stores keep the driver
// error in the chain; their rows hold neither.
func dbFailed(op string, err error) error {
	return failed(op, storekit.Detached(err, detachedKept))
}

// scanFailed wraps err, a failure of a Scan call the identity store made,
// like dbFailed. When err is a column-conversion failure (pgx.ScanArgError),
// its text is replaced with the column's index and name alone, dropping the
// conversion error pgx's own text would carry, which can quote the value;
// any other failure a Scan call can return (a cancelled context, a lost
// connection, a statement the server refused) is wrapped exactly as dbFailed
// would wrap it, since none of those carry a scanned value.
func scanFailed(op string, err error) error {
	var argErr pgx.ScanArgError
	if !errors.As(err, &argErr) {
		return dbFailed(op, err)
	}

	text := "scan error on column index " + strconv.Itoa(argErr.ColumnIndex) +
		", name " + strconv.Quote(argErr.FieldName)

	return failed(op, storekit.DetachedText(err, text, detachedKept))
}

// detachedKept is the sentinels a detached error stays matchable against
// when the driver's error matched them. None carries a value.
var detachedKept = []error{
	context.Canceled,
	context.DeadlineExceeded,
	pgx.ErrTxClosed,
	pgx.ErrTxCommitRollback,
}
