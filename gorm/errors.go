package gorm

import "errors"

// ErrConfig is wrapped by every error a store constructor returns for a wiring
// mistake: a nil database handle, a nil option, a nil option value, an option
// the store does not honour, or, for a store with sealed columns, a nil
// cipher. It lets a consumer tell a configuration error from a database
// failure without matching on message text. Its text, and the text wrapped
// around it, names the problem and never a configured value.
var ErrConfig = errors.New("gorm: invalid configuration")

// ErrNilTransaction is wrapped by the error an operation returns when the
// configured TxResolver reports a transaction but returns a nil handle. The
// operation runs no statement. It marks a defect in the consumer's resolver,
// not a database failure, and its text carries no values.
var ErrNilTransaction = errors.New("gorm: the transaction resolver reported a transaction with a nil handle")
