package store

import "errors"

// ErrIsolationTooStrong is wrapped by the error a store operation returns when
// it is run inside a caller's transaction whose isolation is stronger than
// READ COMMITTED, and its guarantee depends on READ COMMITTED. The error that
// wraps it names the isolation found. The operation writes nothing, and the
// caller's transaction stays usable. A store cannot change a transaction's
// isolation once it has begun, so there is no option to relax it: a consumer
// whose own work needs a stronger isolation runs these operations outside
// that transaction.
var ErrIsolationTooStrong = errors.New("store: the caller's transaction isolation is stronger than READ COMMITTED")
