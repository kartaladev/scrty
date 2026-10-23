package pgschema

const (
	// SetReadCommitted is the first statement of every transaction a store
	// begins for itself, so the transaction runs at READ COMMITTED whatever
	// the database's or the role's default_transaction_isolation is. The
	// stores' conditional writes and counters are written for READ
	// COMMITTED: at REPEATABLE READ a write that waited on a row another
	// transaction changed fails with a serialization failure, and a read
	// does not see what a transaction it waited for committed.
	SetReadCommitted = `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`

	// CurrentIsolation reads the isolation of the transaction it runs in,
	// spelled as PostgreSQL spells it: "read uncommitted", "read committed",
	// "repeatable read" or "serializable".
	CurrentIsolation = `SELECT current_setting('transaction_isolation')`
)

// ReadCommittedOrWeaker reports whether level, as CurrentIsolation reads it,
// behaves as READ COMMITTED. PostgreSQL runs READ UNCOMMITTED as READ
// COMMITTED.
func ReadCommittedOrWeaker(level string) bool {
	return level == "read committed" || level == "read uncommitted"
}
