// Package gorm provides scrty's security-state stores over gorm (*gorm.DB)
// with its PostgreSQL driver. Each store joins a transaction attached with
// WithTx, or one supplied by WithTxResolver, and otherwise runs on the
// *gorm.DB it was built with.
//
// The stores implement the contracts their owning packages define, and keep
// the same records in the same tables as package sqlstore and the pgx
// adapter, so the three are interchangeable over one database. The tables
// are the ones the migrate package creates: nothing here creates or alters a
// table, and no store calls AutoMigrate.
//
// # Construction
//
// Every constructor takes the *gorm.DB and options, and returns the store or
// an error wrapping ErrConfig for a wiring mistake: a nil handle, a nil
// option, a nil option value, or an option the store does not honour. Every
// store honours WithTxResolver; WithIDGenerator, WithClock and
// WithResealOnRead each name the stores that honour them, and any other store
// refuses them rather than ignoring them. The error names the first mistake,
// never a value. A store whose table holds sealed columns (sessions, whose
// provider ID token is sealed; signing keys, whose private material is; and
// MFA enrolments, whose secret is) also requires a seal.Cipher and refuses a
// nil one; there is no unsealed mode. No constructor touches the database.
//
// # Transactions
//
// Each operation runs on one handle, resolved in this order:
//
//  1. with WithTxResolver configured, the transaction the resolver reports;
//  2. otherwise, the transaction attached to the context with WithTx;
//  3. otherwise, the *gorm.DB the store was constructed with.
//
// A configured resolver replaces the context lookup: when it reports no
// transaction, the store uses its *gorm.DB even if one was attached with
// WithTx. When it reports a transaction with a nil handle, the operation runs
// no statement and fails with ErrNilTransaction. A transaction attached
// through another backend's adapter is never seen here. The stores never
// commit or roll back a transaction they did not open.
//
// Every operation is exactly one statement, run on a fresh session of the
// resolved handle with the operation's context: gorm's default transaction
// (a BEGIN and COMMIT around each write) and model hooks are turned off for
// it, and conditions chained on the handle do not carry into it. Refusals — an
// already-consumed token, a duplicate identifier, a save of a session that is
// gone — are the zero rows affected of that statement, never a failed
// statement, so they leave a caller's transaction usable. The limit: any
// statement a store runs inside a caller's transaction that fails for an
// unexpected reason aborts that transaction, as PostgreSQL defines, a read
// (for example one cancelled by a statement timeout) as much as a write.
//
// # Logging
//
// gorm's loggers print each statement with its bound values, which here are
// secrets, digests and user references. Every store operation therefore runs
// with gorm's logger discarded, whatever logger the *gorm.DB or the caller's
// transaction carries. That is not configurable: a store whose statements
// could be logged would put those values in the consumer's logs.
//
// Limit, stated: callbacks and plugins registered on the consumer's *gorm.DB
// (a tracing plugin, for example) still run on every store statement, and see
// its bound values. A consumer registering one owns what it records.
//
// # Errors
//
// Refusals return the owning package's sentinels. Database failures are
// returned wrapped with the name of the operation, and are never reported as
// a refusal or as absence; gorm.ErrRecordNotFound is the only absence. Error
// text never contains stored values, secrets or user references.
package gorm
