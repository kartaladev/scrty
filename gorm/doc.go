// Package gorm provides scrty's security-state stores, and its optional
// identity store (IdentityStore), over gorm (*gorm.DB) with its PostgreSQL
// driver. Each store joins a transaction attached with WithTx, or one
// supplied by WithTxResolver, and otherwise runs on the *gorm.DB it was built
// with.
//
// The stores implement the contracts their owning packages define, and keep
// the same records in the same tables as package sqlstore and the pgx
// adapter, so the three are interchangeable over one database. The tables
// are the ones the migrate package creates (migrate.SecurityState, and
// migrate.Identity for the identity store): nothing here creates or alters a
// table, and no store calls AutoMigrate.
//
// # Construction
//
// Every constructor takes the *gorm.DB and options, and returns the store or
// an error wrapping ErrConfig for a wiring mistake: a nil handle, a handle
// that already carries an error, a nil option, a nil option value, or an
// option the store does not honour. Every store honours WithTxResolver;
// WithIDGenerator, WithClock and WithResealOnRead each name the stores that
// honour them, and any other store refuses them rather than ignoring them. The
// error names the first mistake, never a value; a handle's own error is the
// exception, wrapped so a consumer can match it. A store whose table holds
// sealed columns (sessions, whose provider ID token is sealed; signing keys,
// whose private material is; and MFA enrolments, whose secret is) also
// requires a seal.Cipher and refuses a nil one; there is no unsealed mode. No
// constructor touches the database.
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
// The identity store is the exception: provisioning, updating and retiring a
// password are several statements. Outside a caller's transaction each runs
// in a transaction the store begins and ends itself; inside one it runs under
// a savepoint, so a failure, an unexpected one included, undoes only the
// store's own statements and leaves the caller's transaction usable.
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
// text never contains stored values, secrets or user references. The identity
// store goes further, since its rows hold usernames and password hashes: its
// database failures carry fixed text naming the operation, plus the SQLSTATE
// the driver's error reports, and neither the driver's message nor its error
// value, whose detail fields can carry a failing row.
package gorm
