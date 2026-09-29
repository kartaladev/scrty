// Package pgx keeps scrty's security state in PostgreSQL through native pgx v5
// (a *pgxpool.Pool and pgx.Tx). Each store implements the contract its owning
// package defines, and runs against the tables the core migrate package
// creates, storing the same records in the same tables as the core's
// database/sql stores, with the same guarantees.
//
// The package name matches the module's last path element. A consumer who
// imports it beside github.com/jackc/pgx/v5 names one of the two, for example
// pgxstore "github.com/kartaladev/scrty/pgx".
//
// # Construction
//
// Every constructor takes the *pgxpool.Pool and options, and returns the store
// or an error wrapping ErrConfig for a wiring mistake: a nil pool, a nil
// option, a nil option value, or an option the store does not honour. Every
// store honours WithTxResolver; WithIDGenerator, WithClock and
// WithResealOnRead each name the stores that honour them, and any other store
// refuses them rather than ignoring them. The error names the first mistake,
// never a value.
//
// A store whose table holds sealed columns (sessions, whose provider ID token
// is sealed; signing keys, whose private material is sealed; MFA enrolments,
// whose secret is sealed) also requires a seal.Cipher and refuses a nil one;
// there is no unsealed mode. No constructor touches the database.
//
// # Transactions
//
// Each operation runs one statement on one handle, resolved in this order:
//
//  1. with WithTxResolver configured, the transaction the resolver reports;
//  2. otherwise, the transaction attached to the context with WithTx;
//  3. otherwise, the *pgxpool.Pool the store was constructed with.
//
// A configured resolver replaces the context lookup: when it reports no
// transaction, the store uses its pool even if one was attached with WithTx.
// When it reports a transaction with a nil handle, the operation runs no
// statement and fails with ErrNilTransaction. A transaction attached through
// another backend's adapter, such as the core's sqlstore.WithTx, is never
// seen here. The stores never commit or roll back a transaction they did not
// open.
//
// The identity store's writes are the exception to one statement per
// operation: Provision, Update and RetirePassword each run several statements
// as one unit, in a transaction of their own begun on the pool, or, inside a
// caller's transaction, in a savepoint the store issues on that transaction
// and releases whether the unit succeeds or fails, so their failure leaves the
// caller's transaction usable and no savepoint open.
//
// Refusals — an already-consumed token, a duplicate identifier, a save of a
// session that is gone — are reported without a failed statement, so they
// leave a caller's transaction usable. The limit: any statement a store runs
// inside a caller's transaction that fails for an unexpected reason aborts
// that transaction, as PostgreSQL defines, a read (for example one cancelled
// by a statement timeout) as much as a write. Refusals never do.
//
// # Errors
//
// Refusals return the owning package's sentinels. Database failures, a
// cancelled context among them, are returned wrapped with the name of the
// operation ("pgx: consume one-time token: ..."), and are never reported as a
// refusal or as absence: pgx.ErrNoRows is the only error read as absence.
// Error text never contains stored values, secrets or user references. The
// security-state stores keep the driver's error in the chain. The identity
// store does not: its tables hold usernames and password hashes, which a
// driver error's detail fields can carry, so it returns text of its own
// naming the operation and the SQLSTATE, with the context and pgx sentinels
// the driver's error matched, and leaves the driver's error value and message
// out.
package pgx
