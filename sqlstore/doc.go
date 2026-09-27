// Package sqlstore keeps scrty's security state in PostgreSQL through
// database/sql: sessions, one-time tokens, login attempts, signing keys, MFA
// enrolments, API keys, and OIDC links, flows and handoffs. Each store
// implements the contract its owning package defines, and runs against the
// tables the migrate package creates.
//
// The package depends on the standard library and scrty's core packages only.
// It brings no driver: the consumer opens the *sql.DB with the PostgreSQL
// driver of their choice. A consumer who works with pgx or gorm directly uses
// those adapter modules instead, which store the same records in the same
// tables.
//
// # Construction
//
// Every constructor takes the *sql.DB and options, and returns the store or an
// error wrapping ErrConfig for a wiring mistake: a nil handle, a nil option, a
// nil option value, or an option the store does not honour. Every store
// honours WithTxResolver; WithIDGenerator, WithClock and WithResealOnRead each
// name the stores that honour them, and any other store refuses them rather
// than ignoring them. The error names the first mistake, never a value.
//
// A store whose table holds sealed columns (signing keys, MFA enrolments, and
// sessions, whose provider ID token is sealed) also requires a seal.Cipher and
// refuses a nil one; there is no unsealed mode. No constructor touches the
// database.
//
// # Transactions
//
// Each operation runs on one handle, resolved in this order:
//
//  1. with WithTxResolver configured, the transaction the resolver reports;
//  2. otherwise, the transaction attached to the context with WithTx;
//  3. otherwise, the *sql.DB the store was constructed with.
//
// A configured resolver replaces the context lookup: when it reports no
// transaction, the store uses its *sql.DB even if one was attached with
// WithTx. When it reports a transaction with a nil handle, the operation runs
// no statement and fails with ErrNilTransaction. A transaction attached
// through another backend's adapter is never seen here. The stores never
// commit or roll back a transaction they did not open.
//
// Refusals — an already-consumed token, a duplicate link, a replayed time step
// — are reported without a failed statement, so they leave a caller's
// transaction usable. The limit: any statement a store runs inside a caller's
// transaction that fails for an unexpected reason aborts that transaction, as
// PostgreSQL defines, a read (for example one cancelled by a statement
// timeout) as much as a write. Refusals never do.
//
// # Errors
//
// Refusals return the owning package's sentinels. Database failures are
// returned wrapped with the name of the operation, and are never reported as a
// refusal or as absence. Error text never contains stored values, secrets or
// user references.
package sqlstore
