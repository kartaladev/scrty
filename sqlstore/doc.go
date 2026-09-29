// Package sqlstore keeps scrty's security state in PostgreSQL through
// database/sql: sessions, one-time tokens, login attempts, signing keys, MFA
// enrolments, API keys, and OIDC links, flows and handoffs. IdentityStore
// keeps the identity records beside them: users, their role grants,
// organizations, groups and role privileges. Each store implements the
// contract its owning package defines, and runs against the tables the
// migrate package creates: the security-state stores against
// migrate.SecurityState, the identity store against migrate.Identity.
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
// commit or roll back a transaction they did not open; the identity store
// rolls back only to a savepoint of its own, as below.
//
// Refusals — an already-consumed token, a duplicate link, a replayed time step
// — are reported without a failed statement, so they leave a caller's
// transaction usable. The limit, for the security-state stores: any statement
// they run inside a caller's transaction that fails for an unexpected reason
// aborts that transaction, as PostgreSQL defines, a read (for example one
// cancelled by a statement timeout) as much as a write. Refusals never do.
//
// The identity store's writes differ: inside a caller's transaction,
// IdentityStore.Provision, IdentityStore.Update and
// IdentityStore.RetirePassword run under a savepoint of their own, and roll
// back to it when they fail, so a failed provision, update or retire undoes
// only its own writes and leaves the caller's transaction usable, with the
// caller's earlier work intact. Outside one, each runs in a transaction of its
// own. The identity store's reads follow the
// limit above.
//
// # Errors
//
// Refusals return the owning package's sentinels. Database failures are
// returned wrapped with the name of the operation, and are never reported as a
// refusal or as absence. Error text never contains stored values, secrets or
// user references. The security-state stores keep the driver's error in the
// chain. The identity store does not: its tables hold usernames and password
// hashes, which a driver error's detail fields can carry, so it returns text of
// its own naming the operation and the SQLSTATE, with the context and
// database/sql sentinels the driver's error matched, and leaves the driver's
// error value and message out.
package sqlstore
