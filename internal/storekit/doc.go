// Package storekit holds the driver-independent pieces of the PostgreSQL
// security-state stores: the database/sql stores in package sqlstore, and the
// native pgx and gorm stores in their own modules. It decides how a value is
// represented in the tables the migrate package creates — which text
// PostgreSQL can store, the precision of a stored time, the encoding of a
// sealed secret, the digest a session is keyed by, the handle a login flow is
// found by, the data and successor digest a session row holds — and which
// session sentinel a conditional write that changed no row reports, so the
// three adapters store the same rows and refuse alike, and keeps each
// adapter's scanning, statement running and driver types out of it.
//
// It also runs a session supersession for all three: the order of its
// statements and the refusal each one maps to (Supersede), and the unit it
// runs as, under a savepoint inside a caller's transaction or in one of the
// store's own (Atomically). Each adapter supplies its driver calls through a
// per-call value: begin, commit, rollback, the savepoint statements,
// statement running and scanning, and the wrapping of its errors.
//
// It also holds the helpers the three identity stores share: the parsing of a
// user reference (ParseUserID), the checks and role rules of a user write
// (CheckUser, SurvivingRoles), and the error a database failure is cut down to
// before the identity store returns it (DetachedText), which keeps only the
// sentinels each adapter names and never the driver's text.
//
// The pgx and gorm adapters are separate modules, so this package is a
// cross-module contract, like internal/pgschema: a change here must keep all
// three adapters' tests green.
//
// Its refusals carry no adapter prefix and no operation name. An adapter wraps
// each one with both, so the error a caller sees reads
// "<adapter>: <operation>: <refusal>". RequireCipher is the exception: it is a
// construction check, and wraps the configuration sentinel the adapter hands
// it, which already carries the adapter's prefix; SupersedeRefusal likewise
// returns the adapter's own no-family error as it is, and Supersede returns
// every error its adapter's methods return as it is. The session sentinels
// are returned bare, never wrapped. No error names a value it refuses.
package storekit
