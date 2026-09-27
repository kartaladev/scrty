// Package storekit holds the driver-independent pieces of the PostgreSQL
// security-state stores: the database/sql stores in package sqlstore, and the
// native pgx and gorm stores in their own modules. It decides how a value is
// represented in the tables the migrate package creates — which text
// PostgreSQL can store, the precision of a stored time, the encoding of a
// sealed secret, the digest a session is keyed by, the handle a login flow is
// found by — so the three adapters store the same rows, and keeps each
// adapter's scanning, statement running and driver types out of it.
//
// The pgx and gorm adapters are separate modules, so this package is a
// cross-module contract, like internal/pgschema: a change here must keep all
// three adapters' tests green.
//
// Its refusals carry no adapter prefix and no operation name. An adapter wraps
// each one with both, so the error a caller sees reads
// "<adapter>: <operation>: <refusal>". RequireCipher is the exception: it is a
// construction check, and wraps the configuration sentinel the adapter hands
// it, which already carries the adapter's prefix. No error names a value it
// refuses.
package storekit
