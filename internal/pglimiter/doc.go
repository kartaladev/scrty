// Package pglimiter is the PostgreSQL rate limiter both PostgreSQL adapters
// share: the database/sql one in sqlstore and the native one in pgx. It holds
// everything but the driver call: the configuration the adapters' options
// describe and its validation, the construction rules for a namespace's
// policy, the statements' time and lock-timeout arguments, the backend the
// unavailable decorator wraps, the startup check, the batched prune, and the
// registry a factory claims namespaces in.
//
// It runs every statement through Runner, which each adapter implements over
// its own handle, so the two adapters keep one copy of the rules and count
// together in one table.
//
// The package is internal because consumers configure it through each
// adapter's own options, never directly. Every error it returns that names
// its adapter starts with the prefix the adapter passes ("sqlstore" or
// "pgx").
package pglimiter
