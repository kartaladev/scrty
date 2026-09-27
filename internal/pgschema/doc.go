// Package pgschema holds the SQL text that the database/sql stores in package
// sqlstore and the native pgx stores run alike. Both speak PostgreSQL with $n
// placeholders, so a statement that is identical for the two is written once
// here, beside the table it targets, and each adapter keeps its own row
// scanning. Statements that differ between the adapters stay with the adapter.
//
// The pgx adapter is a separate module, so this SQL is a cross-module
// contract: a change here must keep both adapters' tests green.
//
// The package is internal because the statements are bound to the tables the
// migrate package creates, not an API consumers depend on.
package pgschema
