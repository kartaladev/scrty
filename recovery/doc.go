// Package recovery lets a user who has lost the authenticators their account
// depends on get back in with two independent proofs, never one.
//
// # Saved recovery codes
//
// A set of saved codes is generated for a user and shown to them once. Each
// code carries 128 bits from the configured random source, written as 26
// Crockford base32 characters grouped in fours with dashes. Only the SHA-256
// hash of a code's 16 bytes is stored, and a presented code is looked up by its
// user and that hash, so a store that leaks yields nothing that can be
// presented, and one user's presentations never probe another user's set.
//
// Codes manages a user's set: Generate replaces the whole set in one store
// write, Confirm checks that the user kept it without spending anything, and
// Remaining reports how many unspent codes are left and whether that is low.
// Every presentation is throttled per user, and a presentation refused by the
// throttle is never looked up.
//
// No code, and no spelling of one, is ever written to a log record or the text
// of an error this package returns.
package recovery
