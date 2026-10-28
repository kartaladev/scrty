// Package onetime issues credentials that are spent exactly once.
//
// A Manager issues a token for a purpose and a subject, checks a presented one
// and consumes it. Password resets, magic links, address confirmations and
// anything else of that shape each build their own manager with their own
// purpose, and a token issued under one purpose never passes a check under
// another.
//
// Only the hash of a token's secret is stored, compared in constant time, so a
// store that leaks yields nothing that can be presented. Checking has no side
// effects at all: it can run once per racing caller without spending anything,
// and every refusal — a wrong purpose, an expired token, one already consumed,
// a binding or secret that does not match, even a failure to read the store —
// is reported the same way, so what a caller learns is that the token is not
// good and nothing more.
//
// Consumption is a compare-and-set against a token that has not yet been
// consumed, so exactly one of several concurrent redemptions succeeds. The
// value that consumption takes is obtainable only from a check, which makes
// check-then-consume structural rather than a convention each caller has to
// remember, and a refusal raised between the two leaves the token still
// redeemable.
package onetime
