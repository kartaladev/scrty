// Package ratelimittest is the conformance suite every ratelimit.Limiter
// scrty ships must pass: the in-memory limiter and each shared limiter.
//
// A backend adapts itself to a Harness and calls Run. The suite pins the
// threshold, key separation, the strictly-after window boundary, boundary
// straddling, the newest-stamp cap, ended contexts and concurrent use. When
// the Harness can build a second instance over the same backend scope, Run
// also checks the cross-instance scenarios that make a limiter shared:
// two replicas sharing one limit, a shorter-window replica never disarming a
// longer-window one, and namespaces keeping flows apart.
//
// The suite steps time by whole microseconds at the smallest, because a shared
// limiter may store stamps at microsecond resolution.
package ratelimittest
