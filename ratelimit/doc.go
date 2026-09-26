// Package ratelimit bounds how often one source may fail.
//
// A Limiter counts failures rather than requests, so ordinary traffic never
// throttles the caller making it, and asking whether a key is over its limit
// records nothing on its own. The in-memory limiter keeps a sliding window and
// is the default; a consumer replaces it with one backed by shared storage when
// counts have to hold across replicas.
//
// A SourceKeyer turns a client address into the key those counts are kept
// under, canonicalising it first: an IPv4-mapped address is unmapped, and an
// IPv6 address is keyed by a prefix rather than by the full address, so moving
// within one allocation does not buy a fresh allowance. An address that cannot
// be attributed to a single source is refused outright rather than counted
// under a shared key, because a shared key lets one source spend an allowance
// that every other source behind it also depends on.
//
// A SourceGuard pairs the two: it checks a source before a flow runs and
// records the failure afterwards under the same key, including when the
// caller's own context has already been cancelled — a client that hangs up
// mid-attempt must still be charged for it. A limiter that errors is read as a
// source already over its limit. Failing closed is deliberate: the alternative
// lifts every limit at exactly the moment something is wrong.
//
// A throttled source's address is named in its record on purpose: refusing an
// attempt without saying whose would defeat the record's own point. A
// limiter's own failure is recorded differently — a fixed reason and the
// error's Go type, never the limiter's own text, which can quote a key or a
// value the library never saw.
package ratelimit
