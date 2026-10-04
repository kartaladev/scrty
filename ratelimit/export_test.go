package ratelimit

// SourceKeys exposes the keyer's two-key form to the external test package, so
// the aggregate a guard counts under can be pinned without going through a
// guard and a limiter.
var SourceKeys = (*SourceKeyer).keys
