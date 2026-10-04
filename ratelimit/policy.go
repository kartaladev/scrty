package ratelimit

import "time"

// PolicyReporter is implemented by a Limiter that can say the limit and window
// it counts with.
//
// It is optional. A component that needs a limiter's policy, such as the
// httpsec chain sizing a flow's IPv6 aggregate, asks for it with a type
// assertion, and treats a limiter without it as one whose policy is unknown
// rather than guessing one. MemoryLimiter and the shared limiters scrty ships
// implement it; a consumer's own Limiter may, to get the same treatment.
//
// A limiter's policy is fixed when it is built, so Policy reports the same
// pair on every call, and a caller may read it once.
type PolicyReporter interface {
	// Policy returns the number of failures a key may accumulate, and the
	// window they are counted over.
	Policy() (limit int, window time.Duration)
}
