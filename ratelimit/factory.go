package ratelimit

import (
	"context"
	"slices"
	"time"
)

// LimiterFactory builds the limiter a flow counts its failures through.
//
// Each built-in flow asks for its own namespace, limit and window, so a
// consumer who replaces the storage keeps every flow's own policy. Default:
// MemoryLimiterFactory, which gives each call a limiter of its own in this
// process.
type LimiterFactory interface {
	NewLimiter(namespace string, limit int, window time.Duration) (Limiter, error)
}

// Verifier is implemented by factories and limiters whose backend can be
// checked before traffic. Constructors never perform I/O; a consumer calls
// Verify at startup. It is optional: a factory or limiter with nothing to
// check, such as the in-memory default, does not implement it.
type Verifier interface {
	Verify(ctx context.Context) error
}

// MemoryLimiterFactory returns a factory of in-memory limiters. It is the
// default every built-in flow uses when the consumer supplies neither a limiter
// nor a factory.
//
// Every call builds a new MemoryLimiter with separate buckets; the namespace is
// not needed to keep them apart and is ignored. opts apply to every limiter
// built, so WithMemoryLimiterMaxKeys caps each of them separately: every limiter
// holds at most DefaultMemoryLimiterMaxKeys keys of its own unless that option
// says otherwise. A non-positive limit or window, or an option NewMemoryLimiter refuses,
// is an error wrapping ErrConfig.
func MemoryLimiterFactory(opts ...MemoryOption) LimiterFactory {
	return memoryFactory{opts: slices.Clone(opts)}
}

type memoryFactory struct{ opts []MemoryOption }

// NewLimiter builds a MemoryLimiter, returning a nil Limiter, never a typed
// nil, when construction fails.
func (f memoryFactory) NewLimiter(_ string, limit int, window time.Duration) (Limiter, error) {
	l, err := NewMemoryLimiter(limit, window, f.opts...)
	if err != nil {
		return nil, err
	}

	return l, nil
}
