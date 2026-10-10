package pglimiter

import (
	"fmt"
	"sync"
	"time"

	"github.com/kartaladev/scrty/ratelimit"
)

// Policy is the limit and window a namespace was built with.
type Policy struct {
	Limit  int
	Window time.Duration
}

// String reports the policy as "<limit> per <window>", as the conflict error
// names it.
func (p Policy) String() string { return fmt.Sprintf("%d per %s", p.Limit, p.Window) }

// Registry records the policy each namespace a factory built was first built
// with, so the factory refuses the same namespace with another policy. It is
// safe for concurrent use. The zero value is not usable; use NewRegistry.
type Registry struct {
	mu sync.Mutex
	// built holds the policy each namespace was first built with.
	built map[string]Policy
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{built: map[string]Policy{}}
}

// Claim builds through build, under the registry's lock, unless namespace
// already holds a different policy, and records the policy only when build
// succeeds, so a refused request does not claim the namespace.
//
// A namespace already built with another policy is an error wrapping
// ratelimit.ErrConfig, naming the namespace and both policies, and build is
// not called. A build error is returned as it is. On error the limiter is nil.
func (r *Registry) Claim(namespace string, p Policy, build func() (ratelimit.Limiter, error)) (ratelimit.Limiter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if held, ok := r.built[namespace]; ok && held != p {
		return nil, fmt.Errorf("%w: namespace %q is already built with %s, and was asked for %s; one bucket cannot hold two policies",
			ratelimit.ErrConfig, namespace, held, p)
	}
	l, err := build()
	if err != nil {
		return nil, err
	}
	r.built[namespace] = p

	return l, nil
}
