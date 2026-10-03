package scrtyredis

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kartaladev/scrty/ratelimit"
)

// Factory builds the Redis limiter of each flow that asks for one, so a
// consumer replaces the storage of every flow without restating any flow's
// limit or window. Pass it to httpsec.WithRateLimiterFactory, or to the
// component options of the mfa, recovery and passkey packages.
//
// A namespace asked for twice with the same limit and window gives a second
// limiter over the same buckets, exactly as another replica would: two chains
// built from one factory, or a flow constructed twice, count together. Asked
// for with a different limit or window, it is refused, because one bucket
// cannot hold two policies. The factory cannot see other processes, so every
// replica must still configure a namespace the same way.
//
// It is safe for concurrent use.
type Factory struct {
	client redis.UniversalClient
	opts   []Option
	check  serverCheck

	mu sync.Mutex
	// built holds the policy each namespace was first built with.
	built map[string]policy
}

// policy is the limit and window a namespace was built with.
type policy struct {
	limit  int
	window time.Duration
}

func (p policy) String() string { return fmt.Sprintf("%d per %s", p.limit, p.window) }

var _ ratelimit.LimiterFactory = (*Factory)(nil)

// factoryProbeNamespace is the namespace of the limiter NewLimiterFactory
// builds, and discards, to check client and options once.
const factoryProbeNamespace = "factory"

// NewLimiterFactory returns a Factory whose limiters count in the server
// behind client, each configured by opts.
//
// It checks client and opts as NewLimiter would, so a wiring mistake fails
// here rather than at the first flow's constructor: a nil client (typed nil
// included), a cluster client reading from replicas, a client whose options
// leave ContextTimeoutEnabled off, or an option NewLimiter refuses is an error
// wrapping ratelimit.ErrConfig. The client must set ContextTimeoutEnabled, so
// that the operation timeout and Verify's deadline bound every call; see
// NewLimiter. It performs no I/O; call
// Verify before traffic to check the server itself.
func NewLimiterFactory(client redis.UniversalClient, opts ...Option) (*Factory, error) {
	opts = slices.Clone(opts)
	if _, err := NewLimiter(client, factoryProbeNamespace, 1, time.Second, opts...); err != nil {
		return nil, err
	}

	return &Factory{
		client: client,
		opts:   opts,
		check:  newServerCheck(client, newConfig(opts)),
		built:  map[string]policy{},
	}, nil
}

// NewLimiter returns a limiter counting up to limit failures per key within
// window in namespace, as NewLimiter does with the factory's client and
// options.
//
// A namespace this factory has already built with a different limit or window
// is an error wrapping ratelimit.ErrConfig, naming the namespace and both
// policies; so is anything NewLimiter refuses. A refused request does not
// claim the namespace. On error the limiter is nil.
func (f *Factory) NewLimiter(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	asked := policy{limit: limit, window: window}

	f.mu.Lock()
	defer f.mu.Unlock()

	if p, ok := f.built[namespace]; ok && p != asked {
		return nil, fmt.Errorf("%w: namespace %q is already built with %s, and was asked for %s; one bucket cannot hold two policies",
			ratelimit.ErrConfig, namespace, p, asked)
	}
	l, err := NewLimiter(f.client, namespace, limit, window, f.opts...)
	if err != nil {
		return nil, err
	}
	f.built[namespace] = asked

	return l, nil
}
