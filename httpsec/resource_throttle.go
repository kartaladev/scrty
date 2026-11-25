package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/ratelimit"
)

// resourceServerFlow is the namespace the chain's limiter factory builds the refusal limiter under,
// and the stem of each source's guard, so a source that exhausts its budget at one source still has
// it at another.
const resourceServerFlow = "resource-server"

// The refusal budget a client address gets at each source by default: the API-key limiter's, as an
// API client retries.
const (
	defaultResourceRefusalLimit  = defaultAPIKeyFailureLimit
	defaultResourceRefusalWindow = defaultAPIKeyFailureWindow
)

// optionRefusalLimiter names WithRefusalLimiter in configuration errors.
const optionRefusalLimiter = "WithRefusalLimiter"

// The fixed texts a failing refusal limiter is answered with: a dependency failure, never a refusal.
const (
	textRefusalLimiterFailed = "httpsec: the resource server's refusal limiter could not answer"
	textRefusalLimiterEnded  = "httpsec: the request ended while the resource server's refusal limiter answered"
)

// WithRefusalLimiter counts the resource server's verification refusals through limiter, per client
// address and source: a bad signature, type, audience or claim, an expired token, an inactive or
// unknown one, and a caller that could not be resolved. An address over its budget at a source is
// refused as an invalid token (401) before its token is verified, so no key set is fetched and no
// introspection call is made for it. Binding and nonce answers, an unmet MFA requirement, and
// dependency failures are never counted: an ordinary DPoP client answers a nonce challenge on its
// first request. A limiter that fails is a dependency failure (500), and a request whose client
// address cannot be attributed is refused. A nil limiter is a configuration error from New.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under the namespace
// "resource-server", or else an in-memory limiter, allowing 20 refusals per address and source per
// minute, with the chain's IPv6 aggregate (WithIPv6Aggregate).
//
// Accepted: clients sharing one address behind a gateway or NAT share the budget, so one client's
// refused tokens can have another's valid ones refused until the window passes. A deployment with such
// clients raises the limit, or keys by a trusted proxy's client address (EnableTrustedProxies).
func WithRefusalLimiter(limiter ratelimit.Limiter) ResourceServerOption {
	return func(rs *resourceServer) error {
		rs.limiter, rs.limiterGiven = limiter, true

		return nil
	}
}

// checkLimiter refuses a nil refusal limiter.
func (rs *resourceServer) checkLimiter() error {
	if rs.limiterGiven && nilcheck.IsNil(rs.limiter) {
		return newConfigError("%s (%s) was given %s with a nil limiter", optionResourceServer, rs.id,
			optionRefusalLimiter)
	}

	return nil
}

// buildGuards builds every source's refusal guard, once every option is applied and the chain's
// keyer exists. A source of a resource server without its own limiter shares the limiter the chain's
// factory builds under resourceServerFlow; each guard's flow keeps the sources' buckets apart.
func (s *resourceServers) buildGuards(c *config) error {
	s.guards = make(map[source]sourceGuard)
	s.log = c.logger

	var shared, sharedAggregate ratelimit.Limiter

	n := 0

	for _, rs := range s.modes {
		limiter, aggregate := rs.limiter, ratelimit.Limiter(nil)

		if limiter == nil {
			if shared == nil {
				built, err := c.rateLimiterFactory().NewLimiter(resourceServerFlow, defaultResourceRefusalLimit,
					defaultResourceRefusalWindow)
				if err != nil {
					return newConfigError("%s could not build its refusal limiter for namespace %q: %s",
						optionResourceServer, resourceServerFlow, err)
				}

				agg, err := c.aggregateLimiter(optionResourceServer, resourceServerFlow, nil,
					defaultResourceRefusalLimit, defaultResourceRefusalWindow)
				if err != nil {
					return err
				}

				shared, sharedAggregate = built, agg
			}

			limiter, aggregate = shared, sharedAggregate
		} else {
			agg, err := c.aggregateLimiter(optionResourceServer, resourceServerFlow, limiter,
				defaultResourceRefusalLimit, defaultResourceRefusalWindow)
			if err != nil {
				return err
			}

			aggregate = agg
		}

		opts := []ratelimit.GuardOption{
			ratelimit.WithSourceGuardLogger(c.logger),
			ratelimit.WithSourceGuardKeyer(c.keyer),
			ratelimit.WithSourceGuardLogInterval(c.refusalInterval),
			ratelimit.WithSourceGuardClock(c.clock),
		}
		if c.refusalReporter != nil {
			opts = append(opts, ratelimit.WithSourceGuardLogReporter(c.refusalReporter))
		}

		if aggregate != nil {
			opts = append(opts, ratelimit.WithSourceGuardIPv6Aggregate(c.aggregateBits, aggregate))
		}

		for _, src := range rs.sources {
			guard, err := ratelimit.NewSourceGuard(resourceServerFlow+"-"+strconv.Itoa(n), limiter, opts...)
			if err != nil {
				return newConfigError("%s (%s) could not build the refusal guard of %s: %s", optionResourceServer,
					rs.id, src.name(), err)
			}

			s.guards[src] = guard
			n++
		}
	}

	return nil
}

// flushRefusalLogs reports what the refusal guards are holding back.
func (s *resourceServers) flushRefusalLogs() error {
	for _, g := range s.guards {
		g.Flush()
	}

	return nil
}

// admitSource checks addr's refusal budget at src before src verifies anything. A throttled or
// unattributable address is refused (ErrInvalidToken); a limiter that failed is a dependency failure,
// and the request's own end its context's error.
func (s *resourceServers) admitSource(ctx context.Context, src source, addr string) (ratelimit.Source, error) {
	g := s.guards[src]
	if g == nil {
		// Every source has a guard once the chain is built; a missing one is refused, never waved on.
		return ratelimit.Source{}, ErrInvalidToken
	}

	if reason, ok := classifyAddress(addr); !ok {
		s.log.LogAttrs(ctx, slog.LevelDebug, "httpsec: refusing an access token whose client address cannot be attributed",
			slog.String("flow", resourceServerFlow), slog.String("reason", reason))

		return ratelimit.Source{}, ErrInvalidToken
	}

	rsrc, err := g.Check(ctx, addr)

	switch {
	case err == nil:
		return rsrc, nil
	case overLimit(err):
		return rsrc, ErrInvalidToken
	case endedBeforeTheAnswer(ctx, err):
		return ratelimit.Source{}, diag.Wrap(err, textRefusalLimiterEnded, ctx.Err())
	default:
		// The guard answers a limiter it could not consult as throttled, which the status table answers
		// 401; here it is a dependency failure, so only the limiter's own failure is kept beneath the
		// fixed text.
		return ratelimit.Source{}, diag.Wrap(limiterCause(err), textRefusalLimiterFailed)
	}
}

// limiterCause is the limiter's own failure beneath the guard's refusal, without the guard's
// ratelimit.ErrThrottled, or err itself when it carries none.
func limiterCause(err error) error {
	var f *diag.Fault
	if errors.As(err, &f) {
		if errs := f.Unwrap(); len(errs) > 0 && errs[len(errs)-1] != nil {
			return errs[len(errs)-1]
		}
	}

	return err
}

// countRefusal counts one verification refusal against the source that made it, on a context the
// request's cancellation does not reach, so a client cannot evade the count by hanging up.
func (s *resourceServers) countRefusal(ctx context.Context, src source, rsrc ratelimit.Source) {
	if g := s.guards[src]; g != nil {
		recordSourceFailure(ctx, g, rsrc)
	}
}
