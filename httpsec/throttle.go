package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/ratelimit"
)

//go:generate mockgen -destination=limiter_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/ratelimit Limiter,LimiterFactory

// The reasons an address cannot key a bucket. Each is the tail of the sampler
// key its refusal is recorded under, so an operator reading one record sees
// which of the three is happening without opening the message.
const (
	reasonNoClientAddress = "no-client-address"
	reasonNotSingleIP     = "not-single-ip"
	reasonUnspecified     = "unspecified-address"
)

// sampleKeySeparator joins a sampler key's parts. Every key this package builds
// starts with the flow, so a burst against one flow never holds another flow's
// window open.
const sampleKeySeparator = "|"

// sourceGuard is the part of ratelimit.SourceGuard the throttle seam uses.
//
// It is an interface so the seam's own guarantee — that a recording is made on
// a context the client's disconnect cannot reach — is observable at this
// package's boundary rather than only inside the guard. A consumer never sees
// it: every chain is wired with a real *ratelimit.SourceGuard.
type sourceGuard interface {
	Check(ctx context.Context, clientAddr string) (ratelimit.Source, error)
	RecordFailure(ctx context.Context, s ratelimit.Source)

	// Flush reports the refusal counts the guard's sampler is holding back.
	Flush()
}

// The real guard satisfies the seam, so a change to either is a compile error
// here rather than a surprise where an interceptor is wired.
var _ sourceGuard = (*ratelimit.SourceGuard)(nil)

// rateLimiterFactory is the factory every limiter the chain builds comes from:
// the consumer's (WithRateLimiterFactory), or else the in-memory default,
// writing its per-replica warning through the chain's logger.
//
// It is resolved after every option has been applied, because which logger
// that is is not settled until then.
func (c *config) rateLimiterFactory() ratelimit.LimiterFactory {
	if c.limiterFactory != nil {
		return c.limiterFactory
	}

	return ratelimit.MemoryLimiterFactory(ratelimit.WithMemoryLimiterLogger(c.logger))
}

// resolveSourceGuard builds the per-source guard an endpoint counts its
// failures through.
//
// Every endpoint that guards by source wires it the same way, so they share
// this. The limiter is the consumer's own for that flow when one was given;
// otherwise the chain's factory builds one under the flow's name, with the
// endpoint's own default limit and window. The guard is named after the flow,
// keys its clients by the chain's keyer (WithIPv6SourcePrefix), logs through
// the chain's logger, samples its refusal records over logInterval, the window
// the endpoint's own records are sampled over, and reports the counts it
// suppressed to the chain's refusal-log reporter (WithRefusalLogReporter, or
// the chain's default summary record). Its throttled-source record is the only
// one a throttled attempt produces.
//
// Unless the chain turned it off (WithoutIPv6Aggregate), the guard also counts
// IPv6 sources by the chain's aggregate prefix, in a limiter the chain's
// factory builds under "<flow>-ipv6-aggregate" with limit times the chain's
// multiplier over window, whether or not the flow brought its own limiter.
//
// option is the Enable... option the endpoint came from, so a wiring failure
// names the setting the consumer has to change rather than the internals it
// failed in.
func (c *config) resolveSourceGuard(
	option, flow string,
	limiter ratelimit.Limiter,
	limit int,
	window time.Duration,
	logInterval time.Duration,
) (sourceGuard, error) {
	if limiter == nil {
		built, err := c.rateLimiterFactory().NewLimiter(flow, limit, window)
		if err != nil {
			return nil, newConfigError("%s could not build its limiter for namespace %q: %s",
				option, flow, err)
		}

		limiter = built
	}

	opts := []ratelimit.GuardOption{
		ratelimit.WithSourceGuardLogger(c.logger),
		ratelimit.WithSourceGuardKeyer(c.keyer),
		ratelimit.WithSourceGuardLogInterval(logInterval),
		ratelimit.WithSourceGuardLogReporter(c.refusalLogReporter()),
	}

	// The aggregate is the chain's, not the flow's: it is built from the
	// chain's factory even when the flow brought its own limiter, because a
	// flow's limiter says nothing about the allocation its sources share.
	if c.aggregateOn() {
		namespace := flow + "-ipv6-aggregate"

		// A wrapped product would quietly shrink the aggregate's limit, even
		// below the flow's own, so a multiplier that overflows is refused.
		if limit > math.MaxInt/c.aggregateMultiplier {
			return nil, newConfigError("%s: WithIPv6Aggregate multiplier %d times the %s limit of %d "+
				"overflows an int", option, c.aggregateMultiplier, flow, limit)
		}

		agg, err := c.rateLimiterFactory().NewLimiter(namespace, limit*c.aggregateMultiplier, window)
		if err != nil {
			return nil, newConfigError("%s could not build its IPv6 aggregate limiter for namespace %q: %s",
				option, namespace, err)
		}

		opts = append(opts, ratelimit.WithSourceGuardIPv6Aggregate(c.aggregateBits, agg))
	}

	guard, err := ratelimit.NewSourceGuard(flow, limiter, opts...)
	if err != nil {
		return nil, newConfigError("%s could not build its source guard: %s", option, err)
	}

	return guard, nil
}

// classifyAddress decides whether addr may key a rate-limit bucket, and names
// the reason when it may not.
//
// An address that is not exactly one IP names more than one client — a
// forwarding header's list, a hostname, a host and port — and an unspecified
// address is what a peer that is not a TCP client is reported as. Keying either
// pools unrelated clients into one bucket, where any one of them can spend the
// allowance all the others depend on, so both are refused outright instead. An
// empty address names nobody at all.
func classifyAddress(addr string) (reason string, ok bool) {
	if addr == "" {
		return reasonNoClientAddress, false
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return reasonNotSingleIP, false
	}

	// Unmapped first: IsUnspecified alone is false for ::ffff:0.0.0.0, which is
	// the same address written the other way and would otherwise be keyed on.
	if ip.Unmap().IsUnspecified() {
		return reasonUnspecified, false
	}

	return "", true
}

// sourceThrottled checks the request's source before the guarded work runs, and
// returns the source the failure is later recorded against.
//
// It refuses an address it cannot attribute before the limiter is asked, so
// such a request never reaches a bucket to be pooled in, and it refuses a check
// the limiter could not answer as well: a limiter that cannot answer has not
// said the source is within its limit, and admitting the request would lift
// every limit at exactly the moment something is wrong. Both read to the client
// as an ordinary failed attempt, so a client cannot tell a refused source from
// a wrong credential.
//
// A refused check returns the zero Source, which keys nothing, so no failure
// can be charged to a check that did not pass.
//
// A throttled source is recorded once, by the guard, under the flow and the
// canonical source, with the source's canonical address kept on purpose, since
// an operator reading a throttle record needs to know who was throttled — the
// rate-limiting capability's own contract. A limiter that could not answer at
// all is a different thing: this function records it with only a fixed reason
// ("limiter") and the failing error's Go type, never the error's own text,
// because a consumer's limiter may quote the bucket key back, and that key can
// carry the address or the user reference that built it. A consumer who wants
// that detail logs it inside their own implementation of ratelimit.Limiter.
func sourceThrottled(
	ctx context.Context,
	g sourceGuard,
	clientAddr, flow string,
	s *logsample.Sampler,
	log *slog.Logger,
	now time.Time,
) (ratelimit.Source, error) {
	if reason, ok := classifyAddress(clientAddr); !ok {
		logSampled(ctx, s, log, slog.LevelError, now, flow+sampleKeySeparator+reason,
			"httpsec: refusing a request whose client address cannot be attributed",
			slog.String("flow", flow), slog.String("reason", reason))

		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed
	}

	src, err := g.Check(ctx, clientAddr)
	switch {
	case err == nil:
		return src, nil

	case overLimit(err):
		// The guard has already written the throttled-source record, sampled
		// per flow and canonical source, so addresses grouped into one source
		// share one record. Writing another here would double it, and key it
		// on the raw address, which an attacker rotating within one IPv6
		// allocation chooses.
		return src, err

	case endedBeforeTheAnswer(ctx, err):
		// The client's own doing, not a refusal worth a sampled warning, and
		// sampling it would let ordinary disconnections consume the window a
		// real outage needs. So it is written every time, at debug.
		log.LogAttrs(ctx, slog.LevelDebug,
			"httpsec: the request ended before the rate limiter answered",
			append([]slog.Attr{slog.String("flow", flow)}, diag.Failure("limiter", err)...)...)

		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed

	default:
		// One key per flow: the limiter is either answering for that flow or it
		// is not, and one record per window says so.
		logSampled(ctx, s, log, slog.LevelError, now, flow,
			"httpsec: the rate limiter could not answer",
			append([]slog.Attr{slog.String("flow", flow)}, diag.Failure("limiter", err)...)...)

		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed
	}
}

// overLimit reports whether the guard refused because the source has spent its
// allowance, rather than because it could not ask at all.
//
// The guard answers both with ErrThrottled and tells them apart by what the
// refusal carries: a source over its limit is refused with the sentinel itself,
// while a check that could not be made carries the limiter's own failure
// underneath it. So the question is whether the refusal has anything underneath
// it at all, which reads the difference without this package having to know the
// wrapping's wording.
func overLimit(err error) bool {
	if !errors.Is(err, ratelimit.ErrThrottled) {
		return false
	}

	var (
		wrapped interface{ Unwrap() error }
		joined  interface{ Unwrap() []error }
	)

	return !errors.As(err, &wrapped) && !errors.As(err, &joined)
}

// endedBeforeTheAnswer reports whether the check failed because this request's
// own context ended, rather than because the limiter is unwell.
func endedBeforeTheAnswer(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()

	return ctxErr != nil && errors.Is(err, ctxErr)
}

// recordSourceFailure counts one failure against the source that made it.
//
// It records on a context the request's cancellation does not reach: a client
// that submits a wrong credential and hangs up before the response has still
// made the attempt, and a recording that went with it would let a guesser evade
// the limit simply by not waiting for the answer. The context is otherwise
// passed through, so a limiter reaching a remote store still sees its values.
func recordSourceFailure(ctx context.Context, g sourceGuard, s ratelimit.Source) {
	g.RecordFailure(context.WithoutCancel(ctx), s)
}
