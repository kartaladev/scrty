package httpsec

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// SamplerProbe writes sampled records through one component's sampler and
// flushes it, so a test shows where a key's summary goes without driving a
// whole request.
type SamplerProbe struct {
	Log   func(ctx context.Context, key string)
	Flush func()
}

// ChainSamplerProbe probes the chain's own refusal sampler.
func ChainSamplerProbe(c *Chain) *SamplerProbe {
	return &SamplerProbe{
		Log: func(ctx context.Context, key string) {
			logSampled(ctx, c.sampler, c.logger, slog.LevelInfo, time.Now(), key, "probe")
		},
		Flush: c.sampler.Flush,
	}
}

// RecoverySamplerProbe probes the recovery endpoints' own sampler, wired the
// way the chain wires it, over a chain whose logger is log.
func RecoverySamplerProbe(log *slog.Logger, interval time.Duration) *SamplerProbe {
	i := &recoveryInterceptor{logInterval: interval}
	i.wire(&Chain{logger: log})

	return &SamplerProbe{
		Log: func(ctx context.Context, key string) {
			logSampled(ctx, i.sampler, i.log, slog.LevelInfo, time.Now(), key, "probe")
		},
		Flush: i.sampler.Flush,
	}
}

// EnrolmentSamplerProbe probes the enrolment path's own sampler.
func EnrolmentSamplerProbe(log *slog.Logger, interval time.Duration) *SamplerProbe {
	i := &enrolmentInterceptor{logInterval: interval}
	i.wire(&Chain{logger: log})

	return &SamplerProbe{
		Log: func(ctx context.Context, key string) {
			logSampled(ctx, i.sampler, i.log, slog.LevelInfo, time.Now(), key, "probe")
		},
		Flush: i.sampler.Flush,
	}
}

// PasskeySamplerProbe probes the passwordless endpoints' sampler, which
// reports through the chain's reporter.
func PasskeySamplerProbe(log *slog.Logger, interval time.Duration) *SamplerProbe {
	c := &config{logger: log}
	chain := &Chain{logger: log, reportRefusals: c.refusalLogReporter()}
	sampler := newPasswordlessSampler(chain, interval)

	return &SamplerProbe{
		Log: func(ctx context.Context, key string) {
			logSampled(ctx, sampler, log, slog.LevelInfo, time.Now(), key, "probe")
		},
		Flush: sampler.Flush,
	}
}

// AbortKey is the sampling key a classification abort (a panic) uses, so a
// test can find its summary.
const AbortKey = classificationAbortedKeyPrefix + "panic"

// ChainAbortProbe samples a classification-abort record through the chain's
// own sampler and flushes it, so a test shows where the abort key's summary
// goes. Log ignores its key: every abort of one reason shares AbortKey.
func ChainAbortProbe(c *Chain) *SamplerProbe {
	abort := &errwalk.PanicError{Value: "probe"}

	return &SamplerProbe{
		Log: func(ctx context.Context, _ string) {
			reportAbortSampled(ctx, c.sampler, c.logger, time.Now(), abort)
		},
		Flush: c.sampler.Flush,
	}
}

// GuardSamplerProbe probes a source guard built the way the chain builds one
// (resolveSourceGuard) over a chain whose logger is log, or the routing
// default when log is nil, and whose refusal reporter is report, or the
// default when nil. Log refuses the client address key, which is over its
// limit.
func GuardSamplerProbe(log *slog.Logger, report func(key string, suppressed int)) (*SamplerProbe, error) {
	c := &config{
		logger:     ctxlog.Routing(),
		ipv6Prefix: defaultIPv6SourcePrefix,

		aggregateBits:       defaultIPv6AggregatePrefix,
		aggregateMultiplier: defaultIPv6AggregateMultiplier,

		clock:           clock.System(),
		refusalReporter: report,
	}
	if log != nil {
		c.logger = log
	}

	keyer, err := ratelimit.NewSourceKeyer(ratelimit.WithIPv6SourcePrefix(c.ipv6Prefix))
	if err != nil {
		return nil, err
	}

	c.keyer = keyer

	limiter, err := ratelimit.NewMemoryLimiter(1, time.Hour)
	if err != nil {
		return nil, err
	}

	guard, err := c.resolveSourceGuard("probe", "probe", limiter, 1, time.Hour, time.Hour)
	if err != nil {
		return nil, err
	}

	return &SamplerProbe{
		Log: func(ctx context.Context, addr string) {
			// Spend the limit, then be refused: the refusal is the sampled record.
			for range 2 {
				if src, err := guard.Check(ctx, addr); err == nil {
					guard.RecordFailure(ctx, src)
				}
			}

			_, _ = guard.Check(ctx, addr)
		},
		Flush: guard.Flush,
	}, nil
}
