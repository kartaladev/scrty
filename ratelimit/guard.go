package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// ErrThrottled is returned by SourceGuard.Check for an attempt that must not run:
// the source is over its limit, or the limiter could not say whether it is.
//
// The two are deliberately one error to the caller. A caller that told them
// apart would be deciding, on the request path, whether an outage is a good
// enough reason to allow an attempt it was asked to limit — and the only safe
// answer is the one this package already made.
var ErrThrottled = errors.New("ratelimit: too many failures from this source")

// DefaultLogInterval is how long one written refusal record suppresses further
// records about the same flow, source and reason. It is a minute because that is
// short enough to show an attack as it happens and long enough that the attack
// cannot pay for the logging.
const DefaultLogInterval = time.Minute

// keySeparator joins the flow name to the canonical source in a limiter key.
const keySeparator = ":"

// The sampler key families. Each refusal kind is sampled apart from the others,
// so a flood of one cannot suppress the records of another.
const (
	sampleThrottled       = "throttled"
	sampleLimiterFailure  = "limiter"
	sampleUnattributable  = "unattributable"
	msgThrottled          = "ratelimit: refusing an attempt from a source over its limit"
	msgLimiterUnavailable = "ratelimit: refusing an attempt because the limiter could not be consulted"
	msgContextEnded       = "ratelimit: refusing an attempt whose context had already ended"
	msgUnattributable     = "ratelimit: refusing an attempt from an unattributable client address"
	msgNotRecorded        = "ratelimit: a failed attempt was not counted"
	msgNoSource           = "ratelimit: not recording a failure for a source that did not come from Check"
	msgSuppressed         = "ratelimit: refusal records suppressed"
)

// SourceGuard checks a source before a guarded flow runs and counts the flow's
// failures afterwards, both under one key.
//
// The two steps are separate because only the calling flow knows what counts as
// a failure: a wrong password, a redemption refused for a policy reason, an
// unknown identity. The guard supplies the key and the decision, never the
// judgement.
//
// # Limits, stated
//
// Because checking and recording are separate, a burst of concurrent attempts
// from one source can exceed the limit by up to the burst's concurrency: each
// attempt may pass the check before any of them has recorded. A limit of 5 under
// a burst of 8 therefore admits up to 13 attempts before the source is refused.
// The limit bounds sustained failure, which is what a guessing attack is; it is
// not a semaphore, and making it one would put a lock across the guarded call.
//
// Counts are shared by exactly the guards built over the same Limiter with the
// same flow name. Two guards over one limiter with different flow names keep
// separate counts, and two over separate limiters always do.
//
// A SourceGuard is safe for concurrent use.
type SourceGuard struct {
	flow        string
	limiter     Limiter
	keyer       *SourceKeyer
	logger      *slog.Logger
	clock       Clock
	logInterval time.Duration
	sampler     *logsample.Sampler
}

// NewSourceGuard returns a guard that counts flow's failures in limiter.
//
// The flow name becomes part of every key the guard reads and writes, so a
// source that exhausts one flow's allowance still has its own in another. It is
// joined to the canonical source with a colon; a consumer sharing one limiter
// between flows keeps its flow names free of colons so that two flows cannot
// compose the same key.
//
// An empty flow name, or a missing limiter — including an interface holding a
// nil pointer, which is what an unchecked constructor result looks like — is a
// configuration error wrapping ErrConfig. A guard without a limiter would let
// every attempt through while reading, at the call site, exactly like one that
// limits, so it is refused at wiring time rather than discovered under attack.
//
// Defaults: a SourceKeyer with its own defaults (WithSourceGuardKeyer),
// slog.Default (WithSourceGuardLogger), the system clock (WithSourceGuardClock)
// and DefaultLogInterval for refusal sampling (WithSourceGuardLogInterval).
func NewSourceGuard(flow string, limiter Limiter, opts ...GuardOption) (*SourceGuard, error) {
	keyer, err := NewSourceKeyer()
	if err != nil {
		return nil, fmt.Errorf("ratelimit: default source keyer: %w", err)
	}

	g := &SourceGuard{
		flow:        flow,
		limiter:     limiter,
		keyer:       keyer,
		logger:      slog.Default(),
		clock:       systemClock{},
		logInterval: DefaultLogInterval,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}

	if g.flow == "" {
		return nil, fmt.Errorf(
			"%w: a guard needs a flow name, or its counts would be indistinguishable from "+
				"every other flow sharing the limiter", ErrConfig)
	}
	if nilcheck.IsNil(g.limiter) {
		return nil, fmt.Errorf(
			"%w: a guard for flow %q was given no limiter, so it would refuse nothing",
			ErrConfig, g.flow)
	}
	if g.keyer == nil {
		return nil, fmt.Errorf("%w: the source keyer is nil, so no address could be keyed", ErrConfig)
	}
	if g.logger == nil {
		return nil, fmt.Errorf("%w: the logger is nil, so refusals would go unreported", ErrConfig)
	}
	if g.clock == nil {
		return nil, fmt.Errorf("%w: the clock is nil, so refusal records could not be sampled", ErrConfig)
	}

	g.sampler = logsample.New(g.logInterval, logsample.WithReporter(g.reportSuppressed))

	return g, nil
}

// Check canonicalises clientAddr and asks the limiter about it, without
// recording anything. The Source it returns is what RecordFailure takes if the
// guarded attempt then fails.
//
// It returns an error wrapping ErrSourceUnattributable when the address names no
// single source, and one wrapping ErrThrottled when the source is over its limit
// or the limiter could not answer. In every one of those cases the guarded call
// must not run: the returned Source is the zero value, so nothing can be
// recorded against a check that did not pass.
func (g *SourceGuard) Check(ctx context.Context, clientAddr string) (Source, error) {
	addr, err := g.keyer.Key(clientAddr)
	if err != nil {
		reason := refusalReason(err)
		g.sampled(ctx, slog.LevelWarn, msgUnattributable,
			sampleKey(sampleUnattributable, g.flow, reason),
			slog.String("reason", reason))

		return Source{}, err
	}

	src := Source{key: g.flow + keySeparator + addr, addr: addr}

	exceeded, err := g.limiter.Exceeded(ctx, src.key)
	if err != nil {
		g.reportUnconsultableLimiter(ctx, src, err)

		return Source{}, fmt.Errorf("%w: the limiter could not be consulted: %w", ErrThrottled, err)
	}

	if exceeded {
		g.sampled(ctx, slog.LevelWarn, msgThrottled,
			sampleKey(sampleThrottled, g.flow, src.addr),
			slog.String("source", src.addr))

		return Source{}, ErrThrottled
	}

	return src, nil
}

// RecordFailure counts one failure against the source a Check returned. Which
// outcomes are failures is the calling flow's decision: a refused redemption of
// a credential that was itself valid counts exactly as a wrong guess does, if
// the flow says so.
//
// It takes the source rather than an address so that the key it writes is the
// key the check read, and a zero Source counts nothing — inventing a key would
// charge the failure to a source that made no attempt.
//
// The caller's cancellation is not passed on. A client that hangs up
// mid-attempt must still be charged for the guess it already made, and the
// alternative is an attacker that never pays for a failure it aborts. The
// context is otherwise passed through, so a Limiter reaching a remote store sees
// its values and must bound its own I/O rather than rely on a deadline that is
// no longer there.
//
// It returns nothing. A recording that fails is an outage of the limiter, not a
// judgement about this attempt, and there is nothing a calling flow could
// usefully do with it on the path of a request that has already failed — so it
// is logged, through the same sampler as the refusals.
func (g *SourceGuard) RecordFailure(ctx context.Context, s Source) {
	if s.key == "" {
		g.logger.LogAttrs(ctx, slog.LevelWarn, msgNoSource, slog.String("flow", g.flow))

		return
	}

	if err := g.limiter.RecordFailure(context.WithoutCancel(ctx), s.key); err != nil {
		// This path has no cancellation to blame: the guard stripped it before
		// calling, so an error here is the limiter's own, and a failure that
		// went uncounted is worth a record whatever the caller's context did.
		g.sampled(ctx, slog.LevelWarn, msgNotRecorded,
			sampleKey(sampleLimiterFailure, g.flow, ""),
			slog.String("source", s.addr),
			slog.String("error", err.Error()))
	}
}

// Flush reports every suppressed refusal count the guard is still holding, for
// example at shutdown. Without it a burst that ends before its window does would
// take its own tally with it, and the record of an attack would understate it.
func (g *SourceGuard) Flush() { g.sampler.Flush() }

// reportUnconsultableLimiter writes about a check that could not be made.
//
// A failure the caller's own context caused is written at debug level and
// without sampling: a client that hung up is not an incident, and sampling it
// would let ordinary disconnections consume the window that a real outage needs.
// Everything else is an outage on a path that is now refusing live traffic, and
// is written at warning level under one sampler key per flow — the limiter is
// either up for that flow or it is not, and one record per window says so.
func (g *SourceGuard) reportUnconsultableLimiter(ctx context.Context, s Source, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		g.logger.LogAttrs(ctx, slog.LevelDebug, msgContextEnded,
			slog.String("flow", g.flow),
			slog.String("source", s.addr),
			slog.String("error", err.Error()))

		return
	}

	g.sampled(ctx, slog.LevelWarn, msgLimiterUnavailable,
		sampleKey(sampleLimiterFailure, g.flow, ""),
		slog.String("source", s.addr),
		slog.String("error", err.Error()))
}

// sampled writes one record unless the sampler is holding this key's window
// open, in which case the event is counted and reported later. Every written
// record says how many events it stands for, so a suppressed burst is never
// silently lost.
func (g *SourceGuard) sampled(ctx context.Context, level slog.Level, msg, key string, attrs ...slog.Attr) {
	write, suppressed := g.sampler.Allow(key, g.clock.Now())
	if !write {
		return
	}

	g.logger.LogAttrs(ctx, level, msg,
		append(attrs, slog.String("flow", g.flow), slog.Int("suppressed", suppressed))...)
}

// reportSuppressed accounts for counts the sampler is about to discard, so a
// burst that stops before its window elapses is still reported in full. It runs
// on the goroutine that triggered the eviction, so it only writes one record.
func (g *SourceGuard) reportSuppressed(key string, suppressed int) {
	g.logger.LogAttrs(context.Background(), slog.LevelWarn, msgSuppressed,
		slog.String("flow", g.flow),
		slog.String("key", key),
		slog.Int("suppressed", suppressed))
}

// sampleKey composes a sampler key from the refusal kind, the flow and whatever
// distinguishes one refusal of that kind from another — the source, or the
// reason it could not be attributed. Keeping the kind in the key is what stops a
// flood of one refusal kind suppressing the records of another.
func sampleKey(kind, flow, detail string) string {
	return kind + keySeparator + flow + keySeparator + detail
}
