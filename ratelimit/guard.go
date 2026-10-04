package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// ErrThrottled is returned by SourceGuard.Check for an attempt that must not run:
// the source is over its limit, or the limiter could not say whether it is. The
// source's IPv6 aggregate (WithSourceGuardIPv6Aggregate) being over its limit,
// or its limiter being unable to answer, refuses the same way. So does a limiter
// that is full (ErrLimiterFull): it is refused as throttled, with its own error
// still reachable, and reported as full rather than as down.
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
	sampleLimiterFull     = "full"
	sampleUnattributable  = "unattributable"
	msgThrottled          = "ratelimit: refusing an attempt from a source over its limit"
	msgThrottledAggregate = "ratelimit: refusing an attempt from an IPv6 aggregate over its limit"
	msgLimiterUnavailable = "ratelimit: refusing an attempt because the limiter could not be consulted"
	msgLimiterFull        = "ratelimit: refusing an attempt because the limiter is full"
	msgNotRecordedFull    = "ratelimit: a failed attempt was not counted because the limiter is full"
	reasonLimiterFull     = "limiter-full"
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
	clock       clock.Clock
	logInterval time.Duration
	reporter    func(key string, suppressed int)
	sampler     *logsample.Sampler

	// The IPv6 aggregate (WithSourceGuardIPv6Aggregate). aggregateSet records
	// that the option was given at all, so that a zero prefix or a nil limiter
	// passed to it is refused rather than read as "no aggregate".
	aggregateSet  bool
	aggregateBits int
	aggregate     Limiter
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
// slog.Default (WithSourceGuardLogger), clock.System() (WithSourceGuardClock),
// DefaultLogInterval for refusal sampling (WithSourceGuardLogInterval), a
// summary record through the logger for the counts sampling suppressed
// (WithSourceGuardLogReporter), and no IPv6 aggregate
// (WithSourceGuardIPv6Aggregate).
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
		clock:       clock.System(),
		logInterval: DefaultLogInterval,
	}
	g.reporter = g.reportSuppressed

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
	if err := g.validateAggregate(); err != nil {
		return nil, err
	}
	if g.logger == nil {
		return nil, fmt.Errorf("%w: the logger is nil, so refusals would go unreported", ErrConfig)
	}
	if nilcheck.IsNil(g.clock) {
		return nil, fmt.Errorf("%w: the clock is nil, so refusal records could not be sampled", ErrConfig)
	}
	if g.reporter == nil {
		return nil, fmt.Errorf(
			"%w: the summary reporter is nil, so suppressed refusal counts would be dropped", ErrConfig)
	}

	g.sampler = logsample.New(g.logInterval, logsample.WithReporter(g.reporter))

	return g, nil
}

// validateAggregate refuses an IPv6 aggregate that could not count anything the
// source key does not. It runs after the options, against the keyer the guard
// ends up with, so a consumer's own keyer is held to the same line as the
// default.
func (g *SourceGuard) validateAggregate() error {
	if !g.aggregateSet {
		return nil
	}

	if nilcheck.IsNil(g.aggregate) {
		return fmt.Errorf(
			"%w: the IPv6 aggregate for flow %q was given no limiter", ErrConfig, g.flow)
	}
	if g.aggregateBits < 1 || g.aggregateBits >= maxIPv6Prefix {
		return fmt.Errorf(
			"%w: an IPv6 aggregate of /%d is outside 1..%d, so it would either pool every "+
				"IPv6 source under one key or name a single address",
			ErrConfig, g.aggregateBits, maxIPv6Prefix-1)
	}
	if source := g.keyer.IPv6Prefix(); g.aggregateBits >= source {
		return fmt.Errorf(
			"%w: an IPv6 aggregate of /%d is no wider than the /%d source prefix, so it would "+
				"count nothing the source does not", ErrConfig, g.aggregateBits, source)
	}

	return nil
}

// Check canonicalises clientAddr and asks the limiter about it, without
// recording anything. The Source it returns is what RecordFailure takes if the
// guarded attempt then fails.
//
// It returns an error wrapping ErrSourceUnattributable when the address names no
// single source, and one wrapping ErrThrottled when the source or its IPv6
// aggregate is over its limit, or either limiter could not answer. In every one
// of those cases the guarded call must not run: the returned Source is the zero
// value, so nothing can be recorded against a check that did not pass.
//
// A limiter that could not answer has its own error returned behind fixed
// library text, never its own; ErrThrottled and the limiter's error both stay
// reachable through errors.Is, so a caller's status mapping is unchanged. A
// limiter that is full (ErrLimiterFull) is refused the same way, behind text
// that says so, and is reported as full rather than as unavailable.
func (g *SourceGuard) Check(ctx context.Context, clientAddr string) (Source, error) {
	addr, aggregate, err := g.keyer.keys(clientAddr, g.aggregateBits)
	if err != nil {
		reason := refusalReason(err)
		g.sampled(ctx, slog.LevelWarn, msgUnattributable,
			sampleKey(sampleUnattributable, g.flow, reason),
			slog.String("reason", reason))

		return Source{}, err
	}

	src := Source{key: g.flow + keySeparator + addr, addr: addr}
	if aggregate != "" {
		src.aggregateKey = g.flow + keySeparator + aggregate
		src.aggregateAddr = aggregate
	}

	exceeded, err := g.limiter.Exceeded(ctx, src.key)
	if err != nil {
		return Source{}, g.refuseUnconsultable(ctx, src, err, false)
	}

	if exceeded {
		g.sampled(ctx, slog.LevelWarn, msgThrottled,
			sampleKey(sampleThrottled, g.flow, src.addr),
			slog.String("source", src.addr))

		return Source{}, ErrThrottled
	}

	// The aggregate is asked only once the source has passed: a source already
	// over its own limit is refused either way, and asking a second limiter
	// about it would only spend a round trip on an answer that cannot change.
	if src.aggregateKey == "" {
		return src, nil
	}

	exceeded, err = g.aggregate.Exceeded(ctx, src.aggregateKey)
	if err != nil {
		return Source{}, g.refuseUnconsultable(ctx, src, err, true)
	}

	if exceeded {
		// Sampled by the aggregate, not the source: a client rotating through
		// the /64s of one aggregate is one refusal story, and keying it per
		// source would let every rotation buy a fresh record.
		g.sampled(ctx, slog.LevelWarn, msgThrottledAggregate,
			sampleKey(sampleThrottled, g.flow, src.aggregateAddr),
			slog.String("source", src.addr), slog.String("aggregate", src.aggregateAddr))

		return Source{}, ErrThrottled
	}

	return src, nil
}

// refuseUnconsultable reports a limiter that could not answer and returns the
// refusal for it. The source and the aggregate limiter share it, so an outage of
// either one fails closed in exactly the same way; fromAggregate says which one
// it was, so the record can name the aggregate when that is the limiter down.
func (g *SourceGuard) refuseUnconsultable(ctx context.Context, src Source, err error, fromAggregate bool) error {
	// A context that ended is reported as such, whatever else the error says.
	if errors.Is(err, ErrLimiterFull) && !contextCaused(ctx, err) {
		g.reportFull(ctx, msgLimiterFull, src, fromAggregate)

		return diag.Wrap(err,
			"ratelimit: too many failures from this source: the limiter is full", ErrThrottled)
	}

	g.reportUnconsultableLimiter(ctx, src, err, fromAggregate)

	return diag.Wrap(err,
		"ratelimit: too many failures from this source: the limiter could not be consulted", ErrThrottled)
}

// contextCaused reports whether err is the caller's own context ending.
func contextCaused(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()

	return ctxErr != nil && errors.Is(err, ctxErr)
}

// reportFull writes about a limiter that is holding its maximum number of keys.
// It has its own sampler family, so a flood of new sources at the cap neither
// writes a record per attempt nor takes the slot a real outage needs. The
// limiter's error is not attached: the record's reason says everything it
// could, and the error is the library's own sentinel.
func (g *SourceGuard) reportFull(ctx context.Context, msg string, s Source, fromAggregate bool) {
	attrs := []slog.Attr{slog.String("source", s.addr), slog.String("reason", reasonLimiterFull)}
	if fromAggregate {
		attrs = append(attrs, slog.String("aggregate", s.aggregateAddr))
	}

	g.sampled(ctx, slog.LevelWarn, msg, sampleKey(sampleLimiterFull, g.flow, ""), attrs...)
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

	// This path has no cancellation to blame: the guard strips it before
	// calling, so an error here is the limiter's own, and a failure that went
	// uncounted is worth a record whatever the caller's context did.
	recordCtx := context.WithoutCancel(ctx)

	if err := g.limiter.RecordFailure(recordCtx, s.key); err != nil {
		g.reportNotRecorded(ctx, err, s, false)
	}

	// The aggregate is recorded whether or not the source was. The two are
	// separate counts, often in separate stores, and letting one outage skip
	// the other would hand a rotating client exactly the allowance the
	// aggregate exists to deny. A Source is a plain value, so a caller can hand
	// this guard another guard's: without an aggregate limiter of its own there
	// is nothing here to count it in.
	if s.aggregateKey != "" && g.aggregate != nil {
		if err := g.aggregate.RecordFailure(recordCtx, s.aggregateKey); err != nil {
			g.reportNotRecorded(ctx, err, s, true)
		}
	}
}

// reportNotRecorded writes about a failure a limiter did not count. A full
// limiter goes under the full family, apart from the limiter's other failures,
// so a flood at the cap cannot take the outage record's sampling slot.
func (g *SourceGuard) reportNotRecorded(ctx context.Context, err error, s Source, fromAggregate bool) {
	if errors.Is(err, ErrLimiterFull) {
		g.reportFull(ctx, msgNotRecordedFull, s, fromAggregate)

		return
	}

	attrs := []slog.Attr{slog.String("source", s.addr)}
	if fromAggregate {
		attrs = append(attrs, slog.String("aggregate", s.aggregateAddr))
	}
	g.sampled(ctx, slog.LevelWarn, msgNotRecorded,
		sampleKey(sampleLimiterFailure, g.flow, ""), append(attrs, diag.Failure("limiter", err)...)...)
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
func (g *SourceGuard) reportUnconsultableLimiter(ctx context.Context, s Source, err error, fromAggregate bool) {
	if contextCaused(ctx, err) {
		attrs := append([]slog.Attr{
			slog.String("flow", g.flow),
			slog.String("source", s.addr),
		}, diag.Failure("limiter", err)...)

		g.logger.LogAttrs(ctx, slog.LevelDebug, msgContextEnded, attrs...)

		return
	}

	attrs := []slog.Attr{slog.String("source", s.addr)}
	if fromAggregate {
		attrs = append(attrs, slog.String("aggregate", s.aggregateAddr))
	}
	attrs = append(attrs, diag.Failure("limiter", err)...)
	g.sampled(ctx, slog.LevelWarn, msgLimiterUnavailable,
		sampleKey(sampleLimiterFailure, g.flow, ""), attrs...)
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

// reportSuppressed is the default summary reporter (WithSourceGuardLogReporter).
// It accounts for counts the sampler is about to discard, so a
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
