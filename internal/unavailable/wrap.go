// Package unavailable decides what a shared limiter does while the store it
// counts in cannot be reached.
//
// Wrap puts a decorator around a backend limiter. The decorator bounds every
// backend call with an operation timeout, stops calling a backend that has just
// failed until a probe interval has passed, and answers in the meantime from the
// consumer's chosen ratelimit.UnavailableMode. It also closes the gap a store
// that rejects writes but still answers reads would open: a failure it could not
// record is held against its key on this instance for one window.
//
// The package is internal because consumers configure it through each backend
// module's own options, never directly. It starts no goroutine and needs
// nothing stopped.
//
//go:generate mockgen -source=../../ratelimit/limiter.go -package=unavailable_test -destination=limiter_mock_test.go -typed
package unavailable

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
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	// DefaultTimeout bounds each backend call. A guarded request waits at most
	// this long for its limiter before it is refused.
	DefaultTimeout = 250 * time.Millisecond

	// DefaultProbeInterval is how long the decorator answers from its mode,
	// without calling the backend, after the backend has failed.
	DefaultProbeInterval = time.Second
)

// Config is how a backend module configures the decorator. Start from
// DefaultConfig and change what the consumer chose; Wrap refuses a field left
// at a meaningless zero rather than filling it in. LogInterval's zero is not
// meaningless: it turns sampling off, so a Config built without DefaultConfig
// writes every allow-mode outage record.
type Config struct {
	// Mode is what the limiter does while the backend is unavailable.
	// Default: ratelimit.UnavailableRefuse.
	Mode ratelimit.UnavailableMode

	// Timeout bounds each backend call, records included, even when the
	// caller's context carries no deadline or has had its cancellation
	// stripped, if the backend honours its context's deadline. Default:
	// DefaultTimeout, 250ms.
	//
	// Only a call cut off by this timeout counts as an outage. A caller whose
	// own deadline ends first has ended, and its call never opens the breaker,
	// so against a hung backend each such caller waits its own deadline on
	// every check. A deployment whose request deadlines are shorter than this
	// timeout lowers the timeout below them.
	Timeout time.Duration

	// ProbeInterval is how long the limiter answers from Mode without calling
	// the backend after an unavailable error, in every mode; then one call
	// probes. Default: DefaultProbeInterval, 1s.
	ProbeInterval time.Duration

	// Clock is what the probe interval and the record-error hold are measured
	// by, and what the fall-back limiter stamps with. Default: clock.System().
	Clock clock.Clock

	// Logger receives the degraded-mode transition records. Default:
	// slog.Default().
	Logger *slog.Logger

	// LogInterval is how long, in UnavailableAllow mode, one written outage
	// record suppresses further ones for the namespace. Each written record,
	// and a summary when the backend is back, carries how many were
	// suppressed. Zero or less writes every record, for a consumer whose own
	// handler samples. Default: ratelimit.DefaultLogInterval, one minute.
	LogInterval time.Duration
}

// DefaultConfig returns the configuration every default above describes.
func DefaultConfig() Config {
	return Config{
		Mode:          ratelimit.UnavailableRefuse,
		Timeout:       DefaultTimeout,
		ProbeInterval: DefaultProbeInterval,
		Clock:         clock.System(),
		Logger:        slog.Default(),
		LogInterval:   ratelimit.DefaultLogInterval,
	}
}

// Wrap returns backend decorated with the unavailable handling cfg describes,
// for one namespace's limit and window. The limit and window are the ones the
// backend counts with; the fall-back mode counts locally with the same pair, and
// the record-error hold lasts one window.
//
// The backend must honour its context's deadline: the operation timeout is
// applied through the context, and a backend that ignores it is not bounded by
// it.
//
// A nil backend (typed nil included), an empty namespace, a non-positive limit,
// window, timeout or probe interval, an unknown mode, or a nil clock or logger
// is an error wrapping ratelimit.ErrConfig.
func Wrap(backend ratelimit.Limiter, namespace string, limit int, window time.Duration, cfg Config) (ratelimit.Limiter, error) {
	if err := validate(backend, namespace, limit, window, cfg); err != nil {
		return nil, err
	}

	l := &limiter{
		backend:   backend,
		namespace: namespace,
		mode:      cfg.Mode,
		timeout:   cfg.Timeout,
		clock:     cfg.Clock,
		logger:    cfg.Logger,
		breaker:   &breaker{clock: cfg.Clock, interval: cfg.ProbeInterval},
		hold:      newHold(cfg.Clock, window),
	}
	if cfg.Mode == ratelimit.UnavailableAllow {
		l.sampler = logsample.New(cfg.LogInterval, logsample.WithReporter(l.reportSuppressed))
	}

	if cfg.Mode == ratelimit.UnavailableFallBackToLocal {
		// The local limiter's per-replica warning is silenced: its
		// multiplication applies only while the backend is down, and the
		// transition records say so when it does.
		local, err := ratelimit.NewMemoryLimiter(limit, window,
			ratelimit.WithMemoryLimiterClock(cfg.Clock),
			ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
		if err != nil {
			return nil, err
		}
		l.local = local
	}

	return l, nil
}

func validate(backend ratelimit.Limiter, namespace string, limit int, window time.Duration, cfg Config) error {
	switch {
	case nilcheck.IsNil(backend):
		return fmt.Errorf("%w: the backend limiter is nil", ratelimit.ErrConfig)
	case namespace == "":
		return fmt.Errorf("%w: the namespace is empty", ratelimit.ErrConfig)
	case limit <= 0:
		return fmt.Errorf("%w: a limit of %d throttles every source from its first attempt", ratelimit.ErrConfig, limit)
	case window <= 0:
		return fmt.Errorf("%w: a window of %s counts no failure at all", ratelimit.ErrConfig, window)
	case !knownMode(cfg.Mode):
		return fmt.Errorf("%w: unknown unavailable mode %d", ratelimit.ErrConfig, int(cfg.Mode))
	case cfg.Timeout <= 0:
		return fmt.Errorf("%w: an operation timeout of %s bounds nothing", ratelimit.ErrConfig, cfg.Timeout)
	case cfg.ProbeInterval <= 0:
		return fmt.Errorf("%w: a probe interval of %s would call a failed backend on every request",
			ratelimit.ErrConfig, cfg.ProbeInterval)
	case nilcheck.IsNil(cfg.Clock):
		return fmt.Errorf("%w: the clock is nil", ratelimit.ErrConfig)
	case cfg.Logger == nil:
		return fmt.Errorf("%w: the logger is nil, so outage records would be lost", ratelimit.ErrConfig)
	}

	return nil
}

func knownMode(m ratelimit.UnavailableMode) bool {
	switch m {
	case ratelimit.UnavailableRefuse, ratelimit.UnavailableFallBackToLocal, ratelimit.UnavailableAllow:
		return true
	default:
		return false
	}
}

// Messages of the degraded-mode records. They are fixed so that an operator's
// alert can match them.
const (
	msgFallBack  = "ratelimit: backend unavailable, counting locally"
	msgAllow     = "ratelimit: backend unavailable, allowing every attempt"
	msgRecovered = "ratelimit: backend available again"
	msgAllowSupp = "ratelimit: backend unavailable records suppressed"
)

// limiter is the decorator Wrap returns.
type limiter struct {
	backend   ratelimit.Limiter
	namespace string
	mode      ratelimit.UnavailableMode
	timeout   time.Duration
	clock     clock.Clock
	logger    *slog.Logger
	breaker   *breaker
	// hold is consulted and filled in refuse mode only.
	hold *hold
	// local counts in fall-back mode; nil in the other modes.
	local *ratelimit.MemoryLimiter
	// sampler bounds allow mode's outage records to one per window; nil in
	// the other modes.
	sampler *logsample.Sampler
}

// errHeld is refuse mode's answer for a key whose failure could not be
// recorded within the last window.
var errHeld = fmt.Errorf("%w: a failure for this key could not be recorded", ratelimit.ErrBackendUnavailable)

// Exceeded asks the backend under the operation timeout, or answers from the
// mode while the breaker is open.
//
// A caller context that has already ended is answered true with its error,
// before anything else and in every mode: a caller that hung up is not an
// outage, and is never answered from a degraded mode.
func (l *limiter) Exceeded(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, fmt.Errorf("ratelimit: check abandoned: %w", err)
	}

	if l.mode == ratelimit.UnavailableRefuse && l.hold.held(key) {
		return true, errHeld
	}

	adm, pass := l.breaker.allow()
	if !pass {
		return l.degradedExceeded(ctx, key, ratelimit.ErrBackendUnavailable, true)
	}

	exceeded, err := l.checkBackend(ctx, key, adm)
	switch {
	case err == nil:
		l.succeeded(ctx, adm)
		return l.healthyExceeded(ctx, key, exceeded)
	case ctx.Err() != nil:
		// The caller ended first, its own deadline included: that is not
		// an outage, so the breaker is left as it was.
		l.breaker.abandon(adm)
		return true, diag.Wrap(err, "ratelimit: check abandoned: the caller's context ended")
	default:
		current := l.failed(ctx, adm, err)
		return l.degradedExceeded(ctx, key, unavailableError(err), current)
	}
}

// checkBackend asks the backend under the operation timeout. A backend call
// that panics abandons adm before the panic continues, so a panicking probe
// cannot leave the breaker waiting for an outcome that never comes.
func (l *limiter) checkBackend(ctx context.Context, key string, adm admission) (exceeded bool, err error) {
	callCtx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	returned := false
	defer func() {
		if !returned {
			l.breaker.abandon(adm)
		}
	}()

	exceeded, err = l.backend.Exceeded(callCtx, key)
	returned = true

	return exceeded, err
}

// RecordFailure records through the backend under the operation timeout alone,
// or records according to the mode when the backend is unavailable. The
// caller's cancellation is stripped, because a caller that hangs up must still
// be charged for its attempt.
func (l *limiter) RecordFailure(ctx context.Context, key string) error {
	adm, pass := l.breaker.allow()
	if !pass {
		return l.degradedRecord(ctx, key, ratelimit.ErrBackendUnavailable, true)
	}

	if err := l.recordBackend(ctx, key, adm); err != nil {
		// A stale failure leaves the breaker alone, but its failure still
		// went unrecorded, so the mode handles it all the same: refuse mode
		// holds the key, since the hold protects its count, and fall-back
		// mode counts it locally. Only the outage record is left out.
		current := l.failed(ctx, adm, err)
		return l.degradedRecord(ctx, key, unavailableError(err), current)
	}
	l.succeeded(ctx, adm)

	return nil
}

// recordBackend records through the backend under the operation timeout alone.
// A backend call that panics abandons adm before the panic continues, as in
// checkBackend.
func (l *limiter) recordBackend(ctx context.Context, key string, adm admission) error {
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.timeout)
	defer cancel()

	returned := false
	defer func() {
		if !returned {
			l.breaker.abandon(adm)
		}
	}()

	err := l.backend.RecordFailure(callCtx, key)
	returned = true

	return err
}

// healthyExceeded is the answer when the backend answered. In fall-back mode a
// key is also exceeded on the failures this instance counted locally while it
// could not record them.
//
// A local count that an outage filled refuses the keys it does not hold, but it
// holds no failure for them either, so here such a key counts zero locally and
// the backend's answer stands. Refusing it would let one past outage refuse
// every new source for as long as the local count stayed full.
func (l *limiter) healthyExceeded(ctx context.Context, key string, shared bool) (bool, error) {
	if shared || l.local == nil {
		return shared, nil
	}

	exceeded, err := l.localExceeded(ctx, key)
	if errors.Is(err, ratelimit.ErrLimiterFull) {
		return false, nil
	}

	return exceeded, err
}

// localExceeded asks the fall-back limiter. Its error is either a full local
// count, which refuses a key it does not hold, or the caller's context ending.
// Both quote the key, so each is returned behind fixed text.
func (l *limiter) localExceeded(ctx context.Context, key string) (bool, error) {
	exceeded, err := l.local.Exceeded(ctx, key)
	switch {
	case err == nil:
		return exceeded, nil
	case errors.Is(err, ratelimit.ErrLimiterFull):
		return true, diag.Wrap(err, "ratelimit: the local count is holding its maximum number of keys")
	default:
		return true, diag.Wrap(err, "ratelimit: check abandoned: the caller's context ended")
	}
}

// degradedExceeded answers a check the backend cannot: refuse mode with err,
// which wraps ratelimit.ErrBackendUnavailable; fall-back mode from the local
// count, which refuses a key it does not hold once it is full, so that an
// outage long enough to fill it still fails closed; allow mode with "not
// exceeded", writing its outage record only when outage is set. A stale failure clears it: it reports an outage that has
// already ended, and logging it while the breaker is closed would take the
// sampling slot recovery freed, so the next outage would go unlogged.
func (l *limiter) degradedExceeded(ctx context.Context, key string, err error, outage bool) (bool, error) {
	switch l.mode {
	case ratelimit.UnavailableFallBackToLocal:
		return l.localExceeded(ctx, key)
	case ratelimit.UnavailableAllow:
		if outage {
			l.logAllowing(ctx)
		}
		return false, nil
	default:
		return true, err
	}
}

// degradedRecord handles a failure the backend could not record: refuse mode
// holds the key and returns err; fall-back mode counts it locally; allow mode
// drops it, writing its outage record only when outage is set, as in
// degradedExceeded.
func (l *limiter) degradedRecord(ctx context.Context, key string, err error, outage bool) error {
	switch l.mode {
	case ratelimit.UnavailableFallBackToLocal:
		if err := l.local.RecordFailure(ctx, key); err != nil {
			return diag.Wrap(err, "ratelimit: local count failed")
		}
		return nil
	case ratelimit.UnavailableAllow:
		if outage {
			l.logAllowing(ctx)
		}
		return nil
	default:
		l.hold.add(key)
		return err
	}
}

// failed reports an unavailable error to the breaker, and reports whether the
// failure was current rather than stale (see breaker.failure). When it opened a
// closed breaker, fall-back mode logs the move to local counting; a stale
// failure never opens it, so it is never logged. Allow mode's record is written
// by the degraded answer that follows, under its sampler, for a current failure
// only. Refuse mode writes nothing: it does not degrade, and the guard reports
// each refusal.
func (l *limiter) failed(ctx context.Context, adm admission, err error) (current bool) {
	opened, current := l.breaker.failure(adm)
	if !opened || l.mode != ratelimit.UnavailableFallBackToLocal {
		return current
	}

	attrs := append([]slog.Attr{slog.String("namespace", l.namespace)}, diag.Failure("backend", err)...)
	l.logger.LogAttrs(ctx, slog.LevelError, msgFallBack, attrs...)

	return current
}

// succeeded reports a backend answer to the breaker. When the probe closed it,
// a degrading mode logs that it is counting through the backend again, and
// allow mode first reports what its last sampling window suppressed, then
// forgets its sampling so that the next outage is logged at once.
//
// The records are written after the breaker lock is released, so that no
// handler runs under it. Under a race at recovery their order is therefore not
// guaranteed: a call that reopens the breaker between the close and the flush
// can have its outage record suppressed and counted into the summary, or
// written, either way before "available again", so the new outage reads as if
// it preceded the recovery.
func (l *limiter) succeeded(ctx context.Context, adm admission) {
	if !l.breaker.success(adm) || l.mode == ratelimit.UnavailableRefuse {
		return
	}

	l.sampler.Flush()
	l.logger.LogAttrs(ctx, slog.LevelWarn, msgRecovered, slog.String("namespace", l.namespace))
}

// logAllowing writes allow mode's outage record, at most once per sampling
// window for the namespace, carrying how many unlimited answers the window
// suppressed.
func (l *limiter) logAllowing(ctx context.Context) {
	write, suppressed := l.sampler.Allow(l.namespace, l.clock.Now())
	if !write {
		return
	}

	l.logger.LogAttrs(ctx, slog.LevelError, msgAllow,
		slog.String("namespace", l.namespace), slog.Int("suppressed", suppressed))
}

// reportSuppressed is allow mode's sampler reporter: one record carrying the
// outage records suppressed for the namespace that no later written record
// counts, written when the backend is back or when the count ages out. It runs
// on the goroutine whose call triggered it, with no request context of its own.
func (l *limiter) reportSuppressed(namespace string, suppressed int) {
	l.logger.LogAttrs(context.Background(), slog.LevelWarn, msgAllowSupp,
		slog.String("namespace", namespace), slog.Int("suppressed", suppressed))
}

// unavailableError is what refuse mode returns: fixed text, matching
// ratelimit.ErrBackendUnavailable, with the backend's own error still reachable
// through errors.Is and errors.As but never in the text.
func unavailableError(err error) error {
	return diag.Wrap(err, "ratelimit: backend unavailable", ratelimit.ErrBackendUnavailable)
}

var _ ratelimit.Limiter = (*limiter)(nil)
