package signingkey

import (
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"
)

// ErrConfig is wrapped by every error NewKeyManager returns for a wiring
// mistake, so a consumer can tell a contradictory configuration from a store
// failure without matching on message text.
var ErrConfig = errors.New("signingkey: invalid configuration")

// Option configures a KeyManager. Every default NewKeyManager applies has an
// Option here that replaces it.
type Option func(*KeyManager)

// Clock is the time source the key manager reads creation times, rotation and
// housekeeping from.
//
// With no clock configured the key manager uses the system clock. A consumer
// replaces it through WithClock, which is how a test advances time without
// waiting.
type Clock interface {
	Now() time.Time
}

// Ticker delivers a tick every interval until it is stopped. It is the shape of
// time.Ticker, narrowed to what the background loops use.
type Ticker interface {
	// C returns the channel ticks arrive on. Like time.Ticker's channel, a
	// tick that is not consumed before the next one is due may be dropped.
	C() <-chan time.Time

	// Stop releases the ticker. No further tick arrives after it returns.
	Stop()
}

// TickerClock is the optional half of Clock: a time source that also paces the
// rotation, reload and housekeeping loops, so advancing it runs them without
// waiting for real time to pass.
//
// A Clock that does not implement it paces the loops with time.NewTicker, which
// is what the default system clock does. Implement it to control the cadence as
// well as the creation times — a test's clock, or a consumer coordinating the
// loops with their own scheduler.
type TickerClock interface {
	Clock

	// NewTicker returns a ticker delivering a tick every d.
	NewTicker(d time.Duration) Ticker
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTicker(d time.Duration) Ticker { return realTicker{ticker: time.NewTicker(d)} }

// realTicker adapts time.Ticker to Ticker. time.Ticker exposes its channel as a
// field, which cannot satisfy a method of the same name.
type realTicker struct{ ticker *time.Ticker }

func (r realTicker) C() <-chan time.Time { return r.ticker.C }

func (r realTicker) Stop() { r.ticker.Stop() }

// WithAlgs sets the algorithms a current key is kept for. Default: RS256 only.
// Supported: RS256, ES256 and EdDSA; anything else fails construction.
func WithAlgs(algs ...Alg) Option {
	return func(km *KeyManager) { km.algs = algs }
}

// WithLifetime sets how long a key stays published after it was created.
// Default: 24h. It must be longer than the rotation interval, or a key would
// stop being published while tokens it signed are still valid.
func WithLifetime(d time.Duration) Option {
	return func(km *KeyManager) { km.lifetime = d }
}

// WithRotateInterval sets how often a new key is minted for every configured
// algorithm. Default: 1h.
func WithRotateInterval(d time.Duration) Option {
	return func(km *KeyManager) { km.rotateEvery = d }
}

// WithHousekeepingInterval sets how often keys past their lifetime stop being
// published. Default: 1h.
func WithHousekeepingInterval(d time.Duration) Option {
	return func(km *KeyManager) { km.housekeepEvery = d }
}

// WithReloadInterval sets how often the store is reloaded, which is how
// replicas sharing a store see each other's keys. Default: 1m. It must be
// shorter than the rotation interval, or a replica would miss a rotation.
func WithReloadInterval(d time.Duration) Option {
	return func(km *KeyManager) { km.reloadEvery = d }
}

// WithLogSampleWindow sets how long one written record about a rotation or
// reload failure suppresses further records for the same operation and
// algorithm. Default: 5m.
//
// A store outage fails every interval for as long as it lasts, which without
// sampling is one record per interval. At most one record per window is
// written, and every record states how many failures were suppressed before it,
// so no failure goes unaccounted for. A window of zero or less writes every
// failure, for a consumer whose own handler samples.
//
// The error hook is never sampled: every failure reaches it.
func WithLogSampleWindow(d time.Duration) Option {
	return func(km *KeyManager) { km.sampleWindow = d }
}

// WithKeyStore sets where keys are persisted. Default: NewInMemoryKeyStore,
// which does not survive a restart.
func WithKeyStore(store KeyStore) Option {
	return func(km *KeyManager) { km.store = store }
}

// WithClock sets the time source. Default: the system clock.
//
// A clock that also implements TickerClock paces the background loops as well
// as stamping creation times; one that does not leaves the loops on
// time.NewTicker.
func WithClock(clock Clock) Option {
	return func(km *KeyManager) { km.clock = clock }
}

// WithLogger sets where rotation and reload failures are logged. Default:
// slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(km *KeyManager) { km.logger = logger }
}

// WithErrorHook sets a function called with every rotation and reload failure.
// Default: none. Use it to surface a store outage that would otherwise leave
// one key signing indefinitely.
func WithErrorHook(hook func(error)) Option {
	return func(km *KeyManager) { km.errorHook = hook }
}

// validate reports a configuration that cannot work, so a wiring mistake fails
// at construction rather than at the first rotation.
func (km *KeyManager) validate() error {
	// A nil port is caught here rather than at first use: a nil store or
	// clock would panic during construction, and a nil logger would panic in
	// a background loop at the first failure it tried to report.
	//
	// isNilPort, not == nil, because the shape a real wiring mistake produces is
	// a typed nil — `var s *myStore; WithKeyStore(s)` — and an interface holding
	// a nil pointer is not equal to nil. Comparing against nil alone accepts it
	// and panics on the first call instead.
	if isNilPort(km.store) {
		return fmt.Errorf("%w: key store must not be nil", ErrConfig)
	}

	if isNilPort(km.clock) {
		return fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}

	if isNilPort(km.logger) {
		return fmt.Errorf("%w: logger must not be nil", ErrConfig)
	}

	if len(km.algs) == 0 {
		return fmt.Errorf("%w: at least one algorithm is required", ErrConfig)
	}
	seen := make(map[Alg]struct{}, len(km.algs))

	for _, alg := range km.algs {
		if !supportedAlg(alg) {
			return fmt.Errorf(
				"%w: unsupported algorithm %q, want one of %q, %q or %q",
				ErrConfig, alg, RS256, ES256, EdDSA)
		}

		// One algorithm named twice is still one algorithm. Construction hides a
		// duplicate, because minting skips an algorithm that already has a key,
		// but rotation walks this list directly and would mint, marshal and store
		// one key per mention at every interval, growing the published set each
		// time. A concatenated config list is all it takes.
		if _, dup := seen[alg]; dup {
			return fmt.Errorf("%w: algorithm %q is named more than once", ErrConfig, alg)
		}

		seen[alg] = struct{}{}
	}

	for _, interval := range []struct {
		name  string
		value time.Duration
	}{
		{"lifetime", km.lifetime},
		{"rotate interval", km.rotateEvery},
		{"housekeeping interval", km.housekeepEvery},
		{"reload interval", km.reloadEvery},
	} {
		if interval.value <= 0 {
			return fmt.Errorf("%w: %s must be positive, got %s",
				ErrConfig, interval.name, interval.value)
		}
	}

	if km.lifetime <= km.rotateEvery {
		return fmt.Errorf(
			"%w: lifetime %s must be longer than the rotate interval %s, "+
				"or a key would stop being published while tokens it signed are still valid",
			ErrConfig, km.lifetime, km.rotateEvery)
	}
	if km.reloadEvery >= km.rotateEvery {
		return fmt.Errorf(
			"%w: reload interval %s must be shorter than the rotate interval %s, "+
				"or a replica would miss another replica's rotation",
			ErrConfig, km.reloadEvery, km.rotateEvery)
	}

	// Housekeeping is the only thing that stops publishing an expired key:
	// reload declines to re-add one, but never drops a key already held. So the
	// lifetime is only honoured to within one housekeeping interval, and an
	// interval longer than the lifetime turns the guarantee into a suggestion —
	// a 2-hour lifetime swept every 1000 hours publishes keys for hundreds of
	// times their stated life. Refused rather than quietly relaxed.
	if km.housekeepEvery > km.lifetime {
		return fmt.Errorf(
			"%w: housekeeping interval %s must not exceed the lifetime %s, "+
				"or a key would stay published long past the lifetime it was given",
			ErrConfig, km.housekeepEvery, km.lifetime)
	}

	return nil
}

// isNilPort reports whether v is nil, or a non-nil interface holding a nil
// pointer, map, slice, channel or function.
//
// A consumer's wiring mistake almost always produces the second shape, which
// == nil does not catch.
func isNilPort(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}
