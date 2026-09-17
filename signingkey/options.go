package signingkey

import (
	"errors"
	"fmt"
	"log/slog"
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

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

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

// WithKeyStore sets where keys are persisted. Default: NewInMemoryKeyStore,
// which does not survive a restart.
func WithKeyStore(store KeyStore) Option {
	return func(km *KeyManager) { km.store = store }
}

// WithClock sets the time source. Default: the system clock.
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
	if len(km.algs) == 0 {
		return fmt.Errorf("%w: at least one algorithm is required", ErrConfig)
	}
	for _, alg := range km.algs {
		if !supportedAlg(alg) {
			return fmt.Errorf(
				"%w: unsupported algorithm %q, want one of %q, %q or %q",
				ErrConfig, alg, RS256, ES256, EdDSA)
		}
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
	return nil
}
