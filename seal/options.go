package seal

import (
	"fmt"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// options holds what an Option configures on a sealing store.
type options struct {
	resealOnRead bool
	clock        clock.Clock

	// clockSet and nilClock record what WithClock was given, so newOptions
	// can refuse a clock the store does not use, or a nil one.
	clockSet bool
	nilClock bool
}

// Option configures a sealing store built by NewSigningKeyStore or
// NewEnrolmentStore.
type Option func(*options)

// WithResealOnRead turns re-sealing on read on or off. The default is on.
//
// When it is on, a read that opens a value under a key other than the
// cipher's active key seals the value again under the active key and hands
// the old and the new value to the store's re-seal port, which replaces the
// stored value only if it still holds the old one. A failed re-seal never
// fails the read. Re-sealing is what lets an operator retire a key: a retired
// key is provably unused only once every value sealed under it has been
// rewritten, and re-sealing on read rewrites every value that is read.
//
// Turning it off leaves stored values as they are: a value sealed under a
// retired key stays sealed under it, and keeps needing that key, until the
// record is next written.
func WithResealOnRead(on bool) Option {
	return func(o *options) { o.resealOnRead = on }
}

// newOptions applies opts over the defaults for the sealing store named
// store, refusing a nil option, re-sealing on read, the default, when the
// store has no resealer to re-seal through, a nil clock, and any clock when
// the store keeps no clock (usesClock false).
func newOptions(store string, hasResealer, usesClock bool, opts []Option) (options, error) {
	o := options{resealOnRead: true, clock: clock.System()}
	for _, opt := range opts {
		if opt == nil {
			return options{}, fmt.Errorf("%w: a sealing store option is nil", ErrInvalidConfiguration)
		}
		opt(&o)
	}

	switch {
	case o.clockSet && !usesClock:
		return options{}, fmt.Errorf("%w: the sealing %s store judges no time and takes no clock",
			ErrInvalidConfiguration, store)
	case o.nilClock:
		return options{}, fmt.Errorf("%w: the sealing %s store's clock is nil", ErrInvalidConfiguration, store)
	}

	if o.resealOnRead && !hasResealer {
		return options{}, fmt.Errorf("%w: the sealing %s store re-seals on read but has no resealer",
			ErrInvalidConfiguration, store)
	}

	return o, nil
}

// WithClock replaces the clock NewEnrolmentStore judges an emailed code's
// expiry by. The default is clock.System().
//
// A code is expired from its EmailCodeUntil instant on, and an expired code
// is not opened on read: it is returned as no code, its expiry kept.
//
// The expiry is set, and each attempt charged, by the enrolling method's own
// clock (mfa.WithClock for TOTP). Give this store the same clock: one that
// runs ahead of the method's reads a live code as none, and a correct code is
// then charged an attempt and refused.
//
// NewSigningKeyStore judges no time, so given to it WithClock is a
// configuration error rather than a setting silently ignored. A nil clock,
// typed nil included, is a configuration error too, rather than a silent
// fallback to the wall clock: a caller passing one meant to inject a clock.
func WithClock(clk clock.Clock) Option {
	return func(o *options) {
		o.clockSet = true
		o.nilClock = nilcheck.IsNil(clk)
		o.clock = clk
	}
}
