package seal

import "fmt"

// options holds what an Option configures on a sealing store.
type options struct {
	resealOnRead bool
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
// store, refusing a nil option, and refusing re-sealing on read, the default,
// when the store has no resealer to re-seal through.
func newOptions(store string, hasResealer bool, opts []Option) (options, error) {
	o := options{resealOnRead: true}
	for _, opt := range opts {
		if opt == nil {
			return options{}, fmt.Errorf("%w: a sealing store option is nil", ErrInvalidConfiguration)
		}
		opt(&o)
	}

	if o.resealOnRead && !hasResealer {
		return options{}, fmt.Errorf("%w: the sealing %s store re-seals on read but has no resealer",
			ErrInvalidConfiguration, store)
	}

	return o, nil
}
