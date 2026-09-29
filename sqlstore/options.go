package sqlstore

import (
	"database/sql"
	"fmt"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// optionKind names an option a store may honour beyond WithTxResolver, which
// every store honours. A store declares its set in one call:
//
//	c, err := newConfig(db, opts, optIDGenerator, optClock)
type optionKind uint8

const (
	optIDGenerator optionKind = 1 << iota
	optClock
	optResealOnRead
)

// config is what every store in this package shares: the handle it was
// constructed with and the options applied over the defaults.
type config struct {
	base         *sql.DB
	resolver     TxResolver
	ids          id.Generator
	clock        clock.Clock
	resealOnRead bool

	// honours is the set of optionKinds the constructing store declared.
	honours optionKind

	// problem is the first wiring mistake recorded. A later option, valid or
	// not, never replaces it, so the error names the first problem only.
	problem string
}

// refuse records problem unless an earlier one is already recorded.
func (c *config) refuse(problem string) {
	if c.problem == "" {
		c.problem = problem
	}
}

// applies reports whether the store honours the option of kind k, named name,
// and records a refusal naming the option when it does not.
func (c *config) applies(k optionKind, name string) bool {
	if c.honours&k == 0 {
		c.refuse(name + " does not apply to this store")
		return false
	}

	return true
}

// Option configures a store. Every store honours WithTxResolver; each other
// option is honoured only by the stores its godoc names. An option given to a
// store that does not honour it is a configuration error from the
// constructor, never silently ignored.
type Option func(*config)

// WithTxResolver replaces how a store finds the caller's transaction. The
// default, with no resolver, is the transaction attached to the operation's
// context with WithTx, and the constructed *sql.DB when none is attached.
// Every store honours it.
//
// A configured resolver replaces that context lookup entirely: when it reports
// a transaction the store uses it, and when it reports none the store uses its
// *sql.DB, even if a transaction was attached with WithTx. A resolver that
// reports a transaction with a nil handle makes the operation fail with
// ErrNilTransaction before any statement runs. A nil resolver is a
// configuration error, rather than a silent fallback to the context lookup: a
// caller passing one meant their transaction manager to be asked.
func WithTxResolver(r TxResolver) Option {
	return func(c *config) {
		if r == nil {
			c.refuse("the transaction resolver is nil")
			return
		}
		c.resolver = r
	}
}

// WithIDGenerator replaces the source of the identifiers a store mints for
// records that carry none of their own. It is honoured by the minting stores:
// sessions, signing keys, login attempts, MFA enrolments, OIDC flows, and the
// identity store (the users, role grants and password-history entries it
// creates). The default is
// id.NewV7Generator, whose identifiers sort by the moment they were minted.
//
// Given to any other store, whose records arrive with their own identifier, it
// is a configuration error. A nil generator, including an interface holding a
// nil pointer, is a configuration error.
func WithIDGenerator(g id.Generator) Option {
	return func(c *config) {
		if !c.applies(optIDGenerator, "WithIDGenerator") {
			return
		}
		if nilcheck.IsNil(g) {
			c.refuse("the id generator is nil")
			return
		}
		c.ids = g
	}
}

// WithClock replaces the time source of the stores that judge time themselves:
// the session store (expiry, counts and DeleteExpired), the OIDC flow store
// (the expiry condition of Complete), the one-time token store's reaper, and
// the MFA enrolment store (whether an emailed code's EmailCodeUntil has
// passed, so it is no longer opened on read). The identity store honours it
// too: its tables have no database default for created_at, updated_at or a
// password-history entry's retired_at, and the clock binds every such time it
// writes. The default is clock.System().
//
// For the MFA enrolment store, give it the same clock as the enrolling method
// (mfa.WithClock for TOTP), which sets the code's expiry and charges each
// attempt: a store clock running ahead reads a live code as none, and a
// correct code is then charged an attempt and refused.
//
// Given to any other store, which takes its times from the caller, it is a
// configuration error. A nil clock, typed nil included, is a configuration
// error rather than a silent fallback to the wall clock: a caller passing one
// meant to inject a clock.
func WithClock(clk clock.Clock) Option {
	return func(c *config) {
		if !c.applies(optClock, "WithClock") {
			return
		}
		if nilcheck.IsNil(clk) {
			c.refuse("the clock is nil")
			return
		}
		c.clock = clk
	}
}

// WithResealOnRead turns re-sealing on read on or off for the stores whose
// sealed values are read through package seal: the signing-key and MFA
// enrolment stores. Re-sealing is seal's behaviour: a value found sealed under
// a retired key is written back sealed under the current one. The default is
// on; WithResealOnRead(false) leaves stored values as they are, and they stay
// readable only while the retired key is kept.
//
// Re-sealing is skipped, whatever this option says, for a read that runs
// inside a caller's transaction (attached with WithTx or reported by the
// WithTxResolver resolver). The re-seal is a best-effort write whose failure
// is discarded, and a failed statement aborts a PostgreSQL transaction, so it
// could silently cost the caller their unrelated work. Such a value is
// re-sealed by the next read made outside a transaction.
//
// Given to any other store it is a configuration error.
func WithResealOnRead(on bool) Option {
	return func(c *config) {
		if !c.applies(optResealOnRead, "WithResealOnRead") {
			return
		}
		c.resealOnRead = on
	}
}

// newConfig applies opts over the defaults for a store on base that honours
// the options in honours, besides WithTxResolver, which every store honours.
// It refuses a nil base, a nil option, a nil option value and an option the
// store does not honour with an error wrapping ErrConfig that names the first
// problem and never a value. It never touches the database.
func newConfig(base *sql.DB, opts []Option, honours ...optionKind) (*config, error) {
	if base == nil {
		return nil, fmt.Errorf("%w: the database handle is nil", ErrConfig)
	}

	c := &config{
		base:         base,
		ids:          id.NewV7Generator(),
		clock:        clock.System(),
		resealOnRead: true,
	}
	for _, k := range honours {
		c.honours |= k
	}
	for _, opt := range opts {
		if opt == nil {
			c.refuse("an option is nil")
			continue
		}
		opt(c)
	}

	if c.problem != "" {
		return nil, fmt.Errorf("%w: %s", ErrConfig, c.problem)
	}

	return c, nil
}
