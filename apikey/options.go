package apikey

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// ErrConfig is wrapped by every error NewManager returns for a wiring mistake,
// so a consumer can tell a contradictory configuration from a failure at issue
// or verification time without matching on message text.
var ErrConfig = errors.New("apikey: invalid configuration")

const (
	// defaultPrefix is the prefix presented keys carry with none configured.
	// Two letters is the shortest thing a secret scanner can key on while
	// still leaving the rest of the string to the identifier and the secret.
	defaultPrefix = "sk"

	// maxPrefixLen bounds a configured prefix. Sixteen characters is room for
	// an organisation's name and a suffix; past that the prefix is no longer
	// helping anyone recognise the key at a glance.
	maxPrefixLen = 16

	// secretBytes is how much entropy a key's secret carries. Thirty-two bytes
	// from the operating system's random source put a presented key out of
	// reach of guessing, and leave no reason to make it a consumer choice: the
	// only direction anyone would move it is down.
	secretBytes = 32

	// prefixSeparator divides the prefix from the record identifier, and
	// secretSeparator divides that identifier from the secret. Neither is a
	// legal character in the identifier's own text, so both splits are
	// unambiguous however the halves are shaped.
	prefixSeparator = "_"
	secretSeparator = "."

	// maxPresentedSize bounds the string Verify will look at, in bytes. A
	// presented key is at most a 16-character prefix, a separator, a
	// 36-character identifier, a separator and a 43-character secret; the room
	// above that is slack, not licence.
	maxPresentedSize = 512
)

// Option configures a Manager. Every option names the default it replaces, and
// every default works with no configuration at all.
type Option func(*Manager)

// WithStore replaces where key records are kept. The default is
// NewMemoryStore, which does not survive a restart.
//
// A nil store is a configuration error rather than a silent fallback to memory:
// a consumer who passed one meant to supply their own, and quietly keeping a
// fleet's machine credentials in process memory is not a failure they would
// find out about until a deploy.
func WithStore(s Store) Option { return func(m *Manager) { m.store = s } }

// WithPrefix replaces the prefix presented keys carry. The default is "sk".
//
// The prefix exists so that secret scanners, log redactors and the people
// reading a paste can recognise a key on sight, before anything has to parse
// it. A consumer sets their own so their keys are distinguishable from every
// other product's.
//
// It must be 1 to 16 lowercase ASCII letters or digits; anything else is a
// configuration error. The limit is not decoration: the prefix is matched with
// its separator attached, and a prefix holding an underscore or a dot would
// make the presented form ambiguous to split.
func WithPrefix(p string) Option { return func(m *Manager) { m.prefix = p } }

// WithDigest replaces the one-way function the secret is stored under. The
// default is SHA-256.
//
// The default is deliberately a fast hash and not a password hash. A key's
// secret is 32 bytes read from the operating system's random source, so there
// is no search space for a slow key-derivation function to defend; all a slow
// hash would buy is latency on every machine request. A consumer whose policy
// names a different digest supplies it here, and both issuance and verification
// then use it.
//
// A nil function is a configuration error: there is no safe reading of "store
// the secret under no digest at all".
func WithDigest(d func([]byte) []byte) Option { return func(m *Manager) { m.digest = d } }

// WithIDGenerator replaces the source of record identifiers. The default is
// id.NewV7Generator, whose identifiers sort by the moment they were minted.
//
// A consumer replaces it to mint identifiers their own records can be
// correlated with. A nil generator is a configuration error.
func WithIDGenerator(g id.Generator) Option { return func(m *Manager) { m.ids = g } }

// WithClock replaces the time source. The default is time.Now.
//
// A nil clock is a configuration error rather than a silent fallback: a caller
// passing one meant to inject a clock, and falling back to the wall clock would
// make a test that never advances look like one that does.
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// WithRandom replaces the source key secrets are drawn from. The default is
// crypto/rand.Reader.
//
// It exists so a test can make the entropy source fail, and so a consumer whose
// platform supplies its own cryptographic source can use it. A nil reader is a
// configuration error: falling back would override a deliberate choice about
// where this deployment's randomness comes from.
func WithRandom(r io.Reader) Option { return func(m *Manager) { m.random = r } }

// WithLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: unlike a clock, a nil logger has
// an obvious safe reading — the caller does not want this component's logs —
// and refusing it would make logging mandatory. Only the causes of a
// verification refusal are logged, at debug for an unknown key and at error for
// a store that could not answer, and no log this package writes carries a
// presented key or a secret.
func WithLogger(l *slog.Logger) Option {
	return func(m *Manager) {
		if l != nil {
			m.logger = l
		}
	}
}

// validPrefix reports whether p is 1 to 16 lowercase ASCII letters or digits.
//
// The rule is spelled as a loop rather than a regular expression so that what
// is allowed can be read here, in Go, without a second language in between.
func validPrefix(p string) bool {
	if p == "" || len(p) > maxPrefixLen {
		return false
	}

	for i := range len(p) {
		c := p[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}

	return true
}
