package onetime

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrConfig is wrapped by every error NewManager returns for a wiring mistake,
// so a consumer can tell a contradictory configuration from a failure at issue
// or redemption time without matching on message text.
var ErrConfig = errors.New("onetime: invalid configuration")

const (
	// defaultTTL is how long an issued token stays valid with no time-to-live
	// configured. A quarter of an hour is long enough for someone to find the
	// message and follow the link, and short enough that a link left in an
	// inbox, a proxy log or a chat preview is worthless by the time anyone
	// else reads it.
	defaultTTL = 15 * time.Minute

	// defaultIssuanceWindow is the span IssuedCount counts over, and the
	// distance back from now that a purge must leave untouched, with no window
	// configured. An hour is the span a "how many links have you asked for"
	// limit is usually written against.
	defaultIssuanceWindow = time.Hour

	// secretSeparator divides the record identifier from the secret in a
	// presented token. It is not a legal character in the identifier's own
	// text, so the split is unambiguous however the two halves are shaped.
	secretSeparator = "."

	// maxPresentedSize bounds the string Check will look at, in bytes. A
	// presented token is a 36-character identifier, a separator and a
	// 43-character secret; the room above that is slack, not licence.
	maxPresentedSize = 512
)

// Option configures a Manager. Every option names the default it replaces, and
// every default works with no configuration at all.
type Option func(*Manager)

// WithStore replaces where tokens are kept. The default is NewMemoryStore,
// which does not survive a restart.
//
// A nil store is a configuration error rather than a silent fallback to memory:
// a consumer who passed one meant to supply their own, and quietly keeping
// their users' password-reset tokens in process memory is not a failure they
// would find out about until a deploy.
func WithStore(s Store) Option { return func(m *Manager) { m.store = s } }

// WithTTL replaces how long an issued token stays valid. The default is 15
// minutes. Zero or less is a configuration error: it would expire every token
// at the instant it was issued.
func WithTTL(d time.Duration) Option { return func(m *Manager) { m.ttl = d } }

// WithIssuanceWindow replaces the span IssuedCount counts over and the distance
// back from now that PurgeExpired leaves alone. The default is one hour. Zero
// or less is a configuration error: it would count no issuance at all while
// making every expired record eligible for the next sweep.
func WithIssuanceWindow(d time.Duration) Option {
	return func(m *Manager) { m.issuanceWindow = d }
}

// WithIDGenerator replaces the source of record identifiers. The default is
// id.NewV7Generator, whose identifiers sort by the moment they were minted.
//
// A consumer replaces it to mint identifiers their own records can be
// correlated with. A nil generator is a configuration error.
func WithIDGenerator(g id.Generator) Option { return func(m *Manager) { m.ids = g } }

// WithClock replaces the time source. The default is clock.System().
//
// Any type with Now satisfies clock.Clock, a clockwork fake included. A nil
// clock, typed nil included, is a configuration error rather than a silent
// fallback: a caller passing one meant to inject a clock, and falling back to
// the wall clock would make a test that never advances look like one that
// does.
func WithClock(clk clock.Clock) Option { return func(m *Manager) { m.clock = clk } }

// WithLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: unlike a clock, a nil logger has
// an obvious safe reading — the caller does not want this component's logs —
// and refusing it would make logging mandatory. Only store failures are logged,
// at error level, and no log this package writes carries a presented token, a
// secret or a binding.
func WithLogger(l *slog.Logger) Option {
	return func(m *Manager) {
		if l != nil {
			m.logger = l
		}
	}
}

// WithRandom replaces the source token secrets are drawn from. The default is
// crypto/rand.Reader.
//
// It exists so a test can make the entropy source fail, and so a consumer whose
// platform supplies its own cryptographic source can use it. A nil reader is a
// configuration error: falling back would override a deliberate choice about
// where this deployment's randomness comes from.
func WithRandom(r io.Reader) Option { return func(m *Manager) { m.random = r } }

// IssueOption configures one issuance, rather than the manager behind it.
type IssueOption func(*issuance)

type issuance struct {
	binding string
}

// WithBinding ties the issued token to value, which must be presented again at
// redemption. The default is no binding, and a token issued without one ignores
// whatever binding is presented.
//
// The value is what the consumer chooses to tie the token to — a nonce left in
// the browser that asked for the link, a device identifier, a session handle —
// and this package attaches no meaning to it beyond "the same string must come
// back". Only its hash is stored. An empty value leaves the token unbound,
// because binding to the empty string would be satisfied by presenting nothing.
func WithBinding(value string) IssueOption {
	return func(i *issuance) { i.binding = value }
}
