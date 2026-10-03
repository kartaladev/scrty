package recovery

import (
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	// defaultSetSize is how many codes a set holds with no size configured. Ten
	// is enough to last years of occasional use, and few enough to write down.
	defaultSetSize = 10

	// maxSetSize bounds the size a consumer may configure. It is not a
	// security limit: it only bounds the work one generation does.
	maxSetSize = 100

	// defaultLowThreshold is the remaining count at or below which a set is
	// reported as low, with no threshold configured: two codes left is the
	// last moment a user can still spend one and regenerate with the other in
	// hand.
	defaultLowThreshold = 2

	// defaultCodeLimit and defaultCodeWindow are the failed presentations a user
	// may accumulate before further presentations are refused, with no limiter
	// configured. Five is far more than a person mistypes, and against 128
	// bits it gives a guesser nothing.
	defaultCodeLimit  = 5
	defaultCodeWindow = 15 * time.Minute

	// namespaceCodes names the code-presentation limit to a limiter factory.
	namespaceCodes = "recovery-codes"
)

// CodesOption configures a Codes manager. Every option names the default it
// replaces, and every default works with no configuration at all.
type CodesOption func(*Codes)

// WithCodeStore replaces where code hashes are kept. The default is
// NewMemoryCodeStore, which holds one process's codes and forgets them on
// restart.
//
// A nil store, typed nil included, is a configuration error rather than a
// silent fallback to memory: a consumer who passed one meant to supply their
// own, and quietly keeping their users' recovery codes in process memory is
// not a failure they would find out about until a deploy.
func WithCodeStore(s CodeStore) CodesOption { return func(c *Codes) { c.store = s } }

// WithSetSize replaces how many codes one set holds. The default is 10.
//
// It must be between 1 and 100; anything else is a configuration error. Zero
// codes is no set at all, and the upper bound only caps the work one
// generation does.
func WithSetSize(n int) CodesOption { return func(c *Codes) { c.setSize = n } }

// WithLowThreshold replaces the remaining count at or below which a set is
// reported as low. The default is 2.
//
// Zero reports only an exhausted set as low. A threshold below zero is a
// configuration error, because no count could ever reach it. A threshold at or
// above the set size is accepted, and reports a fresh set as low: that is the
// consumer's call to make, not a contradiction.
func WithLowThreshold(n int) CodesOption { return func(c *Codes) { c.lowThreshold = n } }

// WithCodeLimiter replaces the limiter that counts failed presentations. The
// default is a ratelimit.MemoryLimiter allowing 5 failures per 15 minutes, per
// process.
//
// Failures are counted under CodeThrottleKey(user), and every check and every
// failure goes to this limiter, so a consumer can share one limiter across
// replicas, or across flows, and still find these counts. A limiter that
// cannot answer refuses the presentation.
//
// Both the check and the recording are given the caller's context with its
// cancellation stripped, so a client that hangs up can neither skip the check
// nor avoid the charge. A limiter that reaches a remote store must therefore
// bound its own I/O with its own timeout, rather than rely on the caller's
// deadline.
//
// It takes precedence over WithCodeLimiterFactory.
//
// For this second-factor flow, a shared limiter in
// ratelimit.UnavailableFallBackToLocal mode is the recommended choice: during an
// outage of the shared store each replica still bounds guessing on its own, and
// users are not locked out of sign-in.
//
// A nil limiter, typed nil included, is a configuration error rather than a
// fallback to the default: a consumer who passed one meant to replace it.
func WithCodeLimiter(l ratelimit.Limiter) CodesOption {
	return func(c *Codes) {
		c.limiter = l
		c.limiterSet = true
	}
}

// WithCodeLimiterFactory builds the limiter that counts failed saved-code
// presentations per user through f, under the namespace "recovery-codes" with
// this flow's own limit and window: 5 failures per 15 minutes.
//
// Default: ratelimit.MemoryLimiterFactory, logging through the manager's logger
// and clock, so the limit holds in this process alone. Precedence: a limiter
// given with WithCodeLimiter wins, and f is then never asked; then f; then the
// in-memory default.
//
// For this second-factor flow, a shared limiter in
// ratelimit.UnavailableFallBackToLocal mode is the recommended choice: during an
// outage of the shared store each replica still bounds guessing on its own, and
// users are not locked out of sign-in.
//
// A nil factory, typed nil included, is an error wrapping ErrConfig, as is an
// error from f, which names the namespace.
func WithCodeLimiterFactory(f ratelimit.LimiterFactory) CodesOption {
	return func(c *Codes) {
		c.factory = f
		c.factorySet = true
	}
}

// WithCodesClock replaces the time source that stamps stored and spent codes.
// The default is clock.System().
//
// A nil clock, typed nil included, is a configuration error: falling back to
// the wall clock would make a test whose clock never advances look like one
// that does. The default limiter uses this clock too, so a test that moves it
// moves the presentation window with it.
func WithCodesClock(clk clock.Clock) CodesOption { return func(c *Codes) { c.clock = clk } }

// WithCodesRandom replaces the source codes are drawn from. The default is
// crypto/rand.Reader.
//
// It exists so a test can make the source fail, and so a consumer whose
// platform supplies its own cryptographic source can use it. A nil reader is a
// configuration error: falling back would override a deliberate choice about
// where this deployment's randomness comes from.
func WithCodesRandom(r io.Reader) CodesOption { return func(c *Codes) { c.random = r } }

// WithCodesLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: it has an obvious safe reading,
// that the caller does not want this component's logs. Only dependency
// failures are logged, as a fixed reason and the error's Go type, and no
// record carries a code, a hash or a user reference.
func WithCodesLogger(l *slog.Logger) CodesOption {
	return func(c *Codes) {
		if l != nil {
			c.logger = l
		}
	}
}
