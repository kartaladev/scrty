package recovery

//go:generate mockgen -destination=limiter_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/ratelimit Limiter

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// codeThrottleFlow prefixes every presentation bucket key, so these failures
// never share a bucket with another flow's when a consumer hands the same
// limiter to both.
const codeThrottleFlow = "recovery-code"

// The messages this manager writes. They are constants because a consumer may
// route on them.
const (
	msgCodeLimiterError = "recovery: saved-code limiter could not be consulted"
	msgCodeRecordError  = "recovery: saved-code failure could not be recorded"
	msgCodeStoreError   = "recovery: saved-code store failed"
	msgCodeRandomError  = "recovery: saved-code random source failed"
)

// The fixed texts of errors returned for a failed dependency. The dependency's
// own error stays reachable through errors.Is and errors.As, never in the text.
const (
	errTextCodeStore = "recovery: saved-code store failed"
)

// Count is how many unspent codes a user has, and whether that is low.
//
// Low is true when N is at or below the manager's low threshold, so a
// consumer's interface can prompt a regeneration. The library renders nothing
// itself.
type Count struct {
	N   int
	Low bool
}

// Codes manages users' sets of saved recovery codes.
//
// Generate replaces a user's whole set and returns the new codes once: only
// their hashes are stored, so no one can read them back. Confirm checks that a
// user kept their set, spending nothing. Remaining reports how many codes are
// left and whether that is low.
//
// Every presentation is throttled per user: a user at the limit is refused
// before the code is looked up, and every failed presentation — a malformed
// code, an unknown one, a spent one or another user's — is charged, even when
// the caller has gone away.
//
// With no options a manager keeps codes in process memory, draws them from
// crypto/rand, generates 10 per set, reports 2 or fewer as low, and allows 5
// failed presentations per user per 15 minutes in this process. Every default
// is replaceable.
//
// A Codes is safe for concurrent use as far as its store and limiter are: it
// holds no mutable state of its own after construction.
type Codes struct {
	store        CodeStore
	limiter      ratelimit.Limiter
	clock        clock.Clock
	random       io.Reader
	logger       *slog.Logger
	setSize      int
	lowThreshold int

	// limiterSet records that WithCodeLimiter was given, so a limiter passed
	// as nil is told apart from one never mentioned.
	limiterSet bool
}

// NewCodes returns a saved-code manager.
//
// A set size outside 1–100, a low threshold below zero, or a store, limiter,
// clock or random source given as nil (typed nil included) is a configuration
// error wrapping ErrConfig. A nil logger is ignored.
func NewCodes(opts ...CodesOption) (*Codes, error) {
	c := &Codes{
		store:        NewMemoryCodeStore(),
		clock:        clock.System(),
		random:       rand.Reader,
		logger:       slog.Default(),
		setSize:      defaultSetSize,
		lowThreshold: defaultLowThreshold,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	if c.setSize < 1 || c.setSize > maxSetSize {
		return nil, fmt.Errorf("%w: set size must be between 1 and %d, got %d", ErrConfig, maxSetSize, c.setSize)
	}
	if c.lowThreshold < 0 {
		return nil, fmt.Errorf("%w: low threshold must not be negative, got %d", ErrConfig, c.lowThreshold)
	}
	if nilcheck.IsNil(c.store) {
		return nil, fmt.Errorf("%w: code store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(c.clock) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(c.random) {
		return nil, fmt.Errorf("%w: random source must not be nil", ErrConfig)
	}
	if err := c.resolveLimiter(); err != nil {
		return nil, err
	}

	return c, nil
}

// resolveLimiter supplies the in-memory limiter when no option replaced it,
// and refuses one that was replaced with nothing.
func (c *Codes) resolveLimiter() error {
	if c.limiterSet {
		if nilcheck.IsNil(c.limiter) {
			return fmt.Errorf("%w: code limiter must not be nil", ErrConfig)
		}

		return nil
	}

	l, err := ratelimit.NewMemoryLimiter(defaultCodeLimit, defaultCodeWindow)
	if err != nil {
		return fmt.Errorf("%w: default code limiter: %w", ErrConfig, err)
	}

	c.limiter = l

	return nil
}

// Generate replaces user's set with a new one and returns its codes, grouped
// for display. This is the only time the codes exist in readable form.
//
// Every code is drawn before anything is written, and the set is replaced in
// one store write, so a random source or store that fails leaves the previous
// set exactly as it was, and no code is returned.
func (c *Codes) Generate(ctx context.Context, user identity.UserID) ([]string, error) {
	codes := make([]string, c.setSize)
	hashes := make([][]byte, c.setSize)

	for i := range codes {
		text, hash, err := newCode(c.random)
		if err != nil {
			c.logFailure(ctx, msgCodeRandomError, "random", err)

			return nil, err
		}

		codes[i] = text
		hashes[i] = hash[:]
	}

	if err := c.store.ReplaceSet(ctx, user, hashes, c.clock.Now()); err != nil {
		c.logFailure(ctx, msgCodeStoreError, "store", err)

		return nil, diag.Wrap(err, errTextCodeStore)
	}

	return codes, nil
}

// Confirm checks that presented is one of user's unspent codes, spending
// nothing. It is how a consumer asks a user to show they kept their set.
//
// It is throttled like a recovery: a user at the limit is refused with
// ErrCodeThrottled before the code is looked up, and a wrong code is refused
// with ErrRefused and charged against the user. A store that cannot answer is
// an error that is neither, and charges nothing, unless it gave up because ctx
// ended: a presentation abandoned mid-lookup is charged like a wrong code.
func (c *Codes) Confirm(ctx context.Context, user identity.UserID, presented string) error {
	_, err := c.check(ctx, user, presented)

	return err
}

// Remaining reports how many unspent codes user has, and whether that is at or
// below the low threshold. A user with no set has none, which is low.
func (c *Codes) Remaining(ctx context.Context, user identity.UserID) (Count, error) {
	n, err := c.store.Remaining(ctx, user)
	if err != nil {
		c.logFailure(ctx, msgCodeStoreError, "store", err)

		return Count{}, diag.Wrap(err, errTextCodeStore)
	}

	return Count{N: n, Low: n <= c.lowThreshold}, nil
}

// check is the throttled, write-free check of a presented code, and returns
// the hash that spend takes.
//
// The order is the guarantee: the limiter is asked first, so a throttled user's
// guess is compared against nothing; the code is parsed next, so a malformed
// one never reaches the store; and only then is it looked up.
//
// The limiter is asked, and a malformed or unmatched code charged, with the
// caller's cancellation stripped, so a client that hangs up can neither slip
// past the check nor take back the guess it made. A limiter that cannot answer
// refuses. A store that cannot answer is returned as an error, charged to
// nobody, since it says nothing about the code — unless it gave up because the
// caller went away, which is charged: a guess abandoned mid-lookup is still a
// guess, and a client must not be able to make free guesses by hanging up.
func (c *Codes) check(ctx context.Context, user identity.UserID, presented string) ([32]byte, error) {
	key := CodeThrottleKey(user)

	exceeded, err := c.limiter.Exceeded(context.WithoutCancel(ctx), key)
	if err != nil {
		c.logFailure(ctx, msgCodeLimiterError, "limiter", err)

		return [32]byte{}, ErrCodeThrottled
	}
	if exceeded {
		return [32]byte{}, ErrCodeThrottled
	}

	hash, err := parseCode(presented)
	if err != nil {
		c.recordFailure(ctx, key)

		return [32]byte{}, ErrRefused
	}

	matched, err := c.store.Match(ctx, user, hash[:])
	if err != nil {
		c.logFailure(ctx, msgCodeStoreError, "store", err)

		if causedByCaller(ctx, err) {
			c.recordFailure(ctx, key)
		}

		return [32]byte{}, diag.Wrap(err, errTextCodeStore)
	}
	if !matched {
		c.recordFailure(ctx, key)

		return [32]byte{}, ErrRefused
	}

	return hash, nil
}

// spend spends the code check matched, by the store's conditional write. A code
// spent since the check — by a racing recovery — is refused with ErrRefused,
// and is not charged: the presenter held a real code.
func (c *Codes) spend(ctx context.Context, user identity.UserID, hash [32]byte) error {
	ok, err := c.store.Spend(ctx, user, hash[:], c.clock.Now())
	if err != nil {
		c.logFailure(ctx, msgCodeStoreError, "store", err)

		return diag.Wrap(err, errTextCodeStore)
	}
	if !ok {
		return ErrRefused
	}

	return nil
}

// recordFailure charges one failed presentation to key. The limiter is given a
// context with its cancellation stripped, as that port says to expect. A
// limiter that cannot record is logged and otherwise ignored: it is an outage,
// not a judgement about the presentation, whose refusal stands as it was.
func (c *Codes) recordFailure(ctx context.Context, key string) {
	if err := c.limiter.RecordFailure(context.WithoutCancel(ctx), key); err != nil {
		c.logFailure(ctx, msgCodeRecordError, "limiter", err)
	}
}

// logFailure writes one record of a failed dependency: a fixed reason and the
// error's Go type, never its text, which can quote values the library never
// saw. No record names the user or the code.
//
// A failure the caller's own cancellation caused is written at debug level: a
// client that hung up is not an incident. Every other failure is an outage and
// is written at error level.
func (c *Codes) logFailure(ctx context.Context, msg, reason string, err error) {
	level := slog.LevelError
	if causedByCaller(ctx, err) {
		level = slog.LevelDebug
	}

	c.logger.LogAttrs(ctx, level, msg, diag.Failure(reason, err)...)
}

// causedByCaller reports whether err is the caller's own context ending, rather
// than a dependency failing on its own.
func causedByCaller(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()

	return ctxErr != nil && errors.Is(err, ctxErr)
}

// CodeThrottleKey is the limiter key saved-code presentations for user are
// counted under: "recovery-code|" followed by the user reference, unparsed.
//
// It is exported because a consumer who supplies their own limiter, shared with
// other flows, needs to know which bucket these failures land in — to read it,
// to clear it after an administrative unlock, or to keep their own keys from
// colliding with it.
func CodeThrottleKey(user identity.UserID) string {
	return codeThrottleFlow + "|" + string(user)
}
