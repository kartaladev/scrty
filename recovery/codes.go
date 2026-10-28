package recovery

//go:generate mockgen -destination=limiter_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/ratelimit Limiter,LimiterFactory
//go:generate mockgen -source=codes.go -destination=codes_mock_test.go -package=recovery_test -typed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

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

	// limiterSet records that WithCodesLimiter was given, so a limiter passed
	// as nil is told apart from one never mentioned.
	limiterSet bool

	// factory builds the limiter when no limiter was given; factorySet
	// records that WithCodesLimiterFactory was given, for the same reason.
	factory    ratelimit.LimiterFactory
	factorySet bool
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

// resolveLimiter settles the limiter by precedence: the limiter
// WithCodesLimiter gave, then one built by the factory WithCodesLimiterFactory
// gave, then the in-memory default logging through the manager's logger and
// clock. A limiter or factory replaced with nothing is refused, the factory
// even beside an explicit limiter that would have won.
func (c *Codes) resolveLimiter() error {
	if c.factorySet && nilcheck.IsNil(c.factory) {
		return fmt.Errorf("%w: code limiter factory must not be nil", ErrConfig)
	}

	if c.limiterSet {
		if nilcheck.IsNil(c.limiter) {
			return fmt.Errorf("%w: code limiter must not be nil", ErrConfig)
		}

		return nil
	}

	factory := c.factory
	if !c.factorySet {
		factory = ratelimit.MemoryLimiterFactory(
			ratelimit.WithMemoryLimiterLogger(c.logger),
			ratelimit.WithMemoryLimiterClock(c.clock),
		)
	}

	l, err := factory.NewLimiter(namespaceCodes, defaultCodeLimit, defaultCodeWindow)
	if err != nil {
		return fmt.Errorf("%w: limiter for namespace %q: %w", ErrConfig, namespaceCodes, err)
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

// codeBytes is how much entropy a saved code carries: 128 bits, far beyond
// guessing within any presentation limit. It is not an option, because the only
// direction anyone would move it is down, and the tests pin it so no later
// change can shorten the codes silently.
const codeBytes = 16

const (
	// codeAlphabet is Crockford's base32 alphabet. It omits I, L, O and U, so a
	// code read aloud or copied by hand has no look-alike characters.
	codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// codeChars is how many alphabet characters a code has: 26 characters of 5
	// bits hold 130 bits, the smallest multiple of 5 that fits 128. The two
	// spare bits are the value's leading zeros, which is why the first
	// character is always 0–7.
	codeChars = 26

	// codeGroup is how many characters sit between two dashes.
	codeGroup = 4

	// maxFirstChar is the highest value the first character may carry: with
	// two leading zero bits its 5 bits hold at most 0b00111.
	maxFirstChar = 7
)

// newCode draws one saved code from random and returns it as grouped Crockford
// base32 text, with the SHA-256 hash of its 16 bytes that the store keeps.
//
// A random source that fails or runs short is an error, and no code is
// returned: a code built from fewer bytes than codeBytes would carry less
// entropy than the library promises.
func newCode(random io.Reader) (text string, hash [32]byte, err error) {
	var raw [codeBytes]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		// The reader's own text is not repeated: it belongs to a source the
		// library does not know. The cause stays reachable through errors.Is.
		return "", [32]byte{}, diag.Wrap(err, "recovery: random source failed")
	}

	return encodeCode(raw), sha256.Sum256(raw[:]), nil
}

// encodeCode writes raw as 26 Crockford base32 characters, most significant
// first, grouped in fours with dashes.
//
// The 128 bits are read as a 130-bit big-endian value with two leading zero
// bits, and taken 5 bits at a time. Package encoding/base32 is not used: its
// alphabet differs and it pads a partial group rather than widening the value.
func encodeCode(raw [codeBytes]byte) string {
	out := make([]byte, 0, codeChars+codeChars/codeGroup)

	for i := range codeChars {
		if i > 0 && i%codeGroup == 0 {
			out = append(out, '-')
		}

		out = append(out, codeAlphabet[fiveBits(raw, i)])
	}

	return string(out)
}

// fiveBits returns the i-th 5-bit group of raw read as a 130-bit value with two
// leading zero bits. Group i covers bits [5i-2, 5i+3) of raw, counting from its
// most significant bit; positions before bit 0 are the leading zeros.
func fiveBits(raw [codeBytes]byte, i int) byte {
	var v byte

	for b := 5*i - 2; b < 5*i+3; b++ {
		v <<= 1
		if b >= 0 && raw[b/8]&(0x80>>(b%8)) != 0 {
			v |= 1
		}
	}

	return v
}

// codeValues maps an ASCII byte to its 5-bit value, or to -1 for a byte that is
// not a code character. Lower case folds to upper case, and the look-alikes
// O, I and L read as 0, 1 and 1, as Crockford's decoding defines.
var codeValues = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}

	for v, c := range []byte(codeAlphabet) {
		t[c] = int8(v)
		t[c|0x20] = int8(v) // lower case; a no-op on digits, which have no case
	}

	for _, alias := range []struct{ from, to byte }{{'O', '0'}, {'I', '1'}, {'L', '1'}} {
		t[alias.from] = t[alias.to]
		t[alias.from|0x20] = t[alias.to]
	}

	return t
}()

// parseCode reads a presented saved code and returns the hash the store keeps
// it under.
//
// It ignores dashes wherever they fall and folds case, reads O as 0 and I or L
// as 1, and refuses anything else: another character outside the alphabet
// (spaces and U included), a length other than 26 characters, or a first
// character above 7, which would not fit in 16 bytes. Every refusal is
// ErrRefused, and its text never quotes the presented value.
//
// The hash is taken over the decoded bytes rather than the text, so every
// accepted spelling of one code hashes alike.
func parseCode(presented string) (hash [32]byte, err error) {
	var (
		raw [codeBytes]byte
		n   int
	)

	for i := range len(presented) {
		c := presented[i]
		if c == '-' {
			continue
		}

		v := codeValues[c]
		if v < 0 || n == codeChars || (n == 0 && v > maxFirstChar) {
			return [32]byte{}, ErrRefused
		}

		setFiveBits(&raw, n, byte(v))
		n++
	}

	if n != codeChars {
		return [32]byte{}, ErrRefused
	}

	return sha256.Sum256(raw[:]), nil
}

// setFiveBits writes v as the i-th 5-bit group of raw, read as fiveBits reads
// it. The bits of group 0 that fall before bit 0 are the leading zeros, which
// the caller has already checked are zero.
func setFiveBits(raw *[codeBytes]byte, i int, v byte) {
	for k := range 5 {
		b := 5*i - 2 + k
		if b >= 0 && v&(0x10>>k) != 0 {
			raw[b/8] |= 0x80 >> (b % 8)
		}
	}
}

// CodeStore keeps the hashes of each user's saved recovery codes.
//
// It holds, per user reference, the SHA-256 hash of each code's 16 bytes, when
// it was stored and, once spent, when it was spent. It never sees a code: what
// it holds cannot be presented.
//
// A hash matches only within its own user's set. An unknown code and a spent
// code have the same outcome — false with no error — so nothing above the
// store can tell them apart. An error means the question could not be
// answered, never that the answer was no.
//
// MemoryCodeStore is the default. A consumer supplies a durable one when codes
// must survive a restart or be shared across replicas; any implementation of
// this contract is usable in its place. An implementation must be safe for
// concurrent use.
type CodeStore interface {
	// ReplaceSet removes every code of user and stores hashes as the user's new
	// set, all stamped at, in one operation: a reader never sees a mix of the
	// two sets, and a failure leaves the previous set whole. Inside a caller's
	// transaction, a failure undoes only this operation's own statements.
	//
	// The store keeps its own copies of hashes; the caller may reuse or wipe
	// the slices afterwards.
	ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error

	// Match reports whether user holds an unspent code whose hash is hash.
	// It writes nothing, whether it matches or not.
	Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error)

	// Spend marks user's code whose hash is hash as spent at at, by one
	// conditional write on "not yet spent", and reports whether this call spent
	// it. Of any number of concurrent spends of one code at most one reports
	// true. A refused spend changes nothing, so the first spending time is
	// kept.
	Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error)

	// Remaining counts user's unspent codes. A user with no set has none.
	Remaining(ctx context.Context, user identity.UserID) (int, error)

	// DeleteUser removes every code of user, spent or not, and reports how
	// many were removed.
	DeleteUser(ctx context.Context, user identity.UserID) (int, error)
}

// MemoryCodeStore keeps saved-code hashes in process memory. It is the default
// CodeStore, and it is safe for concurrent use.
//
// Its limit is stated: it holds this process's codes only. A restart forgets
// every set, so every user's saved codes stop working, and behind several
// replicas each keeps its own sets, so a code generated on one is unknown to
// the others. Supply a durable, shared store through WithCodesStore for
// anything beyond a single process.
//
// It keeps its own copies of every hash it is given, so a caller wiping or
// reusing its buffers afterwards changes nothing stored.
type MemoryCodeStore struct {
	mu sync.Mutex
	// sets maps a user to their codes, keyed by hash. A string key is a copy
	// of the hash's bytes, never a view onto the caller's slice.
	sets map[identity.UserID]map[string]*codeEntry
}

// codeEntry is one stored code: when it was stored and, once spent, when.
type codeEntry struct {
	createdAt time.Time
	spentAt   time.Time
}

func (e *codeEntry) spent() bool { return !e.spentAt.IsZero() }

// NewMemoryCodeStore returns an empty in-memory store.
func NewMemoryCodeStore() *MemoryCodeStore {
	return &MemoryCodeStore{sets: make(map[identity.UserID]map[string]*codeEntry)}
}

// ReplaceSet drops user's set and stores hashes in its place, under one lock,
// so no reader sees a mix of the two sets. It cannot fail.
func (s *MemoryCodeStore) ReplaceSet(_ context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	set := make(map[string]*codeEntry, len(hashes))
	for _, h := range hashes {
		set[string(h)] = &codeEntry{createdAt: at}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(set) == 0 {
		delete(s.sets, user)

		return nil
	}

	s.sets[user] = set

	return nil
}

// Match reports whether user holds an unspent code whose hash is hash. It
// writes nothing.
func (s *MemoryCodeStore) Match(_ context.Context, user identity.UserID, hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.sets[user][string(hash)]

	return ok && !e.spent(), nil
}

// Spend marks user's code whose hash is hash as spent at at, if it is not spent
// already, and reports whether this call spent it. The check and the write
// happen under one lock, so of any number of concurrent spends exactly one
// reports true.
func (s *MemoryCodeStore) Spend(_ context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.sets[user][string(hash)]
	if !ok || e.spent() {
		return false, nil
	}

	e.spentAt = at

	return true, nil
}

// Remaining counts user's unspent codes.
func (s *MemoryCodeStore) Remaining(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0

	for _, e := range s.sets[user] {
		if !e.spent() {
			n++
		}
	}

	return n, nil
}

// DeleteUser removes every code of user, spent or not, and reports how many
// were removed.
func (s *MemoryCodeStore) DeleteUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.sets[user])
	delete(s.sets, user)

	return n, nil
}
