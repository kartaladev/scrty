package onetime

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// Tokens issues, checks and consumes the one-time tokens of a single purpose.
//
// One manager serves one purpose, and the purpose is stored on every record it
// issues, so two managers may share a store without either honouring the
// other's tokens: a password-reset token presented to the magic-link manager is
// refused like any other token it did not issue.
//
// Every default is replaceable. With no options a manager keeps its tokens in
// process memory, mints them from crypto/rand, expires them after 15 minutes
// and counts issuance over the hour before now. A consumer supplies a durable
// store through WithStore, a different lifetime through WithTTL, a different
// counting window through WithIssuanceWindow, and a test moves time through
// WithClock without waiting for it.
//
// A Tokens value is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type Tokens struct {
	purpose        string
	store          Store
	storeSet       bool
	ttl            time.Duration
	issuanceWindow time.Duration
	ids            id.Generator
	clock          clock.Clock
	logger         *slog.Logger
	random         io.Reader
}

// ErrConfig is wrapped by every error New returns for a wiring mistake,
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

// Option configures the Tokens. Every option names the default it replaces, and
// every default works with no configuration at all.
type Option func(*Tokens)

// WithStore replaces where tokens are kept. The default is NewMemoryStore,
// which does not survive a restart, and which reads the manager's own clock
// (see WithClock).
//
// A store given here keeps its own clock: the manager never replaces or wraps
// it, so a consumer who gives a manager a clock and a store gives the store the
// same clock themselves.
//
// A nil store is a configuration error rather than a silent fallback to memory:
// a consumer who passed one meant to supply their own, and quietly keeping
// their users' password-reset tokens in process memory is not a failure they
// would find out about until a deploy.
func WithStore(s Store) Option { return func(m *Tokens) { m.store, m.storeSet = s, true } }

// WithTTL replaces how long an issued token stays valid. The default is 15
// minutes. Zero or less is a configuration error: it would expire every token
// at the instant it was issued.
func WithTTL(d time.Duration) Option { return func(m *Tokens) { m.ttl = d } }

// WithIssuanceWindow replaces the span IssuedCount counts over and the distance
// back from now that PurgeExpired leaves alone. The default is one hour. Zero
// or less is a configuration error: it would count no issuance at all while
// making every expired record eligible for the next sweep.
func WithIssuanceWindow(d time.Duration) Option {
	return func(m *Tokens) { m.issuanceWindow = d }
}

// WithIDGenerator replaces the source of record identifiers. The default is
// id.NewV7Generator, whose identifiers sort by the moment they were minted.
//
// A consumer replaces it to mint identifiers their own records can be
// correlated with. A nil generator is a configuration error.
func WithIDGenerator(g id.Generator) Option { return func(m *Tokens) { m.ids = g } }

// WithClock replaces the time source. The default is clock.System().
//
// The default in-memory store reads this same clock, so a manager given a
// fake clock and no store judges expiry and purges on that clock. A store
// given through WithStore keeps its own.
//
// Any type with Now satisfies clock.Clock, a clockwork fake included. A nil
// clock, typed nil included, is a configuration error rather than a silent
// fallback: a caller passing one meant to inject a clock, and falling back to
// the wall clock would make a test that never advances look like one that
// does.
func WithClock(clk clock.Clock) Option { return func(m *Tokens) { m.clock = clk } }

// WithLogger replaces the logger. The default is slog.Default().
//
// A nil logger is ignored rather than refused: unlike a clock, a nil logger has
// an obvious safe reading — the caller does not want this component's logs —
// and refusing it would make logging mandatory. Only store failures are logged,
// at error level, and no log this package writes carries a presented token, a
// secret or a binding.
func WithLogger(l *slog.Logger) Option {
	return func(m *Tokens) {
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
func WithRandom(r io.Reader) Option { return func(m *Tokens) { m.random = r } }

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

// New returns a manager that issues tokens for purpose.
//
// The purpose must be non-empty once surrounding space is removed. A manager
// with no purpose would accept every record in its store, which is exactly how
// a password-reset token comes to open a session as a magic link, so an empty
// one is refused here rather than left to be noticed at the first redemption.
//
// A non-positive time-to-live or issuance window is refused for the same
// reason: a zero time-to-live expires each token at the instant it is issued,
// and a zero issuance window counts no issuance at all while making every
// record eligible for the next purge. Neither can be what the caller meant, and
// both would otherwise look like a working manager that quietly honours
// nothing.
//
// Every port and function this takes is refused when nil, with one exception:
// a nil logger is ignored, because "do not log from this component" is a
// reading a nil logger plainly has, while a nil clock has no reading other than
// a mistake — falling back to the wall clock would make a test whose clock
// never advances look like one that does.
//
// A record of a failed store read or write carries a fixed reason and the
// error's Go type, never the store's own text; a consumer who wants that
// detail logs it inside their own implementation of Store. The token
// identifier, a library-owned value rather than a secret, is kept.
func New(purpose string, opts ...Option) (*Tokens, error) {
	m := &Tokens{
		purpose:        strings.TrimSpace(purpose),
		ttl:            defaultTTL,
		issuanceWindow: defaultIssuanceWindow,
		ids:            id.NewV7Generator(),
		clock:          clock.System(),
		logger:         slog.Default(),
		random:         rand.Reader,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}

	if m.purpose == "" {
		return nil, fmt.Errorf("%w: a purpose is required, or this manager would honour every token in its store", ErrConfig)
	}
	if m.ttl <= 0 {
		return nil, fmt.Errorf("%w: time-to-live must be positive, got %s", ErrConfig, m.ttl)
	}
	if m.issuanceWindow <= 0 {
		return nil, fmt.Errorf("%w: issuance window must be positive, got %s", ErrConfig, m.issuanceWindow)
	}
	if m.storeSet && nilcheck.IsNil(m.store) {
		return nil, fmt.Errorf("%w: store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.ids) {
		return nil, fmt.Errorf("%w: identifier generator must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.clock) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.random) {
		return nil, fmt.Errorf("%w: random source must not be nil", ErrConfig)
	}

	// The default store reads the manager's clock, so a manager on a fake or
	// shifted clock purges by the same time it expires by.
	if !m.storeSet {
		m.store = NewMemoryStore(WithMemoryStoreClock(m.clock))
	}

	return m, nil
}

// Purpose reports the purpose every token this manager issues carries, which is
// what New was given.
func (m *Tokens) Purpose() string { return m.purpose }

// TTL reports how long an issued token stays valid, which is what WithTTL
// configured.
func (m *Tokens) TTL() time.Duration { return m.ttl }

// IssuanceWindow reports the window IssuedCount counts over and PurgeExpired
// takes its cutoff from, which is what WithIssuanceWindow configured.
func (m *Tokens) IssuanceWindow() time.Duration { return m.issuanceWindow }

// secretBytes is how much entropy a token secret carries. Thirty-two bytes put
// a presented token out of reach of guessing, and leave no reason to make it a
// consumer choice: the only direction anyone would move it is down.
const secretBytes = 32

// Issue mints a token for subject and returns it in the one form that ever
// carries the secret: "<record identifier>.<base64url secret>".
//
// The returned string is the only copy of the secret that will exist. What is
// written to the store is its hash, so this string is what the caller must
// deliver to the holder now — there is no second chance to read it back, and
// neither the returned Token nor the store can reproduce it.
//
// The subject is stored and returned exactly as given. It is the consumer's
// value and this package attaches no meaning to it.
//
// WithBinding ties the token to a value the holder must present again at
// redemption, such as a nonce left in the browser that asked for a magic link.
//
// Nothing is stored unless everything succeeded: a random source that cannot
// answer, a generator that cannot mint an identifier and a store that cannot
// insert are each reported, and none of them leaves a record behind or hands
// back a token nobody would honour.
func (m *Tokens) Issue(ctx context.Context, subject string, opts ...IssueOption) (string, Token, error) {
	presented, tok, err := m.mint(subject, opts)
	if err != nil {
		return "", Token{}, err
	}

	if err := m.store.Insert(ctx, tok); err != nil {
		return "", Token{}, diag.Wrap(err, "onetime: store token")
	}

	return presented, tok, nil
}

// IssueWithin is Issue bounded by limit: it mints a token for subject only
// while fewer than limit tokens were issued for subject within the manager's
// issuance window, as IssuedCount counts them, and reports
// ErrIssueLimitReached, storing nothing, once that many have been.
//
// The count and the issue are one decision, taken by the store's InsertWithin.
// Of several callers racing for one subject, on this process or on another
// replica, at most limit are issued a token, where a call to IssuedCount
// followed by Issue would let every one of them read the same count and all
// of them issue. A caller enforcing "at most n links an hour" uses this, not
// that pair.
//
// The limit is the caller's, as it is the caller's policy; the window is the
// manager's, for the reason IssuedCount gives. A limit below one refuses every
// issue. Every other failure is reported as Issue reports it, and is never
// ErrIssueLimitReached: a store that cannot answer is an outage, not a subject
// who asked too often.
func (m *Tokens) IssueWithin(
	ctx context.Context, subject string, limit int, opts ...IssueOption,
) (string, Token, error) {
	presented, tok, err := m.mint(subject, opts)
	if err != nil {
		return "", Token{}, err
	}

	stored, err := m.store.InsertWithin(ctx, tok, tok.IssuedAt.Add(-m.issuanceWindow), limit)
	if err != nil {
		return "", Token{}, diag.Wrap(err, "onetime: store token")
	}
	if !stored {
		return "", Token{}, ErrIssueLimitReached
	}

	return presented, tok, nil
}

// mint draws a token for subject and returns its presented form and the
// record to store, writing nothing.
func (m *Tokens) mint(subject string, opts []IssueOption) (string, Token, error) {
	if subject == "" {
		return "", Token{}, ErrSubjectRequired
	}

	var issue issuance
	for _, opt := range opts {
		if opt != nil {
			opt(&issue)
		}
	}

	raw := make([]byte, secretBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", Token{}, fmt.Errorf("onetime: read random source: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)

	tokenID, err := m.ids.NewID()
	if err != nil {
		return "", Token{}, fmt.Errorf("onetime: generate token identifier: %w", err)
	}

	now := m.clock.Now()
	tok := Token{
		ID:         tokenID,
		Purpose:    m.purpose,
		Subject:    subject,
		SecretHash: hash(secret),
		IssuedAt:   now,
		ExpiresAt:  now.Add(m.ttl),
	}
	if issue.binding != "" {
		tok.BindingHash = hash(issue.binding)
	}

	return tokenID.String() + secretSeparator + secret, tok, nil
}

// Check reports whether presented is a token this manager will honour, and
// returns the proof Consume takes.
//
// It writes nothing, whether it succeeds or fails. That is what lets every one
// of several racing callers check the same token and still leave exactly one
// consumption to decide between them, and it is why a refused check costs the
// holder nothing.
//
// Every refusal is ErrInvalidToken and nothing more. A malformed string, an
// unknown record, another manager's purpose, a token already spent, one past
// its expiry, a secret that does not match, a binding that does not match and a
// store that could not answer are all the same answer, because a caller able to
// tell them apart could enumerate which records exist and which are still
// unspent while holding no valid token at all. A store failure is additionally
// logged at error level, since it is an outage this package has deliberately
// made invisible to the caller and would otherwise leave no trace anywhere.
//
// The binding is compared only when the token was issued with one. A token
// issued unbound ignores whatever is presented here, rather than behaving as
// though it had been bound to the empty string.
//
// Secret and binding comparisons run in constant time, so the answer cannot be
// approached one byte at a time by measuring how long the refusal took.
func (m *Tokens) Check(ctx context.Context, presented, binding string) (Checked, error) {
	// A presented token has one shape and a known length. Refusing anything
	// longer before hashing keeps the work an unauthenticated caller can buy
	// bounded, whatever they paste in.
	if len(presented) > maxPresentedSize {
		return Checked{}, ErrInvalidToken
	}

	rawID, secret, found := strings.Cut(presented, secretSeparator)
	if !found || rawID == "" || secret == "" {
		return Checked{}, ErrInvalidToken
	}

	tokenID, err := id.Parse(rawID)
	if err != nil {
		return Checked{}, ErrInvalidToken
	}

	rec, err := m.store.FindByID(ctx, tokenID)
	if err != nil {
		// ErrTokenNotFound is the store answering, not failing: a record that
		// is not there is an ordinary refusal and says nothing about the
		// store's health.
		if !errors.Is(err, ErrTokenNotFound) {
			m.logger.LogAttrs(ctx, slog.LevelError, "onetime: reading the token store failed",
				append([]slog.Attr{
					slog.String("purpose", m.purpose),
					slog.String("token_id", tokenID.String()),
				}, diag.Failure("token-store", err)...)...)
		}

		return Checked{}, ErrInvalidToken
	}
	if rec == nil {
		return Checked{}, ErrInvalidToken
	}

	if rec.Purpose != m.purpose {
		return Checked{}, ErrInvalidToken
	}
	if !rec.ConsumedAt.IsZero() {
		return Checked{}, ErrInvalidToken
	}
	// Expiry is an instant the token does not survive: at ExpiresAt it is
	// already gone, so the boundary does not depend on a clock's resolution.
	if !m.clock.Now().Before(rec.ExpiresAt) {
		return Checked{}, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare(hash(secret), rec.SecretHash) != 1 {
		return Checked{}, ErrInvalidToken
	}
	if len(rec.BindingHash) > 0 && subtle.ConstantTimeCompare(hash(binding), rec.BindingHash) != 1 {
		return Checked{}, ErrInvalidToken
	}

	return Checked{token: *rec}, nil
}

// Consume spends a token that passed Check.
//
// The proof is what makes this safe to expose: c can only have come from Check,
// so there is no way to spend a token that was never checked. It is not, by
// itself, permission to spend — the store decides that, with one indivisible
// operation that succeeds only while the token is still unspent. A caller
// holding a proof from an earlier check therefore cannot spend the same token
// twice, and of several callers racing on one token exactly one succeeds.
//
// Every failure is ErrInvalidToken: a token someone else already spent, one
// that no longer exists, and a store that could not answer are the same answer
// here for the same reason they are the same answer in Check. The store
// failure is logged at error level, since nothing else records it.
func (m *Tokens) Consume(ctx context.Context, c Checked) error {
	if c.token.ID.IsZero() {
		return ErrInvalidToken
	}

	if err := m.store.Consume(ctx, c.token.ID, m.clock.Now()); err != nil {
		if !errors.Is(err, ErrTokenNotFound) {
			m.logger.LogAttrs(ctx, slog.LevelError, "onetime: marking the token consumed failed",
				append([]slog.Attr{
					slog.String("purpose", m.purpose),
					slog.String("token_id", c.token.ID.String()),
				}, diag.Failure("token-store", err)...)...)
		}

		return ErrInvalidToken
	}

	return nil
}

// Redeem checks presented, runs the caller's own checks in order and then
// spends the token, returning the record it spent.
//
// This is the whole redemption in one call, and the order is the point. The
// caller's checks run after the token has been shown to be good and before it
// is spent, which is the only window in which a refusal costs the holder
// nothing: a check that returns an error has that error returned unchanged —
// not wrapped, not replaced by ErrInvalidToken — and the token stays redeemable
// until it expires. A holder turned away by a rate limit or a pending
// enrolment can come back and use the link they were sent.
//
// A nil check is skipped, so a caller may assemble the slice conditionally
// without guarding each entry.
//
// If the store cannot mark the token consumed, redemption returns
// ErrInvalidToken and no record. Reporting anything else would let a caller
// tell an outage from a spent token, and returning the record would say a
// redemption happened that did not.
func (m *Tokens) Redeem(ctx context.Context, presented, binding string, checks ...Check) (Token, error) {
	c, err := m.Check(ctx, presented, binding)
	if err != nil {
		return Token{}, err
	}

	for _, check := range checks {
		if check == nil {
			continue
		}
		if err := check(ctx, c.token); err != nil {
			return Token{}, err
		}
	}

	if err := m.Consume(ctx, c); err != nil {
		return Token{}, err
	}

	tok := c.token
	tok.ConsumedAt = m.clock.Now()

	return tok, nil
}

// IssuedCount reports how many tokens this manager issued for subject within
// its issuance window before now, spent or not.
//
// The window is the manager's own and no caller may pass a different one. A
// count is what a resend limit or a "too many links requested" rule is built
// on, and a caller free to choose the window could choose one that counts
// nothing. To enforce such a limit, issue with IssueWithin: this count read
// before Issue is not one decision with it, so concurrent callers can all read
// a count below the limit and all issue.
//
// A store that cannot answer is reported. Returning zero on an outage would
// quietly lift every limit resting on this number, at exactly the moment the
// system is least able to notice.
func (m *Tokens) IssuedCount(ctx context.Context, subject string) (int, error) {
	since := m.clock.Now().Add(-m.issuanceWindow)

	n, err := m.store.CountRecentBySubject(ctx, m.purpose, subject, since)
	if err != nil {
		return 0, diag.Wrap(err, "onetime: count recent issuance")
	}

	return n, nil
}

// PurgeExpired deletes this manager's spent records and reports how many went.
//
// It removes only records that are both expired and older than the issuance
// window. The second condition is what keeps a sweep from colliding with
// IssuedCount: a token issued half an hour ago with a quarter-hour life is
// expired, but still inside the hour that limits how often a subject may ask
// for another, and deleting it would hand its holder a fresh allowance. The
// cutoff is therefore the manager's own window, not an argument, for the same
// reason the count's window is not one.
//
// Purging is a capability a store may not have, so it is a separate contract. A
// store that does not implement Reaper returns ErrReapUnsupported rather than
// reporting nothing removed: a sweep that never ran and a sweep that found
// nothing look identical in a metric, and a consumer who wired a store that
// cannot purge deserves to be told rather than to watch it grow.
func (m *Tokens) PurgeExpired(ctx context.Context) (int, error) {
	reaper, ok := m.store.(Reaper)
	if !ok {
		return 0, fmt.Errorf("%w: %T", ErrReapUnsupported, m.store)
	}

	removed, err := reaper.DeleteExpiredBefore(ctx, m.purpose, m.clock.Now().Add(-m.issuanceWindow))
	if err != nil {
		return 0, diag.Wrap(err, "onetime: purge expired tokens")
	}

	return removed, nil
}

// ExpiryTask returns the task that deletes the expired tokens of m's purpose,
// through m.PurgeExpired.
//
// The task is named "one-time-tokens:" followed by the purpose. It sets no
// Interval, because only the deployment knows its cadence, and it accepts no
// cutoff: the manager derives its own from the issuance window it is
// configured with. It never deletes a token that is still inside that window,
// expired or not, so a sweep cannot free issuance quota.
//
// A store that cannot purge yields an error that matches both
// expiry.ErrPurgeUnsupported and ErrReapUnsupported, never a run that removed
// nothing. A consumer who wants a different task name uses ExpiryTaskNamed.
func ExpiryTask(m *Tokens) expiry.Task {
	return ExpiryTaskNamed("one-time-tokens:"+m.Purpose(), m)
}

// ExpiryTaskNamed is ExpiryTask with a name the caller chooses, for owners that
// build on a one-time manager and publish a task under a name of their own.
// Its behaviour, limits and errors are those of ExpiryTask: no interval, no
// cutoff, and nothing inside the issuance window is deleted.
func ExpiryTaskNamed(name string, m *Tokens) expiry.Task {
	return expiry.Task{
		Name: name,
		Run: func(ctx context.Context) (int, error) {
			removed, err := m.PurgeExpired(ctx)
			if errors.Is(err, ErrReapUnsupported) {
				return removed, errors.Join(err, expiry.ErrPurgeUnsupported)
			}

			return removed, err
		},
	}
}
