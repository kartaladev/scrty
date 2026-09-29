package magiclink_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
)

// errStoreDown is the outage the stores below simulate.
var errStoreDown = errors.New("dial tcp: connection refused")

const testPurpose = "magic-link"

// clocks lets a helper reach the clock of a manager another helper built, so
// the tests can keep passing *onetime.Manager around.
var clocks sync.Map // *onetime.Manager -> *clockwork.FakeClock

func testTokens(t *testing.T) *onetime.Manager {
	t.Helper()

	return tokensWithStore(t, nil)
}

func tokensWithStore(t *testing.T, store onetime.Store) *onetime.Manager {
	t.Helper()

	// The token managers built here read a fake clock, so a test can move a
	// link past its expiry instead of waiting for it.
	clock := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))

	opts := []onetime.Option{onetime.WithClock(clock)}
	if store == nil {
		store = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clock))
	}
	opts = append(opts, onetime.WithStore(store))

	tokens, err := onetime.NewManager(testPurpose, opts...)
	require.NoError(t, err)

	clocks.Store(tokens, clock)
	t.Cleanup(func() { clocks.Delete(tokens) })

	return tokens
}

// tokensWithFailingStore builds a manager whose store refuses every write.
func tokensWithFailingStore(t *testing.T) *onetime.Manager {
	t.Helper()

	return tokensWithStore(t, insertFailsStore{Store: onetime.NewMemoryStore()})
}

func advanceClockPast(t *testing.T, tokens *onetime.Manager) {
	t.Helper()

	c, ok := clocks.Load(tokens)
	require.True(t, ok, "the manager was not built by a helper in this package")

	c.(*clockwork.FakeClock).Advance(tokens.TTL() + time.Second)
}

func issueFor(t *testing.T, tokens *onetime.Manager, subject string) string {
	t.Helper()

	presented, _, err := tokens.Issue(t.Context(), subject)
	require.NoError(t, err)

	return presented
}

// freshUnknownToken returns a well-formed token that no store this test uses
// has ever heard of.
func freshUnknownToken(t *testing.T) string {
	t.Helper()

	return issueFor(t, tokensWithStore(t, onetime.NewMemoryStore()), "u-1")
}

func consume(t *testing.T, tokens *onetime.Manager, presented string) {
	t.Helper()

	_, err := tokens.Redeem(t.Context(), presented, "")
	require.NoError(t, err)
}

func newManager(t *testing.T, baseURL string, opts ...magiclink.Option) (*magiclink.Manager, error) {
	t.Helper()

	return magiclink.NewManager(testTokens(t), stubLoader{}, &recordingSender{}, baseURL, opts...)
}

// --- user loaders ---------------------------------------------------------

// stubLoader answers from two fixed maps, or fails every call when err is set.
type stubLoader struct {
	byUsername map[string]*identity.Details
	byID       map[identity.UserID]*identity.Details
	err        error
}

func (l stubLoader) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	if l.err != nil {
		return nil, l.err
	}
	if d, ok := l.byUsername[username]; ok {
		return d, nil
	}

	return nil, identity.ErrUserNotFound
}

func (l stubLoader) LoadByUserID(_ context.Context, userID identity.UserID) (*identity.Details, error) {
	if l.err != nil {
		return nil, l.err
	}
	if d, ok := l.byID[userID]; ok {
		return d, nil
	}

	return nil, identity.ErrUserNotFound
}

func activeLoader() stubLoader {
	return stubLoader{byUsername: map[string]*identity.Details{
		"ada@example.com": {ID: "u-1", Username: "ada@example.com", Active: true},
	}}
}

func activeByID() stubLoader {
	return stubLoader{
		byUsername: map[string]*identity.Details{
			"ada@example.com": {ID: "u-1", Username: "ada@example.com", Active: true},
		},
		byID: map[identity.UserID]*identity.Details{
			"u-1": {ID: "u-1", Username: "ada@example.com", Active: true},
		},
	}
}

// recordingLoader records every username it was asked for.
type recordingLoader struct {
	mu        sync.Mutex
	usernames []string
}

func (l *recordingLoader) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	l.mu.Lock()
	l.usernames = append(l.usernames, username)
	l.mu.Unlock()

	return nil, identity.ErrUserNotFound
}

func (l *recordingLoader) LoadByUserID(context.Context, identity.UserID) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (l *recordingLoader) Usernames() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.usernames...)
}

// mutableLoader is a stubLoader a test rewrites between calls.
type mutableLoader struct {
	mu         sync.Mutex
	byUsername map[string]*identity.Details
	byID       map[identity.UserID]*identity.Details
}

func (l *mutableLoader) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if d, ok := l.byUsername[username]; ok {
		return d, nil
	}

	return nil, identity.ErrUserNotFound
}

func (l *mutableLoader) LoadByUserID(_ context.Context, userID identity.UserID) (*identity.Details, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if d, ok := l.byID[userID]; ok {
		return d, nil
	}

	return nil, identity.ErrUserNotFound
}

func (l *mutableLoader) reassign(from identity.UserID, to *identity.Details) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.byID, from)
	l.byUsername[to.Username] = to
	l.byID[to.ID] = to
}

// flakyLoader fails until Recover is called.
type flakyLoader struct {
	mu      sync.Mutex
	err     error
	healthy stubLoader
}

func (l *flakyLoader) LoadByUsername(ctx context.Context, username string) (*identity.Details, error) {
	l.mu.Lock()
	err := l.err
	l.mu.Unlock()

	if err != nil {
		return nil, err
	}

	return l.healthy.LoadByUsername(ctx, username)
}

func (l *flakyLoader) LoadByUserID(ctx context.Context, userID identity.UserID) (*identity.Details, error) {
	l.mu.Lock()
	err := l.err
	l.mu.Unlock()

	if err != nil {
		return nil, err
	}

	return l.healthy.LoadByUserID(ctx, userID)
}

func (l *flakyLoader) Recover() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.err = nil
	l.healthy = activeByID()
}

// --- senders --------------------------------------------------------------

// recordingSender keeps every message, and declares itself non-blocking so a
// manager will accept it.
type recordingSender struct {
	mu   sync.Mutex
	sent []notify.Message
}

func (s *recordingSender) Send(_ context.Context, msg notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sent = append(s.sent, msg)

	return nil
}

func (s *recordingSender) NonBlocking() bool { return true }

func (s *recordingSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sent)
}

func (s *recordingSender) Last() notify.Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sent) == 0 {
		return notify.Message{}
	}

	return s.sent[len(s.sent)-1]
}

// failingSender accepts a message and fails to deliver it.
type failingSender struct {
	mu    sync.Mutex
	err   error
	count int
}

func (s *failingSender) Send(context.Context, notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.count++

	return s.err
}

func (s *failingSender) NonBlocking() bool { return true }

func (s *failingSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.count
}

// liarSender implements NonBlocking and answers whatever it was told to.
type liarSender struct {
	nonBlocking bool
}

func (s liarSender) Send(context.Context, notify.Message) error { return nil }

func (s liarSender) NonBlocking() bool { return s.nonBlocking }

// --- token stores ---------------------------------------------------------

// countingTokenStore counts how often a consume was attempted.
type countingTokenStore struct {
	onetime.Store

	mu       sync.Mutex
	consumes int
}

func (s *countingTokenStore) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	s.mu.Lock()
	s.consumes++
	s.mu.Unlock()

	return s.Store.Consume(ctx, tokenID, at)
}

func (s *countingTokenStore) Consumes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.consumes
}

// consumeFailsStore reads like any other store and fails the consume write.
type consumeFailsStore struct {
	onetime.Store
}

func (s consumeFailsStore) Consume(context.Context, id.ID, time.Time) error {
	return errStoreDown
}

// insertFailsStore refuses to write a newly issued token.
type insertFailsStore struct {
	onetime.Store
}

func (s insertFailsStore) Insert(context.Context, onetime.Token) error {
	return errStoreDown
}

// failingReader is a random source that is down.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errStoreDown }
