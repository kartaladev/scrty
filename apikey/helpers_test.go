package apikey_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// errStore is what the stores below report. Its text is the shape of a real
// outage, so a test that let it escape would show it in the failure output.
var errStore = errors.New("dial tcp: connection refused")

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// failingReader is a random source that cannot answer.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

// countingKeyStore counts what reaches the store behind it.
//
// It is a decorator rather than a generated mock because what these tests
// assert is that a call did *not* happen — that a malformed key costs no
// lookup — while every other call still behaves exactly as the real store
// does. A mock would have to restate the real store's behaviour to say that.
type countingKeyStore struct {
	apikey.Store

	mu     sync.Mutex
	writes int
	reads  int
	lists  int
}

func (s *countingKeyStore) Put(ctx context.Context, rec apikey.Key) error {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()

	return s.Store.Put(ctx, rec)
}

func (s *countingKeyStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()

	return s.Store.Get(ctx, keyID)
}

func (s *countingKeyStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()

	return s.Store.Revoke(ctx, keyID, at)
}

func (s *countingKeyStore) TouchLastUsed(ctx context.Context, keyID id.ID, at time.Time) error {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()

	return s.Store.TouchLastUsed(ctx, keyID, at)
}

func (s *countingKeyStore) List(ctx context.Context, principal identity.UserID) ([]apikey.Key, error) {
	s.mu.Lock()
	s.lists++
	s.mu.Unlock()

	return s.Store.List(ctx, principal)
}

func (s *countingKeyStore) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writes
}

func (s *countingKeyStore) Reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.reads
}

func (s *countingKeyStore) Lists() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lists
}

// revokeFailsStore is a working store whose Revoke alone cannot succeed.
type revokeFailsStore struct {
	apikey.Store
}

func (s revokeFailsStore) Revoke(context.Context, id.ID, time.Time) (bool, error) {
	return false, errStore
}

// touchFailsStore is a working store whose last-use write alone cannot succeed.
type touchFailsStore struct {
	apikey.Store
}

func (s touchFailsStore) TouchLastUsed(context.Context, id.ID, time.Time) error { return errStore }

// newID mints an identifier for a key that was never issued.
func newID() (id.ID, error) { return id.NewV7Generator().NewID() }

// sha256Of is the digest a manager with no WithDigest uses, restated here so
// the test asserts the documented default rather than whatever the package
// happens to call.
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}

// revokeBarrierStore holds every Revoke of one key until a set number of
// callers have reached it, then lets them all through at once.
//
// It is how a test makes concurrent rotations of one key meet at the write
// that decides them: each has read the key live and issued its replacement
// before any of them revokes, which is the interleaving a read-then-write
// rotation loses to. A revoke of any other key passes straight through. It is
// a decorator, not a generated mock, because every call must still behave as
// the real store does.
type revokeBarrierStore struct {
	apikey.Store

	target  id.ID
	parties int

	mu      sync.Mutex
	arrived int
	all     chan struct{}
}

func newRevokeBarrierStore(inner apikey.Store, target id.ID, parties int) *revokeBarrierStore {
	return &revokeBarrierStore{Store: inner, target: target, parties: parties, all: make(chan struct{})}
}

func (s *revokeBarrierStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	if keyID != s.target {
		return s.Store.Revoke(ctx, keyID, at)
	}

	s.mu.Lock()
	s.arrived++
	if s.arrived == s.parties {
		close(s.all)
	}
	s.mu.Unlock()

	select {
	case <-s.all:
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(10 * time.Second):
		return false, fmt.Errorf("only some of %d rotations reached the revoke", s.parties)
	}

	return s.Store.Revoke(ctx, keyID, at)
}

// advanceOnPutStore moves a fake clock forward each time a key is stored
// after the first, so the key a test issued first can expire between a
// rotation's liveness check and its revoke.
type advanceOnPutStore struct {
	apikey.Store

	clk  *clockwork.FakeClock
	by   time.Duration
	puts *atomic.Int32
}

func (s advanceOnPutStore) Put(ctx context.Context, rec apikey.Key) error {
	if s.puts.Add(1) > 1 {
		s.clk.Advance(s.by)
	}

	return s.Store.Put(ctx, rec)
}

// loseThenCancelStore makes the first Revoke lose: another caller ends the
// key first, and the context of the call in flight is cancelled, as a client
// hanging up would. Every later Revoke refuses a cancelled context, as a
// database driver does, and otherwise behaves as the store beneath.
type loseThenCancelStore struct {
	apikey.Store

	cancel context.CancelFunc
	calls  atomic.Int32
}

func (s *loseThenCancelStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	if s.calls.Add(1) == 1 {
		if _, err := s.Store.Revoke(context.WithoutCancel(ctx), keyID, at); err != nil {
			return false, err
		}

		s.cancel()

		return false, nil
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.Store.Revoke(ctx, keyID, at)
}

// zeroReader is a random source that answers with zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)

	return len(p), nil
}

// emptyForLeadingZero is a consumer digest that returns nothing for an input
// whose first byte is zero, and SHA-256 for every other input. It passes any
// construction probe whose inputs do not start with a zero byte, so it is how
// a test reaches an empty digest at issue and at verification.
func emptyForLeadingZero(b []byte) []byte {
	if len(b) > 0 && b[0] == 0 {
		return nil
	}

	return sha256Of(b)
}
