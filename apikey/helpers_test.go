package apikey_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

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

func (s *countingKeyStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) error {
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

func (s revokeFailsStore) Revoke(context.Context, id.ID, time.Time) error { return errStore }

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
