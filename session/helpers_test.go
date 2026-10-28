package session_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// errNoEntropy stands in for a cryptographic source that has failed. Sessions
// must not be issued at all when it does.
var errNoEntropy = errors.New("no entropy available")

// testUser is the user reference every fixture belongs to unless a case cares
// about which user it is.
const testUser = identity.UserID("u1")

// createdAt is the wall-clock moment the fixtures are created at. It is the
// 09:00 of the spec's scenarios, so a deadline computed here can be read
// against them directly.
var createdAt = time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil an
// unchecked constructor error hands over.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// fixedClock is a consumer's own clock with only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// managerFor returns a manager on the default store with the default
// deadlines, for cases that do not care about either.
func managerFor(t *testing.T, opts ...session.Option) *session.Sessions {
	t.Helper()

	m, err := session.New(opts...)
	require.NoError(t, err)

	return m
}

// managerWithReader returns a manager over store, drawing identifiers from r.
func managerWithReader(t *testing.T, store session.Store, r io.Reader) *session.Sessions {
	t.Helper()

	return managerFor(t, session.WithStore(store), session.WithRandom(r))
}

// managerOnClock returns a manager and the store behind it, both reading the
// same clock, so expiry means the same thing on either side.
func managerOnClock(t *testing.T, clk *clockwork.FakeClock, opts ...session.Option) (*session.Sessions, *session.MemoryStore) {
	t.Helper()

	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	all := append([]session.Option{
		session.WithStore(store),
		session.WithClock(clk),
	}, opts...)

	return managerFor(t, all...), store
}

// liveUnpresented is a live session that has never been loaded.
func liveUnpresented(id string) *session.Session { return familyOf(id, graceFamily) }

// errStoreWrite stands in for a store that cannot take the new entry.
var errStoreWrite = errors.New("store refused the write")

// inFlightStore stands between a strict rotation's two writes: once armed,
// the first Supersede signals and waits on afterSupersede after it has
// written, and failDelete refuses every Delete, the rotation's last write.
type inFlightStore struct {
	*session.MemoryStore

	afterSupersede *gate
	failDelete     bool
}

func (s *inFlightStore) Supersede(ctx context.Context, op session.Supersession) error {
	err := s.MemoryStore.Supersede(ctx, op)
	if s.afterSupersede != nil {
		s.afterSupersede.pass()
	}

	return err
}

func (s *inFlightStore) Delete(ctx context.Context, id string) error {
	if s.failDelete {
		return errStoreWrite
	}

	return s.MemoryStore.Delete(ctx, id)
}

// failFirstMarkStore fails the first MarkPresented of one identifier, as a
// store outage would, and delegates everything else.
type failFirstMarkStore struct {
	*session.MemoryStore

	id   string
	once sync.Once
}

func (s *failFirstMarkStore) MarkPresented(ctx context.Context, id string, at time.Time) error {
	if id == s.id {
		failed := false
		s.once.Do(func() { failed = true })
		if failed {
			return errStoreQuotes
		}
	}

	return s.MemoryStore.MarkPresented(ctx, id, at)
}

// errStoreQuotes is a dependency failure whose text quotes an address and a
// user reference the library never handed it, as a database driver's
// constraint error does. Neither may reach the text of an error session
// returns.
var errStoreQuotes = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// isBare asserts err is sentinel itself, text included.
func isBare(sentinel error) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()

		assert.Same(t, sentinel, err) //nolint:testifylint // identity is the point
		if err != nil {
			assert.Equal(t, sentinel.Error(), err.Error())
		}
	}
}

// fakeCipher is an authenticated cipher in shape only: it binds the additional
// authenticated data and the key, which is everything the sealing store's
// contract rests on, and hides nothing from anyone reading the test.
//
// Tests supply their own rather than reaching for a real implementation,
// because session declares the Cipher port and imports no one who implements
// it.
type fakeCipher struct {
	key byte
}

func (c fakeCipher) Seal(plaintext, additionalData []byte) ([]byte, error) {
	out := make([]byte, 0, len(additionalData)+2+len(plaintext))
	out = append(out, c.key)
	out = append(out, additionalData...)
	out = append(out, 0x00)
	for _, b := range plaintext {
		out = append(out, b^c.key)
	}

	return out, nil
}

func (c fakeCipher) Open(ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) == 0 || ciphertext[0] != c.key {
		return nil, errRetiredKey
	}

	rest := ciphertext[1:]
	end := bytes.IndexByte(rest, 0x00)
	if end < 0 || !bytes.Equal(rest[:end], additionalData) {
		return nil, errWrongAAD
	}

	plaintext := make([]byte, 0, len(rest)-end-1)
	for _, b := range rest[end+1:] {
		plaintext = append(plaintext, b^c.key)
	}

	return plaintext, nil
}

// sealingStore returns a sealing store over a fresh in-memory store, and that
// inner store, so a case can read what actually landed.
func sealingStore(t *testing.T, key byte) (session.Store, *session.MemoryStore) {
	t.Helper()

	clk := clockwork.NewFakeClockAt(createdAt)
	inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	sealing, err := session.NewEncryptedStore(inner, fakeCipher{key: key})
	require.NoError(t, err)

	return sealing, inner
}

// storedSession is one record as a store would receive it from a manager.
// storedFamily is the family storedSession gives every session, since a store
// holds no session without one.
var storedFamily = id.MustParse("01926a4e-0000-7000-8000-0000000000ff")

func storedSession(sessionID string) *session.Session {
	return &session.Session{
		ID:                sessionID,
		UserID:            testUser,
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		CreatedAt:         createdAt,
		LastAccessedAt:    createdAt,
		IdleExpiresAt:     createdAt.Add(30 * time.Minute),
		AbsoluteExpiresAt: createdAt.Add(12 * time.Hour),
		Data:              map[string]string{"k": "v"},
	}
}

// familyOf returns storedSession's session as a member of family.
func familyOf(sessionID string, family id.ID) *session.Session {
	s := storedSession(sessionID)
	s.FamilyID = family
	s.FamilyCreatedAt = s.CreatedAt

	return s
}

// firstRotation supersedes old by successor at createdAt with a one-minute
// window and a retention deadline at storedSession's absolute deadline, as a
// first rotation observes no successor.
func firstRotation(old string, successor *session.Session) session.Supersession {
	return session.Supersession{
		Old:         old,
		AcceptUntil: createdAt.Add(time.Minute),
		RetainUntil: createdAt.Add(12 * time.Hour),
		Successor:   successor,
		Now:         createdAt,
	}
}

var (
	errRetiredKey = errors.New("fake cipher: sealed under another key")
	errWrongAAD   = errors.New("fake cipher: additional data does not match")
)

// graceFamily is the family of the mocked fixtures.
var graceFamily = id.MustParse("0192d2a0-0000-7000-8000-000000000001")

// gate holds one store call until the test opens it, after telling the test
// the call has arrived.
type gate struct {
	arrived chan struct{}
	open    chan struct{}
}

// pass signals arrival and waits until the test opens the gate.
func (g *gate) pass() {
	close(g.arrived)
	<-g.open
}

const day = 24 * time.Hour
