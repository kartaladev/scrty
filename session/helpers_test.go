package session_test

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
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
func managerFor(t *testing.T, opts ...session.ManagerOption) *session.Manager {
	t.Helper()

	m, err := session.NewManager(opts...)
	require.NoError(t, err)

	return m
}

// managerWithReader returns a manager over store, drawing identifiers from r.
func managerWithReader(t *testing.T, store session.Store, r io.Reader) *session.Manager {
	t.Helper()

	return managerFor(t, session.WithStore(store), session.WithRandom(r))
}

// managerOnClock returns a manager and the store behind it, both reading the
// same clock, so expiry means the same thing on either side.
func managerOnClock(t *testing.T, clk *clockwork.FakeClock, opts ...session.ManagerOption) (*session.Manager, *session.MemoryStore) {
	t.Helper()

	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	all := append([]session.ManagerOption{
		session.WithStore(store),
		session.WithClock(clk),
	}, opts...)

	return managerFor(t, all...), store
}
