// Construction, issuance, counting and purging are exercised through tables
// here. A few tests stand outside one because their shape is not "call the
// manager once and assert on the result": they issue a thousand tokens, or read
// the record back out of the store to see what was written.
//
//go:generate mockgen -source=../pkg/id/generator.go -package=onetime_test -destination=idgenerator_mock_test.go -typed
package onetime_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
)

// errNoEntropy stands in for a random source that cannot answer.
var errNoEntropy = errors.New("no entropy")

// errStoreDown stands in for a store that cannot answer.
var errStoreDown = errors.New("store down")

// issuedAt is the instant every test clock starts from.
var issuedAt = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil an
// unchecked constructor error hands over.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// fixedClock is a consumer's own clock with only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// newManager returns a manager and the in-memory store behind it, both reading
// the same clock so that expiry means the same thing on either side.
func newManager(t *testing.T, clk *clockwork.FakeClock, opts ...onetime.Option) (*onetime.Manager, *onetime.MemoryStore) {
	t.Helper()

	store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
	all := append([]onetime.Option{onetime.WithStore(store), onetime.WithClock(clk)}, opts...)

	m, err := onetime.NewManager("magic-link", all...)
	require.NoError(t, err)

	return m, store
}

// secretOf returns the secret half of a presented token.
func secretOf(t *testing.T, presented string) string {
	t.Helper()

	_, secret, ok := strings.Cut(presented, ".")
	require.True(t, ok, "the presented token is not <id>.<secret>")

	return secret
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		purpose string
		opts    []onetime.Option
		assert  func(t *testing.T, m *onetime.Manager, err error)
	}

	configError := func(t *testing.T, m *onetime.Manager, err error) {
		t.Helper()

		require.ErrorIs(t, err, onetime.ErrConfig)
		assert.Nil(t, m, "a refused configuration still handed back a manager")
	}

	var nilStore onetime.Store
	var nilGenerator id.Generator

	cases := []testCase{
		{
			name:    "defaults to a 15 minute time-to-live and a one hour issuance window",
			purpose: "magic-link",
			assert: func(t *testing.T, m *onetime.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 15*time.Minute, m.TTL())
				assert.Equal(t, time.Hour, m.IssuanceWindow())
			},
		},
		{
			name:    "a consumer replaces both durations",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithTTL(24 * time.Hour), onetime.WithIssuanceWindow(6 * time.Hour)},
			assert: func(t *testing.T, m *onetime.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 24*time.Hour, m.TTL())
				assert.Equal(t, 6*time.Hour, m.IssuanceWindow())
			},
		},
		{
			// A purposeless manager would let a password-reset token redeem as
			// a magic link, because the purpose is the only thing that keeps
			// two managers sharing a store apart.
			name:    "an empty purpose is refused",
			purpose: "",
			assert:  configError,
		},
		{
			name:    "a whitespace-only purpose is refused",
			purpose: "   ",
			assert:  configError,
		},
		{
			name:    "a zero time-to-live is refused, because every token would expire as it was issued",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithTTL(0)},
			assert:  configError,
		},
		{
			name:    "a negative time-to-live is refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithTTL(-time.Second)},
			assert:  configError,
		},
		{
			name:    "a zero issuance window is refused, because it counts nothing and purges everything",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithIssuanceWindow(0)},
			assert:  configError,
		},
		{
			name:    "a negative issuance window is refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithIssuanceWindow(-time.Second)},
			assert:  configError,
		},
		{
			name:    "an untyped nil store is refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithStore(nil)},
			assert:  configError,
		},
		{
			name:    "a typed nil store is refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithStore(nilStore)},
			assert:  configError,
		},
		{
			name:    "a typed nil identifier generator is refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithIDGenerator(nilGenerator)},
			assert:  configError,
		},
		{
			name:    "a nil clock is refused, because falling back to the wall clock hides an unadvanced test clock",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithClock(nil)},
			assert:  configError,
		},
		{
			name:    "a typed nil clock is refused like an untyped one, rather than panicking at the first issue",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithClock((*nilClock)(nil))},
			assert:  configError,
		},
		{
			name:    "a consumer clock with only Now is accepted",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithClock(fixedClock{at: issuedAt})},
			assert: func(t *testing.T, m *onetime.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:    "a nil random source is refused, because a silent fallback would hide a deliberate entropy choice",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithRandom(nil)},
			assert:  configError,
		},
		{
			name:    "a nil logger is ignored rather than refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithLogger(nil)},
			assert: func(t *testing.T, m *onetime.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:    "a consumer logger is accepted",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))},
			assert: func(t *testing.T, m *onetime.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:    "a nil option is ignored",
			purpose: "magic-link",
			opts:    []onetime.Option{nil},
			assert: func(t *testing.T, m *onetime.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := onetime.NewManager(tc.purpose, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

func TestIssue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		subject string
		issue   []onetime.IssueOption
		manager func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore)
		assert  func(t *testing.T, store *onetime.MemoryStore, presented string, tok onetime.Token, err error)
	}

	plain := func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
		t.Helper()

		return newManager(t, clk)
	}

	cases := []testCase{
		{
			name:    "a presented token is the record identifier, a dot, and 32 random bytes in base64url",
			subject: "ada@example.com",
			manager: plain,
			assert: func(t *testing.T, _ *onetime.MemoryStore, presented string, tok onetime.Token, err error) {
				require.NoError(t, err)

				rawID, secret, ok := strings.Cut(presented, ".")
				require.True(t, ok, "the presented token is not <id>.<secret>")
				assert.Equal(t, tok.ID.String(), rawID)

				decoded, err := base64.RawURLEncoding.DecodeString(secret)
				require.NoError(t, err, "the secret is not unpadded base64url")
				assert.Len(t, decoded, 32)
			},
		},
		{
			name:    "the subject and purpose are stored unchanged",
			subject: "  Ada O'Hara  ",
			manager: plain,
			assert: func(t *testing.T, _ *onetime.MemoryStore, _ string, tok onetime.Token, err error) {
				require.NoError(t, err)
				assert.Equal(t, "  Ada O'Hara  ", tok.Subject,
					"the library interpreted a subject that belongs to the consumer")
				assert.Equal(t, "magic-link", tok.Purpose)
			},
		},
		{
			name:    "expiry is the issue time plus the time-to-live",
			subject: "ada@example.com",
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
				t.Helper()

				return newManager(t, clk, onetime.WithTTL(24*time.Hour))
			},
			assert: func(t *testing.T, _ *onetime.MemoryStore, _ string, tok onetime.Token, err error) {
				require.NoError(t, err)
				assert.Equal(t, issuedAt, tok.IssuedAt)
				assert.Equal(t, issuedAt.Add(24*time.Hour), tok.ExpiresAt)
				assert.True(t, tok.ConsumedAt.IsZero(), "a freshly issued token was already spent")
			},
		},
		{
			// The subject is what every count, every audit line and every
			// consumer lookup keys on. Issuing without one would put a record
			// in the store that belongs to nobody.
			name:    "an empty subject is refused and nothing is stored",
			subject: "",
			manager: plain,
			assert: func(t *testing.T, store *onetime.MemoryStore, presented string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrSubjectRequired)
				assert.Empty(t, presented)
				assert.Zero(t, store.Len(), "a refused issuance still wrote a record")
			},
		},
		{
			name:    "a random source that fails is an error, never a weaker secret",
			subject: "ada@example.com",
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
				t.Helper()

				return newManager(t, clk, onetime.WithRandom(iotest.ErrReader(errNoEntropy)))
			},
			assert: func(t *testing.T, store *onetime.MemoryStore, presented string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, errNoEntropy)
				assert.Empty(t, presented)
				assert.Zero(t, store.Len(), "a failed issuance still wrote a record")
			},
		},
		{
			name:    "a short read from the random source is an error, never a shorter secret",
			subject: "ada@example.com",
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
				t.Helper()

				return newManager(t, clk, onetime.WithRandom(strings.NewReader("too short")))
			},
			assert: func(t *testing.T, store *onetime.MemoryStore, presented string, _ onetime.Token, err error) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, store.Len(), "a failed issuance still wrote a record")
			},
		},
		{
			name:    "an identifier generator that fails is an error",
			subject: "ada@example.com",
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
				t.Helper()

				gen := NewMockGenerator(gomock.NewController(t))
				gen.EXPECT().NewID().Return(id.Nil, errNoEntropy)

				return newManager(t, clk, onetime.WithIDGenerator(gen))
			},
			assert: func(t *testing.T, store *onetime.MemoryStore, presented string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, errNoEntropy)
				assert.Empty(t, presented)
				assert.Zero(t, store.Len(), "a failed issuance still wrote a record")
			},
		},
		{
			name:    "a consumer generator supplies the record identifier",
			subject: "ada@example.com",
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
				t.Helper()

				gen := NewMockGenerator(gomock.NewController(t))
				gen.EXPECT().NewID().Return(id.MustParse("01999f00-0000-7000-8000-00000000abcd"), nil)

				return newManager(t, clk, onetime.WithIDGenerator(gen))
			},
			assert: func(t *testing.T, _ *onetime.MemoryStore, presented string, tok onetime.Token, err error) {
				require.NoError(t, err)
				assert.Equal(t, id.MustParse("01999f00-0000-7000-8000-00000000abcd"), tok.ID)
				assert.True(t, strings.HasPrefix(presented, "01999f00-0000-7000-8000-00000000abcd."))
			},
		},
		{
			name:    "a store that cannot insert is reported, not swallowed",
			subject: "ada@example.com",
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Manager, *onetime.MemoryStore) {
				t.Helper()

				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errStoreDown)

				m, err := onetime.NewManager("magic-link",
					onetime.WithStore(store), onetime.WithClock(clk))
				require.NoError(t, err)

				return m, nil
			},
			assert: func(t *testing.T, _ *onetime.MemoryStore, presented string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, errStoreDown)
				assert.Empty(t, presented, "a token nobody stored was handed to the caller")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(issuedAt)
			m, store := tc.manager(t, clk)

			presented, tok, err := m.Issue(t.Context(), tc.subject, tc.issue...)
			tc.assert(t, store, presented, tok, err)
		})
	}
}

// TestIssueDefaultClockIsTheSystemClock is the time-source scenario "System
// clock by default": with no clock option, a manager and the default
// in-memory store behind it both read the system clock, so an issued token's
// expiry lands the lifetime after the system time at issue. It stands outside
// TestIssue's table because it needs the real wall clock read around the call,
// which the table's shared runner has no row-specific room for.
func TestIssueDefaultClockIsTheSystemClock(t *testing.T) {
	t.Parallel()

	m, err := onetime.NewManager("magic-link", onetime.WithTTL(5*time.Minute))
	require.NoError(t, err)

	before := time.Now()
	_, tok, err := m.Issue(t.Context(), "ada@example.com")
	after := time.Now()
	require.NoError(t, err)

	assert.False(t, tok.ExpiresAt.Before(before.Add(5*time.Minute)),
		"expiry landed before the earliest system time plus the lifetime")
	assert.False(t, tok.ExpiresAt.After(after.Add(5*time.Minute)),
		"expiry landed after the latest system time plus the lifetime")
}

func TestIssuedIdentifiersNeverCollide(t *testing.T) {
	t.Parallel()

	m, _ := newManager(t, clockwork.NewFakeClockAt(issuedAt))

	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		_, duplicate := seen[tok.ID.String()]
		require.False(t, duplicate, "a record identifier repeated")
		seen[tok.ID.String()] = struct{}{}

		_, secretDuplicate := seen[secretOf(t, presented)]
		require.False(t, secretDuplicate, "a token secret repeated")
		seen[secretOf(t, presented)] = struct{}{}
	}
}

func TestIssuedSecretsAreOnlyStoredAsHashes(t *testing.T) {
	t.Parallel()

	const binding = "device-nonce-a"

	clk := clockwork.NewFakeClockAt(issuedAt)
	m, store := newManager(t, clk)

	presented, tok, err := m.Issue(t.Context(), "ada@example.com", onetime.WithBinding(binding))
	require.NoError(t, err)

	secret := secretOf(t, presented)

	stored, err := store.FindByID(t.Context(), tok.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)

	secretSum := sha256.Sum256([]byte(secret))
	assert.Equal(t, secretSum[:], stored.SecretHash)
	assert.NotContains(t, string(stored.SecretHash), secret, "the secret itself reached the store")

	bindingSum := sha256.Sum256([]byte(binding))
	assert.Equal(t, bindingSum[:], stored.BindingHash)
	assert.NotContains(t, string(stored.BindingHash), binding, "the binding itself reached the store")

	assert.NotContains(t, fmt.Sprintf("%+v", tok), secret,
		"the record the manager returned carries the secret it was supposed to keep out of reach")
	assert.NotContains(t, fmt.Sprintf("%+v", tok), binding)
}

func TestAnUnboundTokenStoresNoBindingHash(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(issuedAt)
	m, store := newManager(t, clk)

	_, tok, err := m.Issue(t.Context(), "ada@example.com")
	require.NoError(t, err)

	stored, err := store.FindByID(t.Context(), tok.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Nil(t, stored.BindingHash,
		"an absent binding was stored as a hash of the empty string, which any caller could present")
}

// sha256Of is what the package stores for a secret or a binding.
func sha256Of(value string) []byte {
	sum := sha256.Sum256([]byte(value))

	return sum[:]
}

// managerFor returns a second manager over an existing store, so that a test
// can show one purpose's tokens are invisible to another's.
func managerFor(t *testing.T, purpose string, store onetime.Store, clk *clockwork.FakeClock, opts ...onetime.Option) *onetime.Manager {
	t.Helper()

	all := append([]onetime.Option{onetime.WithStore(store), onetime.WithClock(clk)}, opts...)

	m, err := onetime.NewManager(purpose, all...)
	require.NoError(t, err)

	return m
}

// issueAgo issues a token as though it had been issued ago before issuedAt, and
// leaves the clock back at issuedAt.
func issueAgo(t *testing.T, clk *clockwork.FakeClock, m *onetime.Manager, subject string, ago time.Duration) string {
	t.Helper()

	clk.Advance(issuedAt.Add(-ago).Sub(clk.Now()))
	defer func() { clk.Advance(issuedAt.Sub(clk.Now())) }()

	presented, _, err := m.Issue(t.Context(), subject)
	require.NoError(t, err)

	return presented
}

func TestIssuedCount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []onetime.Option
		issue  func(t *testing.T, clk *clockwork.FakeClock, m, other *onetime.Manager)
		assert func(t *testing.T, n int, err error)
	}

	counts := func(want int) func(t *testing.T, n int, err error) {
		return func(t *testing.T, n int, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, want, n)
		}
	}

	cases := []testCase{
		{
			name:   "a subject nobody issued for counts nothing",
			assert: counts(0),
		},
		{
			name: "every issue inside the window counts",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", 5*time.Minute)
				issueAgo(t, clk, m, "ada@example.com", 10*time.Minute)
				issueAgo(t, clk, m, "ada@example.com", 59*time.Minute)
			},
			assert: counts(3),
		},
		{
			name: "an issue older than the window does not count",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", 10*time.Minute)
				issueAgo(t, clk, m, "ada@example.com", 70*time.Minute)
			},
			assert: counts(1),
		},
		{
			name: "an issue exactly at the edge of the window still counts",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", time.Hour)
			},
			assert: counts(1),
		},
		{
			name: "an issue one moment before the edge does not",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", time.Hour+time.Nanosecond)
			},
			assert: counts(0),
		},
		{
			name: "another subject is not counted",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, m, "bob@example.com", 5*time.Minute)
			},
			assert: counts(0),
		},
		{
			name: "the same subject under another purpose is not counted",
			issue: func(t *testing.T, clk *clockwork.FakeClock, _, other *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, other, "ada@example.com", 5*time.Minute)
			},
			assert: counts(0),
		},
		{
			name: "a consumer window widens what counts",
			opts: []onetime.Option{onetime.WithIssuanceWindow(6 * time.Hour)},
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", 70*time.Minute)
			},
			assert: counts(1),
		},
		{
			name: "a consumed token still counts, because it was still issued",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Manager) {
				t.Helper()

				presented := issueAgo(t, clk, m, "ada@example.com", 5*time.Minute)
				_, err := m.Redeem(t.Context(), presented, "")
				require.NoError(t, err)
			},
			assert: counts(1),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(issuedAt)
			m, store := newManager(t, clk, tc.opts...)
			other := managerFor(t, "email-code", store, clk)

			if tc.issue != nil {
				tc.issue(t, clk, m, other)
			}

			n, err := m.IssuedCount(t.Context(), "ada@example.com")
			tc.assert(t, n, err)
		})
	}
}

func TestIssuedCountReportsAStoreThatCannotAnswer(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)
	store.EXPECT().
		CountRecentBySubject(gomock.Any(), "magic-link", "ada@example.com", issuedAt.Add(-time.Hour)).
		Return(0, errStoreDown)

	clk := clockwork.NewFakeClockAt(issuedAt)
	m, err := onetime.NewManager("magic-link", onetime.WithStore(store), onetime.WithClock(clk))
	require.NoError(t, err)

	n, err := m.IssuedCount(t.Context(), "ada@example.com")
	// A count is a quota decision, not a token decision: reporting zero on an
	// outage would silently raise every limit built on top of it.
	require.ErrorIs(t, err, errStoreDown)
	assert.Zero(t, n)
}

func TestPurgeExpired(t *testing.T) {
	t.Parallel()

	t.Run("a token still inside the issuance window survives, so a sweep cannot free quota", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		// Expired a quarter of an hour ago, but issued only half an hour ago,
		// so IssuedCount still counts it and the purge must leave it alone.
		issueAgo(t, clk, m, "ada@example.com", 30*time.Minute)

		removed, err := m.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Zero(t, removed)

		n, err := m.IssuedCount(t.Context(), "ada@example.com")
		require.NoError(t, err)
		assert.Equal(t, 1, n, "a purge freed quota that IssuedCount still counts")
		assert.Equal(t, 1, store.Len())
	})

	t.Run("a token older than the window but not yet expired survives", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk, onetime.WithTTL(24*time.Hour))

		presented := issueAgo(t, clk, m, "ada@example.com", 2*time.Hour)

		removed, err := m.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Zero(t, removed)
		assert.Equal(t, 1, store.Len())

		_, err = m.Redeem(t.Context(), presented, "")
		require.NoError(t, err, "the purge broke a live token")
	})

	t.Run("a token both expired and past the window is removed", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		issueAgo(t, clk, m, "ada@example.com", 90*time.Minute)

		removed, err := m.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, removed)
		assert.Zero(t, store.Len())
	})

	t.Run("another purpose's records are left alone", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)
		other := managerFor(t, "email-code", store, clk)

		issueAgo(t, clk, m, "ada@example.com", 90*time.Minute)
		issueAgo(t, clk, other, "ada@example.com", 90*time.Minute)

		removed, err := m.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, removed)
		assert.Equal(t, 1, store.Len(), "a sweep reached into another purpose's records")
	})

	t.Run("a store that cannot purge says so rather than reporting nothing removed", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		// MockStore implements Store and nothing more. No EXPECT: a store that
		// cannot purge must be refused without a round trip.
		store := NewMockStore(ctrl)

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, err := onetime.NewManager("magic-link", onetime.WithStore(store), onetime.WithClock(clk))
		require.NoError(t, err)

		removed, err := m.PurgeExpired(t.Context())
		require.ErrorIs(t, err, onetime.ErrReapUnsupported,
			"a store with no reaper reported a successful sweep that never happened")
		assert.Zero(t, removed)
	})

	t.Run("a reaper that cannot answer is reported", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		store := newReapableStore(NewMockStore(ctrl), NewMockReaper(ctrl))
		store.MockReaper.EXPECT().
			DeleteExpiredBefore(gomock.Any(), "magic-link", issuedAt.Add(-time.Hour)).
			Return(0, errStoreDown)

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, err := onetime.NewManager("magic-link", onetime.WithStore(store), onetime.WithClock(clk))
		require.NoError(t, err)

		removed, err := m.PurgeExpired(t.Context())
		require.ErrorIs(t, err, errStoreDown)
		assert.Zero(t, removed)
	})
}

// reapableStore is a store that can also purge, assembled from the two
// generated mocks so a test can drive each half independently.
type reapableStore struct {
	*MockStore
	MockReaper *MockReaper
}

func newReapableStore(store *MockStore, reaper *MockReaper) *reapableStore {
	return &reapableStore{MockStore: store, MockReaper: reaper}
}

func (s *reapableStore) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	return s.MockReaper.DeleteExpiredBefore(ctx, purpose, retainSince)
}
