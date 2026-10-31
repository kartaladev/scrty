// Construction, issuance, checking, consumption, counting and purging are
// exercised through tables here. A few tests stand outside one because their
// shape is not "call the manager once and assert on the result": they issue a
// thousand tokens, race many callers, call through a mock store the table's
// runner does not build, or read the package's own source.
//
//go:generate mockgen -source=../../pkg/id/generator.go -package=onetime_test -destination=idgenerator_mock_test.go -typed

package onetime_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// errNoEntropy stands in for a random source that cannot answer.
var errNoEntropy = errors.New("no entropy")

// errStoreDown stands in for a store that cannot answer.
var errStoreDown = errors.New("store down")

// newManager returns a manager and the in-memory store behind it, both reading
// the same clock so that expiry means the same thing on either side.
func newManager(t *testing.T, clk *clockwork.FakeClock, opts ...onetime.Option) (*onetime.Tokens, *onetime.MemoryStore) {
	t.Helper()

	store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
	all := append([]onetime.Option{onetime.WithStore(store), onetime.WithClock(clk)}, opts...)

	m, err := onetime.New("magic-link", all...)
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
		assert  func(t *testing.T, m *onetime.Tokens, err error)
	}

	configError := func(t *testing.T, m *onetime.Tokens, err error) {
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
			assert: func(t *testing.T, m *onetime.Tokens, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 15*time.Minute, m.TokenTTL())
				assert.Equal(t, time.Hour, m.IssuanceWindow())
			},
		},
		{
			name:    "a consumer replaces both durations",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithTokenTTL(24 * time.Hour), onetime.WithIssuanceWindow(6 * time.Hour)},
			assert: func(t *testing.T, m *onetime.Tokens, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, 24*time.Hour, m.TokenTTL())
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
			opts:    []onetime.Option{onetime.WithTokenTTL(0)},
			assert:  configError,
		},
		{
			name:    "a negative time-to-live is refused",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithTokenTTL(-time.Second)},
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
			assert: func(t *testing.T, m *onetime.Tokens, err error) {
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
			assert: func(t *testing.T, m *onetime.Tokens, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:    "a consumer logger is accepted",
			purpose: "magic-link",
			opts:    []onetime.Option{onetime.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))},
			assert: func(t *testing.T, m *onetime.Tokens, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:    "a nil option is ignored",
			purpose: "magic-link",
			opts:    []onetime.Option{nil},
			assert: func(t *testing.T, m *onetime.Tokens, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := onetime.New(tc.purpose, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

// Standalone from TestNewManager: each row also issues, moves the clock and purges.
func TestNewManager_DefaultStoreFollowsClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// offset places the manager's clock relative to the system clock.
		offset time.Duration
		// store is the explicit store option, nil for none.
		store func(clk clockwork.Clock) onetime.Option
		// window is the issuance window.
		window time.Duration
		// advance is how far the clock moves after issuing.
		advance time.Duration
		assert  func(t *testing.T, m *onetime.Tokens, token string, purged int, err error)
	}

	cases := []testCase{
		{
			name:    "a clock ahead of the system clock purges what it expired",
			offset:  365 * 24 * time.Hour,
			window:  time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, _ *onetime.Tokens, _ string, purged int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, purged)
			},
		},
		{
			name:    "a clock behind the system clock keeps a live token",
			offset:  -365 * 24 * time.Hour,
			window:  10 * time.Minute,
			advance: 12 * time.Minute,
			assert: func(t *testing.T, m *onetime.Tokens, token string, purged int, err error) {
				require.NoError(t, err)
				assert.Zero(t, purged, "a token inside its lifetime must not be purged")
				_, checkErr := m.Check(t.Context(), token, "")
				assert.NoError(t, checkErr, "the token is still live")
			},
		},
		{
			name:   "an explicit store keeps its own clock",
			offset: 365 * 24 * time.Hour,
			store: func(clockwork.Clock) onetime.Option {
				return onetime.WithStore(onetime.NewMemoryStore())
			},
			window:  time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, _ *onetime.Tokens, _ string, purged int, err error) {
				require.NoError(t, err)
				assert.Zero(t, purged, "the consumer's store judges expiry on its own clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fc := clockwork.NewFakeClockAt(time.Now().Add(tc.offset))
			opts := []onetime.Option{
				onetime.WithClock(fc),
				onetime.WithTokenTTL(15 * time.Minute),
				onetime.WithIssuanceWindow(tc.window),
			}
			if tc.store != nil {
				opts = append(opts, tc.store(fc))
			}
			m, err := onetime.New("email-change", opts...)
			require.NoError(t, err)

			ctx := t.Context()
			token, _, err := m.Issue(ctx, "carol")
			require.NoError(t, err)
			fc.Advance(tc.advance)

			purged, err := m.PurgeExpired(ctx)
			tc.assert(t, m, token, purged, err)
		})
	}
}

func TestIssue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		subject string
		issue   []onetime.IssueOption
		manager func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore)
		assert  func(t *testing.T, store *onetime.MemoryStore, presented string, tok onetime.Token, err error)
	}

	plain := func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
		t.Helper()

		return newManager(t, clk)
	}

	// binding is what the bound row issues with.
	const binding = "device-nonce-a"

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
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
				t.Helper()

				return newManager(t, clk, onetime.WithTokenTTL(24*time.Hour))
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
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
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
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
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
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
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
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
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
			manager: func(t *testing.T, clk *clockwork.FakeClock) (*onetime.Tokens, *onetime.MemoryStore) {
				t.Helper()

				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errStoreDown)

				m, err := onetime.New("magic-link",
					onetime.WithStore(store), onetime.WithClock(clk))
				require.NoError(t, err)

				return m, nil
			},
			assert: func(t *testing.T, _ *onetime.MemoryStore, presented string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, errStoreDown)
				assert.Empty(t, presented, "a token nobody stored was handed to the caller")
			},
		},
		{
			name:    "issued secrets are only stored as hashes",
			subject: "ada@example.com",
			issue:   []onetime.IssueOption{onetime.WithBinding(binding)},
			manager: plain,
			assert: func(t *testing.T, store *onetime.MemoryStore, presented string, tok onetime.Token, err error) {
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
			},
		},
		{
			name:    "an unbound token stores no binding hash",
			subject: "ada@example.com",
			manager: plain,
			assert: func(t *testing.T, store *onetime.MemoryStore, _ string, tok onetime.Token, err error) {
				require.NoError(t, err)

				stored, err := store.FindByID(t.Context(), tok.ID)
				require.NoError(t, err)
				require.NotNil(t, stored)

				assert.Nil(t, stored.BindingHash,
					"an absent binding was stored as a hash of the empty string, which any caller could present")
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

	m, err := onetime.New("magic-link", onetime.WithTokenTTL(5*time.Minute))
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

// Standalone: it issues a thousand tokens from one manager, not one per row.
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

func TestIssueWithin(t *testing.T) {
	t.Parallel()

	type env struct {
		m     *onetime.Tokens
		store *onetime.MemoryStore
		clk   *clockwork.FakeClock
	}

	type testCase struct {
		name string
		// subject is who the issue is for; empty means "ana".
		subject string
		limit   int
		// setup issues or moves time before the call.
		setup  func(t *testing.T, ctx context.Context, e env)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, e env, presented string, tok onetime.Token, err error)
	}

	issueN := func(n int, subject string) func(t *testing.T, ctx context.Context, e env) {
		return func(t *testing.T, ctx context.Context, e env) {
			for range n {
				_, _, err := e.m.Issue(ctx, subject)
				require.NoError(t, err)
			}
		}
	}

	cases := []testCase{
		{
			name:  "below the limit a token is issued and redeemable",
			limit: 5,
			setup: issueN(4, "ana"),
			assert: func(t *testing.T, e env, presented string, tok onetime.Token, err error) {
				require.NoError(t, err)
				assert.Equal(t, "ana", tok.Subject)
				_, err = e.m.Check(t.Context(), presented, "")
				require.NoError(t, err, "the bounded token is one the manager honours")
				assert.Equal(t, 5, e.store.Len())
			},
		},
		{
			name:  "at the limit nothing is issued and nothing is stored",
			limit: 5,
			setup: issueN(5, "ana"),
			assert: func(t *testing.T, e env, presented string, tok onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Empty(t, presented)
				assert.Zero(t, tok)
				assert.Equal(t, 5, e.store.Len(), "a refused issue writes nothing")
			},
		},
		{
			name:  "another subject's tokens do not count",
			limit: 1,
			setup: issueN(3, "bob"),
			assert: func(t *testing.T, _ env, _ string, _ onetime.Token, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:  "tokens issued before the manager's window no longer count",
			limit: 2,
			setup: func(t *testing.T, ctx context.Context, e env) {
				issueN(2, "ana")(t, ctx, e)
				e.clk.Advance(time.Hour + time.Second)
			},
			assert: func(t *testing.T, _ env, _ string, _ onetime.Token, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:  "a token issued exactly at the window's start still counts",
			limit: 2,
			setup: func(t *testing.T, ctx context.Context, e env) {
				issueN(2, "ana")(t, ctx, e)
				e.clk.Advance(time.Hour)
			},
			assert: func(t *testing.T, _ env, _ string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
			},
		},
		{
			name:  "a limit below one refuses every issue",
			limit: 0,
			assert: func(t *testing.T, e env, _ string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Zero(t, e.store.Len())
			},
		},
		{
			name:    "an empty subject is refused before the limit is consulted",
			subject: "-",
			limit:   5,
			assert: func(t *testing.T, e env, _ string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrSubjectRequired)
				assert.Zero(t, e.store.Len())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			clk := clockwork.NewFakeClockAt(issuedAt)
			m, store := newManager(t, clk)
			e := env{m: m, store: store, clk: clk}
			if tc.setup != nil {
				tc.setup(t, ctx, e)
			}

			subject := tc.subject
			switch subject {
			case "":
				subject = "ana"
			case "-":
				subject = ""
			}

			presented, tok, err := m.IssueWithin(ctx, subject, tc.limit)
			tc.assert(t, e, presented, tok, err)
		})
	}
}

// Standalone from TestIssueWithin: it calls through a mock store, not the memory store that table builds.
func TestIssueWithin_StoreDecision(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		expect func(s *MockStore)
		assert func(t *testing.T, presented string, err error)
	}

	cases := []testCase{
		{
			name: "the store is asked once, with the window's start and the caller's limit",
			expect: func(s *MockStore) {
				s.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), issuedAt.Add(-time.Hour), 3).
					DoAndReturn(func(_ context.Context, tok onetime.Token, _ time.Time, _ int) (bool, error) {
						assert.Equal(t, "magic-link", tok.Purpose)
						assert.Equal(t, "ana", tok.Subject)
						return true, nil
					})
			},
			assert: func(t *testing.T, presented string, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, presented)
			},
		},
		{
			name: "a store that cannot decide is an outage, never the limit",
			expect: func(s *MockStore) {
				s.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errStoreDown)
			},
			assert: func(t *testing.T, presented string, err error) {
				require.ErrorIs(t, err, errStoreDown)
				assert.NotErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Empty(t, presented)
			},
		},
		{
			name: "a store that refuses is the limit",
			expect: func(s *MockStore) {
				s.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
			},
			assert: func(t *testing.T, presented string, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Empty(t, presented)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			tc.expect(store)
			m, err := onetime.New("magic-link",
				onetime.WithStore(store), onetime.WithClock(clockwork.NewFakeClockAt(issuedAt)))
			require.NoError(t, err)

			presented, _, err := m.IssueWithin(t.Context(), "ana", 3)
			tc.assert(t, presented, err)
		})
	}
}

// TestIssueWithin_ConcurrentBoundedIssuesStayWithinLimit releases twenty
// bounded issues at once against a limit of five, for each of fifty subjects
// raced together: for every subject exactly five are issued and the rest are
// refused as the limit. Many subjects, not one, because a single burst over
// an in-memory store finishes too quickly to interleave reliably.
//
// Standalone: it races a thousand bounded issues rather than making one call.
func TestIssueWithin_ConcurrentBoundedIssuesStayWithinLimit(t *testing.T) {
	t.Parallel()

	const subjects, racers, limit = 50, 20, 5

	m, store := newManager(t, clockwork.NewFakeClockAt(issuedAt))

	errs := make([][]error, subjects)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for s := range subjects {
		errs[s] = make([]error, racers)
		for i := range racers {
			wg.Go(func() {
				<-start
				_, _, errs[s][i] = m.IssueWithin(t.Context(), fmt.Sprintf("subject-%d", s), limit)
			})
		}
	}
	close(start)
	wg.Wait()

	for s, subjectErrs := range errs {
		issued, refused := 0, 0
		for _, err := range subjectErrs {
			switch {
			case err == nil:
				issued++
			case assert.ErrorIs(t, err, onetime.ErrIssueLimitReached):
				refused++
			}
		}
		assert.Equal(t, limit, issued, "subject %d: issued", s)
		assert.Equal(t, racers-limit, refused, "subject %d: refused as the limit", s)
	}
	assert.Equal(t, subjects*limit, store.Len(), "stored")
}

// liveRecord is the record Issue would have written for checkTokenID: unspent,
// issued at issuedAt and valid for the default quarter of an hour.
func liveRecord(t *testing.T) onetime.Token {
	t.Helper()

	return onetime.Token{
		ID:         checkTokenID,
		Purpose:    "magic-link",
		Subject:    "ada@example.com",
		SecretHash: sha256Of(checkSecret),
		IssuedAt:   issuedAt,
		ExpiresAt:  issuedAt.Add(15 * time.Minute),
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		record    func(t *testing.T) onetime.Token
		storeErr  error
		presented string
		binding   string
		at        time.Time // when the check runs; zero means a minute after issue
		opts      []onetime.Option
		assert    func(t *testing.T, c onetime.Checked, err error, logs string)
	}

	refused := func(t *testing.T, c onetime.Checked, err error, _ string) {
		t.Helper()

		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.Zero(t, c, "a refused check still handed back a proof of checking")
	}

	cases := []testCase{
		{
			name:      "a live token checks and yields its record",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, checkTokenID, c.Token().ID)
				assert.Equal(t, "ada@example.com", c.Token().Subject)
			},
		},
		{
			name:      "a token one moment before expiry still checks",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(15*time.Minute - time.Nanosecond),
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			// Expiry is an instant the token does not survive, not one it is
			// still good for. Anything else makes the boundary a matter of the
			// store's clock resolution.
			name:      "a token exactly at its expiry is refused",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(15 * time.Minute),
			assert:    refused,
		},
		{
			name:      "a token past its expiry is refused",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(16 * time.Minute),
			assert:    refused,
		},
		{
			name: "a consumer time-to-live keeps a token alive that the default would have expired",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.ExpiresAt = issuedAt.Add(24 * time.Hour)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(16 * time.Minute),
			opts:      []onetime.Option{onetime.WithTokenTTL(24 * time.Hour)},
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "a token issued for another purpose is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.Purpose = "email-code"

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			assert:    refused,
		},
		{
			name: "a token already consumed is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.ConsumedAt = issuedAt.Add(30 * time.Second)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			assert:    refused,
		},
		{
			name:      "a wrong secret is refused",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, 32)),
			assert:    refused,
		},
		{
			name: "a wrong binding is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.BindingHash = sha256Of(checkBinding)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   "device-nonce-b",
			assert:    refused,
		},
		{
			name: "a bound token checks with its own binding",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.BindingHash = sha256Of(checkBinding)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   checkBinding,
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "a bound token presented with no binding is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.BindingHash = sha256Of(checkBinding)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   "",
			assert:    refused,
		},
		{
			// A token issued without a binding has nothing to compare against,
			// so a presented one is simply not part of the decision. Refusing
			// it would make an unbound token behave as though it were bound to
			// the empty string.
			name:      "an unbound token ignores a presented binding",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   "device-nonce-b",
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name:      "a record that does not exist is refused exactly like a wrong secret",
			storeErr:  onetime.ErrTokenNotFound,
			presented: checkTokenID.String() + "." + checkSecret,
			assert:    refused,
		},
		{
			name:      "a store that cannot answer is refused the same way and logged at error level",
			storeErr:  errStoreDown,
			presented: checkTokenID.String() + "." + checkSecret,
			assert: func(t *testing.T, c onetime.Checked, err error, logs string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.NotErrorIs(t, err, errStoreDown,
					"the store's own failure reached the caller, who can now tell an outage from a bad token")
				assert.Zero(t, c)
				assert.Contains(t, logs, "level=ERROR", "a store outage passed unreported")
				assert.NotContains(t, logs, checkSecret, "the log carried the presented secret")
			},
		},
		// A malformed token sets no record and no store error, so the store
		// expects no call at all: it must be refused on its own shape, before it
		// can buy a caller a single store lookup.
		{
			name:      "an empty string",
			presented: "",
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
		{
			name:      "no separator",
			presented: checkTokenID.String() + checkSecret,
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
		{
			name:      "an empty identifier",
			presented: "." + checkSecret,
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
		{
			name:      "an empty secret",
			presented: checkTokenID.String() + ".",
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
		{
			name:      "an identifier that is not an identifier",
			presented: "not-an-id." + checkSecret,
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
		{
			name:      "a separator and nothing else",
			presented: ".",
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
		{
			name:      "an oversized identifier half",
			presented: strings.Repeat("a", 4096) + "." + checkSecret,
			at:        issuedAt,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.Zero(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			ctrl := gomock.NewController(t)

			store := NewMockStore(ctrl)
			// No EXPECT for Insert or Consume: any write during a check is the
			// failure this table pins on every row.
			switch {
			case tc.storeErr != nil:
				store.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, tc.storeErr)
			case tc.record != nil:
				rec := tc.record(t)
				store.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&rec, nil)
			}

			at := tc.at
			if at.IsZero() {
				at = issuedAt.Add(time.Minute)
			}
			clk := clockwork.NewFakeClockAt(at)

			opts := append([]onetime.Option{
				onetime.WithStore(store),
				onetime.WithClock(clk),
				onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
			}, tc.opts...)

			m, err := onetime.New("magic-link", opts...)
			require.NoError(t, err)

			c, err := m.Check(t.Context(), tc.presented, tc.binding)
			tc.assert(t, c, err, logs.String())
		})
	}
}

// Standalone from TestCheck: it checks one token three times against a store that expects exactly three reads.
func TestCheckingRepeatedlyWritesNothingAndKeepsSucceeding(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	rec := liveRecord(t)

	store := NewMockStore(ctrl)
	// Three reads, no writes. A check that wrote could not be run once per
	// racing caller, which is the whole reason it is separate from Consume.
	store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil).Times(3)

	clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))
	m, err := onetime.New("magic-link",
		onetime.WithStore(store), onetime.WithClock(clk))
	require.NoError(t, err)

	for range 3 {
		c, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
		require.NoError(t, err)
		assert.Equal(t, checkTokenID, c.Token().ID)
	}
}

// TestSecretAndBindingAreComparedInConstantTime reads the package's own source.
//
// No black-box test can tell a constant-time comparison from a fast one: both
// return the same answers, and timing them is exactly the measurement an
// attacker has to make thousands of times to learn anything. So the guarantee
// is pinned where it is decided — in the comparison the code performs — rather
// than inferred from behaviour that cannot show it.
func TestSecretAndBindingAreComparedInConstantTime(t *testing.T) {
	t.Parallel()

	sources, err := filepath.Glob("*.go")
	require.NoError(t, err)

	fset := token.NewFileSet()

	var parsed []*ast.File
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		parsed = append(parsed, file)
	}
	require.NotEmpty(t, parsed, "the production package did not parse")

	var (
		checkBody     *ast.FuncDecl
		checkFile     *ast.File
		constantTime  int
		shortCircuits []string
	)

	for _, file := range parsed {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "Check" {
				continue
			}
			checkBody, checkFile = fn, file
		}
	}
	require.NotNil(t, checkBody, "no Check method was found to inspect")

	ast.Inspect(checkBody, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		switch {
		case pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare":
			constantTime++
		case pkg.Name == "bytes" && (sel.Sel.Name == "Equal" || sel.Sel.Name == "Compare"),
			pkg.Name == "strings" && (sel.Sel.Name == "EqualFold" || sel.Sel.Name == "Compare"),
			pkg.Name == "reflect" && sel.Sel.Name == "DeepEqual",
			pkg.Name == "slices" && sel.Sel.Name == "Equal":
			shortCircuits = append(shortCircuits, pkg.Name+"."+sel.Sel.Name)
		}

		return true
	})

	var imported bool
	for _, spec := range checkFile.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		require.NoError(t, err)
		if path == "crypto/subtle" {
			imported = true
		}
	}

	assert.True(t, imported, "the file declaring Check does not import crypto/subtle")
	assert.GreaterOrEqual(t, constantTime, 2,
		"Check makes fewer than two constant-time comparisons, so the secret or the binding is compared some other way")
	assert.Empty(t, shortCircuits,
		"Check compares with a primitive that returns as soon as two bytes differ, which times the answer out one byte at a time")
}

// errRateLimited stands for a caller's own refusal: a reason the holder can fix
// and come back from, which is exactly why it must not cost them their token.
var errRateLimited = errors.New("too many attempts, try again later")

func TestConsume(t *testing.T) {
	t.Parallel()

	t.Run("a checked token is spent, and spending it again is refused", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)
		first, err := m.Check(t.Context(), presented, "")
		require.NoError(t, err)
		require.NoError(t, m.Consume(t.Context(), first))

		spentAt := issuedAt.Add(time.Minute)
		stored, err := store.FindByID(t.Context(), tok.ID)
		require.NoError(t, err)
		assert.Equal(t, spentAt, stored.ConsumedAt)

		// A holder who kept the proof of an earlier check cannot spend the
		// token twice with it: consumption is decided in the store, not by
		// what the caller is holding.
		clk.Advance(time.Minute)
		err = m.Consume(t.Context(), first)
		require.ErrorIs(t, err, onetime.ErrInvalidToken)

		stored, err = store.FindByID(t.Context(), tok.ID)
		require.NoError(t, err)
		assert.Equal(t, spentAt, stored.ConsumedAt,
			"the second attempt moved the recorded consumption time")
	})

	t.Run("a Checked a caller declared for themselves names no record and is refused", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		// No EXPECT: an empty proof must be refused without a store round trip.
		store := NewMockStore(ctrl)

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, err := onetime.New("magic-link",
			onetime.WithStore(store), onetime.WithClock(clk))
		require.NoError(t, err)

		require.ErrorIs(t, m.Consume(t.Context(), onetime.Checked{}), onetime.ErrInvalidToken)
	})

	t.Run("a store that cannot mark the token consumed is refused, not reported", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))
		ctrl := gomock.NewController(t)
		rec := liveRecord(t)

		store := NewMockStore(ctrl)
		store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
		store.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).Return(errStoreDown)

		var logs bytes.Buffer
		m, err := onetime.New("magic-link",
			onetime.WithStore(store), onetime.WithClock(clk),
			onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		require.NoError(t, err)

		c, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
		require.NoError(t, err)

		err = m.Consume(t.Context(), c)
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.NotErrorIs(t, err, errStoreDown,
			"the store's own failure reached the caller, who can now tell an outage from a spent token")
		assert.Contains(t, logs.String(), "level=ERROR", "a store outage passed unreported")
	})
}

func TestRedeem(t *testing.T) {
	t.Parallel()

	t.Run("a valid token is checked, the caller's checks run in order, and it is spent once", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)

		var order []string
		redeemed, err := m.Redeem(t.Context(), presented, "",
			func(_ context.Context, got onetime.Token) error {
				order = append(order, "first")
				assert.Equal(t, tok.ID, got.ID, "the caller's check was handed another token")
				assert.Equal(t, "ada@example.com", got.Subject)

				return nil
			},
			nil, // a nil check is skipped rather than panicked on
			func(context.Context, onetime.Token) error {
				order = append(order, "second")

				return nil
			},
		)
		require.NoError(t, err)

		assert.Equal(t, []string{"first", "second"}, order)
		assert.Equal(t, tok.ID, redeemed.ID)
		assert.Equal(t, "ada@example.com", redeemed.Subject)
		assert.Equal(t, issuedAt.Add(time.Minute), redeemed.ConsumedAt,
			"the record handed back does not say when it was spent")

		_, err = m.Redeem(t.Context(), presented, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken, "the token was spent twice")

		assert.Equal(t, 1, store.Len())
	})

	t.Run("a caller check error is returned unchanged and spends nothing", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, store := newManager(t, clk)

		presented, tok, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)

		refused, err := m.Redeem(t.Context(), presented, "",
			func(context.Context, onetime.Token) error { return errRateLimited })
		require.ErrorIs(t, err, errRateLimited, "the caller's reason was replaced")
		assert.NotErrorIs(t, err, onetime.ErrInvalidToken,
			"a refusal the holder can come back from was reported as a bad token")
		assert.Zero(t, refused)

		stored, err := store.FindByID(t.Context(), tok.ID)
		require.NoError(t, err)
		assert.True(t, stored.ConsumedAt.IsZero(), "a refused redemption marked the token consumed")

		// The whole point: the holder fixes the problem and still has a token.
		clk.Advance(time.Minute)
		redeemed, err := m.Redeem(t.Context(), presented, "")
		require.NoError(t, err, "a refusal spent the token")
		assert.Equal(t, tok.ID, redeemed.ID)
	})

	t.Run("the first refusing check stops the rest, and none of them spends the token", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, _ := newManager(t, clk)

		presented, _, err := m.Issue(t.Context(), "ada@example.com")
		require.NoError(t, err)

		clk.Advance(time.Minute)

		var reached bool
		_, err = m.Redeem(t.Context(), presented, "",
			func(context.Context, onetime.Token) error { return errRateLimited },
			func(context.Context, onetime.Token) error {
				reached = true

				return nil
			},
		)
		require.ErrorIs(t, err, errRateLimited)
		assert.False(t, reached, "a check after the refusal still ran")

		clk.Advance(time.Minute)
		_, err = m.Redeem(t.Context(), presented, "")
		require.NoError(t, err, "a refusal spent the token")
	})

	t.Run("a refused check never runs when the token itself is bad", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		m, _ := newManager(t, clk)

		var reached bool
		_, err := m.Redeem(t.Context(), "not-a-token", "",
			func(context.Context, onetime.Token) error {
				reached = true

				return nil
			})
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.False(t, reached, "the caller's check was handed a token that had not passed a check")
	})

	t.Run("a consumption failure is a refusal and no subject", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))
		ctrl := gomock.NewController(t)
		rec := liveRecord(t)

		store := NewMockStore(ctrl)
		store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
		store.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).Return(errStoreDown)

		var logs bytes.Buffer
		m, err := onetime.New("magic-link",
			onetime.WithStore(store), onetime.WithClock(clk),
			onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		require.NoError(t, err)

		tok, err := m.Redeem(t.Context(), checkTokenID.String()+"."+checkSecret, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.Zero(t, tok, "a redemption that did not happen handed back a subject")
		assert.Contains(t, logs.String(), "level=ERROR")
		assert.NotContains(t, logs.String(), checkSecret, "the log carried the presented secret")
	})
}

// TestExactlyOneOfManyRacingRedemptionsSpendsTheToken is the reason Consume is
// a compare-and-set in the store rather than a read followed by a write here.
//
// Standalone: it races fifty redeemers on one token rather than making one call.
func TestExactlyOneOfManyRacingRedemptionsSpendsTheToken(t *testing.T) {
	t.Parallel()

	const redeemers = 50

	clk := clockwork.NewFakeClockAt(issuedAt)
	m, store := newManager(t, clk)

	presented, tok, err := m.Issue(t.Context(), "ada@example.com")
	require.NoError(t, err)

	clk.Advance(time.Minute)

	var (
		succeeded atomic.Int64
		refused   atomic.Int64
		start     sync.WaitGroup
		done      sync.WaitGroup
	)
	start.Add(1)

	for range redeemers {
		done.Add(1)
		go func() {
			defer done.Done()

			start.Wait()
			if _, err := m.Redeem(t.Context(), presented, ""); err == nil {
				succeeded.Add(1)

				return
			}
			refused.Add(1)
		}()
	}

	start.Done()
	done.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "the token was spent more than once")
	assert.Equal(t, int64(redeemers-1), refused.Load())

	stored, err := store.FindByID(t.Context(), tok.ID)
	require.NoError(t, err)
	assert.Equal(t, issuedAt.Add(time.Minute), stored.ConsumedAt)
}

// managerFor returns a second manager over an existing store, so that a test
// can show one purpose's tokens are invisible to another's.
func managerFor(t *testing.T, purpose string, store onetime.Store, clk *clockwork.FakeClock, opts ...onetime.Option) *onetime.Tokens {
	t.Helper()

	all := append([]onetime.Option{onetime.WithStore(store), onetime.WithClock(clk)}, opts...)

	m, err := onetime.New(purpose, all...)
	require.NoError(t, err)

	return m
}

// issueAgo issues a token as though it had been issued ago before issuedAt, and
// leaves the clock back at issuedAt.
func issueAgo(t *testing.T, clk *clockwork.FakeClock, m *onetime.Tokens, subject string, ago time.Duration) string {
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
		issue  func(t *testing.T, clk *clockwork.FakeClock, m, other *onetime.Tokens)
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
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", 5*time.Minute)
				issueAgo(t, clk, m, "ada@example.com", 10*time.Minute)
				issueAgo(t, clk, m, "ada@example.com", 59*time.Minute)
			},
			assert: counts(3),
		},
		{
			name: "an issue older than the window does not count",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", 10*time.Minute)
				issueAgo(t, clk, m, "ada@example.com", 70*time.Minute)
			},
			assert: counts(1),
		},
		{
			name: "an issue exactly at the edge of the window still counts",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", time.Hour)
			},
			assert: counts(1),
		},
		{
			name: "an issue one moment before the edge does not",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", time.Hour+time.Nanosecond)
			},
			assert: counts(0),
		},
		{
			name: "another subject is not counted",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, m, "bob@example.com", 5*time.Minute)
			},
			assert: counts(0),
		},
		{
			name: "the same subject under another purpose is not counted",
			issue: func(t *testing.T, clk *clockwork.FakeClock, _, other *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, other, "ada@example.com", 5*time.Minute)
			},
			assert: counts(0),
		},
		{
			name: "a consumer window widens what counts",
			opts: []onetime.Option{onetime.WithIssuanceWindow(6 * time.Hour)},
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
				t.Helper()

				issueAgo(t, clk, m, "ada@example.com", 70*time.Minute)
			},
			assert: counts(1),
		},
		{
			name: "a consumed token still counts, because it was still issued",
			issue: func(t *testing.T, clk *clockwork.FakeClock, m, _ *onetime.Tokens) {
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

// Standalone from TestIssuedCount: it counts through a mock store, not the memory store that table builds.
func TestIssuedCountReportsAStoreThatCannotAnswer(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)
	store.EXPECT().
		CountRecentBySubject(gomock.Any(), "magic-link", "ada@example.com", issuedAt.Add(-time.Hour)).
		Return(0, errStoreDown)

	clk := clockwork.NewFakeClockAt(issuedAt)
	m, err := onetime.New("magic-link", onetime.WithStore(store), onetime.WithClock(clk))
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
		m, store := newManager(t, clk, onetime.WithTokenTTL(24*time.Hour))

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
		m, err := onetime.New("magic-link", onetime.WithStore(store), onetime.WithClock(clk))
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
		m, err := onetime.New("magic-link", onetime.WithStore(store), onetime.WithClock(clk))
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

var expiryEpoch = time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)

// storeOnly hides everything but the Store contract, so a wrapped store has no
// Reaper.
type storeOnly struct{ onetime.Store }

// expiryManager builds a manager of purpose over store and clk, with the explicit
// lifetime (15m) and issuance window (1h) the cases reason about.
func expiryManager(t *testing.T, purpose string, store onetime.Store, clk clockwork.Clock) *onetime.Tokens {
	t.Helper()

	m, err := onetime.New(purpose,
		onetime.WithStore(store),
		onetime.WithClock(clk),
		onetime.WithTokenTTL(15*time.Minute),
		onetime.WithIssuanceWindow(time.Hour),
	)
	require.NoError(t, err)

	return m
}

func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) (expiry.Task, func(t *testing.T))
		assert func(t *testing.T, task expiry.Task, removed int, err error)
	}

	cases := []testCase{
		{
			name: "an expired token inside the issuance window is kept and the count unchanged",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
				m := expiryManager(t, "email-change", store, clk)

				_, _, err := m.Issue(t.Context(), "carol")
				require.NoError(t, err)
				clk.Advance(30 * time.Minute) // past the 15m lifetime, inside the 1h window

				return onetime.ExpiryTask(m), func(t *testing.T) {
					n, err := m.IssuedCount(t.Context(), "carol")
					require.NoError(t, err)
					assert.Equal(t, 1, n, "a sweep must not free issuance quota")
					assert.Equal(t, 1, store.Len())
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
		{
			name: "an expired token past the issuance window is removed",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
				m := expiryManager(t, "email-change", store, clk)

				_, _, err := m.Issue(t.Context(), "carol")
				require.NoError(t, err)
				clk.Advance(2 * time.Hour)

				return onetime.ExpiryTask(m), func(t *testing.T) { assert.Zero(t, store.Len()) }
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "separate purposes stay separate",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
				mine := expiryManager(t, "email-change", store, clk)
				other := expiryManager(t, "magic-link", store, clk)

				for _, m := range []*onetime.Tokens{mine, other} {
					_, _, err := m.Issue(t.Context(), "carol")
					require.NoError(t, err)
				}
				clk.Advance(2 * time.Hour)

				return onetime.ExpiryTask(mine), func(t *testing.T) {
					assert.Equal(t, 1, store.Len(), "the other purpose's record stays")
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "a store that cannot purge matches both sentinels",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := storeOnly{onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}

				return onetime.ExpiryTask(expiryManager(t, "email-change", store, clk)), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
		{
			name: "name carries the purpose and no interval is set",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				m := expiryManager(t, "email-change", onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)), clk)

				return onetime.ExpiryTask(m), func(*testing.T) {}
			},
			assert: func(t *testing.T, task expiry.Task, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "one-time-tokens:email-change", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "a chosen name replaces the default and the body is shared",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := storeOnly{onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}

				return onetime.ExpiryTaskNamed("magiclink-tokens", expiryManager(t, "magic-link", store, clk)), func(*testing.T) {}
			},
			assert: func(t *testing.T, task expiry.Task, _ int, err error) {
				assert.Equal(t, "magiclink-tokens", task.Name)
				assert.Zero(t, task.Interval)
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			task, after := tc.setup(t)
			require.NotNil(t, task.Run, "the task must carry a Run")

			removed, err := task.Run(t.Context())
			tc.assert(t, task, removed, err)
			after(t)
		})
	}
}

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// TestOnetimeStoreFailureRecords pins that a store failure at either of the
// manager's two store call sites — reading a token during Check and marking
// one consumed — is recorded through a fixed reason and the error's type,
// never the store's own text, while the public token identifier stays.
func TestOnetimeStoreFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) onetime.Store
		act    func(t *testing.T, m *onetime.Tokens) error
		assert func(t *testing.T, err error, logs string)
	}

	// storeFailureRecord asserts what both store call sites promise: the
	// token refused, and a record with the fixed reason, the store's error
	// type and the public token id, never the store's text.
	storeFailureRecord := func(t *testing.T, err error, logs string) {
		t.Helper()
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.NotContains(t, logs, "alice@example.com")
		assert.NotContains(t, logs, "u-123")
		assert.Contains(t, logs, "reason=token-store")
		assert.Contains(t, logs, "error_type=*errors.errorString", "the store's own error type")
		assert.Contains(t, logs, "token_id="+checkTokenID.String(), "the public token identifier stays")
	}

	cases := []testCase{
		{
			name: "Check's store read fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(nil, errRedactionFixture)
				return s
			},
			act: func(t *testing.T, m *onetime.Tokens) error {
				t.Helper()
				_, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
				return err
			},
			assert: storeFailureRecord,
		},
		{
			name: "Consume's store write fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				rec := liveRecord(t)
				s := NewMockStore(ctrl)
				s.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
				s.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).Return(errRedactionFixture)
				return s
			},
			act: func(t *testing.T, m *onetime.Tokens) error {
				t.Helper()
				c, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
				require.NoError(t, err)
				return m.Consume(t.Context(), c)
			},
			assert: storeFailureRecord,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			ctrl := gomock.NewController(t)
			clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))

			m, err := onetime.New("magic-link",
				onetime.WithStore(tc.store(t, ctrl)),
				onetime.WithClock(clk),
				onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			require.NoError(t, err)

			actErr := tc.act(t, m)
			tc.assert(t, actErr, logs.String())
		})
	}
}

// TestOnetimeReturnedErrors pins task 5.7: an error caused by the store at
// Issue, IssuedCount or PurgeExpired carries fixed library text, with the
// store's own error still reachable by identity.
func TestOnetimeReturnedErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) onetime.Store
		call   func(t *testing.T, m *onetime.Tokens) error
		assert func(t *testing.T, err error)
	}

	// wrappedAs returns the shape every site here shares: the error carries
	// text, the fixture's text is gone, and the store's own error is still
	// reachable by identity.
	wrappedAs := func(text string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.EqualError(t, err, text)
			assert.NotContains(t, err.Error(), "alice@example.com")
			assert.NotContains(t, err.Error(), "u-123")
			assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
		}
	}

	cases := []testCase{
		{
			name: "Issue's store insert fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *onetime.Tokens) error {
				t.Helper()
				_, _, err := m.Issue(t.Context(), "ada@example.com")
				return err
			},
			assert: wrappedAs("onetime: store token"),
		},
		{
			name: "IssuedCount's store count fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().CountRecentBySubject(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(0, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *onetime.Tokens) error {
				t.Helper()
				_, err := m.IssuedCount(t.Context(), "ada@example.com")
				return err
			},
			assert: wrappedAs("onetime: count recent issuance"),
		},
		{
			name: "PurgeExpired's reaper fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := newReapableStore(NewMockStore(ctrl), NewMockReaper(ctrl))
				s.MockReaper.EXPECT().DeleteExpiredBefore(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(0, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *onetime.Tokens) error {
				t.Helper()
				_, err := m.PurgeExpired(t.Context())
				return err
			},
			assert: wrappedAs("onetime: purge expired tokens"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := onetime.New("magic-link", onetime.WithStore(tc.store(t, ctrl)))
			require.NoError(t, err)

			tc.assert(t, tc.call(t, m))
		})
	}
}
