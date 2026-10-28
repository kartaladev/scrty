package magiclink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/token/onetime"
)

func TestNewMagicLinkManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		baseURL string
		// tokens is the token manager; nil means testTokens.
		tokens func(t *testing.T) *onetime.Tokens
		// users is the user loader; nil means stubLoader{}.
		users func() identity.UserLoader
		// sender is the sender; nil means a recordingSender.
		sender func(t *testing.T) notify.Sender
		opts   []magiclink.Option
		assert func(t *testing.T, m *magiclink.Links, err error)
	}

	configError := func(t *testing.T, m *magiclink.Links, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, magiclink.ErrConfig)
		assert.Nil(t, m)
	}

	ok := func(t *testing.T, m *magiclink.Links, err error) {
		require.NoError(t, err)
		assert.NotNil(t, m)
	}

	smtp := func(t *testing.T) notify.Sender {
		t.Helper()

		s, err := notify.NewSMTPSender("smtp.example.com")
		require.NoError(t, err)

		return s
	}

	validTokens := func(t *testing.T) *onetime.Tokens { return testTokens(t) }

	// A nil *mutableLoader satisfies identity.UserLoader through pointer
	// receivers, so the interface field carries a type descriptor even though
	// the pointer is nil — a plain `== nil` check misses it and construction
	// would otherwise succeed, for the loader to panic on its nil receiver at
	// first use.
	var nilTypedLoader *mutableLoader

	cases := []testCase{
		{name: "missing", baseURL: "", assert: configError},
		{name: "host-relative", baseURL: "/login", assert: configError},
		{name: "cleartext on a public host", baseURL: "http://app.example.com", assert: configError},
		{name: "scheme only", baseURL: "https://", assert: configError},
		{name: "not a URL", baseURL: "://nonsense", assert: configError},
		{name: "carries a path", baseURL: "https://app.example.com/app", assert: configError},
		{name: "https", baseURL: "https://app.example.com", assert: ok},
		{name: "https with a port", baseURL: "https://app.example.com:8443", assert: ok},
		{name: "loopback over http", baseURL: "http://localhost:3000", assert: ok},
		{name: "loopback by address", baseURL: "http://127.0.0.1:3000", assert: ok},
		{
			name:    "the SMTP sender is refused",
			baseURL: "https://app.example.com",
			sender:  smtp,
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
				assert.Contains(t, strings.ToLower(err.Error()), "synchronous")
			},
		},
		{
			name:    "a sender reporting NonBlocking false is refused",
			baseURL: "https://app.example.com",
			sender:  func(_ *testing.T) notify.Sender { return liarSender{nonBlocking: false} },
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name:    "the queued sender is accepted",
			baseURL: "https://app.example.com",
			sender: func(t *testing.T) notify.Sender {
				t.Helper()

				q, err := notify.NewQueuedSender(smtp(t))
				require.NoError(t, err)
				t.Cleanup(func() { _ = q.Close(context.WithoutCancel(t.Context())) })

				return q
			},
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name:    "the consumer may accept synchronous delivery explicitly",
			baseURL: "https://app.example.com",
			sender:  smtp,
			opts:    []magiclink.Option{magiclink.WithSynchronousDelivery()},
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name:    "a nil sender is refused",
			baseURL: "https://app.example.com",
			sender:  func(_ *testing.T) notify.Sender { return nil },
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			// A plain `== nil` check misses this: the interface carries a type
			// descriptor for *recordingSender even though the pointer itself is
			// nil, so the comparison is false and construction would otherwise
			// succeed — only for Send to panic on the nil receiver at first use.
			name:    "a typed nil sender is refused the same as an absent one",
			baseURL: "https://app.example.com",
			sender:  func(_ *testing.T) notify.Sender { return (*recordingSender)(nil) },
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name:    "no token manager",
			baseURL: "https://app.example.com",
			tokens:  func(*testing.T) *onetime.Tokens { return nil },
			users:   func() identity.UserLoader { return stubLoader{} },
			assert:  configError,
		},
		{
			name:    "no user loader",
			baseURL: "https://app.example.com",
			tokens:  validTokens,
			users:   func() identity.UserLoader { return nil },
			assert:  configError,
		},
		{
			name:    "a typed nil user loader is refused the same as an absent one",
			baseURL: "https://app.example.com",
			tokens:  validTokens,
			users:   func() identity.UserLoader { return nilTypedLoader },
			assert:  configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tokens := testTokens(t)
			if tc.tokens != nil {
				tokens = tc.tokens(t)
			}

			var users identity.UserLoader = stubLoader{}
			if tc.users != nil {
				users = tc.users()
			}

			var sender notify.Sender = &recordingSender{}
			if tc.sender != nil {
				sender = tc.sender(t)
			}

			m, err := magiclink.New(tokens, users, sender, tc.baseURL, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

// requestReturnsNoError pins the one thing about Request's signature the whole
// capability rests on: there is no error beside the result, so a caller has
// nothing to branch on and cannot leak which addresses have accounts.
var requestReturnsNoError func(*magiclink.Links, context.Context, string, string) magiclink.RequestResult = (*magiclink.Links).Request

// sendCounter is what every sender in these tests offers: how many messages it
// was handed, whether or not it managed to deliver them.
type sendCounter interface {
	notify.Sender
	Count() int
}

var linkPattern = regexp.MustCompile(`https?://\S+`)

func extractLink(t *testing.T, body string) string {
	t.Helper()

	link := linkPattern.FindString(body)
	require.NotEmpty(t, link, "the message carries no link")

	return link
}

// Standalone from TestRequest: its cases swap the token manager and the sender, and count what one request adds after a prepared history.
func TestRequestIsUniform(t *testing.T) {
	t.Parallel()

	known := &identity.Details{ID: "u-1", Username: "ada@example.com", Active: true}

	type testCase struct {
		name   string
		loader identity.UserLoader
		tokens func(t *testing.T) *onetime.Tokens
		sender func() sendCounter
		opts   []magiclink.Option
		// prepare runs before the request under test, so a branch that needs
		// history can build it.
		prepare func(t *testing.T, m *magiclink.Links)
		assert  func(t *testing.T, got magiclink.RequestResult, sent int)
	}

	// sameShape is the assertion the whole capability rests on: whatever
	// happened, the caller is handed a nonce of one fixed length and can tell
	// nothing from it.
	sameShape := func(wantSent int) func(*testing.T, magiclink.RequestResult, int) {
		return func(t *testing.T, got magiclink.RequestResult, sent int) {
			assert.Len(t, got.BindingNonce, magiclink.BindingNonceLength,
				"every branch returns a binding nonce of the same length")
			assert.Equal(t, wantSent, sent)
		}
	}

	cases := []testCase{
		{
			name:   "an active user, and a link is sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			assert: sameShape(1),
		},
		{
			name:   "an unknown address",
			loader: stubLoader{byUsername: map[string]*identity.Details{}},
			assert: sameShape(0),
		},
		{
			name: "a disabled user",
			loader: stubLoader{byUsername: map[string]*identity.Details{
				"ada@example.com": {ID: "u-1", Username: "ada@example.com", Active: false},
			}},
			assert: sameShape(0),
		},
		{
			name:   "the loader is down",
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
			assert: sameShape(0),
		},
		{
			name:   "the issuance limit is reached",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			prepare: func(t *testing.T, m *magiclink.Links) {
				t.Helper()

				for range 5 {
					m.Request(t.Context(), "ada@example.com", "/")
				}
			},
			assert: sameShape(0),
		},
		{
			name:   "the token store fails",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			tokens: tokensWithFailingStore,
			assert: sameShape(0),
		},
		{
			name:   "the message cannot be sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			sender: func() sendCounter { return &failingSender{err: errors.New("smtp: 451 temporary failure")} },
			// The attempt is made and its failure is swallowed, so the caller
			// cannot tell a delivered link from an undelivered one either.
			assert: sameShape(1),
		},
		{
			name:   "the random source fails",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			opts:   []magiclink.Option{magiclink.WithRandom(failingReader{})},
			assert: func(t *testing.T, got magiclink.RequestResult, sent int) {
				// The one documented exception: with no randomness there is no
				// nonce to return and no link to issue. What a caller can tell
				// from it is that the random source is broken, which is the
				// same for every address.
				assert.Empty(t, got.BindingNonce)
				assert.Zero(t, sent)
			},
		},
		{
			name:   "binding disabled, and a link is sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			opts:   []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, got magiclink.RequestResult, sent int) {
				assert.Empty(t, got.BindingNonce, "a disabled binding returns no nonce, ever")
				assert.Equal(t, 1, sent)
			},
		},
		{
			name:   "binding disabled, and the address is unknown",
			loader: stubLoader{byUsername: map[string]*identity.Details{}},
			opts:   []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, got magiclink.RequestResult, sent int) {
				assert.Empty(t, got.BindingNonce)
				assert.Zero(t, sent)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var sender sendCounter = &recordingSender{}
			if tc.sender != nil {
				sender = tc.sender()
			}

			tokens := testTokens(t)
			if tc.tokens != nil {
				tokens = tc.tokens(t)
			}

			m, err := magiclink.New(tokens, tc.loader, sender, "https://app.example.com", tc.opts...)
			require.NoError(t, err)

			if tc.prepare != nil {
				tc.prepare(t, m)
			}

			before := sender.Count()
			got := m.Request(t.Context(), "ada@example.com", "/dashboard")

			tc.assert(t, got, sender.Count()-before)
		})
	}
}

func TestRequest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// loader is the user loader; nil means activeLoader().
		loader identity.UserLoader
		// baseURL is the link's base; empty means https://app.example.com.
		baseURL string
		opts    []magiclink.Option
		address string
		next    string
		assert  func(t *testing.T, got magiclink.RequestResult, sender *recordingSender)
	}

	defaultLoader := &recordingLoader{}
	resolverLoader := &recordingLoader{}

	resolver := func(_ context.Context, address string) (*identity.Details, error) {
		if address == "ada@example.com" {
			return &identity.Details{ID: "u-7", Active: true}, nil
		}

		return nil, identity.ErrUserNotFound
	}

	consumerRenderer := func(link, _ string) notify.Message {
		return notify.Message{
			To:       "other@example.com", // must be overridden
			Subject:  "Sign in to Payroll",
			TextBody: "Go to " + link,
		}
	}

	var seen string
	recordingRenderer := func(link, next string) notify.Message {
		seen = next

		return notify.Message{Subject: "s", TextBody: link}
	}

	cases := []testCase{
		{
			name:    "by default the address reaches the loader unchanged",
			loader:  defaultLoader,
			address: " Ada@Example.com",
			next:    "/",
			assert: func(t *testing.T, _ magiclink.RequestResult, _ *recordingSender) {
				loader := defaultLoader

				assert.Equal(t, []string{" Ada@Example.com"}, loader.Usernames(),
					"never trimmed, never case-folded")
			},
		},
		{
			name:    "a consumer resolver is the only path",
			loader:  resolverLoader,
			opts:    []magiclink.Option{magiclink.WithAddressResolver(resolver)},
			address: "ada@example.com",
			next:    "/",
			assert: func(t *testing.T, _ magiclink.RequestResult, sender *recordingSender) {
				loader := resolverLoader

				assert.Empty(t, loader.Usernames(), "LoadByUsername is not called")
				assert.Equal(t, 1, sender.Count())
			},
		},
		{
			name:    "the link joins the base, the confirm path, the token and the target",
			address: "ada@example.com",
			next:    "/dashboard?tab=a&b=c",
			assert: func(t *testing.T, _ magiclink.RequestResult, sender *recordingSender) {
				require.Equal(t, 1, sender.Count())
				link := extractLink(t, sender.Last().TextBody)

				u, err := url.Parse(link)
				require.NoError(t, err)

				assert.Equal(t, "https", u.Scheme)
				assert.Equal(t, "app.example.com", u.Host)
				assert.Equal(t, "/login/magic/confirm", u.Path)
				assert.NotEmpty(t, u.Query().Get("token"))
				assert.Equal(t, "/dashboard?tab=a&b=c", u.Query().Get("next"),
					"the target is query-escaped, so its own separators survive")
			},
		},
		{
			name:    "a consumer confirm path is used",
			baseURL: "https://app.example.com:8443",
			opts:    []magiclink.Option{magiclink.WithConfirmPath("/auth/link")},
			address: "ada@example.com",
			next:    "/",
			assert: func(t *testing.T, _ magiclink.RequestResult, sender *recordingSender) {
				require.Equal(t, 1, sender.Count())

				u, err := url.Parse(extractLink(t, sender.Last().TextBody))
				require.NoError(t, err)

				assert.Equal(t, "app.example.com:8443", u.Host)
				assert.Equal(t, "/auth/link", u.Path)
			},
		},
		{
			name:    "a consumer renderer chooses the subject but not the recipient",
			opts:    []magiclink.Option{magiclink.WithRenderer(consumerRenderer)},
			address: "ada@example.com",
			next:    "/",
			assert: func(t *testing.T, _ magiclink.RequestResult, sender *recordingSender) {
				require.Equal(t, 1, sender.Count())
				assert.Equal(t, "Sign in to Payroll", sender.Last().Subject)
				assert.Equal(t, "ada@example.com", sender.Last().To,
					"the recipient is the submitted address, whatever the renderer returns")
			},
		},
		{
			name:    "the renderer receives the redirect target",
			opts:    []magiclink.Option{magiclink.WithRenderer(recordingRenderer)},
			address: "ada@example.com",
			next:    "/dashboard",
			assert: func(t *testing.T, _ magiclink.RequestResult, sender *recordingSender) {
				require.Equal(t, 1, sender.Count())
				assert.Equal(t, "/dashboard", seen)
			},
		},
		{
			name:    "magic link surface",
			loader:  activeByID(),
			address: "ada@example.com",
			next:    "/",
			assert: func(t *testing.T, got magiclink.RequestResult, sender *recordingSender) {
				require.NotNil(t, requestReturnsNoError)

				assert.Len(t, got.BindingNonce, magiclink.BindingNonceLength,
					"BindingNonceLength is the length a caller builds a decoy to match")
				assert.Equal(t, 1, sender.Count())
			},
		},
		{
			name:    "default renderer",
			address: "ada@example.com",
			next:    "/",
			assert: func(t *testing.T, _ magiclink.RequestResult, sender *recordingSender) {
				require.Equal(t, 1, sender.Count())
				msg := sender.Last()

				assert.Contains(t, msg.TextBody, "https://app.example.com/login/magic/confirm?")
				assert.Regexp(t, `(?i)expires`, msg.TextBody)
				assert.Regexp(t, `(?i)once`, msg.TextBody)
				assert.Empty(t, msg.From, "the sender's own configured address is used")

				for _, brand := range []string{"scrty", "kartala", "Payroll", "Acme"} {
					assert.NotContains(t, strings.ToLower(msg.Subject), strings.ToLower(brand))
					assert.NotContains(t, strings.ToLower(msg.TextBody), strings.ToLower(brand))
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var loader identity.UserLoader = activeLoader()
			if tc.loader != nil {
				loader = tc.loader
			}

			baseURL := "https://app.example.com"
			if tc.baseURL != "" {
				baseURL = tc.baseURL
			}

			sender := &recordingSender{}

			m, err := magiclink.New(testTokens(t), loader, sender, baseURL, tc.opts...)
			require.NoError(t, err)

			got := m.Request(t.Context(), tc.address, tc.next)

			tc.assert(t, got, sender)
		})
	}
}

// Standalone from TestRequest: each case sends one request past its limit and counts every send, not one request's.
func TestRequestIssuanceLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		opts  []magiclink.Option
		limit int
	}

	cases := []testCase{
		{name: "the default of five", limit: 5},
		{name: "a consumer limit of two", opts: []magiclink.Option{magiclink.WithIssuanceLimit(2)}, limit: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sender := &recordingSender{}

			m, err := magiclink.New(testTokens(t), activeLoader(), sender,
				"https://app.example.com", tc.opts...)
			require.NoError(t, err)

			for range tc.limit + 1 {
				m.Request(t.Context(), "ada@example.com", "/")
			}

			assert.Equal(t, tc.limit, sender.Count(),
				"the attempt past the limit issues nothing and sends nothing")
		})
	}
}

// countHoldingStore is a memory token store whose recent-issue count, once
// read, waits until every racer has read it too (or a bound passes), so a
// flow that counts and then issues lets the whole burst see the same count.
// A flow that decides with one bounded insert never calls the count, and the
// hold costs it nothing.
type countHoldingStore struct {
	*onetime.MemoryStore

	racers int

	mu      sync.Mutex
	counted int
	all     chan struct{}
}

func newCountHoldingStore(racers int) *countHoldingStore {
	return &countHoldingStore{MemoryStore: onetime.NewMemoryStore(), racers: racers, all: make(chan struct{})}
}

func (s *countHoldingStore) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	n, err := s.MemoryStore.CountRecentBySubject(ctx, purpose, subject, since)

	s.mu.Lock()
	s.counted++
	if s.counted == s.racers {
		close(s.all)
	}
	s.mu.Unlock()

	select {
	case <-s.all:
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}

	return n, err
}

// TestRequest_ConcurrentBurstStaysWithinIssuanceLimit releases twenty link
// requests for one address at once against the default limit of five: exactly
// five links are stored and exactly five messages are sent.
//
// Standalone: twenty goroutines race one address against a store that holds every count.
func TestRequest_ConcurrentBurstStaysWithinIssuanceLimit(t *testing.T) {
	t.Parallel()

	const racers, limit = 20, 5

	store := newCountHoldingStore(racers)
	sender := &recordingSender{}
	m, err := magiclink.New(tokensWithStore(t, store), activeLoader(), sender, "https://app.example.com")
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			m.Request(t.Context(), "ada@example.com", "/")
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, limit, store.Len(), "links issued")
	assert.Equal(t, limit, sender.Count(), "emails sent")
	assert.Equal(t, store.Len(), sender.Count(), "every issued link is sent, and nothing else")
}

func TestRedeem(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// loader is the user loader; nil means activeByID().
		loader identity.UserLoader
		// store wraps the memory token store; nil leaves it as it is.
		store func(inner onetime.Store) onetime.Store
		// bound issues the link bound to a nonce the caller never presents.
		bound bool
		// prepare turns the valid link into what is presented; nil presents it
		// as issued, with no binding.
		prepare func(t *testing.T, tokens *onetime.Tokens, valid string) (presented, binding string)
		checks  []magiclink.Check
		// assert receives the redemption, its error, and how many consumes the
		// redemption attempted.
		assert func(t *testing.T, r magiclink.Redemption, redeemErr error, consumes int)
	}

	notConsumed := func(wantErr error) func(*testing.T, magiclink.Redemption, error, int) {
		return func(t *testing.T, r magiclink.Redemption, err error, consumes int) {
			assert.ErrorIs(t, err, wantErr)
			assert.Empty(t, r.Principal.ID, "a refusal establishes nobody")
			assert.Zero(t, consumes, "a refusal before the last step must not spend the link")
		}
	}

	uniform := func(t *testing.T, r magiclink.Redemption, redeemErr error, _ int) {
		assert.ErrorIs(t, redeemErr, magiclink.ErrInvalidLink,
			"every one of these is the same error to the caller")
		assert.Empty(t, r.Principal.ID, "no session may be established")
	}

	keepValid := func(_ *testing.T, _ *onetime.Tokens, valid string) (string, string) {
		return valid, ""
	}

	consumerErr := errors.New("terms not accepted")

	changed := time.Date(2025, 11, 2, 9, 30, 0, 0, time.UTC)

	var (
		seenPrincipal identity.Principal
		seenChanged   time.Time
	)

	check := func(_ context.Context, p identity.Principal, passwordChangedAt time.Time) error {
		seenPrincipal = p
		seenChanged = passwordChangedAt

		return nil
	}

	cases := []testCase{
		{
			name:   "the user is gone",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name: "the user is disabled",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1", Active: false},
			}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name:   "the loader is down",
			loader: stubLoader{err: errStoreDown},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name: "the loader answers with another user",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-9", Active: true},
			}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name:   "a consumer check refuses",
			loader: activeByID(),
			checks: []magiclink.Check{
				func(context.Context, identity.Principal, time.Time) error { return consumerErr },
			},
			assert: notConsumed(consumerErr),
		},
		{
			name:   "everything passes",
			loader: activeByID(),
			assert: func(t *testing.T, r magiclink.Redemption, err error, consumes int) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
				assert.Equal(t, 1, consumes, "success is the only thing that spends it")
			},
		},
		{
			name:    "malformed token",
			prepare: func(*testing.T, *onetime.Tokens, string) (string, string) { return "nonsense", "" },
			assert:  uniform,
		},
		{
			name: "unknown token",
			prepare: func(t *testing.T, _ *onetime.Tokens, _ string) (string, string) {
				return freshUnknownToken(t), ""
			},
			assert: uniform,
		},
		{
			name: "expired token",
			prepare: func(t *testing.T, tokens *onetime.Tokens, valid string) (string, string) {
				advanceClockPast(t, tokens)

				return valid, ""
			},
			assert: uniform,
		},
		{
			name: "already consumed",
			prepare: func(t *testing.T, tokens *onetime.Tokens, valid string) (string, string) {
				consume(t, tokens, valid)

				return valid, ""
			},
			assert: uniform,
		},
		{
			name: "wrong secret",
			prepare: func(_ *testing.T, _ *onetime.Tokens, valid string) (string, string) {
				return valid[:len(valid)-4] + "AAAA", ""
			},
			assert: uniform,
		},
		{
			name:    "wrong binding",
			bound:   true,
			prepare: func(_ *testing.T, _ *onetime.Tokens, valid string) (string, string) { return valid, "wrong-nonce" },
			assert:  uniform,
		},
		{
			name:    "user not found",
			prepare: keepValid,
			loader:  stubLoader{byID: map[identity.UserID]*identity.Details{}},
			assert:  uniform,
		},
		{
			name:    "user disabled",
			prepare: keepValid,
			loader:  stubLoader{byID: map[identity.UserID]*identity.Details{"u-1": {ID: "u-1", Active: false}}},
			assert:  uniform,
		},
		{
			name:    "user mismatched",
			prepare: keepValid,
			loader:  stubLoader{byID: map[identity.UserID]*identity.Details{"u-1": {ID: "u-9", Active: true}}},
			assert:  uniform,
		},
		{
			name:    "loader outage",
			prepare: keepValid,
			loader:  stubLoader{err: errStoreDown},
			assert:  uniform,
		},
		{
			name:    "the consume write fails",
			prepare: keepValid,
			store:   func(inner onetime.Store) onetime.Store { return consumeFailsStore{Store: inner} },
			assert:  uniform,
		},
		{
			name: "a loader that answers with another user is refused",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-9", Active: true}, // asked for u-1, answers u-9
			}},
			assert: func(t *testing.T, r magiclink.Redemption, err error, _ int) {
				assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
				assert.Empty(t, r.Principal.ID)
			},
		},
		{
			name: "checks see the resolved principal",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1", Username: "ada@example.com", Name: "Ada", Active: true, PasswordChangedAt: changed},
			}},
			checks: []magiclink.Check{check},
			assert: func(t *testing.T, r magiclink.Redemption, err error, _ int) {
				require.NoError(t, err)

				assert.Equal(t, identity.UserID("u-1"), seenPrincipal.ID)
				assert.Equal(t, "Ada", seenPrincipal.Name)
				assert.Equal(t, changed, seenChanged)
				assert.Equal(t, changed, r.PasswordChangedAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loader := tc.loader
			if loader == nil {
				loader = activeByID()
			}

			var inner onetime.Store = onetime.NewMemoryStore()
			if tc.store != nil {
				inner = tc.store(inner)
			}

			store := &countingTokenStore{Store: inner}
			tokens := tokensWithStore(t, store)

			m, err := magiclink.New(tokens, loader, &recordingSender{}, "https://app.example.com",
				magiclink.WithSameDeviceBinding(false))
			require.NoError(t, err)

			issueOpts := []onetime.IssueOption(nil)
			if tc.bound {
				issueOpts = append(issueOpts, onetime.WithBinding("the-right-nonce"))
			}

			valid, _, err := tokens.Issue(t.Context(), "u-1", issueOpts...)
			require.NoError(t, err)

			presented, binding := valid, ""
			if tc.prepare != nil {
				presented, binding = tc.prepare(t, tokens, valid)
			}

			before := store.Consumes()
			r, redeemErr := m.Redeem(t.Context(), presented, binding, tc.checks...)

			tc.assert(t, r, redeemErr, store.Consumes()-before)
		})
	}
}

// Standalone from TestRedeem: it issues through Request and reassigns the username before redeeming.
func TestRedeemBindsToUserReference(t *testing.T) {
	t.Parallel()

	t.Run("a reissued username does not inherit a live link", func(t *testing.T) {
		t.Parallel()

		loader := &mutableLoader{
			byUsername: map[string]*identity.Details{
				"ada": {ID: "u-1", Username: "ada", Active: true},
			},
			byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1", Username: "ada", Active: true},
			},
		}

		sender := &recordingSender{}

		m, err := magiclink.New(testTokens(t), loader, sender, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		// The link goes out through the real request path, so what it records
		// about the user is the production decision under test.
		m.Request(t.Context(), "ada", "/")
		require.Equal(t, 1, sender.Count())

		link, err := url.Parse(extractLink(t, sender.Last().TextBody))
		require.NoError(t, err)

		presented := link.Query().Get("token")
		require.NotEmpty(t, presented)

		// u-1 is deleted and the username is given to u-2.
		loader.reassign("u-1", &identity.Details{ID: "u-2", Username: "ada", Active: true})

		r, err := m.Redeem(t.Context(), presented, "")
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
		assert.Empty(t, r.Principal.ID, "no session may be established for u-2")
	})
}

// Standalone from TestRedeem: each case redeems twice, changing the cause of the refusal in between.
func TestRefusalDoesNotSpendLink(t *testing.T) {
	t.Parallel()

	t.Run("a refusal, then the cause is fixed, then the same link works", func(t *testing.T) {
		t.Parallel()

		mustEnrol := errors.New("enrolment required")

		var enrolled atomic.Bool

		check := func(context.Context, identity.Principal, time.Time) error {
			if !enrolled.Load() {
				return mustEnrol
			}

			return nil
		}

		tokens := testTokens(t)

		m, err := magiclink.New(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		_, err = m.Redeem(t.Context(), presented, "", check)
		require.ErrorIs(t, err, mustEnrol)

		enrolled.Store(true)

		r, err := m.Redeem(t.Context(), presented, "", check)
		require.NoError(t, err, "the link survived the refusal")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})

	t.Run("a transient loader failure, then recovery", func(t *testing.T) {
		t.Parallel()

		loader := &flakyLoader{err: errStoreDown}

		tokens := testTokens(t)

		m, err := magiclink.New(tokens, loader, &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		_, err = m.Redeem(t.Context(), presented, "")
		require.ErrorIs(t, err, magiclink.ErrInvalidLink)

		loader.Recover()

		_, err = m.Redeem(t.Context(), presented, "")
		assert.NoError(t, err)
	})
}

// Standalone from TestRedeem: it redeems twice, the second time without the checks.
func TestConsumerChecksReturnedUnchanged(t *testing.T) {
	t.Parallel()

	termsNotAccepted := errors.New("terms not accepted")

	var secondRan atomic.Bool

	first := func(context.Context, identity.Principal, time.Time) error { return termsNotAccepted }
	second := func(context.Context, identity.Principal, time.Time) error {
		secondRan.Store(true)

		return nil
	}

	tokens := testTokens(t)

	m, err := magiclink.New(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")

	_, err = m.Redeem(t.Context(), presented, "", first, second)

	assert.ErrorIs(t, err, termsNotAccepted, "returned unchanged, not wrapped in ErrInvalidLink")
	assert.NotErrorIs(t, err, magiclink.ErrInvalidLink)
	assert.False(t, secondRan.Load(), "later checks do not run")

	// And the link survived.
	_, err = m.Redeem(t.Context(), presented, "")
	assert.NoError(t, err)
}

// Standalone from TestRedeem: each case issues through Request with binding on by default, and redeems with the nonce it returned.
func TestRedeemRequiresBinding(t *testing.T) {
	t.Parallel()

	// issueThroughRequest runs the real request path and hands back the token
	// from the emailed link together with the binding nonce the caller got.
	issueThroughRequest := func(t *testing.T, m *magiclink.Links, sender *recordingSender) (string, string) {
		t.Helper()

		result := m.Request(t.Context(), "ada@example.com", "/")
		require.Equal(t, 1, sender.Count())

		u, err := url.Parse(extractLink(t, sender.Last().TextBody))
		require.NoError(t, err)

		return u.Query().Get("token"), result.BindingNonce
	}

	t.Run("by default the binding is required", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		m, err := magiclink.New(testTokens(t), activeByID(), sender, "https://app.example.com")
		require.NoError(t, err)

		token, nonce := issueThroughRequest(t, m, sender)
		require.Len(t, nonce, magiclink.BindingNonceLength)

		_, err = m.Redeem(t.Context(), token, "another-device")
		require.ErrorIs(t, err, magiclink.ErrInvalidLink, "another device holds no binding")

		r, err := m.Redeem(t.Context(), token, nonce)
		require.NoError(t, err, "the refusal did not spend the link")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})

	t.Run("a consumer may disable it", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		m, err := magiclink.New(testTokens(t), activeByID(), sender, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		token, nonce := issueThroughRequest(t, m, sender)
		assert.Empty(t, nonce)

		r, err := m.Redeem(t.Context(), token, "whatever-another-device-sent")
		require.NoError(t, err, "a presented binding is ignored when binding is off")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})
}

// Standalone from TestRedeem: it keeps binding on and requests a link before redeeming, to read what both log.
func TestRedeemLogsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tokens := testTokens(t)

	m, err := magiclink.New(tokens,
		stubLoader{err: errStoreDown},
		&recordingSender{}, "https://app.example.com",
		magiclink.WithLogger(logger))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")
	binding := "the-binding-nonce"

	m.Request(t.Context(), "ada@example.com", "/")

	_, err = m.Redeem(t.Context(), presented, binding)
	require.ErrorIs(t, err, magiclink.ErrInvalidLink)

	logged := buf.String()
	require.NotEmpty(t, logged, "the causes are logged, or this proves nothing")

	assert.NotContains(t, logged, presented, "the token must not be logged")
	assert.NotContains(t, logged, binding, "the binding value must not be logged")
	assert.NotContains(t, logged, "ada@example.com", "the submitted address must not be logged")
}

// Standalone: sixteen goroutines redeem one link at once.
func TestRedeemRace(t *testing.T) {
	t.Parallel()

	tokens := testTokens(t)

	m, err := magiclink.New(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")
	ctx := t.Context()

	const goroutines = 16

	var (
		wg        sync.WaitGroup
		succeeded atomic.Int64
		checkRuns atomic.Int64
		start     = make(chan struct{})
	)

	// A check runs for every racing attempt, which is why a check is
	// documented as having to be free of side effects.
	check := func(context.Context, identity.Principal, time.Time) error {
		checkRuns.Add(1)

		return nil
	}

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			<-start

			if _, redeemErr := m.Redeem(ctx, presented, "", check); redeemErr == nil {
				succeeded.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "one link, one session")
	assert.Positive(t, checkRuns.Load())
}

// Standalone from TestExpiryTask: it calls PurgeExpired directly, not through the task.
func TestManager_PurgeExpired(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	tokens, err := onetime.New("magic-link",
		onetime.WithStore(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))),
		onetime.WithClock(clk), onetime.WithTTL(15*time.Minute), onetime.WithIssuanceWindow(time.Hour))
	require.NoError(t, err)

	_, _, err = tokens.Issue(t.Context(), "carol")
	require.NoError(t, err)
	clk.Advance(2 * time.Hour)

	m, err := magiclink.New(tokens, stubLoader{}, &recordingSender{}, "https://app.example.com")
	require.NoError(t, err)

	removed, err := m.PurgeExpired(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
}

// noPurgeStore hides the reaper of the memory store, so the store it wraps
// can insert and count but cannot purge.
type noPurgeStore struct {
	onetime.Store
}

func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// store is the token store; nil means a purge-capable memory store.
		store func(clock *clockwork.FakeClock) onetime.Store
		// age is how long ago carol's one token was issued.
		age    time.Duration
		assert func(t *testing.T, task expiry.Task, tokens *onetime.Tokens, removed int, err error)
	}

	cases := []testCase{
		{
			name: "a token expired but inside the issuance window is kept and still counted",
			age:  30 * time.Minute,
			assert: func(t *testing.T, _ expiry.Task, tokens *onetime.Tokens, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)

				n, cerr := tokens.IssuedCount(t.Context(), "carol")
				require.NoError(t, cerr)
				assert.Equal(t, 1, n, "a sweep freed issuance quota")
			},
		},
		{
			name: "a token expired and past the issuance window is deleted",
			age:  2 * time.Hour,
			assert: func(t *testing.T, _ expiry.Task, _ *onetime.Tokens, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "the task is named magiclink-tokens and sets no interval",
			age:  time.Minute,
			assert: func(t *testing.T, task expiry.Task, _ *onetime.Tokens, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "magiclink-tokens", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "a store that cannot purge matches ErrPurgeUnsupported",
			store: func(clock *clockwork.FakeClock) onetime.Store {
				return noPurgeStore{Store: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clock))}
			},
			age: 2 * time.Hour,
			assert: func(t *testing.T, _ expiry.Task, _ *onetime.Tokens, removed int, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
			var store onetime.Store = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
			if tc.store != nil {
				store = tc.store(clk)
			}

			tokens, err := onetime.New("magic-link",
				onetime.WithStore(store), onetime.WithClock(clk),
				onetime.WithTTL(15*time.Minute), onetime.WithIssuanceWindow(time.Hour))
			require.NoError(t, err)

			_, _, err = tokens.Issue(t.Context(), "carol")
			require.NoError(t, err)
			clk.Advance(tc.age)

			m, err := magiclink.New(tokens, stubLoader{}, &recordingSender{}, "https://app.example.com")
			require.NoError(t, err)

			task := magiclink.ExpiryTask(m)
			var removed int
			if task.Run != nil {
				removed, err = task.Run(t.Context())
			}
			tc.assert(t, task, tokens, removed, err)
		})
	}
}

// errStoreFailure is the dependency error every row proves against: a store's own
// text, quoting a username and a user reference the record must never repeat.
var errStoreFailure = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// failingRandomSource is a consumer-supplied WithRandom port that is down. Its
// error carries the same store text every other row proves against, so the
// row shows that a port's error text is redacted here too, not only a store's.
type failingRandomSource struct{}

func (failingRandomSource) Read([]byte) (int, error) { return 0, errStoreFailure }

// magiclinkFailureRecords decodes every JSON line buf holds, so a case can
// assert on fields rather than on message text.
func magiclinkFailureRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var out []map[string]any

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line %q", line)
		out = append(out, rec)
	}

	return out
}

// assertReasonRecorded is what every row here asserts: that some record among
// recs carries reason and names the failing error's Go type. It is shared
// rather than repeated per case because every row makes the identical claim
// about a different reason word.
func assertReasonRecorded(t *testing.T, recs []map[string]any, reason string) {
	t.Helper()

	var found bool

	for _, rec := range recs {
		if rec["reason"] == reason {
			found = true

			assert.NotEmpty(t, rec["error_type"], "the record does not name the error's type")
		}
	}

	assert.True(t, found, "no record carried reason %q", reason)
}

// TestMagicLinkFailureRecords pins the diagnostic-redaction requirement: every
// dependency this manager depends on — the token store's count and issue, the
// sender, the address resolver and the redemption user loader — is recorded by
// a fixed reason and the error's Go type, never by the error's own text.
//
// Each row's manager is built differently — a failing count, a failing
// insert, a failing sender, a failing resolver, a failing redemption loader —
// so each is a run closure rather than a shared call shape.
func TestMagicLinkFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) *bytes.Buffer
		assert func(t *testing.T, recs []map[string]any)
	}

	known := &identity.Details{ID: "u-1", Username: "ada@example.com", Active: true}

	cases := []testCase{
		{
			name: "the link cannot be issued",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "token-issue")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				tokens := tokensWithStore(t, insertFailsStore{Store: onetime.NewMemoryStore()})

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}

				m, err := magiclink.New(tokens, loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the sign-in message cannot be sent",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "sender")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}
				sender := &failingSender{err: errStoreFailure}

				m, err := magiclink.New(testTokens(t), loader, sender, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the submitted address cannot be resolved",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "resolver")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				loader := stubLoader{err: errStoreFailure}

				m, err := magiclink.New(testTokens(t), loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the binding nonce's random source fails",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "random-source")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				loader := stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}}

				m, err := magiclink.New(testTokens(t), loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithRandom(failingRandomSource{}), magiclink.WithLogger(logger))
				require.NoError(t, err)

				m.Request(t.Context(), "ada@example.com", "/")

				return &buf
			},
		},
		{
			name: "the link's user cannot be loaded at redemption",
			assert: func(t *testing.T, recs []map[string]any) {
				assertReasonRecorded(t, recs, "user-loader")
			},
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				tokens := testTokens(t)
				presented := issueFor(t, tokens, "u-1")

				loader := stubLoader{err: errStoreFailure}

				m, err := magiclink.New(tokens, loader, &recordingSender{}, "https://app.example.com",
					magiclink.WithSameDeviceBinding(false), magiclink.WithLogger(logger))
				require.NoError(t, err)

				_, _ = m.Redeem(t.Context(), presented, "")

				return &buf
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buf := tc.run(t)
			rendered := buf.String()

			assert.NotContains(t, rendered, "alice@example.com", "a written record leaked the store's address")
			assert.NotContains(t, rendered, "u-123", "a written record leaked the store's user reference")
			assert.NotContains(t, rendered, "ada@example.com", "a written record leaked the submitted address")

			recs := magiclinkFailureRecords(t, buf)
			require.NotEmpty(t, recs, "the failure was never reported")

			tc.assert(t, recs)
		})
	}
}
