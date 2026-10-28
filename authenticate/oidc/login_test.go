package oidc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// authorizeParams parses an authorization redirect, requiring it to be
// addressed to endpoint.
func authorizeParams(t *testing.T, redirect, endpoint string) url.Values {
	t.Helper()

	u, err := url.Parse(redirect)
	require.NoError(t, err)
	want, err := url.Parse(endpoint)
	require.NoError(t, err)
	assert.Equal(t, want.Scheme+"://"+want.Host+want.Path, u.Scheme+"://"+u.Host+u.Path,
		"the redirect must go to the provider's authorization endpoint")

	return u.Query()
}

// authorizeFlow returns the flow the manager's default store holds under
// handle.
func authorizeFlow(t *testing.T, m *oidc.RelyingParty, handle string) oidc.Flow {
	t.Helper()

	store, ok := oidc.WiringOf(m).Flows.(*oidc.MemoryFlowStore)
	require.True(t, ok, "the manager must hold the default in-memory store")
	f, found := oidc.FlowForTest(store, handle)
	require.True(t, found, "the handle must name a stored flow")

	return f
}

// authorizeNoFlowStore is a flow store that fails the test if touched.
func authorizeNoFlowStore(t *testing.T) oidc.Option {
	t.Helper()
	return oidc.WithFlowStore(NewMockFlowStore(gomock.NewController(t)))
}

func TestManagerAuthorize(t *testing.T) {
	t.Parallel()

	sevens := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	past := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

	// nextRecorded asserts that the login succeeded and that its flow recorded
	// want as the next path.
	nextRecorded := func(want string) func(t *testing.T, m *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
		return func(t *testing.T, m *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
			t.Helper()

			require.NoError(t, err, "an over-long next never fails the login")
			assert.Equal(t, want, authorizeFlow(t, m, got.Handle).Next)
		}
	}

	atBound := "/" + strings.Repeat("a", 2047)

	type testCase struct {
		name     string
		provider string
		next     string
		// opts are extra manager options; the provider's outbound client is
		// always given.
		opts   func(t *testing.T, p *testProvider) []oidc.Option
		setup  func(p *testProvider)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, m *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error)
	}

	cases := []testCase{
		{
			name: "the redirect carries PKCE, state and nonce", provider: "corp", next: "/after?x=1",
			assert: func(t *testing.T, m *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				f := authorizeFlow(t, m, got.Handle)

				assert.Equal(t, "code", q.Get("response_type"))
				assert.Equal(t, "client-corp", q.Get("client_id"))
				assert.Equal(t, "https://app.example/login/oauth2/callback/corp", q.Get("redirect_uri"))
				assert.Equal(t, "openid profile email", q.Get("scope"))
				assert.Equal(t, "S256", q.Get("code_challenge_method"))
				sum := sha256.Sum256([]byte(f.Verifier))
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))
				assert.Equal(t, f.State, q.Get("state"))
				assert.Equal(t, f.Nonce, q.Get("nonce"))
				assert.False(t, q.Has("code_verifier"), "the verifier never goes to the authorization endpoint")
				assert.NotContains(t, got.RedirectURL, f.Verifier)
				assert.NotContains(t, got.RedirectURL, "client_secret")
				assert.NotContains(t, got.RedirectURL, "secret-corp")

				for _, v := range []string{f.State, f.Nonce, f.Verifier, got.Handle} {
					raw, err := base64.RawURLEncoding.DecodeString(v)
					require.NoError(t, err)
					assert.Len(t, raw, 32, "every flow secret carries 256 bits")
				}
				assert.Equal(t, "corp", f.Provider)
				assert.Equal(t, "/after?x=1", f.Next, "next is stored verbatim")
			},
		},
		{
			name: "requested acr values are sent space-separated in the configured order", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithProviderAssurance("corp", oidc.Assurance{
					AcceptedAMR: []string{"mfa"},
					RequestACR:  []string{"urn:corp:loa:3", "urn:corp:loa:2"},
				})}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.Equal(t, []string{"urn:corp:loa:3 urn:corp:loa:2"}, q["acr_values"])
			},
		},
		{
			name: "nothing is requested by default", provider: "corp",
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.False(t, q.Has("acr_values"))
			},
		},
		{
			name: "a configuration requesting nothing sends no acr_values", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithProviderAssurance("corp", oidc.Assurance{
					AcceptedACR: []string{"urn:corp:loa:2"},
				})}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.False(t, q.Has("acr_values"), "accepting an acr is not requesting one")
			},
		},
		{
			name: "another provider's requested acr values are not sent", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithProviderAssurance("groups", oidc.Assurance{
					RequestACR: []string{"urn:groups:loa:2"},
				})}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.False(t, q.Has("acr_values"))
			},
		},
		{
			name: "requested acr values join a pinned endpoint's own parameters", provider: "pinned",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithProviderAssurance("pinned", oidc.Assurance{
					RequestACR: []string{"gold"},
				})}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/pinned/authorize")
				assert.Equal(t, "gold", q.Get("acr_values"))
				assert.Equal(t, "login", q.Get("prompt"))
			},
		},
		{
			name: "two attempts carry different values", provider: "corp",
			assert: func(t *testing.T, m *oidc.RelyingParty, p *testProvider, first oidc.Authorization, err error) {
				require.NoError(t, err)
				second, err := m.Authorize(t.Context(), "corp", "")
				require.NoError(t, err)

				q1 := authorizeParams(t, first.RedirectURL, p.Issuer()+"/authorize")
				q2 := authorizeParams(t, second.RedirectURL, p.Issuer()+"/authorize")
				for _, k := range []string{"state", "nonce", "code_challenge"} {
					assert.NotEqual(t, q1.Get(k), q2.Get(k), k)
				}
				assert.NotEqual(t, first.Handle, second.Handle)
			},
		},
		{
			name: "consumer scopes are requested exactly", provider: "groups",
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.Equal(t, "openid groups", q.Get("scope"))
				assert.Equal(t, "client-groups", q.Get("client_id"))
			},
		},
		{
			name: "the flow is stored for the default TTL", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithClock(clockwork.NewFakeClockAt(past))}
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				assert.Equal(t, past.Add(10*time.Minute), got.ExpiresAt)
				f := authorizeFlow(t, m, got.Handle)
				assert.Equal(t, past.Add(10*time.Minute), f.ExpiresAt)

				// The default store judges expiry by the manager's clock: by
				// time.Now this flow expired long ago.
				_, err = oidc.WiringOf(m).Flows.Complete(t.Context(), got.Handle, "corp", f.State)
				require.NoError(t, err, "the default store must share the manager's clock")
			},
		},
		{
			name: "the flow is stored for the consumer's TTL", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{
					oidc.WithClock(clockwork.NewFakeClockAt(past)),
					oidc.WithFlowTTL(3 * time.Minute),
				}
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				assert.Equal(t, past.Add(3*time.Minute), got.ExpiresAt)
				assert.Equal(t, past.Add(3*time.Minute), authorizeFlow(t, m, got.Handle).ExpiresAt)
			},
		},
		{
			name: "the configured random source is used", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithRandom(bytes.NewReader(bytes.Repeat([]byte{7}, 4096)))}
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.Equal(t, sevens, q.Get("state"))
				assert.Equal(t, sevens, q.Get("nonce"))
				sum := sha256.Sum256([]byte(sevens))
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))
				assert.Equal(t, sevens, got.Handle, "the default store must share the manager's random source")
				assert.Equal(t, sevens, authorizeFlow(t, m, got.Handle).Verifier)
			},
		},
		{
			name: "a consumer flow store receives the flow", provider: "corp", next: "/n",
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				store := NewMockFlowStore(gomock.NewController(t))
				store.EXPECT().Begin(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, f oidc.Flow) (string, error) {
						assert.Equal(t, "corp", f.Provider)
						assert.Equal(t, "/n", f.Next)
						assert.NotEmpty(t, f.State)
						assert.NotEmpty(t, f.Nonce)
						assert.NotEmpty(t, f.Verifier)
						return "consumer-handle", nil
					})
				return []oidc.Option{oidc.WithFlowStore(store)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				assert.Equal(t, "consumer-handle", got.Handle)
			},
		},
		{
			name: "a store refusal fails the authorization", provider: "corp",
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				store := NewMockFlowStore(gomock.NewController(t))
				store.EXPECT().Begin(gomock.Any(), gomock.Any()).Return("", oidc.ErrFlowStoreFull)
				return []oidc.Option{oidc.WithFlowStore(store)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrFlowStoreFull)
				assert.Empty(t, got.RedirectURL)
				assert.Empty(t, got.Handle)
			},
		},
		{
			name: "the authorization endpoint's own query is kept", provider: "pinned",
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/pinned/authorize")
				assert.Equal(t, "login", q.Get("prompt"))
				assert.Equal(t, "code", q.Get("response_type"))
				assert.Equal(t, int64(0), p.discoveryCalls.Load(), "pinned endpoints are never discovered")
			},
		},
		{
			name: "an unknown provider stores no flow", provider: "nope",
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				return []oidc.Option{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, p *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				assert.Equal(t, oidc.Authorization{}, got)
				assert.Equal(t, int64(0), p.discoveryCalls.Load())
			},
		},
		{
			name: "an encoded slash is an unknown provider", provider: "corp%2F..",
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				return []oidc.Option{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, _ oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
			},
		},
		{
			name: "a trailing slash is an unknown provider", provider: "corp/",
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				return []oidc.Option{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, _ oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
			},
		},
		{
			name: "a discovery failure is a provider failure and stores no flow", provider: "corp",
			setup: func(p *testProvider) { p.failDiscovery.Store(true) },
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				return []oidc.Option{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.Equal(t, oidc.Authorization{}, got)
			},
		},
		{
			name: "a failing random source stores no flow", provider: "corp",
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				return []oidc.Option{oidc.WithRandom(errReader{}), authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, errFlowRandom)
				assert.Equal(t, oidc.Authorization{}, got)
			},
		},
		{
			name: "a canceled context stores no flow", provider: "corp",
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			opts: func(t *testing.T, _ *testProvider) []oidc.Option {
				return []oidc.Option{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.RelyingParty, _ *testProvider, got oidc.Authorization, err error) {
				require.Error(t, err)
				assert.Equal(t, oidc.Authorization{}, got)
			},
		},
		{name: "a next of exactly 2048 bytes is recorded", provider: "corp", next: atBound, assert: nextRecorded(atBound)},
		{name: "a next of 2049 bytes is not recorded", provider: "corp", next: atBound + "a", assert: nextRecorded("")},
		{name: "a next of 1 MiB is not recorded", provider: "corp", next: "/" + strings.Repeat("a", 1<<20), assert: nextRecorded("")},
		{name: "a short next is recorded verbatim", provider: "corp", next: "/after?x=1", assert: nextRecorded("/after?x=1")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			if tc.setup != nil {
				tc.setup(p)
			}
			groups := p.Provider("groups")
			groups.Scopes = []string{"openid", "groups"}
			pinned := p.Provider("pinned")
			pinned.AuthorizationEndpoint = p.Issuer() + "/pinned/authorize?prompt=login"
			pinned.TokenEndpoint = p.Issuer() + "/token"
			pinned.JWKSURI = p.Issuer() + "/jwks"
			reg, err := oidc.NewRegistry(p.Provider("corp"), groups, pinned)
			require.NoError(t, err)

			opts := []oidc.Option{oidc.WithOutboundClient(p.Outbound(t))}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t, p)...)
			}
			m, err := oidc.NewRelyingParty(reg, stubBroker{}, opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			got, err := m.Authorize(ctx, tc.provider, tc.next)
			tc.assert(t, m, p, got, err)
		})
	}
}

func alice() *identity.Principal { return &identity.Principal{ID: "user-alice", Username: "alice"} }

func TestManagerCallback(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbDown := errors.New("db down")

	type testCase struct {
		name string
		// flows, when set, replaces the default store; no flow is begun then.
		flows  func(t *testing.T) oidc.FlowStore
		setup  func(t *testing.T, e *callbackEnv)
		act    func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error)
		assert func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error)
	}

	spentByLater := func(t *testing.T, e *callbackEnv) {
		t.Helper()
		_, err := e.genuine(t)
		require.ErrorIs(t, err, oidc.ErrInvalidState, "the flow must be spent")
	}
	stillCompletable := func(t *testing.T, e *callbackEnv) {
		t.Helper()
		got, err := e.genuine(t)
		require.NoError(t, err, "the victim's genuine callback must still complete")
		assert.Equal(t, alice(), got.Principal)
	}
	consumerWant := &identity.Principal{ID: "user-alice", Username: "alice"}

	cases := []testCase{
		{
			name: "a successful callback returns the brokered principal and the provider session",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
						assert.Equal(t, "corp", ext.Provider)
						assert.Equal(t, e.p.Issuer(), ext.Issuer)
						assert.Equal(t, "subject-1", ext.Subject)
						assert.Equal(t, "alice@corp.example", ext.Email)
						assert.True(t, ext.EmailVerified)
						assert.Equal(t, "provider-session", ext.Claims["sid"])
						return alice(), nil
					})
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.CallbackResult{
					Principal: alice(),
					Provider:  "corp",
					Issuer:    e.p.Issuer(),
					SessionID: "provider-session",
					IDToken:   e.idTok,
					Next:      "/after",
				}, got)
				spentByLater(t, e)
			},
		},
		{
			name: "a forged callback leaves the victim's flow completable",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "attacker-code", "attacker", e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load(), "nothing is exchanged")
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "a callback through another provider's path leaves the flow completable",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "partner", "the-code", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "an empty code is refused without touching the flow",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load())
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "an unknown provider",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "nope", "the-code", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "a store fault propagates as itself",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, dbDown)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, dbDown)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
				assert.Contains(t, e.logs.String(), "level=ERROR")
			},
		},
		{
			name: "an exchange failure spends the flow",
			setup: func(_ *testing.T, e *callbackEnv) {
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusBadRequest, `{"error":"invalid_grant"}`
				})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) { return e.genuine(t) },
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
				spentByLater(t, e)
			},
		},
		{
			name: "an invalid ID token spends the flow and reaches no broker",
			setup: func(t *testing.T, e *callbackEnv) {
				bad := e.p.Sign(t, map[string]any{
					"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
					"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nonce": "an-earlier-flow",
				})
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusOK, `{"id_token":"` + bad + `"}`
				})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) { return e.genuine(t) },
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Contains(t, e.logs.String(), "nonce", "the cause reaches the log")
				spentByLater(t, e)
			},
		},
		{
			name: "a refused ID token's claim values never reach the log or the error",
			setup: func(t *testing.T, e *callbackEnv) {
				bad := e.p.Sign(t, map[string]any{
					"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
					"exp": now.Add(time.Minute).Unix(), "iat": "alice@corp.example", "nonce": e.flow.Nonce,
				})
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusOK, `{"id_token":"` + bad + `"}`
				})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) { return e.genuine(t) },
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
				require.Contains(t, e.logs.String(), "invalid-id-token", "the refusal is logged")
				assert.NotContains(t, e.logs.String(), "alice@corp.example")
				assert.NotContains(t, err.Error(), "alice@corp.example")
			},
		},
		{
			name: "a store that completes another provider's flow has still spent it",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "partner", State: "s", Nonce: "n", Verifier: "v"}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent, "the store consumed the flow")
				assert.Equal(t, oidc.CallbackResult{}, got)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load(), "no code is exchanged")
			},
		},
		{
			name: "a broker refusal is returned as itself",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(nil, oidc.ErrNoLinkedAccount)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
				spentByLater(t, e)
			},
		},
		{
			name: "a malformed amr is warned about by provider and claim, never its value, and the login proceeds",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": "mfa"})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err, "a malformed claim never fails the login")
				assert.Equal(t, alice(), got.Principal)
				assert.Empty(t, got.AMR, "a malformed amr asserts nothing")
				out := e.logs.String()
				assert.Contains(t, out, "level=WARN")
				assert.Contains(t, out, "reason=malformed-assurance-claim")
				assert.Contains(t, out, "provider=corp")
				assert.Contains(t, out, "claim=amr")
				assert.NotContains(t, out, "mfa", "the claim's value never reaches a log")
			},
		},
		{
			name: "an amr holding a NUL is warned about as malformed, never its value, and the login proceeds",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"mfa-marker\x00"}})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err, "an unstorable claim never fails the login")
				assert.Equal(t, alice(), got.Principal)
				assert.Empty(t, got.AMR, "an unstorable amr asserts nothing")
				out := e.logs.String()
				assert.Contains(t, out, "reason=malformed-assurance-claim")
				assert.Contains(t, out, "claim=amr")
				assert.NotContains(t, out, "mfa-marker", "the claim's value never reaches a log")
			},
		},
		{
			name: "a malformed acr is warned about without its value",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"acr": map[string]any{"level": "gold-marker"}})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
				out := e.logs.String()
				assert.Contains(t, out, "provider=corp")
				assert.Contains(t, out, "claim=acr")
				assert.NotContains(t, out, "gold-marker")
			},
		},
		{
			name: "malformed assurance warnings are sampled under the provider's callback key",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"mfa", 1}, "acr": 2})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, strings.Count(e.logs.String(), "reason=malformed-assurance-claim"),
					"the second warning in the window is held back")
				require.NoError(t, e.m.FlushRefusalLogs())
				out := e.logs.String()
				assert.Contains(t, out, "reason=oidc.callback:malformed-assurance-claim:corp suppressed=1")
				assert.NotContains(t, out, "mfa")
			},
		},
		{
			name: "well-formed assurance claims write no warning",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"pwd", "mfa"}, "acr": "urn:corp:loa:2"})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.NotContains(t, e.logs.String(), "malformed-assurance-claim")
			},
		},
		{
			name: "the asserted amr and acr travel in the result, amr in order without duplicates",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"pwd", "mfa", "mfa"}, "acr": "urn:corp:loa:2"})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, _ *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, got.AMR)
				assert.Equal(t, "urn:corp:loa:2", got.ACR)
			},
		},
		{
			name: "a broker returning no principal and no error is a failure",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(nil, nil)
				return e.genuine(t)
			},
			assert: func(t *testing.T, _ *callbackEnv, got oidc.CallbackResult, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
			},
		},
		// The "Consumer broker" scenario of the identity-linking spec: a consumer
		// IdentityBroker, given to NewRelyingParty in place of the library's own
		// *oidc.Broker, replaces linking, provisioning and mirroring entirely. It
		// receives every claim of the verified ID token unchanged — including a
		// nested claim and one the library does not recognise — and its returned
		// principal, provider and session become the callback's result. The
		// consumer broker is NewRelyingParty's broker argument directly, so the
		// library's own broker collaborators — a link store and a user
		// provisioner — are never constructed and never sit in the call path.
		{
			name: "consumer broker",
			setup: func(t *testing.T, e *callbackEnv) {
				signedClaims := map[string]any{
					"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
					"exp": e.now.Add(5 * time.Minute).Unix(), "iat": e.now.Unix(),
					"nonce": e.flow.Nonce, "sid": "provider-session",
					"email": "alice@corp.example", "email_verified": true,
					"department":       "R&D",
					"realm_access":     map[string]any{"roles": []any{"editor", "viewer"}},
					"x_unknown_claim1": "kept-unchanged",
				}
				idTok := e.p.Sign(t, signedClaims)
				verifier := e.flow.Verifier
				e.p.SetTokenResponse(func(r *http.Request) (int, string) {
					if r.ParseForm() != nil || r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") != verifier {
						return http.StatusBadRequest, `{"error":"invalid_grant"}`
					}
					return http.StatusOK, `{"access_token":"at","id_token":"` + idTok + `"}`
				})

				wantClaims := jsonRoundTrip(t, signedClaims)

				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
						assert.Equal(t, "corp", ext.Provider)
						assert.Equal(t, e.p.Issuer(), ext.Issuer)
						assert.Equal(t, "subject-1", ext.Subject)
						assert.Equal(t, "alice@corp.example", ext.Email)
						assert.True(t, ext.EmailVerified)
						// The whole map, not a handful of hand-picked keys: a dropped
						// claim, an added one or a type change would go unnoticed by
						// the targeted checks above but not by this one.
						assert.Equal(t, wantClaims, ext.Claims)
						return consumerWant, nil
					})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.genuine(t)
			},
			assert: func(t *testing.T, _ *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Same(t, consumerWant, got.Principal)
				assert.Equal(t, "corp", got.Provider)
				assert.Equal(t, "provider-session", got.SessionID)
				assert.Equal(t, "/after", got.Next)
			},
		},
		// A flow store's completion failure is recorded through the fixed reason
		// and the error's type, never the store's own text — unlike the
		// callback's invalid-id-token record, which keeps the library's own
		// protocol-failure text on purpose.
		{
			name: "failure records",
			flows: func(t *testing.T) oidc.FlowStore {
				t.Helper()
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, errRedactionFixture)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, errRedactionFixture, "the store's error is still reachable by identity")
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)

				logs := e.logs.String()
				assert.NotContains(t, logs, "alice@example.com")
				assert.NotContains(t, logs, "u-123")
				assert.Contains(t, logs, "reason=flow-store")
				assert.Contains(t, logs, "error_type=")
			},
		},
		{
			name: "a canceled context fails the callback",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return e.m.Callback(ctx, "corp", "the-code", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, _ *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, oidc.CallbackResult{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, tc.flows)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			got, err := tc.act(t, e)
			tc.assert(t, e, got, err)
			assertNoFlowSecretsLogged(t, e)
		})
	}
}

// jsonRoundTrip marshals v and decodes it back into a fresh map[string]any,
// the same shape encoding/json produces reading an arbitrary token payload
// (numbers as float64, objects and arrays generically typed). It gives a
// test the expected claims exactly as the library will have decoded them,
// rather than as the test authored them.
func jsonRoundTrip(t *testing.T, v map[string]any) map[string]any {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func TestManagerCallbackAbortFlow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbDown := errors.New("db down")

	type testCase struct {
		name   string
		flows  func(t *testing.T) oidc.FlowStore
		act    func(t *testing.T, e *callbackEnv) (bool, error)
		assert func(t *testing.T, e *callbackEnv, ended bool, err error)
	}

	cases := []testCase{
		{
			name: "a forged error link changes nothing",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "", e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.False(t, ended)
				e.expectBroker(1)
				_, err = e.genuine(t)
				require.NoError(t, err, "the victim's genuine callback must still complete")
			},
		},
		{
			name: "an error link with a wrong state changes nothing",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "attacker", e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.False(t, ended)
				e.expectBroker(1)
				_, err = e.genuine(t)
				require.NoError(t, err)
			},
		},
		{
			name: "a genuine denial ends the flow",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.True(t, ended)
				_, err = e.genuine(t)
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load())
			},
		},
		{
			name: "a store that completes another provider's flow has ended it",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "partner", State: "s"}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, _ *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.True(t, ended, "the store consumed the flow, so the cookie may go")
			},
		},
		{
			name: "an unknown provider ends nothing",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "nope", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				assert.False(t, ended)
				e.expectBroker(1)
				_, err = e.genuine(t)
				require.NoError(t, err)
			},
		},
		{
			name: "a store fault propagates as itself",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, dbDown)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, _ *callbackEnv, ended bool, err error) {
				require.ErrorIs(t, err, dbDown)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
				assert.False(t, ended)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, tc.flows)
			ended, err := tc.act(t, e)
			tc.assert(t, e, ended, err)
			assertNoFlowSecretsLogged(t, e)
		})
	}
}

// assertNoFlowSecretsLogged fails when a flow secret or token reached a log.
func assertNoFlowSecretsLogged(t *testing.T, e *callbackEnv) {
	t.Helper()

	out := e.logs.String()
	for _, secret := range []string{e.flow.State, e.flow.Nonce, e.flow.Verifier, e.idTok, e.auth.Handle,
		url.QueryEscape(e.flow.State), "the-code", "secret-corp"} {
		if secret != "" {
			assert.NotContains(t, out, secret)
		}
	}
}

// tokenRequest is what the test provider's token endpoint received.
type tokenRequest struct {
	form   url.Values
	header http.Header
}

// recordTokenRequests makes p's token endpoint answer status and body, and
// returns a function reporting the last request it received.
func recordTokenRequests(t *testing.T, p *testProvider, status int, body string) func() tokenRequest {
	t.Helper()

	var (
		mu   sync.Mutex
		last tokenRequest
	)
	p.SetTokenResponse(func(r *http.Request) (int, string) {
		err := r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			last = tokenRequest{form: r.PostForm, header: r.Header.Clone()}
		}
		return status, body
	})

	return func() tokenRequest {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

func TestExchange(t *testing.T) {
	t.Parallel()

	const (
		code     = "the-code"
		verifier = "the-verifier"
		idToken  = "header.payload.signature"
		redirect = "https://app.example/login/oauth2/callback/"
	)
	okBody := `{"access_token":"at-secret","refresh_token":"rt-secret","token_type":"Bearer","id_token":"` + idToken + `"}`
	longTail := "TAIL-BEYOND-THE-BOUND"

	type testCase struct {
		name     string
		provider string
		status   int
		body     string
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, got string, err error, req tokenRequest, logs string)
	}

	cases := []testCase{
		{
			name: "client_secret_post sends credentials in the form", provider: "corp",
			status: http.StatusOK, body: okBody,
			assert: func(t *testing.T, got string, err error, req tokenRequest, _ string) {
				require.NoError(t, err)
				assert.Equal(t, idToken, got)
				assert.Equal(t, url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"redirect_uri":  {redirect + "corp"},
					"code_verifier": {verifier},
					"client_id":     {"client-corp"},
					"client_secret": {"secret-corp"},
				}, req.form)
				assert.Empty(t, req.header.Get("Authorization"))
			},
		},
		{
			name: "client_secret_basic sends a Basic header and no secret field", provider: "basic",
			status: http.StatusOK, body: okBody,
			assert: func(t *testing.T, got string, err error, req tokenRequest, _ string) {
				require.NoError(t, err)
				assert.Equal(t, idToken, got)
				want := "Basic " + base64.StdEncoding.EncodeToString(
					[]byte(url.QueryEscape("client:basic")+":"+url.QueryEscape("s3cr t/+%")))
				assert.Equal(t, want, req.header.Get("Authorization"))
				assert.False(t, req.form.Has("client_secret"))
				assert.False(t, req.form.Has("client_id"))
				assert.Equal(t, code, req.form.Get("code"))
				assert.Equal(t, verifier, req.form.Get("code_verifier"))
				assert.Equal(t, "authorization_code", req.form.Get("grant_type"))
				assert.Equal(t, redirect+"basic", req.form.Get("redirect_uri"))
			},
		},
		{
			name: "invalid_grant is a provider failure that hides the description", provider: "corp",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","error_description":"code reused by 203.0.113.9"}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, logs string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
				assert.NotContains(t, err.Error(), "203.0.113.9")
				assert.NotContains(t, err.Error(), "invalid_grant")
				assert.Contains(t, logs, "203.0.113.9", "the provider's answer is logged")
				assert.Contains(t, logs, "level=WARN")
			},
		},
		{
			name: "a long error body is logged truncated", provider: "corp",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","error_description":"` + strings.Repeat("x", 300) + longTail + `"}`,
			assert: func(t *testing.T, _ string, err error, _ tokenRequest, logs string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Contains(t, logs, "xxxxxxxx")
				assert.NotContains(t, logs, longTail)
				assert.NotContains(t, err.Error(), "xxxxxxxx")
			},
		},
		{
			name: "a response without an ID token is a provider failure", provider: "corp",
			status: http.StatusOK, body: `{"access_token":"at-secret","token_type":"Bearer"}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
				assert.NotContains(t, err.Error(), "at-secret")
			},
		},
		{
			name: "an empty ID token is a provider failure", provider: "corp",
			status: http.StatusOK, body: `{"id_token":""}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
			},
		},
		{
			name: "a malformed JSON response is a provider failure", provider: "corp",
			status: http.StatusOK, body: `<html>gateway says 203.0.113.9</html>`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
				assert.NotContains(t, err.Error(), "203.0.113.9")
			},
		},
		{
			name: "a success status with an error member is a provider failure", provider: "corp",
			status: http.StatusOK, body: `{"error":"server_error","id_token":"` + idToken + `"}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
			},
		},
		{
			name: "the provider's access and refresh tokens are discarded", provider: "corp",
			status: http.StatusOK, body: okBody,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, logs string) {
				require.NoError(t, err)
				assert.Equal(t, idToken, got, "the raw ID token is the only output")
				assert.NotContains(t, logs, "at-secret")
				assert.NotContains(t, logs, "rt-secret")
			},
		},
		{
			name: "a canceled context sends nothing usable", provider: "corp",
			status: http.StatusOK, body: okBody,
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			basic := p.Provider("basic")
			basic.ClientID = "client:basic"
			basic.ClientSecret = "s3cr t/+%"
			basic.ClientAuth = oidc.ClientSecretBasic
			reg, err := oidc.NewRegistry(p.Provider("corp"), basic)
			require.NoError(t, err)

			var logs bytes.Buffer
			m, err := oidc.NewRelyingParty(reg, stubBroker{},
				oidc.WithOutboundClient(p.Outbound(t)), oidc.WithLogger(testTextLogger(&logs)))
			require.NoError(t, err)
			// Discovery first, on a live context, so the canceled-context row
			// reaches the exchange itself.
			_, err = oidc.MetadataForTest(m, t.Context(), tc.provider)
			require.NoError(t, err)

			last := recordTokenRequests(t, p, tc.status, tc.body)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			got, err := oidc.ExchangeForTest(ctx, m, tc.provider, code, verifier)

			out := logs.String()
			for _, secret := range []string{code, verifier, "secret-corp", "s3cr t/+%"} {
				assert.NotContains(t, out, secret, "no credential reaches a log")
			}
			tc.assert(t, got, err, last(), out)
		})
	}
}
