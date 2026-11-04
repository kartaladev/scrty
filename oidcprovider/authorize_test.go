package oidcprovider_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	authzRedirect  = "https://rp.example.com/cb"
	authzChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	authzState     = "xyz"
	publishedKid   = "published"
)

// authzClients are the registrations the rows ask as.
func authzClients() []oidcprovider.Client {
	secret := []byte("0123456789abcdef0123456789abcdef")

	return []oidcprovider.Client{
		{
			ID:           "billing-web",
			Name:         "Billing",
			Type:         oidcprovider.Confidential,
			Secret:       secret,
			RedirectURIs: []string{authzRedirect},
			Scopes:       []string{"openid", "profile", "email", "offline_access", "api.read"},
			Resources:    []string{"https://api.example.com", "https://data.example.com", "https://frag.example.com#x", "/relative"},
			GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		},
		{
			ID:           "code-only",
			Type:         oidcprovider.Confidential,
			Secret:       secret,
			RedirectURIs: []string{"https://code-only.example.com/cb"},
			Scopes:       []string{"openid", "profile"},
		},
		{
			ID:           "nonce-web",
			Type:         oidcprovider.Confidential,
			Secret:       secret,
			PKCE:         oidcprovider.PKCEOrNonce,
			RedirectURIs: []string{"https://nonce.example.com/cb"},
			Scopes:       []string{"openid", "api.read"},
		},
		{
			ID:           "tenant-web",
			Type:         oidcprovider.Confidential,
			Secret:       secret,
			RedirectURIs: []string{"https://rp.example.com/cb?tenant=a"},
			Scopes:       []string{"openid"},
		},
		{
			ID:           "public-spa",
			Type:         oidcprovider.Public,
			RedirectURIs: []string{"https://spa.example.com/cb"},
			Scopes:       []string{"openid"},
		},
		{
			ID:              "native-app",
			Type:            oidcprovider.Public,
			ApplicationType: oidcprovider.Native,
			RedirectURIs:    []string{"http://127.0.0.1/cb"},
			Scopes:          []string{"openid"},
		},
	}
}

// authzParams is a request every check accepts, for rows about one thing.
func authzParams() url.Values {
	return url.Values{
		"client_id":             {"billing-web"},
		"redirect_uri":          {authzRedirect},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {authzState},
		"code_challenge":        {authzChallenge},
		"code_challenge_method": {"S256"},
	}
}

// asClient makes a row ask as another client, at its one redirect URI.
func asClient(v url.Values, id, redirectURI string) {
	v.Set("client_id", id)
	v.Set("redirect_uri", redirectURI)
}

// authzFixture holds what a row's request did: a record of everything parked, so a
// refusal can be seen to park nothing.
type authzFixture struct {
	parked []*oidcprovider.PendingRequest
}

func newAuthzProvider(t *testing.T, keys signingkey.KeySource, deps func(*testing.T, *oidcprovider.Deps), opts ...oidcprovider.Option) (*oidcprovider.Provider, *authzFixture) {
	t.Helper()

	f := &authzFixture{}
	store := NewMockPendingRequestStore(gomock.NewController(t))
	store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *oidcprovider.PendingRequest) error {
			f.parked = append(f.parked, r)

			return nil
		},
	).AnyTimes()

	d := oidcprovider.Deps{
		Issuer:       issuer,
		Clients:      authzClients(),
		Keys:         keys,
		Users:        users(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}
	if deps != nil {
		deps(t, &d)
	}
	p, err := oidcprovider.New(d, append([]oidcprovider.Option{oidcprovider.WithPendingRequestStore(store)}, opts...)...)
	require.NoError(t, err)

	return p, f
}

type authzAssert = func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error)

// unredirectable is the refusal that must never reach a browser as a redirect.
func unredirectable(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()
	require.ErrorIs(t, err, oidcprovider.ErrInvalidAuthorization)
	assert.Equal(t, oidcprovider.ErrInvalidAuthorization.Error(), err.Error(), "the text holds no request value")
	assert.Empty(t, res.Location)
	assert.Empty(t, res.FlowSecret)
	assert.Empty(t, f.parked)
}

// redirected is a refusal answered at redirectURI, with state as given and no other
// parameter than the protocol's.
func redirected(redirectURI, code, state string) authzAssert {
	return func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		loc, parseErr := url.Parse(res.Location)
		require.NoError(t, parseErr)
		target := strings.SplitN(redirectURI, "?", 2)[0]
		assert.Equal(t, target, loc.Scheme+"://"+loc.Host+loc.Path)

		q := loc.Query()
		assert.Equal(t, []string{code}, q["error"])
		assert.Equal(t, []string{issuer}, q["iss"])
		if state == "" {
			assert.NotContains(t, q, "state")
		} else {
			assert.Equal(t, []string{state}, q["state"])
		}
		assert.NotContains(t, q, "error_description")
		assert.NotContains(t, q, "error_uri")
		assert.NotContains(t, q, "code")
		assert.Empty(t, res.FlowSecret)
		assert.Empty(t, f.parked)
	}
}

func refused(code string) authzAssert { return redirected(authzRedirect, code, authzState) }

// refusedUnreflected is a refusal whose state is itself at fault, so it is not sent back.
func refusedUnreflected(code string) authzAssert { return redirected(authzRedirect, code, "") }

// proceeds parks the request, and hands the parked record to check.
func proceeds(check func(t *testing.T, r *oidcprovider.PendingRequest)) authzAssert {
	return func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		require.Len(t, f.parked, 1)
		assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?req=rh."), "the login URL with the handle")
		assert.NotEmpty(t, res.FlowSecret)
		if check != nil {
			check(t, f.parked[0])
		}
	}
}

func set(name, value string) func(url.Values) {
	return func(v url.Values) { v.Set(name, value) }
}

func without(name string) func(url.Values) {
	return func(v url.Values) { v.Del(name) }
}

func repeated(name, value string) func(url.Values) {
	return func(v url.Values) { v.Add(name, value) }
}

// hintFixture is a key source publishing one key, and what signs under it.
type hintFixture struct {
	private *rsa.PrivateKey
	foreign *rsa.PrivateKey
	keys    signingkey.KeySource
}

func newHintFixture(t *testing.T) *hintFixture {
	t.Helper()

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keys := NewMockKeySource(gomock.NewController(t))
	keys.EXPECT().VerificationKeys(gomock.Any()).Return([]signingkey.PublicKey{
		{Kid: publishedKid, Alg: signingkey.RS256, Key: &private.PublicKey},
	}, nil).AnyTimes()
	keys.EXPECT().Signer(gomock.Any(), gomock.Any()).Return(publishedKid, private, nil).AnyTimes()

	return &hintFixture{private: private, foreign: foreign, keys: keys}
}

func hintClaims(overrides map[string]any) map[string]any {
	claims := map[string]any{
		"iss": issuer,
		"sub": "u-1",
		"aud": "billing-web",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)

			continue
		}
		claims[name] = value
	}

	return claims
}

// issued is a token as the provider's own issuer writes it, at the given time.
func (h *hintFixture) issued(t *testing.T, typ, iss string, at time.Time) string {
	t.Helper()

	issuing, err := token.NewIssuer(h.keys, signingkey.RS256, iss, token.WithClock(clockwork.NewFakeClockAt(at)))
	require.NoError(t, err)
	raw, err := issuing.Issue(t.Context(), token.Issue{
		Type:     typ,
		Subject:  "u-1",
		ID:       "j-1",
		Audience: []string{"billing-web"},
	})
	require.NoError(t, err)

	return raw
}

// roundTripFunc is a transport written as a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestValidateAuthorizationRequest(t *testing.T) {
	t.Parallel()

	hints := newHintFixture(t)
	idHeader := map[string]any{"kid": publishedKid, "typ": "JWT"}

	publicDER, err := x509.MarshalPKIXPublicKey(&hints.private.PublicKey)
	require.NoError(t, err)

	// requestURIHits counts what the outbound client sends. The URL a row names is https,
	// which the client allows, so any fetch of it reaches this transport and is seen.
	var requestURIHits atomic.Int32
	watching := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requestURIHits.Add(1)

		return nil, errors.New("request_uri must never be fetched")
	})}
	watchedOutbound, err := outbound.New(outbound.WithHTTPClient(watching))
	require.NoError(t, err)

	const big = 1 << 20
	// bigHint is a genuine hint carrying n bytes of padding in a claim.
	bigHint := func(n int) string {
		return signed(t, "RS256", hints.private, idHeader, hintClaims(map[string]any{"groups": strings.Repeat("g", n)}))
	}
	over := func(n int) string { return strings.Repeat("a", n+1) }

	type testCase struct {
		name   string
		deps   func(*testing.T, *oidcprovider.Deps)
		opts   []oidcprovider.Option
		params func(url.Values)
		ctx    func(context.Context) context.Context
		assert authzAssert
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	// emptyRegistry is a registry any call to which fails the row.
	emptyRegistry := func(t *testing.T, d *oidcprovider.Deps) {
		t.Helper()
		d.Clients, d.Registry = nil, NewMockClientRegistry(gomock.NewController(t))
	}
	// registerRedirect adds a URI to billing-web's registered ones.
	registerRedirect := func(uri string) func(*testing.T, *oidcprovider.Deps) {
		return func(t *testing.T, d *oidcprovider.Deps) {
			t.Helper()
			i := slices.IndexFunc(d.Clients, func(c oidcprovider.Client) bool { return c.ID == "billing-web" })
			require.GreaterOrEqual(t, i, 0)
			d.Clients[i].RedirectURIs = append(slices.Clone(d.Clients[i].RedirectURIs), uri)
		}
	}
	require.Greater(t, len(bigHint(3<<10)), 4096, "the 5 KiB row must sit past the general bound")
	require.Less(t, len(bigHint(3<<10)), 8192)
	require.Greater(t, len(bigHint(8<<10)), 8192)
	// jsonForm is the JSON serialization of a compact token, which signs the same.
	jsonForm := func(compact string) string {
		parts := strings.Split(compact, ".")

		return `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`
	}

	cases := []testCase{
		// The client and redirect URI come first, and nothing else can turn their
		// refusal into a redirect.
		{name: "unknown client", params: set("client_id", "nobody"), assert: unredirectable},
		{name: "client_id missing", params: without("client_id"), assert: unredirectable},
		{name: "client_id empty counts as missing", params: set("client_id", ""), assert: unredirectable},
		{name: "client_id repeated, one registered", params: repeated("client_id", "billing-web"), assert: unredirectable},
		{name: "client_id repeated, one empty", params: repeated("client_id", ""), assert: unredirectable},
		{name: "client_id not printable", params: set("client_id", "billing\x00web"), assert: unredirectable},
		{name: "client_id over 4 KiB", params: set("client_id", over(4096)), assert: unredirectable},
		{name: "redirect_uri missing, though the client registered one", params: without("redirect_uri"), assert: unredirectable},
		{name: "client_id over 4 KiB reaches no registry", deps: emptyRegistry, params: set("client_id", over(4096)), assert: unredirectable},
		{name: "redirect_uri over 4 KiB reaches no registry", deps: emptyRegistry, params: set("redirect_uri", authzRedirect+"?"+over(4096)), assert: unredirectable},
		{name: "a repeated client_id reaches no registry", deps: emptyRegistry, params: repeated("client_id", "billing-web"), assert: unredirectable},
		{name: "a repeated redirect_uri reaches no registry", deps: emptyRegistry, params: repeated("redirect_uri", authzRedirect), assert: unredirectable},
		{name: "redirect_uri empty counts as missing", params: set("redirect_uri", ""), assert: unredirectable},
		{name: "redirect_uri repeated, both registered", params: repeated("redirect_uri", authzRedirect), assert: unredirectable},
		{name: "redirect_uri repeated, one empty", params: repeated("redirect_uri", ""), assert: unredirectable},
		{name: "redirect_uri unregistered", params: set("redirect_uri", "https://evil.example.com/cb"), assert: unredirectable},
		{name: "redirect_uri with a trailing slash", params: set("redirect_uri", authzRedirect+"/"), assert: unredirectable},
		{name: "redirect_uri with a query", params: set("redirect_uri", authzRedirect+"?x=1"), assert: unredirectable},
		{name: "redirect_uri with a fragment", params: set("redirect_uri", authzRedirect+"#x"), assert: unredirectable},
		{name: "redirect_uri in another case", params: set("redirect_uri", "https://RP.example.com/cb"), assert: unredirectable},
		{name: "redirect_uri with user information", params: set("redirect_uri", "https://rp.example.com@evil.example.com/cb"), assert: unredirectable},
		{name: "redirect_uri of another client", params: set("redirect_uri", "https://spa.example.com/cb"), assert: unredirectable},
		{name: "redirect_uri dropping the registered query", params: func(v url.Values) { asClient(v, "tenant-web", authzRedirect) }, assert: unredirectable},
		{name: "redirect_uri over 4 KiB", params: set("redirect_uri", authzRedirect+"?"+over(4096)), assert: unredirectable},
		{
			name: "unknown client, with every other parameter bad too",
			params: func(v url.Values) {
				v.Set("client_id", "nobody")
				v.Set("response_type", "token")
				v.Set("scope", "admin")
				v.Set("state", strings.Repeat("s", big))
				v.Set("prompt", "none login")
				v.Set("max_age", "-1")
				v.Set("code_challenge_method", "plain")
				v.Set("request_uri", "https://rp.example.com/req/1")
				v.Add("scope", "openid")
			},
			assert: unredirectable,
		},
		{
			name: "unregistered redirect URI, with every other parameter bad too",
			params: func(v url.Values) {
				v.Set("redirect_uri", "https://evil.example.com/cb")
				v.Set("response_type", "token")
				v.Del("scope")
				v.Set("request", "x")
				v.Set("response_mode", "form_post")
				v.Set("id_token_hint", "not-a-token")
			},
			assert: unredirectable,
		},
		{
			name: "a loopback name a native client did not register",
			params: func(v url.Values) {
				asClient(v, "native-app", "http://127.0.0.1.evil.example.com/cb")
			},
			assert: unredirectable,
		},
		{
			name: "a registry outage is no refusal, and no redirect",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				registry := NewMockClientRegistry(gomock.NewController(t))
				registry.EXPECT().Client(gomock.Any(), "billing-web").Return(nil, errors.New("registry secret text"))
				d.Clients, d.Registry = nil, registry
			},
			params: func(url.Values) {},
			assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				require.NotErrorIs(t, err, oidcprovider.ErrInvalidAuthorization)
				assert.NotContains(t, err.Error(), "registry secret text")
				assert.Empty(t, res.Location)
				assert.Empty(t, f.parked)
			},
		},
		{
			name: "a caller who left is not reported as an outage",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				registry := NewMockClientRegistry(gomock.NewController(t))
				registry.EXPECT().Client(gomock.Any(), "billing-web").DoAndReturn(
					func(ctx context.Context, _ string) (*oidcprovider.RegisteredClient, error) {
						return nil, ctx.Err()
					},
				)
				d.Clients, d.Registry = nil, registry
			},
			params: func(url.Values) {},
			ctx:    cancelled,
			assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Empty(t, res.Location)
				assert.Empty(t, f.parked)
			},
		},

		// response_type and response_mode.
		{name: "code request accepted", params: func(url.Values) {}, assert: proceeds(nil)},
		{name: "implicit flow", params: set("response_type", "id_token token"), assert: refused(oidcprovider.CodeUnsupportedResponseType)},
		{name: "token alone", params: set("response_type", "token"), assert: refused(oidcprovider.CodeUnsupportedResponseType)},
		{name: "hybrid flow", params: set("response_type", "code id_token"), assert: refused(oidcprovider.CodeUnsupportedResponseType)},
		{name: "response_type missing", params: without("response_type"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "response_type empty counts as missing", params: set("response_type", ""), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "response_type repeated", params: repeated("response_type", "code"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "response_mode form_post", params: set("response_mode", "form_post"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "response_mode fragment", params: set("response_mode", "fragment"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "response_mode query", params: set("response_mode", "query"), assert: proceeds(nil)},
		{name: "response_mode empty counts as omitted", params: set("response_mode", ""), assert: proceeds(nil)},

		// Repeated and empty parameters.
		{name: "scope repeated", params: repeated("scope", "openid"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "scope repeated, one empty", params: repeated("scope", ""), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "nonce repeated", params: func(v url.Values) { v["nonce"] = []string{"a", "b"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "code_challenge repeated", params: repeated("code_challenge", authzChallenge), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "code_challenge_method repeated", params: repeated("code_challenge_method", "plain"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "prompt repeated", params: func(v url.Values) { v["prompt"] = []string{"login", "login"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age repeated", params: func(v url.Values) { v["max_age"] = []string{"1", "1"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "response_mode repeated", params: func(v url.Values) { v["response_mode"] = []string{"query", "query"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "login_hint repeated", params: func(v url.Values) { v["login_hint"] = []string{"a", "b"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "id_token_hint repeated", params: func(v url.Values) { v["id_token_hint"] = []string{"a", "b"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt repeated", params: func(v url.Values) { v["dpop_jkt"] = []string{"a", "b"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "request_uri repeated", params: func(v url.Values) { v["request_uri"] = []string{"a", "b"} }, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "state repeated is refused, with neither value sent back", params: repeated("state", "other"), assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
		{name: "an unknown parameter repeated is ignored", params: func(v url.Values) { v["unknown"] = []string{"a", "b"} }, assert: proceeds(nil)},
		{name: "resource repeated is allowed", params: func(v url.Values) {
			v["resource"] = []string{"https://api.example.com", "https://data.example.com"}
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"https://api.example.com", "https://data.example.com"}, r.Resources)
		})},
		{name: "state= counts as omitted", params: set("state", ""), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.State)
		})},
		{name: "state= counts as omitted on an error too", params: func(v url.Values) {
			v.Set("state", "")
			v.Del("scope")
		}, assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
		{name: "no state at all", params: func(v url.Values) {
			v.Del("state")
			v.Del("scope")
		}, assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
		{name: "nonce= counts as omitted", params: set("nonce", ""), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.Nonce)
		})},

		// The string bounds.
		{name: "state of 1 MiB", params: set("state", strings.Repeat("s", big)), assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
		{name: "state of 5 KiB", params: set("state", strings.Repeat("s", 5<<10)), assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
		{name: "state past the bound by one", params: set("state", over(2048)), assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
		{name: "state at the bound", params: set("state", strings.Repeat("a", 2048)), assert: proceeds(nil)},
		{name: "nonce past the bound", params: set("nonce", over(2048)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "nonce at the bound", params: set("nonce", strings.Repeat("a", 2048)), assert: proceeds(nil)},
		{name: "login_hint past the bound", params: set("login_hint", over(2048)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "login_hint at the bound", params: set("login_hint", strings.Repeat("a", 2048)), assert: proceeds(nil)},
		{name: "scope past the bound", params: set("scope", "openid"+strings.Repeat(" ", 4091)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "scope at the bound", params: set("scope", "openid"+strings.Repeat(" ", 4090)), assert: proceeds(nil)},
		{name: "resource past the bound", params: set("resource", "https://api.example.com/"+over(2048)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "a resource past the bound beside a good one", params: func(v url.Values) {
			v["resource"] = []string{"https://api.example.com", "https://api.example.com/" + over(2048)}
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "11 resource values", params: func(v url.Values) {
			for range 11 {
				v.Add("resource", "https://api.example.com")
			}
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "10 resource values", params: func(v url.Values) {
			for range 10 {
				v.Add("resource", "https://api.example.com")
			}
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"https://api.example.com"}, r.Resources, "a repeat is kept once")
		})},
		{name: "ui_locales over 4 KiB", params: set("ui_locales", over(4096)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "claims_locales over 4 KiB", params: set("claims_locales", over(4096)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "acr_values over 4 KiB", params: set("acr_values", over(4096)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "display over 4 KiB", params: set("display", over(4096)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "prompt over 4 KiB", params: set("prompt", over(4096)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age over 4 KiB", params: set("max_age", over(4096)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "id_token_hint over 8 KiB", params: set("id_token_hint", over(8192)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "a genuine id_token_hint of 5 KiB is accepted", params: set("id_token_hint", bigHint(3<<10)), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, "u-1", r.IDTokenHintSubject)
		})},
		{name: "a genuine id_token_hint past the bound is refused unverified", deps: func(t *testing.T, d *oidcprovider.Deps) {
			t.Helper()
			d.Keys = plainKeys(t)
		}, params: set("id_token_hint", bigHint(8<<10)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "a consumer widens the id_token_hint bound", opts: []oidcprovider.Option{oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{IDTokenHint: 16 << 10})},
			params: set("id_token_hint", bigHint(8<<10)), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
				t.Helper()
				assert.Equal(t, "u-1", r.IDTokenHintSubject)
			})},
		{name: "dpop_jkt over 4 KiB", params: set("dpop_jkt", over(4096)), opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "an unknown parameter over 4 KiB is ignored", params: set("unknown", over(4096)), assert: proceeds(nil)},
		{
			name:   "a consumer widens a bound",
			opts:   []oidcprovider.Option{oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{State: 3 << 10})},
			params: set("state", strings.Repeat("s", 3<<10)),
			assert: proceeds(nil),
		},
		{
			name:   "a consumer narrows a bound",
			opts:   []oidcprovider.Option{oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{Nonce: 4})},
			params: set("nonce", "12345"),
			assert: refused(oidcprovider.CodeInvalidRequest),
		},

		// PKCE.
		{name: "challenge missing, confidential client", params: func(v url.Values) {
			v.Del("code_challenge")
			v.Del("code_challenge_method")
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "challenge missing, a nonce does not do on the default", params: func(v url.Values) {
			v.Del("code_challenge")
			v.Del("code_challenge_method")
			v.Set("nonce", "n-1")
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "challenge missing, public client", params: func(v url.Values) {
			asClient(v, "public-spa", "https://spa.example.com/cb")
			v.Set("scope", "openid")
			v.Del("code_challenge")
			v.Del("code_challenge_method")
		}, assert: redirected("https://spa.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},
		{name: "plain method", params: set("code_challenge_method", "plain"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "another method", params: set("code_challenge_method", "S512"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "method in another case", params: set("code_challenge_method", "s256"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "method missing is not defaulted to plain", params: without("code_challenge_method"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "method empty counts as missing", params: set("code_challenge_method", ""), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "method given without a challenge", params: without("code_challenge"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "challenge of 42 characters", params: set("code_challenge", strings.Repeat("a", 42)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "challenge of 129 characters", params: set("code_challenge", strings.Repeat("a", 129)), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "challenge of 43 characters", params: set("code_challenge", strings.Repeat("a", 43)), assert: proceeds(nil)},
		{name: "challenge of 128 characters", params: set("code_challenge", strings.Repeat("a", 128)), assert: proceeds(nil)},
		{name: "challenge from outside the unreserved set", params: set("code_challenge", strings.Repeat("a", 42)+"+"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "challenge of every unreserved kind", params: set("code_challenge", "AZaz09-._~"+strings.Repeat("a", 33)), assert: proceeds(nil)},
		{name: "the challenge is kept", params: func(url.Values) {}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, authzChallenge, r.Challenge)
		})},

		// PKCE-or-nonce.
		{name: "PKCEOrNonce: a nonce and no challenge", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "openid")
			v.Set("nonce", "n-1")
			v.Del("code_challenge")
			v.Del("code_challenge_method")
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, "n-1", r.Nonce)
			assert.Empty(t, r.Challenge)
		})},
		{name: "PKCEOrNonce: a challenge and no nonce", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "openid")
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, authzChallenge, r.Challenge)
		})},
		{name: "PKCEOrNonce: neither", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "openid")
			v.Del("code_challenge")
			v.Del("code_challenge_method")
		}, assert: redirected("https://nonce.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},
		{name: "PKCEOrNonce: an empty nonce is no nonce", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "openid")
			v.Set("nonce", "")
			v.Del("code_challenge")
			v.Del("code_challenge_method")
		}, assert: redirected("https://nonce.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},
		{name: "PKCEOrNonce: plain is refused whatever else it sends", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "openid")
			v.Set("nonce", "n-1")
			v.Set("code_challenge_method", "plain")
		}, assert: redirected("https://nonce.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},
		{name: "PKCEOrNonce: a method without a challenge is refused beside a nonce", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "openid")
			v.Set("nonce", "n-1")
			v.Del("code_challenge")
		}, assert: redirected("https://nonce.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},
		{name: "PKCEOrNonce: a nonce protects nothing where no ID token is issued", params: func(v url.Values) {
			asClient(v, "nonce-web", "https://nonce.example.com/cb")
			v.Set("scope", "api.read")
			v.Set("nonce", "n-1")
			v.Del("code_challenge")
			v.Del("code_challenge_method")
		}, assert: redirected("https://nonce.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},

		// Scopes.
		{name: "scope missing", params: without("scope"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "scope empty counts as missing", params: set("scope", ""), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "scope of spaces holds nothing", params: set("scope", "   "), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "scope not allowed", params: set("scope", "openid admin"), assert: refused(oidcprovider.CodeInvalidScope)},
		{name: "scope in another case is not allowed", params: set("scope", "OpenID"), assert: refused(oidcprovider.CodeInvalidScope)},
		{name: "scope split by a tab is one unknown value", params: set("scope", "openid\tprofile"), assert: refused(oidcprovider.CodeInvalidScope)},
		{name: "a plain OAuth request proceeds", params: set("scope", "api.read"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"api.read"}, r.Scopes)
		})},
		{name: "messy scope", params: set("scope", "openid  openid profile"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"openid", "profile"}, r.Scopes)
		})},
		{name: "offline_access kept for a client with the refresh grant", params: set("scope", "openid offline_access"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"openid", "offline_access"}, r.Scopes)
		})},
		{name: "offline_access dropped without the refresh grant", params: func(v url.Values) {
			asClient(v, "code-only", "https://code-only.example.com/cb")
			v.Set("scope", "openid offline_access")
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"openid"}, r.Scopes)
		})},
		{name: "offline_access alone leaves no scope", params: func(v url.Values) {
			asClient(v, "code-only", "https://code-only.example.com/cb")
			v.Set("scope", "offline_access")
		}, assert: redirected("https://code-only.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)},

		// The grant types.
		{name: "a client without the authorization_code grant", deps: func(_ *testing.T, d *oidcprovider.Deps) {
			d.Clients = append(d.Clients, oidcprovider.Client{
				ID: "refresh-only", Type: oidcprovider.Confidential,
				Secret:       []byte("0123456789abcdef0123456789abcdef"),
				RedirectURIs: []string{"https://ro.example.com/cb"},
				Scopes:       []string{"openid"},
				GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantRefreshToken},
			})
		}, params: func(v url.Values) {
			asClient(v, "refresh-only", "https://ro.example.com/cb")
			v.Set("scope", "openid")
		}, assert: redirected("https://ro.example.com/cb", oidcprovider.CodeUnauthorizedClient, authzState)},

		// Resources.
		{name: "resource not allowed", params: set("resource", "https://other.example.com"), assert: refused(oidcprovider.CodeInvalidTarget)},
		{name: "resource with a fragment", params: set("resource", "https://api.example.com#x"), assert: refused(oidcprovider.CodeInvalidTarget)},
		{name: "resource with an empty fragment", params: set("resource", "https://api.example.com#"), assert: refused(oidcprovider.CodeInvalidTarget)},
		{name: "resource with a fragment, though the client lists it", params: set("resource", "https://frag.example.com#x"), assert: refused(oidcprovider.CodeInvalidTarget)},
		{name: "resource not absolute, though the client lists it", params: set("resource", "/relative"), assert: refused(oidcprovider.CodeInvalidTarget)},
		{name: "resource allowed", params: set("resource", "https://api.example.com"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"https://api.example.com"}, r.Resources)
		})},
		{name: "resource= counts as omitted", params: set("resource", ""), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.Resources)
		})},
		{name: "one bad resource among good ones", params: func(v url.Values) {
			v["resource"] = []string{"https://api.example.com", "https://other.example.com"}
		}, assert: refused(oidcprovider.CodeInvalidTarget)},

		// Request objects.
		{name: "request given", params: set("request", "eyJhbGciOiJub25lIn0.e30."), assert: refused(oidcprovider.CodeRequestNotSupported)},
		{name: "request= counts as omitted", params: set("request", ""), assert: proceeds(nil)},
		{name: "request_uri given, and never fetched", opts: []oidcprovider.Option{oidcprovider.WithOutbound(watchedOutbound)}, params: set("request_uri", "https://rp.example.com/req/1"), assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
			t.Helper()
			refused(oidcprovider.CodeRequestURINotSupported)(t, f, res, err)
			assert.Zero(t, requestURIHits.Load())
		}},
		{name: "request_uri= counts as omitted", params: set("request_uri", ""), assert: proceeds(nil)},

		// prompt.
		{name: "prompt=none, with no browser session yet", params: set("prompt", "none"), assert: refused(oidcprovider.CodeLoginRequired)},
		{name: "prompt=none login", params: set("prompt", "none login"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "prompt=login none", params: set("prompt", "login none"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "prompt=none with a value the provider does not define", params: set("prompt", "none create"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "prompt=login consent", params: set("prompt", "login consent"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"login", "consent"}, r.Prompt)
		})},
		{name: "display and an unknown prompt value", params: func(v url.Values) {
			v.Set("display", "popup")
			v.Set("prompt", "create")
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.Prompt)
		})},
		{name: "an unknown prompt value beside a known one", params: set("prompt", "create login"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"login"}, r.Prompt)
		})},
		{name: "prompt=select_account is kept", params: set("prompt", "select_account"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, []string{"select_account"}, r.Prompt)
		})},
		{name: "prompt= counts as omitted", params: set("prompt", ""), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.Prompt)
		})},

		// max_age.
		{name: "max_age negative", params: set("max_age", "-1"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age negative zero", params: set("max_age", "-0"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age with a sign", params: set("max_age", "+5"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age not numeric", params: set("max_age", "abc"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age fractional", params: set("max_age", "1.5"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age with a space", params: set("max_age", " 5"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age in hex", params: set("max_age", "0x10"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age in other digits", params: set("max_age", "٣"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age past int64", params: set("max_age", "9223372036854775808"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age past int32", params: set("max_age", "2147483648"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "max_age at int32", params: set("max_age", "2147483647"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			require.NotNil(t, r.MaxAge)
			assert.Equal(t, 2147483647, *r.MaxAge)
		})},
		{name: "max_age=0 is kept apart from none", params: set("max_age", "0"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			require.NotNil(t, r.MaxAge)
			assert.Zero(t, *r.MaxAge)
		})},
		{name: "max_age=300", params: set("max_age", "300"), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			require.NotNil(t, r.MaxAge)
			assert.Equal(t, 300, *r.MaxAge)
		})},
		{name: "max_age= counts as omitted", params: set("max_age", ""), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Nil(t, r.MaxAge)
		})},

		// id_token_hint.
		{name: "hint from this provider", params: set("id_token_hint", hints.issued(t, token.TypeIDToken, issuer, time.Now())), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, "u-1", r.IDTokenHintSubject)
		})},
		{name: "expired hint from this provider", params: set("id_token_hint", hints.issued(t, token.TypeIDToken, issuer, time.Now().Add(-48*time.Hour))), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, "u-1", r.IDTokenHintSubject)
		})},
		{name: "access token as a hint", params: set("id_token_hint", hints.issued(t, token.TypeAccessToken, issuer, time.Now())), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "logout token as a hint", params: set("id_token_hint", hints.issued(t, token.TypeLogoutToken, issuer, time.Now())), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "first-party token as a hint", params: set("id_token_hint", signed(t, "RS256", hints.private, map[string]any{"kid": publishedKid, "typ": token.TypeFirstParty}, hintClaims(nil))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint declaring no type", params: set("id_token_hint", signed(t, "RS256", hints.private, map[string]any{"kid": publishedKid}, hintClaims(nil))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint signed by another key under a published kid", params: set("id_token_hint", signed(t, "RS256", hints.foreign, idHeader, hintClaims(nil))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint from another issuer", params: set("id_token_hint", hints.issued(t, token.TypeIDToken, "https://other.example.com", time.Now())), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint naming no subject", params: set("id_token_hint", signed(t, "RS256", hints.private, idHeader, hintClaims(map[string]any{"sub": nil}))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint naming no kid", params: set("id_token_hint", signed(t, "RS256", hints.private, map[string]any{"typ": "JWT"}, hintClaims(nil))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint in the JSON serialization", params: set("id_token_hint", jsonForm(signed(t, "RS256", hints.private, idHeader, hintClaims(nil)))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint in the general JSON serialization with two signatures", params: func(v url.Values) {
			parts := strings.Split(signed(t, "RS256", hints.private, idHeader, hintClaims(nil)), ".")
			second := strings.Split(signed(t, "RS256", hints.foreign, idHeader, hintClaims(nil)), ".")
			v.Set("id_token_hint", `{"payload":"`+parts[1]+`","signatures":[{"protected":"`+parts[0]+`","signature":"`+parts[2]+`"},{"protected":"`+second[0]+`","signature":"`+second[2]+`"}]}`)
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint in the general JSON serialization with one signature", params: func(v url.Values) {
			parts := strings.Split(signed(t, "RS256", hints.private, idHeader, hintClaims(nil)), ".")
			v.Set("id_token_hint", `{"payload":"`+parts[1]+`","signatures":[{"protected":"`+parts[0]+`","signature":"`+parts[2]+`"}]}`)
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint in JSON with no signatures", params: set("id_token_hint", `{"payload":"e30","signatures":[]}`), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint in JSON with an empty object", params: set("id_token_hint", `{}`), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint that is no token", params: set("id_token_hint", "not-a-token"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint under alg none", params: set("id_token_hint", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"`+publishedKid+`"}`))+"."+base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+issuer+`","sub":"u-1"}`))+"."), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint under HS256, keyed by the public key", params: set("id_token_hint", signed(t, "HS256", publicDER, idHeader, hintClaims(nil))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint under an algorithm its key does not verify", params: set("id_token_hint", signed(t, "PS256", hints.private, idHeader, hintClaims(nil))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint wrapping a token of its own", params: set("id_token_hint", signedPayload(t, "RS256", hints.private, idHeader, []byte(signed(t, "RS256", hints.private, idHeader, hintClaims(nil))))), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "hint under an unpublished kid counts as none", params: set("id_token_hint", signed(t, "RS256", hints.foreign, map[string]any{"kid": "retired", "typ": "JWT"}, hintClaims(nil))), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.IDTokenHintSubject)
		})},
		{name: "id_token_hint= counts as omitted", params: set("id_token_hint", ""), assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Empty(t, r.IDTokenHintSubject)
		})},
		{
			name: "a key source outage is no refusal, and no redirect",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys(gomock.Any()).Return(nil, errors.New("key service secret text"))
				d.Keys = keys
			},
			params: set("id_token_hint", signed(t, "RS256", hints.private, idHeader, hintClaims(nil))),
			assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotContains(t, err.Error(), "key service secret text")
				assert.Empty(t, res.Location)
				assert.Empty(t, f.parked)
			},
		},
		{
			name: "a published key of no usable type is an outage, not a refusal",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys(gomock.Any()).Return([]signingkey.PublicKey{
					{Kid: publishedKid, Alg: signingkey.RS256, Key: "not a key"},
				}, nil)
				d.Keys = keys
			},
			params: set("id_token_hint", signed(t, "RS256", hints.private, idHeader, hintClaims(nil))),
			assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Empty(t, res.Location)
				assert.Empty(t, f.parked)
			},
		},
		{
			name: "a published key under no known algorithm is an outage, not a refusal",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys(gomock.Any()).Return([]signingkey.PublicKey{
					{Kid: publishedKid, Alg: "XX999", Key: &hints.private.PublicKey},
				}, nil)
				d.Keys = keys
			},
			params: set("id_token_hint", signed(t, "RS256", hints.private, idHeader, hintClaims(nil))),
			assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Empty(t, res.Location)
				assert.Empty(t, f.parked)
			},
		},
		{
			name: "a caller leaving during the key lookup is no outage",
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys(gomock.Any()).DoAndReturn(
					func(ctx context.Context) ([]signingkey.PublicKey, error) { return nil, ctx.Err() },
				)
				d.Keys = keys
			},
			params: set("id_token_hint", signed(t, "RS256", hints.private, idHeader, hintClaims(nil))),
			ctx:    cancelled,
			assert: func(t *testing.T, _ *authzFixture, _ oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
			},
		},

		// dpop_jkt.
		{name: "dpop_jkt while DPoP is off", params: set("dpop_jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt= counts as omitted while DPoP is off", params: set("dpop_jkt", ""), assert: proceeds(nil)},
		{
			name:   "a consumer turns DPoP on",
			opts:   []oidcprovider.Option{oidcprovider.WithDPoP()},
			params: set("dpop_jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
			assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
				t.Helper()
				assert.Equal(t, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", r.DPoPJKT)
			}),
		},
		{name: "dpop_jkt not base64url", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "not a thumbprint!"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt one character short", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt one character long", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4IA"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt padded", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I="), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt non-canonical in its last character", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4J"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt std alphabet", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I"), assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "dpop_jkt with a newline among 43 characters", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, params: set("dpop_jkt", "\n0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"), assert: refused(oidcprovider.CodeInvalidRequest)},

		// What is kept for the consumer's page.
		{name: "hints and locales are kept and judged by no one", params: func(v url.Values) {
			v.Set("login_hint", "ada@example.com")
			v.Set("ui_locales", "fr-CA  en")
			v.Set("claims_locales", "de")
			v.Set("acr_values", "urn:example:high urn:example:low")
			v.Set("nonce", "n-1")
		}, assert: proceeds(func(t *testing.T, r *oidcprovider.PendingRequest) {
			t.Helper()
			assert.Equal(t, "billing-web", r.ClientID)
			assert.Equal(t, authzRedirect, r.RedirectURI)
			assert.Equal(t, authzState, r.State)
			assert.Equal(t, "n-1", r.Nonce)
			assert.Equal(t, "ada@example.com", r.LoginHint)
			assert.Equal(t, []string{"fr-CA", "en"}, r.UILocales)
			assert.Equal(t, []string{"de"}, r.ClaimsLocales)
			assert.Equal(t, []string{"urn:example:high", "urn:example:low"}, r.ACRValues)
		})},

		// What the redirect carries.
		{name: "state with reserved characters comes back exact", params: func(v url.Values) {
			v.Set("state", "a&b=c #d")
			v.Del("scope")
		}, assert: redirected(authzRedirect, oidcprovider.CodeInvalidRequest, "a&b=c #d")},
		{name: "a redirect URI's own query is kept", params: func(v url.Values) {
			asClient(v, "tenant-web", "https://rp.example.com/cb?tenant=a")
			v.Del("scope")
		}, assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
			t.Helper()
			redirected("https://rp.example.com/cb", oidcprovider.CodeInvalidRequest, authzState)(t, f, res, err)
			assert.True(t, strings.HasPrefix(res.Location, "https://rp.example.com/cb?tenant=a&"), "the registered URI is kept as bytes")
			loc, parseErr := url.Parse(res.Location)
			require.NoError(t, parseErr)
			assert.Equal(t, []string{"a"}, loc.Query()["tenant"])
		}},
		{name: "a redirect URI ending in ? gets the answer straight after it", deps: registerRedirect("https://rp.example.com/cb?"), params: func(v url.Values) {
			asClient(v, "billing-web", "https://rp.example.com/cb?")
			v.Del("scope")
		}, assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(res.Location, "https://rp.example.com/cb?error="), "got %s", res.Location)
			assert.Empty(t, f.parked)
		}},
		{name: "a redirect URI ending in & gets the answer straight after it", deps: registerRedirect("https://rp.example.com/cb?tenant=a&"), params: func(v url.Values) {
			asClient(v, "billing-web", "https://rp.example.com/cb?tenant=a&")
			v.Del("scope")
		}, assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(res.Location, "https://rp.example.com/cb?tenant=a&error="), "got %s", res.Location)
			assert.Empty(t, f.parked)
		}},
		{name: "a native client is answered on the port it asked on", params: func(v url.Values) {
			asClient(v, "native-app", "http://127.0.0.1:53124/cb")
			v.Del("scope")
		}, assert: redirected("http://127.0.0.1:53124/cb", oidcprovider.CodeInvalidRequest, authzState)},

		// Which refusal is first.
		{name: "response_type before scope", params: func(v url.Values) {
			v.Set("response_type", "token")
			v.Del("scope")
		}, assert: refused(oidcprovider.CodeUnsupportedResponseType)},
		{name: "a repeat before response_type", params: func(v url.Values) {
			v.Set("response_type", "token")
			v.Add("scope", "openid")
		}, assert: refused(oidcprovider.CodeInvalidRequest)},
		{name: "scope before resource", params: func(v url.Values) {
			v.Set("scope", "admin")
			v.Set("resource", "https://other.example.com")
		}, assert: refused(oidcprovider.CodeInvalidScope)},
		{
			name: "a hint is judged last, so a bad request costs no key lookup",
			params: func(v url.Values) {
				v.Set("max_age", "-1")
				v.Set("id_token_hint", signed(t, "RS256", hints.private, idHeader, hintClaims(nil)))
			},
			deps: func(t *testing.T, d *oidcprovider.Deps) {
				t.Helper()
				d.Keys = plainKeys(t)
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
	}

	// Every string the request carries, in the two forms a text column refuses. Each is
	// refused here as the request's own fault, so a durable store never answers it 500.
	unstorable := map[string]string{"a NUL": "a\x00b", "invalid UTF-8": "a\xffb"}
	for form, value := range unstorable {
		for _, name := range []string{
			"nonce", "login_hint", "scope", "resource", "ui_locales", "claims_locales", "acr_values",
			"response_type", "response_mode", "code_challenge", "code_challenge_method", "prompt",
			"max_age", "display", "id_token_hint", "dpop_jkt", "request", "request_uri",
		} {
			cases = append(cases, testCase{
				name:   name + " holding " + form,
				opts:   []oidcprovider.Option{oidcprovider.WithDPoP()},
				params: set(name, value),
				assert: func(t *testing.T, f *authzFixture, res oidcprovider.AuthorizeResult, err error) {
					t.Helper()
					refused(oidcprovider.CodeInvalidRequest)(t, f, res, err)
					assert.NotContains(t, res.Location, url.QueryEscape(value), "the value is not echoed")
				},
			})
		}
		cases = append(cases,
			testCase{name: "state holding " + form + " is not sent back", params: set("state", value), assert: refusedUnreflected(oidcprovider.CodeInvalidRequest)},
			testCase{name: "a second resource holding " + form, params: func(v url.Values) {
				v["resource"] = []string{"https://api.example.com", value}
			}, assert: refused(oidcprovider.CodeInvalidRequest)},
			testCase{name: "client_id holding " + form, deps: emptyRegistry, params: set("client_id", value), assert: unredirectable},
			testCase{name: "redirect_uri holding " + form, params: set("redirect_uri", authzRedirect+value), assert: unredirectable},
			testCase{name: "an unknown client, with a state holding " + form, params: func(v url.Values) {
				v.Set("client_id", "nobody")
				v.Set("state", value)
			}, assert: unredirectable},
			testCase{name: "an unregistered redirect URI, with a nonce holding " + form, params: func(v url.Values) {
				v.Set("redirect_uri", "https://evil.example.com/cb")
				v.Set("nonce", value)
			}, assert: unredirectable},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			p, f := newAuthzProvider(t, hints.keys, tc.deps, tc.opts...)

			params := authzParams()
			tc.params(params)
			res, err := p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: params})

			tc.assert(t, f, res, err)
		})
	}
}

// TestValidate_SilentHint looks at validation alone, under the answer Authorize gives
// every prompt=none while it has no browser session to answer from.
func TestValidate_SilentHint(t *testing.T) {
	t.Parallel()

	hints := newHintFixture(t)
	retired := signed(t, "RS256", hints.foreign, map[string]any{"kid": "retired", "typ": "JWT"}, hintClaims(nil))
	valid := signed(t, "RS256", hints.private, map[string]any{"kid": publishedKid, "typ": "JWT"}, hintClaims(nil))

	cases := []struct {
		name   string
		params url.Values
		assert func(t *testing.T, code, subject string)
	}{
		{
			name:   "a retired key's hint with prompt=none answers login_required",
			params: url.Values{"prompt": {"none"}, "id_token_hint": {retired}},
			assert: func(t *testing.T, code, _ string) {
				t.Helper()
				assert.Equal(t, oidcprovider.CodeLoginRequired, code)
			},
		},
		{
			name:   "a retired key's hint with no prompt counts as none",
			params: url.Values{"id_token_hint": {retired}},
			assert: func(t *testing.T, code, subject string) {
				t.Helper()
				assert.Empty(t, code)
				assert.Empty(t, subject)
			},
		},
		{
			name:   "a valid hint with prompt=none passes validation",
			params: url.Values{"prompt": {"none"}, "id_token_hint": {valid}},
			assert: func(t *testing.T, code, subject string) {
				t.Helper()
				assert.Empty(t, code)
				assert.Equal(t, "u-1", subject)
			},
		},
		{
			name:   "a request refused otherwise is refused for that first",
			params: url.Values{"prompt": {"none"}, "id_token_hint": {retired}, "dpop_jkt": {"x"}},
			assert: func(t *testing.T, code, _ string) {
				t.Helper()
				assert.Equal(t, oidcprovider.CodeInvalidRequest, code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, _ := newAuthzProvider(t, hints.keys, nil)
			params := authzParams()
			for name, values := range tc.params {
				params[name] = values
			}

			code, subject := p.ValidateForTest(t.Context(), params)
			tc.assert(t, code, subject)
		})
	}
}

func TestProvider_DPoPEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, enabled bool)
	}{
		{name: "off by default", assert: func(t *testing.T, enabled bool) {
			t.Helper()
			assert.False(t, enabled)
		}},
		{name: "on when the consumer says so", opts: []oidcprovider.Option{oidcprovider.WithDPoP()}, assert: func(t *testing.T, enabled bool) {
			t.Helper()
			assert.True(t, enabled)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, _ := newAuthzProvider(t, plainKeys(t), nil, tc.opts...)
			tc.assert(t, p.DPoPEnabled())
		})
	}
}
