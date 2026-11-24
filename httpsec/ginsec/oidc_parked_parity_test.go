package ginsec_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The upstream identity provider the parked-login parity rows sign in through, and the
// provider registered for it beside one whose metadata cannot be discovered.
const (
	parkedUpstream     = "corp"
	parkedUndiscovered = "lost"
	parkedSubject      = "sub-1"
	parkedUser         = "u-1"
	parkedSecret       = "secret-corp-0123456789abcdef0123456789abcdef" //nolint:gosec // G101: a fixture secret
	parkedState        = "s-1"
)

// parkedSetup is what a parked-login parity row changes of its world.
type parkedSetup struct {
	// tokenDown makes the upstream's token endpoint answer 503.
	tokenDown bool
	// inactive makes completion's user loader answer a disabled user.
	inactive bool
	// toClient is WithOIDCFailToClient.
	toClient bool
	// lifetime replaces the parked request's lifetime.
	lifetime time.Duration
}

// parkedWorld is a provider completing federated sign-ins on the server, with the
// upstream it signs in through.
type parkedWorld struct {
	p     *oidcprovider.Provider
	chain *httpsec.Chain
}

// parkedIDToken is an HS256 ID token of the upstream at issuer for parkedSubject,
// whose nonce is nonce.
func parkedIDToken(t *testing.T, issuer, nonce string) string {
	t.Helper()

	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(b)
	}

	now := time.Now()
	signing := enc(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + enc(map[string]any{
		"iss": issuer, "aud": "app", "sub": parkedSubject, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})

	mac := hmac.New(sha256.New, []byte(parkedSecret))
	mac.Write([]byte(signing))

	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func newParkedWorld(t *testing.T, s parkedSetup) *parkedWorld {
	t.Helper()

	up := httptest.NewUnstartedServer(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if s.tokenDown || r.ParseForm() != nil {
			http.Error(w, `{"error":"temporarily_unavailable"}`, http.StatusServiceUnavailable)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "discarded", "token_type": "Bearer",
			"id_token": parkedIDToken(t, "https://"+r.Host, r.PostForm.Get("code")),
		})
	})
	up.Config.Handler = mux
	up.StartTLS()
	t.Cleanup(up.Close)

	registry, err := oidc.NewRegistry(
		oidc.Provider{
			Name: parkedUpstream, Issuer: up.URL, ClientID: "app", ClientSecret: parkedSecret,
			RedirectURL:           parityIssuer + httpsec.DefaultOIDCCallbackPath + parkedUpstream,
			AuthorizationEndpoint: up.URL + "/authorize", TokenEndpoint: up.URL + "/token",
			JWKSURI: up.URL + "/jwks", SigningAlgs: []string{"HS256"},
		},
		oidc.Provider{
			Name: parkedUndiscovered, Issuer: up.URL + "/" + parkedUndiscovered, ClientID: "app",
			ClientSecret: parkedSecret,
			RedirectURL:  parityIssuer + httpsec.DefaultOIDCCallbackPath + parkedUndiscovered,
		},
	)
	require.NoError(t, err)

	active := &identity.Details{ID: parkedUser, Username: "ada", Active: true}

	brokerUsers := NewMockUserLoader(gomock.NewController(t))
	brokerUsers.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(active, nil).AnyTimes()

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider: parkedUpstream, Issuer: up.URL, Subject: parkedSubject, UserID: parkedUser, CreatedAt: time.Now(),
	}))

	broker, err := oidc.NewBroker(links, brokerUsers)
	require.NoError(t, err)

	client, err := outbound.New(outbound.WithHTTPClient(up.Client()), outbound.WithAllowedSchemes("https", "http"))
	require.NoError(t, err)

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	rp, err := oidc.NewRelyingParty(registry, broker, oidc.WithOutboundClient(client), oidc.WithFlowStore(flows))
	require.NoError(t, err)

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	completing := active
	if s.inactive {
		completing = &identity.Details{ID: parkedUser, Username: "ada"}
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(completing, nil).AnyTimes()

	popts := []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer(), oidcprovider.WithoutBrowserSessions()}
	if s.lifetime > 0 {
		popts = append(popts, oidcprovider.WithPendingRequestLifetime(s.lifetime))
	}

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: parityIssuer,
		Clients: []oidcprovider.Client{{
			ID: parityClient, Type: oidcprovider.Confidential, Secret: []byte(paritySecret),
			RedirectURIs: []string{parityCallback}, Scopes: []string{"openid"},
			GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode},
		}},
		Keys:         keys,
		Users:        users,
		LoginURL:     parityIssuer + "/login",
		ConsentURL:   parityIssuer + "/consent",
		LogoutURL:    parityIssuer + "/logout-page",
		LoggedOutURL: parityIssuer + "/bye",
	}, popts...)
	require.NoError(t, err)

	store, err := session.NewMemoryStore()
	require.NoError(t, err)

	sessions, err := session.New(session.WithStore(store), session.WithEndObserver(p))
	require.NoError(t, err)

	handoff, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), users)
	require.NoError(t, err)

	login := []httpsec.OIDCOption{httpsec.WithOIDCProviderCompletion()}
	if s.toClient {
		login = append(login, httpsec.WithOIDCFailToClient())
	}

	chain, err := httpsec.New(
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.WithoutIPv6Aggregate(),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableOIDCProvider(p),
		httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: rp, Handoff: handoff, Users: users}, login...),
	)
	require.NoError(t, err)

	return &parkedWorld{p: p, chain: chain}
}

// park parks a request of parityClient with parkedState, and returns its handle and
// the browser's provider flow cookie.
func (w *parkedWorld) park(t *testing.T) (string, *http.Cookie) {
	t.Helper()

	res, err := w.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: url.Values{
		"response_type": {"code"}, "client_id": {parityClient}, "redirect_uri": {parityCallback},
		"scope": {"openid"}, "state": {parkedState},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}})
	require.NoError(t, err)

	loc, err := url.Parse(res.Location)
	require.NoError(t, err)

	return loc.Query().Get(oidcprovider.HandleParam), &http.Cookie{Name: parityFlowCookie, Value: res.FlowSecret, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// start is the login page's start of a federated login with provider for handle,
// carrying flow.
func parkedStart(t *testing.T, provider, handle string, flow *http.Cookie) *http.Request {
	t.Helper()

	next := parityIssuer + "/login?" + url.Values{oidcprovider.HandleParam: {handle}}.Encode()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		parityIssuer+httpsec.DefaultOIDCAuthorizePath+provider+"?"+url.Values{httpsec.DefaultOIDCNextParam: {next}}.Encode(), nil)
	r.AddCookie(flow)
	r.RemoteAddr = paritySource

	return r
}

// parkedCallback starts a federated login for a request parked in w, through net/http,
// and returns the upstream's redirect back: with error=access_denied when denied, or
// with a code.
func parkedCallback(t *testing.T, w *parkedWorld, denied bool, after func()) *http.Request {
	t.Helper()

	handle, flow := w.park(t)
	if after != nil {
		after()
	}

	rec := httptest.NewRecorder()
	w.chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, parkedStart(t, parkedUpstream, handle, flow))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	upstream, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)

	q := url.Values{"state": {upstream.Query().Get("state")}}
	if denied {
		q.Set("error", "access_denied")
	} else {
		q.Set("code", upstream.Query().Get("nonce"))
	}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		parityIssuer+httpsec.DefaultOIDCCallbackPath+parkedUpstream+"?"+q.Encode(), nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}

	r.AddCookie(flow)

	return r
}

// parkedParityAnswer is the compared part of a parked login's answer.
func parkedParityAnswer(status int, h http.Header, body string) parityAnswer {
	a := parityOf(status, h, body)
	if v := h.Values("Referrer-Policy"); len(v) > 0 {
		a.header["Referrer-Policy"] = v
	}

	return a
}

// TestParkedFailureParity pins that a failed brokered login for a parked request is
// answered out of gin as out of net/http: the return to the login page from the
// callback, an upstream error, the start and completion, and the answer at the client
// for a request expired within its grace window and under WithOIDCFailToClient.
func TestParkedFailureParity(t *testing.T) {
	t.Parallel()

	toLogin := func(code string) func(t *testing.T, a parityAnswer) {
		return func(t *testing.T, a parityAnswer) {
			t.Helper()

			require.Equal(t, http.StatusSeeOther, a.status, a.body)

			loc, err := url.Parse(a.header["Location"][0])
			require.NoError(t, err)
			assert.Equal(t, parityIssuer+"/login", loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(t, code, loc.Query().Get(httpsec.DefaultOIDCLoginErrorParam))
			assert.Equal(t, []string{"no-store"}, a.header["Cache-Control"])
		}
	}

	toClient := func(code string) func(t *testing.T, a parityAnswer) {
		return func(t *testing.T, a parityAnswer) {
			t.Helper()

			require.Equal(t, http.StatusSeeOther, a.status, a.body)

			loc, err := url.Parse(a.header["Location"][0])
			require.NoError(t, err)
			assert.Equal(t, parityCallback, loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(t, url.Values{"error": {code}, "state": {parkedState}, "iss": {parityIssuer}}, loc.Query())
		}
	}

	cases := []struct {
		name    string
		setup   parkedSetup
		request func(t *testing.T, w *parkedWorld) *http.Request
		assert  func(t *testing.T, a parityAnswer)
	}{
		{
			name:  "a callback's upstream outage returns to the login page",
			setup: parkedSetup{tokenDown: true},
			request: func(t *testing.T, w *parkedWorld) *http.Request {
				t.Helper()

				return parkedCallback(t, w, false, nil)
			},
			assert: toLogin(oidcprovider.CodeTemporarilyUnavailable),
		},
		{
			name: "an upstream error= returns to the login page",
			request: func(t *testing.T, w *parkedWorld) *http.Request {
				t.Helper()

				return parkedCallback(t, w, true, nil)
			},
			assert: toLogin(oidcprovider.CodeAccessDenied),
		},
		{
			name: "a start that cannot discover returns to the login page",
			request: func(t *testing.T, w *parkedWorld) *http.Request {
				t.Helper()

				handle, flow := w.park(t)

				return parkedStart(t, parkedUndiscovered, handle, flow)
			},
			assert: toLogin(oidcprovider.CodeTemporarilyUnavailable),
		},
		{
			name:  "completion's refusal of a disabled user returns to the login page",
			setup: parkedSetup{inactive: true},
			request: func(t *testing.T, w *parkedWorld) *http.Request {
				t.Helper()

				return parkedCallback(t, w, false, nil)
			},
			assert: toLogin(oidcprovider.CodeAccessDenied),
		},
		{
			name:  "a request expired within its grace window is answered at the client",
			setup: parkedSetup{tokenDown: true, lifetime: 50 * time.Millisecond},
			request: func(t *testing.T, w *parkedWorld) *http.Request {
				t.Helper()

				return parkedCallback(t, w, false, func() { time.Sleep(100 * time.Millisecond) })
			},
			assert: toClient(oidcprovider.CodeAccessDenied),
		},
		{
			name:  "WithOIDCFailToClient answers the client",
			setup: parkedSetup{tokenDown: true, toClient: true},
			request: func(t *testing.T, w *parkedWorld) *http.Request {
				t.Helper()

				return parkedCallback(t, w, false, nil)
			},
			assert: toClient(oidcprovider.CodeTemporarilyUnavailable),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			run := func(serve func(w *parkedWorld, r *http.Request) parityAnswer) parityAnswer {
				w := newParkedWorld(t, tc.setup)
				r := tc.request(t, w)
				r.RemoteAddr = paritySource

				return serve(w, r)
			}

			viaNetHTTP := run(func(w *parkedWorld, r *http.Request) parityAnswer {
				rec := httptest.NewRecorder()
				w.chain.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, r)

				return parkedParityAnswer(rec.Code, rec.Header(), rec.Body.String())
			})

			viaGin := run(func(w *parkedWorld, r *http.Request) parityAnswer {
				eng := gin.New()
				eng.Use(ginsec.Middleware(w.chain))

				rec := serve(eng, r)

				return parkedParityAnswer(rec.Code, rec.Header(), rec.Body.String())
			})

			tc.assert(t, viaNetHTTP)
			assert.Equal(t, normalizeParked(viaNetHTTP), normalizeParked(viaGin))
		})
	}
}

// normalizeParked drops what differs between two runs rather than two adapters: the
// handle in a Location to the login page is minted afresh by each run's world.
func normalizeParked(a parityAnswer) parityAnswer {
	out := parityAnswer{status: a.status, body: a.body, header: map[string][]string{}}
	for k, v := range a.header {
		out.header[k] = v
	}

	if loc, ok := a.header["Location"]; ok && len(loc) == 1 {
		if u, err := url.Parse(loc[0]); err == nil {
			q := u.Query()
			if q.Has(oidcprovider.HandleParam) {
				q.Set(oidcprovider.HandleParam, "h")
				u.RawQuery = q.Encode()
				out.header["Location"] = []string{u.String()}
			}
		}
	}

	return out
}
