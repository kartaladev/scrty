package ginsec_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The provider the parity rows run against. Its issuer is plain HTTP on a loopback host,
// which every adapter's in-memory transport can reach without TLS.
const (
	parityIssuer   = "http://127.0.0.1:8080"
	parityClient   = "parity-web"
	paritySecret   = "0123456789abcdef0123456789abcdef" //nolint:gosec // G101: a fixture secret
	parityCallback = "https://rp.example.com/cb"
	parityDevice   = "parity-tv"
	// parityFlowCookie is the flow cookie's name on a plain-HTTP issuer.
	parityFlowCookie = "scrty-op-flow"
	// paritySource is the client address every parity request comes from.
	paritySource = "192.0.2.20:4711"
)

// parityWorld is a provider on a chain with the session bearer, the 429 answer for
// throttled clients and the code-entry redirects, built afresh for each request run.
type parityWorld struct {
	p     *oidcprovider.Provider
	chain *httpsec.Chain
}

func newParityWorld(t *testing.T) *parityWorld {
	t.Helper()

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(
		&identity.Details{ID: "u-1", Username: "ada", Active: true}, nil).AnyTimes()

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: parityIssuer,
		Clients: []oidcprovider.Client{
			{
				ID: parityClient, Type: oidcprovider.Confidential, Secret: []byte(paritySecret),
				RedirectURIs: []string{parityCallback}, Scopes: []string{"openid"},
				GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode},
			},
			{
				ID: parityDevice, Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
				Scopes: []string{"openid"}, GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantDeviceCode},
			},
		},
		Keys:         keys,
		Users:        users,
		LoginURL:     parityIssuer + "/login",
		ConsentURL:   parityIssuer + "/consent",
		LogoutURL:    parityIssuer + "/logout-page",
		LoggedOutURL: parityIssuer + "/bye",
	},
		oidcprovider.WithLoopbackHTTPIssuer(),
		oidcprovider.WithoutBrowserSessions(),
		oidcprovider.WithDeviceAuthorization(parityIssuer+"/enter-code",
			oidcprovider.WithUserCodeKey(bytes.Repeat([]byte{7}, oidcprovider.MinUserCodeKeyBytes))),
	)
	require.NoError(t, err)

	store, err := session.NewMemoryStore()
	require.NoError(t, err)

	sessions, err := session.New(session.WithStore(store), session.WithEndObserver(p))
	require.NoError(t, err)

	// One failure throttles the token endpoint's source, for a minute.
	tokenLimiter, err := ratelimit.NewMemoryLimiter(1, time.Minute)
	require.NoError(t, err)

	chain, err := httpsec.New(
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.WithoutIPv6Aggregate(),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableOIDCProvider(p,
			httpsec.WithOIDCTokenLimiter(tokenLimiter),
			httpsec.WithOIDCThrottle429(),
			httpsec.WithOIDCEntryRedirects(),
		),
	)
	require.NoError(t, err)

	return &parityWorld{p: p, chain: chain}
}

// parityAnswer is the part of a response the parity rows compare.
type parityAnswer struct {
	status int
	header map[string][]string
	body   string
}

// parityHeaders are the headers the rows' answers set.
var parityHeaders = []string{"WWW-Authenticate", "Retry-After", "Location", "Content-Type", "Cache-Control"}

// parityOf reads the compared part of a response. A Content-Type on a response with no
// body is left out: an adapter's framework may name one where net/http names none
// (fiber's default), and nothing in this work sets it.
func parityOf(status int, h http.Header, body string) parityAnswer {
	a := parityAnswer{status: status, header: map[string][]string{}, body: body}
	for _, name := range parityHeaders {
		if name == "Content-Type" && body == "" {
			continue
		}

		if v := h.Values(name); len(v) > 0 {
			a.header[name] = v
		}
	}

	return a
}

// parityRequest is one request a row sends, built against a fresh world.
type parityRequest func(t *testing.T, w *parityWorld) *http.Request

// parityBody is a POST of body to path, declared as contentType, with cookies. Its
// Content-Length is stated as a header too, since a request an adapter test replays
// over a raw transport is sent with its headers alone.
func parityBody(t *testing.T, path, contentType, body string, cookies ...*http.Cookie) *http.Request {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, parityIssuer+path, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))

	for _, c := range cookies {
		r.AddCookie(c)
	}

	return r
}

// parityForm is a form POST to path, as client presenting client_secret_basic.
func parityForm(path string, form url.Values, id, secret string) parityRequest {
	return func(t *testing.T, _ *parityWorld) *http.Request {
		t.Helper()

		r := parityBody(t, path, "application/x-www-form-urlencoded", form.Encode())
		r.SetBasicAuth(id, secret)

		return r
	}
}

// parityRows are the requests whose answers must not depend on the adapter. Each row is
// a sequence: every request runs, and the last one's answer is compared.
var parityRows = []struct {
	name     string
	requests []parityRequest
	assert   func(t *testing.T, a parityAnswer)
}{
	{
		name: "the cancel endpoint ends a parked request",
		requests: []parityRequest{func(t *testing.T, w *parityWorld) *http.Request {
			t.Helper()

			res, err := w.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: url.Values{
				"response_type": {"code"}, "client_id": {parityClient}, "redirect_uri": {parityCallback},
				"scope": {"openid"}, "state": {"xyz"},
				"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
				"code_challenge_method": {"S256"},
			}})
			require.NoError(t, err)

			loc, err := url.Parse(res.Location)
			require.NoError(t, err)

			return parityBody(t, "/oauth2/authorize/cancel", "application/json",
				`{"req":"`+loc.Query().Get(oidcprovider.HandleParam)+`"}`,
				&http.Cookie{Name: parityFlowCookie, Value: res.FlowSecret})
		}},
		assert: func(t *testing.T, a parityAnswer) {
			t.Helper()

			require.Equal(t, http.StatusOK, a.status, a.body)
			assert.Contains(t, a.body, `"redirect_to"`)
			assert.Contains(t, a.body, "error=access_denied")
		},
	},
	{
		name: "a refused bearer token at a consumer's route is challenged",
		requests: []parityRequest{func(t *testing.T, _ *parityWorld) *http.Request {
			t.Helper()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, parityIssuer+"/api", nil)
			r.Header.Set("Authorization", "Bearer unknown-session")

			return r
		}},
		assert: func(t *testing.T, a parityAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusUnauthorized, a.status)
			assert.Equal(t, []string{`Bearer error="invalid_token"`}, a.header["WWW-Authenticate"])
		},
	},
	{
		name: "a throttled client source is answered 429",
		requests: []parityRequest{
			parityForm("/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, parityClient, "wrong"),
			parityForm("/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, parityClient, paritySecret),
		},
		assert: func(t *testing.T, a parityAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusTooManyRequests, a.status)
			assert.Equal(t, []string{"60"}, a.header["Retry-After"])
			assert.JSONEq(t, `{"error":"temporarily_unavailable"}`, a.body)
		},
	},
	{
		name: "an unknown user code is sent back to the code-entry page",
		requests: []parityRequest{func(t *testing.T, _ *parityWorld) *http.Request {
			t.Helper()

			return httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				parityIssuer+"/oauth2/device?user_code=BBBB-BBBB", nil)
		}},
		assert: func(t *testing.T, a parityAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusSeeOther, a.status)
			assert.Equal(t, []string{parityIssuer + "/enter-code?result=invalid"}, a.header["Location"])
		},
	},
}

// TestOIDCProviderParity pins that the provider's answers changed by this work, and the
// bearer challenge, come out of gin as they do out of net/http: the same status, headers
// and body.
func TestOIDCProviderParity(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, requests []parityRequest, serve func(*parityWorld, *http.Request) parityAnswer) parityAnswer {
		t.Helper()

		w := newParityWorld(t)

		var last parityAnswer

		for _, build := range requests {
			r := build(t, w)
			r.RemoteAddr = paritySource
			last = serve(w, r)
		}

		return last
	}

	route := func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) }

	for _, tc := range parityRows {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			viaNetHTTP := run(t, tc.requests, func(w *parityWorld, r *http.Request) parityAnswer {
				rec := httptest.NewRecorder()
				w.chain.Middleware()(http.HandlerFunc(route)).ServeHTTP(rec, r)

				return parityOf(rec.Code, rec.Header(), rec.Body.String())
			})

			viaGin := run(t, tc.requests, func(w *parityWorld, r *http.Request) parityAnswer {
				eng := gin.New()
				eng.Use(ginsec.Middleware(w.chain))
				eng.GET("/api", func(gc *gin.Context) { gc.Status(http.StatusNoContent) })

				rec := serve(eng, r)

				return parityOf(rec.Code, rec.Header(), rec.Body.String())
			})

			tc.assert(t, viaNetHTTP)
			assert.Equal(t, viaNetHTTP, viaGin)
		})
	}
}
