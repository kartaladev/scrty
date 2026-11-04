package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

const (
	flowCookie       = "__Host-scrty-op-flow"
	flowCookiePlain  = "scrty-op-flow"
	flowSession      = "__Host-scrty-op-session"
	flowSessionPlain = "scrty-op-session"

	flowWeb        = "flow-web"
	flowFirstParty = "flow-first-party"
	flowAddr       = "192.0.2.20:4711"
	flowOtherAddr  = "192.0.2.21:4711"
	flowLoopback   = "http://127.0.0.1:8080"

	flowAuthorizePath = "/oauth2/authorize"
	flowResumePath    = "/oauth2/authorize/resume"
)

// flowSetup is what a row asks of its provider and chain.
type flowSetup struct {
	issuer       string
	provider     []oidcprovider.Option
	sessions     []session.Option
	endpoint     []httpsec.OIDCProviderOption
	bearer       func(t *testing.T, w *opFlow) httpsec.Option
	chain        func(t *testing.T, w *opFlow) []httpsec.Option
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)
	noHandler    bool
}

// flowPendingStore counts what reaches the pending-request store.
type flowPendingStore struct {
	*oidcprovider.MemoryPendingRequestStore

	creates, loads atomic.Int64
}

func (s *flowPendingStore) Create(ctx context.Context, r *oidcprovider.PendingRequest) error {
	s.creates.Add(1)

	return s.MemoryPendingRequestStore.Create(ctx, r)
}

func (s *flowPendingStore) Load(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
	s.loads.Add(1)

	return s.MemoryPendingRequestStore.Load(ctx, digest)
}

// flowRegistry counts the client lookups a request cost.
type flowRegistry struct {
	*oidcprovider.MemoryRegistry

	reads atomic.Int64
}

func (r *flowRegistry) Client(ctx context.Context, id string) (*oidcprovider.RegisteredClient, error) {
	r.reads.Add(1)

	return r.MemoryRegistry.Client(ctx, id)
}

// opFlow is a provider on a chain, with what a row inspects it through. Its error
// handler answers the status table and keeps the error it was handed.
type opFlow struct {
	issuer   string
	clk      *clockwork.FakeClock
	p        *oidcprovider.Provider
	chain    *httpsec.Chain
	sessions *session.Sessions
	users    *MockUserLoader
	pending  *flowPendingStore
	registry *flowRegistry
	consents *oidcprovider.MemoryConsentStore
	grants   *oidcprovider.MemoryGrantStore
	apiKey   string
	lastErr  atomic.Pointer[error]
}

func flowClients() []oidcprovider.Client {
	secret := []byte(tokenSecret)
	scopes := []string{"openid", "profile", "email", "offline_access"}
	both := []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}

	return []oidcprovider.Client{
		{
			ID: flowWeb, Name: "Flow Web", Type: oidcprovider.Confidential, Secret: secret,
			RedirectURIs: []string{rpCallback}, Scopes: scopes, GrantTypes: both,
		},
		{
			ID: flowFirstParty, Type: oidcprovider.Confidential, Secret: secret, FirstParty: true,
			RedirectURIs: []string{rpCallback}, Scopes: scopes, GrantTypes: both,
		},
	}
}

func newOPFlow(t *testing.T, setup flowSetup) *opFlow {
	t.Helper()

	w := &opFlow{issuer: setup.issuer, clk: clockwork.NewFakeClockAt(time.Now())}
	if w.issuer == "" {
		w.issuer = opIssuer
	}

	w.pending = &flowPendingStore{MemoryPendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore(
		oidcprovider.WithMemoryStoreClock(w.clk)))}
	w.registry = &flowRegistry{MemoryRegistry: must.Must(oidcprovider.NewMemoryRegistry(flowClients()))}
	w.consents = must.Must(oidcprovider.NewMemoryConsentStore())
	w.grants = must.Must(oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(w.clk)))

	w.users = NewMockUserLoader(gomock.NewController(t))
	w.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: user, Username: string(user), Active: true}, nil
		},
	).AnyTimes()

	popts := append([]oidcprovider.Option{
		oidcprovider.WithClock(w.clk),
		oidcprovider.WithPendingRequestStore(w.pending),
		oidcprovider.WithConsentStore(w.consents),
		oidcprovider.WithGrantStore(w.grants),
	}, setup.provider...)
	if w.issuer == flowLoopback {
		popts = append(popts, oidcprovider.WithLoopbackHTTPIssuer())
	}

	var err error

	w.p, err = oidcprovider.New(oidcprovider.Deps{
		Issuer:       w.issuer,
		Registry:     w.registry,
		Keys:         tokenKeys(),
		Users:        w.users,
		LoginURL:     w.issuer + "/login",
		ConsentURL:   w.issuer + "/consent",
		LogoutURL:    w.issuer + "/logout-page",
		LoggedOutURL: w.issuer + "/bye",
	}, popts...)
	require.NoError(t, err)

	w.sessions = must.Must(session.New(append([]session.Option{
		session.WithClock(w.clk),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(w.clk)))),
		session.WithEndObserver(w.p),
	}, setup.sessions...)...))

	bearer := httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users})
	if setup.bearer != nil {
		bearer = setup.bearer(t, w)
	}

	opts := []httpsec.Option{
		httpsec.WithClock(w.clk),
		bearer,
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(w.p, setup.endpoint...),
	}

	switch {
	case setup.errorHandler != nil:
		opts = append(opts, httpsec.WithErrorHandler(setup.errorHandler))
	case !setup.noHandler:
		opts = append(opts, httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
			w.lastErr.Store(&err)
			rw.WriteHeader(httpsec.StatusForError(err))
		}))
	}

	if setup.chain != nil {
		opts = append(opts, setup.chain(t, w)...)
	}

	w.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return w
}

// flowAnswer is the endpoint's whole response, and the error the chain's handling
// was handed, if it was.
type flowAnswer struct {
	status   int
	header   http.Header
	body     string
	cookies  []*http.Cookie
	passedOn bool
	err      error
}

func (a flowAnswer) cookie(name string) *http.Cookie {
	for _, c := range a.cookies {
		if c.Name == name {
			return c
		}
	}

	return nil
}

// location is where the answer sends the browser.
func (a flowAnswer) location(t *testing.T) *url.URL {
	t.Helper()

	u, err := url.Parse(a.header.Get("Location"))
	require.NoError(t, err)

	return u
}

// redirectTo is the URL in a resume's document.
func (a flowAnswer) redirectTo(t *testing.T) *url.URL {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)
	assert.Len(t, doc, 1, "the document holds only where the browser goes")

	raw, ok := doc["redirect_to"].(string)
	require.True(t, ok, a.body)

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

type flowChange func(r *http.Request)

func flowCookieOf(name, value string) flowChange {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: name, Value: value}) } //nolint:gosec // G124: a request sends no attributes
}

func flowBearer(credential string) flowChange {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+credential) }
}

func flowFrom(addr string) flowChange {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// flowPlainHTTP makes a request arrive with no TLS.
func flowPlainHTTP(r *http.Request) { r.TLS = nil }

func (w *opFlow) serve(t *testing.T, r *http.Request, change []flowChange) flowAnswer {
	t.Helper()

	r.RemoteAddr = flowAddr
	for _, c := range change {
		c(r)
	}

	var passedOn bool

	h := w.chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
	rec := httptest.NewRecorder()

	w.lastErr.Store(nil)
	h.ServeHTTP(rec, r)

	a := flowAnswer{
		status:   rec.Code,
		header:   rec.Header(),
		body:     rec.Body.String(),
		cookies:  rec.Result().Cookies(), //nolint:bodyclose // a recorder's body needs no closing
		passedOn: passedOn,
	}
	if err := w.lastErr.Load(); err != nil {
		a.err = *err
	}

	return a
}

// authorizeGET sends params to the authorization endpoint by GET.
func (w *opFlow) authorizeGET(t *testing.T, params url.Values, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		w.issuer+flowAuthorizePath+"?"+params.Encode(), nil)

	return w.serve(t, r, change)
}

// authorizePOST sends form to the authorization endpoint by form POST.
func (w *opFlow) authorizePOST(t *testing.T, form url.Values, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		w.issuer+flowAuthorizePath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return w.serve(t, r, change)
}

// flowParams is a valid request from clientID, with change applied.
func flowParams(clientID string, change ...func(url.Values)) url.Values {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {rpCallback},
		"scope":                 {"openid profile"},
		"state":                 {"xyz"},
		"code_challenge":        {pkceChallengeS256},
		"code_challenge_method": {"S256"},
	}
	for _, c := range change {
		c(params)
	}

	return params
}

// park parks a request from clientID and returns its handle and the flow secret.
func (w *opFlow) park(t *testing.T, clientID string, change ...func(url.Values)) (string, string) {
	t.Helper()

	return w.parkIn(t, flowCookie, clientID, change...)
}

func (w *opFlow) parkIn(t *testing.T, cookie, clientID string, change ...func(url.Values)) (string, string) {
	t.Helper()

	var send []flowChange
	if cookie == flowCookiePlain {
		send = append(send, flowPlainHTTP)
	}

	a := w.authorizeGET(t, flowParams(clientID, change...), send...)
	require.Equal(t, http.StatusSeeOther, a.status, a.body)

	flow := a.cookie(cookie)
	require.NotNil(t, flow, "the flow cookie is set")

	return a.location(t).Query().Get(oidcprovider.HandleParam), flow.Value
}

// session is a stored full session of u-1.
func (w *opFlow) session(t *testing.T, opts ...session.CreateOption) *session.Session {
	t.Helper()

	s, err := w.sessions.Create(t.Context(), "u-1",
		append([]session.CreateOption{session.WithFirstFactor(factor.Password)}, opts...)...)
	require.NoError(t, err)

	return s
}

// browserSession is a browser-session secret from a login resumed through the
// provider, by a sign-in of the session s.
func (w *opFlow) browserSession(t *testing.T, s *session.Session) string {
	t.Helper()

	handle, flow := w.park(t, flowWeb)

	res, err := w.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle:     handle,
		FlowSecret: flow,
		SignIn: &oidcprovider.SignIn{
			User:              s.UserID,
			Family:            s.FamilyID,
			AuthenticatedAt:   s.AuthenticatedAt,
			AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		},
		IdleTimeout: w.sessions.IdleTimeout(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.BrowserSessionSecret)

	return res.BrowserSessionSecret
}

// stage says where a handle stands, which is how a row sees it unspent.
func (w *opFlow) stage(t *testing.T, handle, flow string) oidcprovider.Stage {
	t.Helper()

	view, err := w.p.PendingRequest(t.Context(), handle, flow)
	require.NoError(t, err)

	return view.Stage
}

func TestOIDCAuthorizeEndpoint(t *testing.T) {
	t.Parallel()

	const consumerPage = "<h1>That application is not known</h1>"

	refusedUnredirected := func(t *testing.T, w *opFlow, a flowAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusBadRequest, a.status)
		assert.Empty(t, a.header.Get("Location"), "the browser is not redirected")
		require.ErrorIs(t, a.err, httpsec.ErrOIDCInvalidAuthorization)
		assert.Empty(t, a.body)
		assert.Empty(t, a.cookies)
		assert.Zero(t, w.pending.creates.Load(), "nothing is parked")
	}

	redirectedWith := func(code string) func(*testing.T, *opFlow, flowAnswer) {
		return func(t *testing.T, w *opFlow, a flowAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusSeeOther, a.status)

			at := a.location(t)
			assert.Equal(t, rpCallback, at.Scheme+"://"+at.Host+at.Path)
			assert.Equal(t, code, at.Query().Get("error"))
			assert.Equal(t, "xyz", at.Query().Get("state"))
			assert.Equal(t, w.issuer, at.Query().Get("iss"))
			assert.False(t, at.Query().Has("error_description"))
			assert.Zero(t, w.pending.creates.Load(), "nothing is parked")
		}
	}

	parkedAtLogin := func(t *testing.T, w *opFlow, a flowAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusSeeOther, a.status)

		at := a.location(t)
		assert.Equal(t, w.issuer+"/login", at.Scheme+"://"+at.Host+at.Path)

		flow := a.cookie(flowCookie)
		require.NotNil(t, flow, "the flow cookie is set")
		assert.Equal(t, "/", flow.Path)
		assert.True(t, flow.Secure)
		assert.True(t, flow.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, flow.SameSite)
		assert.Empty(t, flow.Domain)

		view, err := w.p.PendingRequest(t.Context(), at.Query().Get(oidcprovider.HandleParam), flow.Value)
		require.NoError(t, err)
		assert.Equal(t, flowWeb, view.ClientID)
		assert.Equal(t, []string{"openid", "profile"}, view.Scopes)
		assert.False(t, a.passedOn)
	}

	type testCase struct {
		name   string
		setup  flowSetup
		send   func(t *testing.T, w *opFlow) flowAnswer
		assert func(t *testing.T, w *opFlow, a flowAnswer)
	}

	cases := []testCase{
		{
			name: "a valid GET goes to the login page, with the flow cookie",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: parkedAtLogin,
		},
		{
			name: "a valid form POST goes to the login page",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizePOST(t, flowParams(flowWeb))
			},
			assert: parkedAtLogin,
		},
		{
			name: "a POST's parameters come from its body, never its query",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				params := flowParams(flowWeb)
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					w.issuer+flowAuthorizePath+"?"+params.Encode(), strings.NewReader("state=abc"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return w.serve(t, r, nil)
			},
			assert: refusedUnredirected,
		},
		{
			name: "an unregistered redirect URI is not redirected to",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) {
					p.Set("redirect_uri", "https://evil.example.com/cb")
				}))
			},
			assert: refusedUnredirected,
		},
		{
			name: "an unknown client is not redirected to",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams("nobody"))
			},
			assert: refusedUnredirected,
		},
		{
			name: "a repeated redirect URI is not redirected to",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) {
					p.Add("redirect_uri", rpCallback)
				}))
			},
			assert: refusedUnredirected,
		},
		{
			name:  "with no error handler the refusal is a bare 400",
			setup: flowSetup{noHandler: true},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams("nobody"))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Empty(t, a.header.Get("Location"))
				assert.Empty(t, a.body)
			},
		},
		{
			name: "a consumer's error handler shows its page, and the browser stays",
			setup: flowSetup{errorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				if errors.Is(err, httpsec.ErrOIDCInvalidAuthorization) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(consumerPage))
				}
			}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) {
					p.Set("redirect_uri", "https://evil.example.com/cb")
				}))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Equal(t, consumerPage, a.body)
				assert.Empty(t, a.header.Get("Location"))
			},
		},
		{
			name: "a missing scope is redirected with its error",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) { p.Del("scope") }))
			},
			assert: redirectedWith("invalid_request"),
		},
		{
			name: "a repeated parameter in a form POST is invalid_request",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizePOST(t, flowParams(flowWeb, func(p url.Values) { p.Add("scope", "email") }))
			},
			assert: redirectedWith("invalid_request"),
		},
		{
			name: "a repeated parameter in a GET is invalid_request",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) { p.Add("nonce", "n"); p.Add("nonce", "m") }))
			},
			assert: redirectedWith("invalid_request"),
		},
		{
			name: "every parameter the provider reads reaches it from a GET",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) {
					p.Set("login_hint", "ada@example.com")
					p.Set("ui_locales", "de")
					p.Set("claims_locales", "fr")
					p.Set("acr_values", "urn:example:high")
					p.Set("max_age", "300")
					p.Set("prompt", "login")
				}))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status)

				view, err := w.p.PendingRequest(t.Context(),
					a.location(t).Query().Get(oidcprovider.HandleParam), a.cookie(flowCookie).Value)
				require.NoError(t, err)
				assert.Equal(t, "ada@example.com", view.LoginHint)
				assert.Equal(t, []string{"de"}, view.UILocales)
				assert.Equal(t, []string{"fr"}, view.ClaimsLocales)
				assert.Equal(t, []string{"urn:example:high"}, view.ACRValues)
				assert.Equal(t, []string{"login"}, view.Prompt)
				require.NotNil(t, view.MaxAge)
				assert.Equal(t, 300, *view.MaxAge)
			},
		},
		{
			name: "a request object is refused, read from the query like the rest",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) {
					p.Set("request_uri", "https://rp.example.com/req/1")
				}))
			},
			assert: redirectedWith("request_uri_not_supported"),
		},
		{
			name: "a flow cookie the browser holds is kept",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				_, flow := w.park(t, flowWeb)

				return w.authorizeGET(t, flowParams(flowWeb), flowCookieOf(flowCookie, flow))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status)
				assert.Nil(t, a.cookie(flowCookie), "the cookie the browser holds stands")
				assert.Equal(t, int64(2), w.pending.creates.Load())
			},
		},
		{
			name: "a flow cookie the provider could not have minted is replaced",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb), flowCookieOf(flowCookie, "planted"))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status)
				require.NotNil(t, a.cookie(flowCookie))
				assert.NotEqual(t, "planted", a.cookie(flowCookie).Value)
			},
		},
		{
			name: "two requests parked in one cookie jar both resume",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				first, flow := w.park(t, flowWeb)
				second := w.authorizeGET(t, flowParams(flowWeb), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusSeeOther, second.status)

				s := w.session(t)
				for _, handle := range []string{first, second.location(t).Query().Get(oidcprovider.HandleParam)} {
					_, err := w.p.Resume(t.Context(), oidcprovider.ResumeInput{
						Handle:     handle,
						FlowSecret: flow,
						SignIn: &oidcprovider.SignIn{
							User: s.UserID, Family: s.FamilyID, AuthenticatedAt: s.AuthenticatedAt,
							AbsoluteExpiresAt: s.AbsoluteExpiresAt,
						},
					})
					require.NoError(t, err)
				}

				return second
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusSeeOther, a.status)
			},
		},
		{
			name: "a valid browser session answers with a code",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				secret := w.browserSession(t, w.session(t))

				return w.authorizeGET(t, flowParams(flowFirstParty), flowCookieOf(flowSession, secret))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status)

				at := a.location(t)
				assert.NotEmpty(t, at.Query().Get("code"))
				assert.Equal(t, "xyz", at.Query().Get("state"))
				assert.Equal(t, w.issuer, at.Query().Get("iss"))
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			},
		},
		{
			name: "a browser session under the unprefixed name is not read on a TLS issuer",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				secret := w.browserSession(t, w.session(t))

				return w.authorizeGET(t, flowParams(flowFirstParty), flowCookieOf(flowSessionPlain, secret))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, w.issuer+"/login", a.location(t).Scheme+"://"+a.location(t).Host+a.location(t).Path)
			},
		},
		{
			name: "a flow cookie under the unprefixed name is not read on a TLS issuer",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				_, flow := w.park(t, flowWeb)

				return w.authorizeGET(t, flowParams(flowWeb), flowCookieOf(flowCookiePlain, flow))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.NotNil(t, a.cookie(flowCookie), "a planted name is no cookie, so a new one is set")
			},
		},
		{
			name: "with no browser session a silent request answers login_required",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) { p.Set("prompt", "none") }))
			},
			assert: redirectedWith("login_required"),
		},
		{
			name: "a browser session idles out on the chain's manager's timeout, which each use extends",
			setup: flowSetup{
				sessions: []session.Option{session.WithIdleTimeout(time.Minute), session.WithAbsoluteTimeout(time.Hour)},
			},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				secret := w.browserSession(t, w.session(t))

				w.clk.Advance(50 * time.Second)
				used := w.authorizeGET(t, flowParams(flowFirstParty), flowCookieOf(flowSession, secret))
				require.NotEmpty(t, used.location(t).Query().Get("code"), "inside the idle timeout")

				w.clk.Advance(50 * time.Second)
				used = w.authorizeGET(t, flowParams(flowFirstParty), flowCookieOf(flowSession, secret))
				require.NotEmpty(t, used.location(t).Query().Get("code"), "the use extended it")

				w.clk.Advance(61 * time.Second)

				return w.authorizeGET(t, flowParams(flowFirstParty), flowCookieOf(flowSession, secret))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				at := a.location(t)
				assert.Equal(t, w.issuer+"/login", at.Scheme+"://"+at.Host+at.Path)
			},
		},
		{
			name:  "the loopback issuer's flow cookie has no prefix and is not Secure",
			setup: flowSetup{issuer: flowLoopback},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, "plain http is what the loopback issuer serves")
				assert.Nil(t, a.cookie(flowCookie))

				flow := a.cookie(flowCookiePlain)
				require.NotNil(t, flow)
				assert.False(t, flow.Secure)
				assert.True(t, flow.HttpOnly)
				assert.Equal(t, http.SameSiteLaxMode, flow.SameSite)
				assert.Equal(t, "/", flow.Path)
			},
		},
		{
			name:  "the loopback issuer reads its cookies under their unprefixed names",
			setup: flowSetup{issuer: flowLoopback},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				_, flow := w.parkIn(t, flowCookiePlain, flowWeb)
				s := w.session(t)

				second := w.authorizeGET(t, flowParams(flowWeb), flowCookieOf(flowCookiePlain, flow))
				require.Nil(t, second.cookie(flowCookiePlain), "the flow cookie is kept")

				res, err := w.p.Resume(t.Context(), oidcprovider.ResumeInput{
					Handle:     second.location(t).Query().Get(oidcprovider.HandleParam),
					FlowSecret: flow,
					SignIn: &oidcprovider.SignIn{
						User: s.UserID, Family: s.FamilyID, AuthenticatedAt: s.AuthenticatedAt,
						AbsoluteExpiresAt: s.AbsoluteExpiresAt,
					},
				})
				require.NoError(t, err)

				return w.authorizeGET(t, flowParams(flowFirstParty),
					flowCookieOf(flowSessionPlain, res.BrowserSessionSecret))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.NotEmpty(t, a.location(t).Query().Get("code"))
			},
		},
		{
			name: "a parked request's answer carries no-store",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusSeeOther, a.status)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			},
		},
		{
			name: "an error redirect carries no-store",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb, func(p url.Values) { p.Del("scope") }))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusSeeOther, a.status)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			},
		},
		{
			name: "a refusal the chain answers carries no-store",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams("nobody"))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			},
		},
		{
			name: "a request not made over TLS is refused, and nothing parks",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb), flowPlainHTTP)
			},
			assert: refusedUnredirected,
		},
		{
			name: "a method the endpoint does not serve is answered here, and not passed on",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, w.issuer+flowAuthorizePath, nil)

				return w.serve(t, r, nil)
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, "GET, POST", a.header.Get("Allow"))
				assert.False(t, a.passedOn)
			},
		},
		{
			name: "a POST whose body is not a form is refused with no redirect",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+flowAuthorizePath,
					strings.NewReader(flowParams(flowWeb).Encode()))
				r.Header.Set("Content-Type", "text/plain")

				return w.serve(t, r, nil)
			},
			assert: refusedUnredirected,
		},
		{
			name: "a POST whose form does not parse is refused with no redirect",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+flowAuthorizePath,
					strings.NewReader("client_id=%zz"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return w.serve(t, r, nil)
			},
			assert: refusedUnredirected,
		},
		{
			name: "a POST over the default body limit is too large",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizePOST(t, flowParams(flowWeb, func(p url.Values) {
					p.Set("padding", strings.Repeat("a", int(httpsec.DefaultLoginBodyLimit)))
				}))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
				assert.Empty(t, a.header.Get("Location"))
				assert.Zero(t, w.pending.creates.Load())
			},
		},
		{
			name:  "a consumer's body limit replaces the default",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCAuthorizeBodyLimit(16)}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizePOST(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
			},
		},
		{
			name: "past a consumer's limit a source is refused before anything is validated",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCAuthorizeLimiter(must.Must(ratelimit.NewMemoryLimiter(1, time.Minute))),
			}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				first := w.authorizeGET(t, flowParams("nobody"))
				require.ErrorIs(t, first.err, httpsec.ErrOIDCInvalidAuthorization, "an invalid client is charged")
				w.registry.reads.Store(0)

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, ratelimit.ErrThrottled)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				assert.Empty(t, a.header.Get("Location"))
				assert.Zero(t, w.registry.reads.Load(), "no client was looked up")
				assert.Zero(t, w.pending.creates.Load(), "nothing is parked")

				other := w.authorizeGET(t, flowParams(flowWeb), flowFrom(flowOtherAddr))
				assert.Equal(t, http.StatusSeeOther, other.status, "another source is still heard")
			},
		},
		{
			name: "a parked request is charged, because anyone can park one",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCAuthorizeLimiter(must.Must(ratelimit.NewMemoryLimiter(1, time.Minute))),
			}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				w.park(t, flowWeb)

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, ratelimit.ErrThrottled)
				assert.Equal(t, int64(1), w.pending.creates.Load())
			},
		},
		{
			name: "an answer that parks nothing is not charged",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCAuthorizeLimiter(must.Must(ratelimit.NewMemoryLimiter(1, time.Minute))),
			}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				bad := flowParams(flowWeb, func(p url.Values) { p.Del("scope") })
				for range 3 {
					require.Equal(t, http.StatusSeeOther, w.authorizeGET(t, bad).status)
				}

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, w.issuer+"/login", a.location(t).Scheme+"://"+a.location(t).Host+a.location(t).Path)
			},
		},
		{
			name: "the default limit lets a source park 300 requests a minute",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				for range 300 {
					require.Equal(t, http.StatusSeeOther, w.authorizeGET(t, flowParams(flowWeb)).status)
				}

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, ratelimit.ErrThrottled)
				assert.Equal(t, int64(300), w.pending.creates.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)
			a := tc.send(t, w)
			tc.assert(t, w, a)
		})
	}
}

func TestOIDCProviderFlowOptions(t *testing.T) {
	t.Parallel()

	var nilLimiter *ratelimit.MemoryLimiter

	type testCase struct {
		name string
		opt  httpsec.OIDCProviderOption
		says string
	}

	cases := []testCase{
		{name: "a nil limiter", opt: httpsec.WithOIDCAuthorizeLimiter(nil), says: "WithOIDCAuthorizeLimiter"},
		{name: "a typed nil limiter", opt: httpsec.WithOIDCAuthorizeLimiter(nilLimiter), says: "WithOIDCAuthorizeLimiter"},
		{name: "a zero body limit", opt: httpsec.WithOIDCAuthorizeBodyLimit(0), says: "WithOIDCAuthorizeBodyLimit"},
		{name: "a negative body limit", opt: httpsec.WithOIDCAuthorizeBodyLimit(-1), says: "WithOIDCAuthorizeBodyLimit"},
		{name: "a nil resume limiter", opt: httpsec.WithOIDCResumeLimiter(nil), says: "WithOIDCResumeLimiter"},
		{name: "a typed nil resume limiter", opt: httpsec.WithOIDCResumeLimiter(nilLimiter), says: "WithOIDCResumeLimiter"},
		{name: "a zero resume body limit", opt: httpsec.WithOIDCResumeBodyLimit(0), says: "WithOIDCResumeBodyLimit"},
		{name: "a negative resume body limit", opt: httpsec.WithOIDCResumeBodyLimit(-1), says: "WithOIDCResumeBodyLimit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &opFixture{keys: tokenKeys()}
			p := f.provider(t)

			_, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, tc.opt))...)
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, tc.says)
		})
	}
}
