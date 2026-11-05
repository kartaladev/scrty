package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	logoutEndSessionPath = "/oauth2/logout"
	logoutConfirmPath    = "/oauth2/logout/confirm"
	logoutPagePath       = "/logout-page"
	logoutByePath        = "/bye"
	logoutRPBye          = "https://rp.example.com/bye"
	logoutNative         = "flow-native"
	logoutNativeBye      = "http://127.0.0.1/bye"
)

// logoutRetiredKeys sign a hint with a key the provider does not publish.
var logoutRetiredKeys = sync.OnceValue(func() *signingkey.Keys {
	return must.Must(signingkey.New(context.Background(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
})

// logoutPending records what an end-session request parks, which nothing can read back
// through a handle. The login stages a fixture parks on its way are left out.
type logoutPending struct {
	*oidcprovider.MemoryPendingRequestStore

	mu     sync.Mutex
	parked []oidcprovider.PendingRequest
}

func (s *logoutPending) Create(ctx context.Context, r *oidcprovider.PendingRequest) error {
	if r.Stage == oidcprovider.StageLogout {
		s.mu.Lock()
		s.parked = append(s.parked, *r)
		s.mu.Unlock()
	}

	return s.MemoryPendingRequestStore.Create(ctx, r)
}

func (s *logoutPending) last(t *testing.T) oidcprovider.PendingRequest {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.parked, "a request was parked")

	return s.parked[len(s.parked)-1]
}

func (s *logoutPending) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.parked)
}

// logoutGrants is a grant store whose end of a sign-in can be made to fail.
type logoutGrants struct {
	*oidcprovider.MemoryGrantStore

	outage atomic.Bool
}

var errLogoutGrantsDown = errors.New("grant store down: secret-store-text")

func (s *logoutGrants) EndSignIns(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
	if s.outage.Load() {
		return nil, errLogoutGrantsDown
	}

	return s.MemoryGrantStore.EndSignIns(ctx, sel, at)
}

// logoutFlow is a provider on a chain whose clients registered post-logout URIs, with
// what a logout row inspects.
type logoutFlow struct {
	*opFlow

	parked   *logoutPending
	grantsAt *logoutGrants
	browsers *oidcprovider.MemoryBrowserSessionStore
	events   *eventRecorder
}

// logoutSetup is what a logout row asks beside a flow's setup.
type logoutSetup struct {
	flowSetup

	withoutBrowsers bool
}

func newLogoutFlow(t *testing.T, setup logoutSetup) *logoutFlow {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	w := &logoutFlow{
		parked: &logoutPending{MemoryPendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore(
			oidcprovider.WithMemoryStoreClock(clk)))},
		grantsAt: &logoutGrants{MemoryGrantStore: must.Must(oidcprovider.NewMemoryGrantStore(
			oidcprovider.WithMemoryStoreClock(clk)))},
		events: &eventRecorder{},
	}

	fs := setup.flowSetup
	fs.provider = append([]oidcprovider.Option{
		oidcprovider.WithPendingRequestStore(w.parked),
		oidcprovider.WithGrantStore(w.grantsAt),
	}, fs.provider...)

	if setup.withoutBrowsers {
		fs.provider = append(fs.provider, oidcprovider.WithoutBrowserSessions())
	} else {
		w.browsers = must.Must(oidcprovider.NewMemoryBrowserSessionStore(oidcprovider.WithMemoryStoreClock(clk)))
		fs.provider = append(fs.provider, oidcprovider.WithBrowserSessionStore(w.browsers))
	}

	chain := fs.chain
	fs.chain = func(t *testing.T, flow *opFlow) []httpsec.Option {
		t.Helper()

		opts := []httpsec.Option{httpsec.EnableSecurityEvents(w.events.sink)}
		if chain != nil {
			opts = append(opts, chain(t, flow)...)
		}

		return opts
	}

	w.opFlow = newOPFlow(t, fs)

	web := flowClients()[0]
	web.PostLogoutRedirectURIs = []string{logoutRPBye}
	require.NoError(t, w.registry.Put(t.Context(), web))
	require.NoError(t, w.registry.Put(t.Context(), oidcprovider.Client{
		ID: logoutNative, Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
		RedirectURIs: []string{"http://127.0.0.1/cb"}, PostLogoutRedirectURIs: []string{logoutNativeBye},
		Scopes: []string{"openid"},
	}))

	return w
}

// logoutSignIn is a sign-in held in a browser, with one grant it ends and one that
// outlives it.
type logoutSignIn struct {
	session        *session.Session
	browser        string
	online, tagged id.ID
}

// signIn signs u-1 in, in a browser, when the provider keeps browser sessions.
func (w *logoutFlow) signIn(t *testing.T) logoutSignIn {
	t.Helper()

	s := w.session(t)
	in := logoutSignIn{session: s, online: logoutNewID(t), tagged: logoutNewID(t)}

	if w.browsers != nil {
		in.browser = w.browserSession(t, s)
	}

	now := w.clk.Now()
	for _, g := range []oidcprovider.Grant{
		{Family: in.online, User: s.UserID, ClientID: flowWeb, SignInFamily: s.FamilyID},
		{Family: in.tagged, User: s.UserID, ClientID: flowWeb, SignInFamily: s.FamilyID, Offline: true},
	} {
		g.Scopes, g.CreatedAt, g.ExpiresAt, g.AuthTime = []string{"openid"}, now, now.Add(time.Hour), now
		require.NoError(t, w.grantsAt.Create(t.Context(), &g))
	}

	return in
}

var logoutIDs = id.NewV7Generator()

func logoutNewID(t *testing.T) id.ID {
	t.Helper()

	made, err := logoutIDs.NewID()
	require.NoError(t, err)

	return made
}

// stands reports the sign-in as its stores hold it.
func (w *logoutFlow) stands(t *testing.T, in logoutSignIn) (bool, bool, bool) {
	t.Helper()

	_, err := w.sessions.Load(t.Context(), in.session.ID)
	sessionLive := err == nil

	var browserLive bool

	if w.browsers != nil && in.browser != "" {
		// A login resumed afresh would mint another, so what the browser holds is asked of
		// the authorization endpoint: it answers from the session or parks at the login page.
		a := w.authorizeGET(t, flowParams(flowFirstParty), flowCookieOf(flowSession, in.browser))
		browserLive = a.location(t).Path != "/login"
	}

	grant, err := w.grantsAt.Load(t.Context(), in.online)
	require.NoError(t, err)

	return sessionLive, browserLive, !grant.Revoked
}

// assertEnded checks that the whole sign-in has ended, and that a grant holding
// offline_access is left working.
func (w *logoutFlow) assertEnded(t *testing.T, in logoutSignIn) {
	t.Helper()

	sessionLive, browserLive, grantLive := w.stands(t, in)
	assert.False(t, sessionLive, "the sign-in's session has gone")
	assert.False(t, browserLive, "the browser session has gone")
	assert.False(t, grantLive, "the grant without offline_access is revoked")

	offline, err := w.grantsAt.Load(t.Context(), in.tagged)
	require.NoError(t, err)
	assert.False(t, offline.Revoked, "the grant with offline_access outlives its sign-in")
}

// assertStands checks that nothing of the sign-in has ended.
func (w *logoutFlow) assertStands(t *testing.T, in logoutSignIn) {
	t.Helper()

	sessionLive, browserLive, grantLive := w.stands(t, in)
	assert.True(t, sessionLive, "the sign-in's session stands")
	assert.True(t, grantLive, "the grant stands")

	if in.browser != "" {
		assert.True(t, browserLive, "the browser session stands")
	}
}

// logoutHint is an ID token of the flow's provider for flowWeb, naming family, with
// change applied before it is signed.
func (w *logoutFlow) logoutHint(t *testing.T, family id.ID, change ...func(*token.Issue)) string {
	t.Helper()

	return w.logoutHintFrom(t, w.issuer, tokenKeys(), w.clk, family, change...)
}

func (w *logoutFlow) logoutHintFrom(
	t *testing.T, issuer string, keys signingkey.KeySource, clk clockwork.Clock, family id.ID, change ...func(*token.Issue),
) string {
	t.Helper()

	made, err := token.NewIssuer(keys, signingkey.RS256, issuer, token.WithClock(clk))
	require.NoError(t, err)

	in := token.Issue{
		Type:     token.TypeIDToken,
		Subject:  "u-1",
		ID:       logoutNewID(t).String(),
		Audience: []string{flowWeb},
		Lifetime: 5 * time.Minute,
		Claims:   map[string]any{"sid": family.String()},
	}
	for _, c := range change {
		c(&in)
	}

	raw, err := made.Issue(t.Context(), in)
	require.NoError(t, err)

	return raw
}

// endSessionGET sends params to the end-session endpoint by GET.
func (w *logoutFlow) endSessionGET(t *testing.T, params url.Values, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		w.issuer+logoutEndSessionPath+"?"+params.Encode(), nil)

	return w.serve(t, r, change)
}

// endSessionPOST sends params to the end-session endpoint by form POST.
func (w *logoutFlow) endSessionPOST(t *testing.T, params url.Values, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		w.issuer+logoutEndSessionPath, strings.NewReader(params.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return w.serve(t, r, change)
}

// assertParked checks that the browser was sent to the logout page with a handle, the
// flow cookie set, and the request parked at its logout stage.
func (w *logoutFlow) assertParked(t *testing.T, a flowAnswer) oidcprovider.PendingRequest {
	t.Helper()

	require.Equal(t, http.StatusSeeOther, a.status, a.body)
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	assert.Equal(t, logoutPagePath, a.location(t).Path)
	assert.NotEmpty(t, a.location(t).Query().Get(oidcprovider.HandleParam), "the page is given a handle")
	assert.NotNil(t, a.cookie(flowCookie), "the handle is bound to a flow cookie")
	assert.Nil(t, a.cookie(flowSession), "the browser session's cookie is left alone")
	assert.False(t, a.passedOn)

	r := w.parked.last(t)
	assert.Equal(t, oidcprovider.StageLogout, r.Stage)

	return r
}

// assertRefused checks a refusal: the chain's 400, with no redirect, nothing parked and
// no body of the library's.
func (w *logoutFlow) assertRefused(t *testing.T, a flowAnswer) {
	t.Helper()

	require.ErrorIs(t, a.err, httpsec.ErrOIDCInvalidEndSession)
	require.ErrorIs(t, a.err, oidcprovider.ErrInvalidEndSession)
	assert.Equal(t, http.StatusBadRequest, a.status)
	assert.Empty(t, a.header.Get("Location"), "the browser is not redirected")
	assert.Empty(t, a.body)
	assert.Zero(t, w.parked.count(), "nothing is parked")
	assert.False(t, a.passedOn)
}

// assertClearsBrowser checks that the answer drops the browser-session cookie, with the
// attributes it was set with, so that a browser matches it.
func assertClearsBrowser(t *testing.T, a flowAnswer) {
	t.Helper()

	c := a.cookie(flowSession)
	require.NotNil(t, c, "the browser-session cookie is cleared")
	assert.Empty(t, c.Value)
	assert.Negative(t, c.MaxAge)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
}

func logoutParams(pairs ...string) url.Values {
	params := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		params.Add(pairs[i], pairs[i+1])
	}

	return params
}

// TestOIDCEndSession runs every row by GET and by form POST, which must behave alike.
func TestOIDCEndSession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		setup     logoutSetup
		noBrowser bool
		params    func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values
		assert    func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer)
	}

	hintOnly := func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
		t.Helper()

		return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID))
	}

	endsTo := func(target string) func(*testing.T, *logoutFlow, logoutSignIn, flowAnswer) {
		return func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
			t.Helper()

			require.Equal(t, http.StatusSeeOther, a.status, a.body)
			assert.Equal(t, target, a.header.Get("Location"))
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.False(t, a.passedOn)
			assertClearsBrowser(t, a)
			assert.Zero(t, w.parked.count(), "nothing was asked, so nothing is parked")
			w.assertEnded(t, in)
		}
	}

	refused := func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
		t.Helper()

		w.assertRefused(t, a)
		w.assertStands(t, in)
	}

	asks := func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
		t.Helper()

		r := w.assertParked(t, a)
		assert.Empty(t, r.RedirectURI, "nothing confirmed where the browser may return to")
		assert.Empty(t, r.State)
		w.assertStands(t, in)
	}

	cases := []testCase{
		{
			name:   "a hint naming the browser's sign-in ends it, with no question",
			params: hintOnly,
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name: "an expired hint naming the browser's sign-in ends it too",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				past := clockwork.NewFakeClockAt(w.clk.Now().Add(-24 * time.Hour))

				return logoutParams("id_token_hint", w.logoutHintFrom(t, w.issuer, tokenKeys(), past, in.session.FamilyID))
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name: "a registered URI gets the browser back, with its state",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "state", "s-1")
			},
			assert: endsTo(logoutRPBye + "?state=s-1"),
		},
		{
			name: "a registered URI with no state has none added",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye)
			},
			assert: endsTo(logoutRPBye),
		},
		{
			name: "client_id equal to the hint's audience is accepted",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID), "client_id", flowWeb,
					"post_logout_redirect_uri", logoutRPBye)
			},
			assert: endsTo(logoutRPBye),
		},
		{
			name: "an unregistered URI goes to the logged-out page, the sign-in still ended",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", "https://evil.example.com/bye", "state", "s-1")
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name: "a query added to a registered URI goes to the logged-out page",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye+"?next=https://evil.example.com")
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name: "a URI another client registered goes to the logged-out page",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutNativeBye)
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			// Authorization's rule forgives a loopback port, and this one must not.
			name: "another port on a registered loopback URI is not an exact match",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				hint := w.logoutHint(t, in.session.FamilyID, func(i *token.Issue) { i.Audience = []string{logoutNative} })

				return logoutParams("id_token_hint", hint, "post_logout_redirect_uri", "http://127.0.0.1:9999/bye")
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name: "a hint for a client since removed still ends the sign-in, with no way back to it",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				require.NoError(t, w.registry.Delete(t.Context(), logoutNative))
				hint := w.logoutHint(t, in.session.FamilyID, func(i *token.Issue) { i.Audience = []string{logoutNative} })

				return logoutParams("id_token_hint", hint, "post_logout_redirect_uri", logoutNativeBye)
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name: "logout_hint and ui_locales are accepted and not acted on",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"logout_hint", "someone-else@example.com", "ui_locales", "fr-CA fr en")
			},
			assert: endsTo(opIssuer + logoutByePath),
		},
		{
			name:  "WithLogoutConfirmation asks even on a matching hint",
			setup: logoutSetup{flowSetup: flowSetup{provider: []oidcprovider.Option{oidcprovider.WithLogoutConfirmation()}}},
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "state", "s-1")
			},
			assert: func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
				t.Helper()

				r := w.assertParked(t, a)
				assert.Equal(t, logoutRPBye, r.RedirectURI, "a valid hint keeps the way back for the answer")
				assert.Equal(t, "s-1", r.State)
				w.assertStands(t, in)
			},
		},
		{
			name: "no hint asks",
			params: func(*testing.T, *logoutFlow, logoutSignIn) url.Values {
				return url.Values{}
			},
			assert: asks,
		},
		{
			name: "a hint signed by a key no longer published counts as none",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint",
					w.logoutHintFrom(t, w.issuer, logoutRetiredKeys(), w.clk, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "state", "s-1")
			},
			assert: asks,
		},
		{
			name: "client_id and its registered URI with no hint never reach that URI",
			params: func(*testing.T, *logoutFlow, logoutSignIn) url.Values {
				return logoutParams("client_id", flowWeb, "post_logout_redirect_uri", logoutRPBye, "state", "s-1")
			},
			assert: asks,
		},
		{
			name: "a client_id no client holds, with no hint, is no error",
			params: func(*testing.T, *logoutFlow, logoutSignIn) url.Values {
				return logoutParams("client_id", "nobody\x00")
			},
			assert: asks,
		},
		{
			name: "a valid hint for another sign-in asks, and ends neither",
			params: func(t *testing.T, w *logoutFlow, _ logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, w.session(t).FamilyID),
					"post_logout_redirect_uri", logoutRPBye)
			},
			assert: func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
				t.Helper()

				r := w.assertParked(t, a)
				assert.Equal(t, logoutRPBye, r.RedirectURI)
				assert.Equal(t, flowWeb, r.ClientID)
				w.assertStands(t, in)
			},
		},
		{
			name:      "a valid hint in a browser with no session asks, and is no error",
			noBrowser: true,
			params:    hintOnly,
			assert: func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
				t.Helper()

				w.assertParked(t, a)
				w.assertStands(t, in)
			},
		},
		{
			name:  "a provider keeping no browser sessions asks on every hint",
			setup: logoutSetup{withoutBrowsers: true},
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID))
			},
			assert: func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
				t.Helper()

				w.assertParked(t, a)
				w.assertStands(t, in)
			},
		},
		{
			name: "a hint with no sid names no sign-in, and asks",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID, func(i *token.Issue) {
					delete(i.Claims, "sid")
				}))
			},
			assert: func(t *testing.T, w *logoutFlow, in logoutSignIn, a flowAnswer) {
				t.Helper()

				w.assertParked(t, a)
				w.assertStands(t, in)
			},
		},
		{
			name: "a forged hint is refused",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				genuine := strings.Split(w.logoutHint(t, id.Nil), ".")
				named := strings.Split(w.logoutHint(t, in.session.FamilyID), ".")

				return logoutParams("id_token_hint", named[0]+"."+named[1]+"."+genuine[2],
					"post_logout_redirect_uri", logoutRPBye)
			},
			assert: refused,
		},
		{
			name: "a hint whose audience is not client_id is refused",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID), "client_id", flowFirstParty)
			},
			assert: refused,
		},
		{
			name: "a hint with more than one audience is refused, naming no one client",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID, func(i *token.Issue) {
					i.Audience = []string{flowWeb, flowFirstParty}
				}))
			},
			assert: refused,
		},
		{
			name: "an access token offered as a hint is refused",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID, func(i *token.Issue) {
					i.Type = token.TypeAccessToken
				}))
			},
			assert: refused,
		},
		{
			name: "a hint from another issuer is refused",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint",
					w.logoutHintFrom(t, "https://other.example.com", tokenKeys(), w.clk, in.session.FamilyID))
			},
			assert: refused,
		},
		{
			name: "a hint that is no token is refused",
			params: func(*testing.T, *logoutFlow, logoutSignIn) url.Values {
				return logoutParams("id_token_hint", "not-a-token")
			},
			assert: refused,
		},
		{
			name: "a hint past its bound is refused unread",
			params: func(*testing.T, *logoutFlow, logoutSignIn) url.Values {
				return logoutParams("id_token_hint", strings.Repeat("a", 8193))
			},
			assert: refused,
		},
		{
			name: "a repeated hint is refused, because neither can be chosen",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				hint := w.logoutHint(t, in.session.FamilyID)

				return logoutParams("id_token_hint", hint, "id_token_hint", hint)
			},
			assert: refused,
		},
		{
			name: "a repeated redirect URI is refused",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "post_logout_redirect_uri", "https://evil.example.com/")
			},
			assert: refused,
		},
		{
			name: "a state past its bound is refused, and never reflected",
			params: func(t *testing.T, w *logoutFlow, in logoutSignIn) url.Values {
				t.Helper()

				return logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "state", strings.Repeat("s", 2049))
			},
			assert: refused,
		},
		{
			name: "a state a durable store could not hold is refused, and not answered as an outage",
			params: func(*testing.T, *logoutFlow, logoutSignIn) url.Values {
				return logoutParams("state", "s\x00")
			},
			assert: refused,
		},
	}

	send := map[string]func(*logoutFlow, *testing.T, url.Values, ...flowChange) flowAnswer{
		http.MethodGet:  (*logoutFlow).endSessionGET,
		http.MethodPost: (*logoutFlow).endSessionPOST,
	}

	for method, request := range send {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				w := newLogoutFlow(t, tc.setup)
				in := w.signIn(t)
				params := tc.params(t, w, in)

				var change []flowChange
				if in.browser != "" && !tc.noBrowser {
					change = append(change, flowCookieOf(flowSession, in.browser))
				}

				tc.assert(t, w, in, request(w, t, params, change...))
			})
		}
	}
}

// TestOIDCEndSession_Endpoint covers what a row of TestOIDCEndSession cannot share: how
// the endpoint answers what it never reads as a logout request, and what it depends on.
func TestOIDCEndSession_Endpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup logoutSetup
		run   func(t *testing.T, w *logoutFlow)
	}

	oneAllowed := func() httpsec.OIDCProviderOption {
		return httpsec.WithOIDCEndSessionLimiter(must1(ratelimit.NewMemoryLimiter(1, time.Minute)))
	}

	cases := []testCase{
		{
			name: "a method it does not serve is answered here, and never reaches the application",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, w.issuer+logoutEndSessionPath, nil)
				a := w.serve(t, r, nil)
				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, "GET, POST", a.header.Get("Allow"))
				assert.False(t, a.passedOn)
			},
		},
		{
			name: "a request not made over TLS is refused",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				a := w.endSessionGET(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)),
					flowCookieOf(flowSession, in.browser), flowPlainHTTP)
				w.assertRefused(t, a)
				w.assertStands(t, in)
			},
		},
		{
			name:  "the loopback issuer answers plain http, under its unprefixed cookies",
			setup: logoutSetup{flowSetup: flowSetup{issuer: flowLoopback}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				a := w.endSessionGET(t, url.Values{}, flowPlainHTTP)
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.NotNil(t, a.cookie(flowCookiePlain))

				s := w.session(t)
				handle, flow := w.parkIn(t, flowCookiePlain, flowWeb)
				res, err := w.p.Resume(t.Context(), oidcprovider.ResumeInput{
					Handle: handle, FlowSecret: flow, IdleTimeout: w.sessions.IdleTimeout(),
					SignIn: &oidcprovider.SignIn{
						User: s.UserID, Family: s.FamilyID, AuthenticatedAt: s.AuthenticatedAt,
						AbsoluteExpiresAt: s.AbsoluteExpiresAt,
					},
				})
				require.NoError(t, err)

				a = w.endSessionGET(t, logoutParams("id_token_hint", w.logoutHint(t, s.FamilyID)), flowPlainHTTP,
					flowCookieOf(flowSessionPlain, res.BrowserSessionSecret))
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, flowLoopback+logoutByePath, a.header.Get("Location"))

				cleared := a.cookie(flowSessionPlain)
				require.NotNil(t, cleared, "the cookie is cleared by the name it goes by")
				assert.Negative(t, cleared.MaxAge)
				assert.False(t, cleared.Secure)
			},
		},
		{
			name: "a form POST not declared as a form is refused",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+logoutEndSessionPath,
					strings.NewReader(url.Values{}.Encode()))
				r.Header.Set("Content-Type", "text/plain")
				w.assertRefused(t, w.serve(t, r, nil))
			},
		},
		{
			name: "a query that does not parse is refused",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					w.issuer+logoutEndSessionPath+"?id_token_hint=%zz", nil)
				w.assertRefused(t, w.serve(t, r, nil))
			},
		},
		{
			name:  "a body past the limit is refused",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCEndSessionBodyLimit(4)}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				a := w.endSessionPOST(t, logoutParams("logout_hint", "longer-than-the-limit"))
				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
				assert.Zero(t, w.parked.count())
			},
		},
		{
			name: "a grant store failing answers 500, with the session still loadable and no redirect",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				w.grantsAt.outage.Store(true)

				a := w.endSessionGET(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)),
					flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				assert.Empty(t, a.header.Get("Location"))
				assert.NotContains(t, a.body, "secret-store-text")
				assert.Nil(t, a.cookie(flowSession))

				_, err := w.sessions.Load(t.Context(), in.session.ID)
				require.NoError(t, err, "the sign-in's session is not deleted past a failure")
			},
		},
		{
			name: "the end is reported as a logout's is",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				a := w.endSessionGET(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)),
					flowCookieOf(flowSession, in.browser))
				require.Equal(t, http.StatusSeeOther, a.status)

				for _, name := range []string{event.SessionLogout, event.AuthnTokenRevoked} {
					got := w.events.named(name)
					require.Len(t, got, 1, name)
					assert.Equal(t, in.session.UserID, got[0].User)
					assert.Equal(t, event.OutcomeSuccess, got[0].Outcome)
				}
			},
		},
		{
			name: "a sign-in with no session left reports no logout",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				gone := w.session(t)
				gone.FamilyID = logoutNewID(t)

				a := w.endSessionGET(t, logoutParams("id_token_hint", w.logoutHint(t, gone.FamilyID)),
					flowCookieOf(flowSession, w.browserSession(t, gone)))
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, opIssuer+logoutByePath, a.header.Get("Location"), "there was still a browser session to end")
				assert.Empty(t, w.events.named(event.SessionLogout), "no session of the family was there to end")
			},
		},
		{
			name: "a limiter that cannot answer is refused, failing closed",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCEndSessionLimiter(flowDownLimiter{}),
			}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				a := w.endSessionGET(t, url.Values{})
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
				assert.Zero(t, w.parked.count())
			},
		},
		{
			name:  "a parked request is charged to its source, and a source past its limit is refused unread",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{oneAllowed()}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, w.endSessionGET(t, url.Values{}).status)

				a := w.endSessionGET(t, url.Values{})
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
				assert.Equal(t, 1, w.parked.count(), "a refused source parks nothing")

				other := w.endSessionGET(t, url.Values{}, flowFrom(flowOtherAddr))
				assert.Equal(t, http.StatusSeeOther, other.status, "another source has its own count")
			},
		},
		{
			name:  "a refused hint is charged to its source",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{oneAllowed()}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				params := logoutParams("id_token_hint", "not-a-token")
				w.assertRefused(t, w.endSessionGET(t, params))

				a := w.endSessionGET(t, params)
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
			},
		},
		{
			name:  "a sign-in ended with no question costs its source nothing",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{oneAllowed()}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				for range 2 {
					in := w.signIn(t)
					a := w.endSessionGET(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)),
						flowCookieOf(flowSession, in.browser))
					require.Equal(t, http.StatusSeeOther, a.status, a.body)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newLogoutFlow(t, tc.setup))
		})
	}
}

// TestOIDCEndSession_Options covers what the endpoint's options refuse.
func TestOIDCEndSession_Options(t *testing.T) {
	t.Parallel()

	var nilLimiter *ratelimit.MemoryLimiter

	type testCase struct {
		name string
		opt  httpsec.OIDCProviderOption
		says string
	}

	cases := []testCase{
		{name: "a nil limiter", opt: httpsec.WithOIDCEndSessionLimiter(nil), says: "WithOIDCEndSessionLimiter"},
		{name: "a typed nil limiter", opt: httpsec.WithOIDCEndSessionLimiter(nilLimiter), says: "WithOIDCEndSessionLimiter"},
		{name: "a zero body limit", opt: httpsec.WithOIDCEndSessionBodyLimit(0), says: "WithOIDCEndSessionBodyLimit"},
		{name: "a negative body limit", opt: httpsec.WithOIDCEndSessionBodyLimit(-1), says: "WithOIDCEndSessionBodyLimit"},
		{name: "a nil confirm limiter", opt: httpsec.WithOIDCLogoutConfirmLimiter(nil), says: "WithOIDCLogoutConfirmLimiter"},
		{name: "a typed nil confirm limiter", opt: httpsec.WithOIDCLogoutConfirmLimiter(nilLimiter), says: "WithOIDCLogoutConfirmLimiter"},
		{name: "a zero confirm body limit", opt: httpsec.WithOIDCLogoutConfirmBodyLimit(0), says: "WithOIDCLogoutConfirmBodyLimit"},
		{name: "a negative confirm body limit", opt: httpsec.WithOIDCLogoutConfirmBodyLimit(-1), says: "WithOIDCLogoutConfirmBodyLimit"},
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

// logoutQuote is v as a JSON string.
func logoutQuote(v string) string { return strconv.Quote(v) }

// logoutDoc reads an answer's document.
func logoutDoc(t *testing.T, a flowAnswer) map[string]any {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)

	return doc
}
