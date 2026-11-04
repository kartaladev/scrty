package httpsec_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

const (
	endsClient      = "billing-web"
	endsLogoutURI   = "https://rp.example.com/backchannel"
	endsOnlineScope = "openid profile"
	endsOffline     = "openid profile offline_access"

	// endsOutageText is what a failing grant store says, which nothing may repeat.
	endsOutageText = "the grant store holds row 42 and cannot reach it"
)

// faultyGrants is the default grant store, made to fail a sign-in's end on demand.
type faultyGrants struct {
	*oidcprovider.MemoryGrantStore

	failing atomic.Bool
	// during runs as an end begins, to change what surrounds it.
	during atomic.Pointer[func()]
}

func (g *faultyGrants) EndSignIns(
	ctx context.Context, sel oidcprovider.SignInSelector, at time.Time,
) ([]oidcprovider.Grant, error) {
	if during := g.during.Load(); during != nil {
		(*during)()
	}

	if g.failing.Load() {
		return nil, errors.New(endsOutageText)
	}

	return g.MemoryGrantStore.EndSignIns(ctx, sel, at)
}

// faultyBrowsers is the default browser-session store, made to fail on demand.
type faultyBrowsers struct {
	*oidcprovider.MemoryBrowserSessionStore

	failing atomic.Bool
}

func (b *faultyBrowsers) DeleteBySignIn(ctx context.Context, sel oidcprovider.SignInSelector) (int, error) {
	if b.failing.Load() {
		return 0, errors.New(endsOutageText)
	}

	return b.MemoryBrowserSessionStore.DeleteBySignIn(ctx, sel)
}

// toldClients keeps the logout tokens handed to delivery, as a relying party's queue would.
type toldClients struct {
	mu     sync.Mutex
	tokens []string
	uris   []string

	refusing atomic.Bool
}

func (c *toldClients) Deliver(_ context.Context, uri, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tokens, c.uris = append(c.tokens, token), append(c.uris, uri)

	if c.refusing.Load() {
		return errors.New("the relying party answered 500")
	}

	return nil
}

// endsEvents keeps what the provider reports.
type endsEvents struct {
	mu  sync.Mutex
	all []event.Event
}

func (s *endsEvents) sink(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.all = append(s.all, e)
}

func (s *endsEvents) named(name string) []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []event.Event

	for _, e := range s.all {
		if e.Name == name {
			out = append(out, e)
		}
	}

	return out
}

// signInEnds is a provider on a chain with every path that can end a sign-in, and a
// client that registered a back-channel logout URI. Its stores fail on demand, and what
// its client is told is kept.
type signInEnds struct {
	*opFlow

	grants   *faultyGrants
	browsers *faultyBrowsers
	told     *toldClients
	events   *endsEvents
	logs     *syncBuffer
	creds    *passkey.MemoryCredentialStore
}

// endsSetup is what a test asks of the fixture beyond its defaults.
type endsSetup struct {
	// logoutFirst enables logout before the provider, so that the order the options
	// are given in is what a row varies.
	logoutFirst bool
	// chain adds options, given the fixture with its manager built.
	chain func(t *testing.T, f *signInEnds) []httpsec.Option
}

func newSignInEnds(t *testing.T, setup endsSetup) *signInEnds {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	f := &signInEnds{
		opFlow: &opFlow{issuer: opIssuer, clk: clk},
		told:   &toldClients{},
		events: &endsEvents{},
		logs:   &syncBuffer{},
		creds:  passkey.NewMemoryCredentialStore(),
		grants: &faultyGrants{MemoryGrantStore: must.Must(oidcprovider.NewMemoryGrantStore(
			oidcprovider.WithMemoryStoreClock(clk)))},
		browsers: &faultyBrowsers{MemoryBrowserSessionStore: must.Must(oidcprovider.NewMemoryBrowserSessionStore(
			oidcprovider.WithMemoryStoreClock(clk)))},
	}

	f.registry = &flowRegistry{MemoryRegistry: must.Must(oidcprovider.NewMemoryRegistry([]oidcprovider.Client{{
		ID: endsClient, Name: "Billing", Type: oidcprovider.Confidential, Secret: []byte(tokenSecret),
		RedirectURIs: []string{rpCallback}, Scopes: strings.Fields(endsOffline),
		GrantTypes:           []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		BackChannelLogoutURI: endsLogoutURI,
	}}))}
	f.consents = must.Must(oidcprovider.NewMemoryConsentStore())

	f.users = NewMockUserLoader(gomock.NewController(t))
	f.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: user, Username: string(user), Active: true}, nil
		},
	).AnyTimes()

	var err error

	f.p, err = oidcprovider.New(oidcprovider.Deps{
		Issuer:       f.issuer,
		Registry:     f.registry,
		Keys:         tokenKeys(),
		Users:        f.users,
		LoginURL:     f.issuer + "/login",
		ConsentURL:   f.issuer + "/consent",
		LogoutURL:    f.issuer + "/logout-page",
		LoggedOutURL: f.issuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))),
		oidcprovider.WithConsentStore(f.consents),
		oidcprovider.WithGrantStore(f.grants),
		oidcprovider.WithBrowserSessionStore(f.browsers),
		oidcprovider.WithLogoutDelivery(f.told),
		oidcprovider.WithSecurityEvents(f.events.sink),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.p.Shutdown(context.Background()) }) //nolint:usetesting // t.Context has ended by now

	f.sessions = must.Must(session.New(
		session.WithClock(clk),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))),
		session.WithEndObserver(f.p),
	))

	logout := httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions})
	provider := httpsec.EnableOIDCProvider(f.p)

	opts := []httpsec.Option{
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: f.users}),
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
			f.lastErr.Store(&err)
			rw.WriteHeader(httpsec.StatusForError(err))
		}),
	}
	if setup.logoutFirst {
		opts = append(opts, logout, provider)
	} else {
		opts = append(opts, provider, logout)
	}

	if setup.chain != nil {
		opts = append(opts, setup.chain(t, f)...)
	}

	f.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return f
}

// signIn stores a new password sign-in of u-1.
func (f *signInEnds) signIn(t *testing.T) *session.Session {
	t.Helper()

	return f.session(t)
}

// endsGrant is what a sign-in left a client holding, and the browser holding.
type endsGrant struct {
	refresh string
	browser string
}

// grantFrom runs the authorization code flow through the chain, from the sign-in s,
// and exchanges the code for its tokens. scope says whether the grant holds offline_access.
func (f *signInEnds) grantFrom(t *testing.T, s *session.Session, scope string) endsGrant {
	t.Helper()

	require.NoError(t, f.consents.Give(t.Context(), s.UserID, endsClient, strings.Fields(scope),
		strings.Contains(scope, "offline_access"), f.clk.Now()))

	handle, flow := f.park(t, endsClient, func(v url.Values) {
		v.Set("scope", scope)
	})

	resumed := f.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	require.Equal(t, http.StatusOK, resumed.status, resumed.body)

	code := resumed.redirectTo(t).Query().Get("code")
	require.NotEmpty(t, code, resumed.body)

	exchanged := f.atToken(t, exchangeOf(code))
	require.Equal(t, http.StatusOK, exchanged.status, exchanged.body)

	var doc struct {
		Refresh string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(exchanged.body), &doc), exchanged.body)
	require.NotEmpty(t, doc.Refresh, exchanged.body)

	return endsGrant{refresh: doc.Refresh, browser: resumed.sessionSecret(t)}
}

// atToken posts form to the token endpoint, as the client.
func (f *signInEnds) atToken(t *testing.T, form url.Values) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+"/oauth2/token",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(endsClient, tokenSecret)

	return f.serve(t, r, nil)
}

// refreshRefused is the check that a grant has ended.
func (f *signInEnds) refreshRefused(t *testing.T, g endsGrant) {
	t.Helper()

	a := f.atToken(t, refreshOf(g.refresh))
	assert.Equal(t, http.StatusBadRequest, a.status, a.body)
	assert.Contains(t, a.body, "invalid_grant")
}

// refreshWorks is the check that a grant still stands.
func (f *signInEnds) refreshWorks(t *testing.T, g endsGrant) {
	t.Helper()

	a := f.atToken(t, refreshOf(g.refresh))
	assert.Equal(t, http.StatusOK, a.status, a.body)
}

// silentError is what a prompt=none request from this browser is answered with:
// empty when the browser's session answers it.
func (f *signInEnds) silentError(t *testing.T, g endsGrant) string {
	t.Helper()

	a := f.authorizeGET(t, flowParams(endsClient, func(v url.Values) { v.Set("prompt", "none") }),
		flowCookieOf(flowSession, g.browser))
	require.Equal(t, http.StatusSeeOther, a.status, a.body)

	return a.location(t).Query().Get("error")
}

// endsToken is what a logout token states.
type endsToken struct {
	Sub string   `json:"sub"`
	Sid string   `json:"sid"`
	Aud []string `json:"aud"`
}

// toldOf waits for every delivery to finish, which stops the provider's delivery,
// and returns the tokens its client was told.
func (f *signInEnds) toldOf(t *testing.T) []endsToken {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	require.NoError(t, f.p.Shutdown(ctx))

	f.told.mu.Lock()
	defer f.told.mu.Unlock()

	out := make([]endsToken, 0, len(f.told.tokens))

	for i, raw := range f.told.tokens {
		assert.Equal(t, endsLogoutURI, f.told.uris[i])

		parts := strings.Split(raw, ".")
		require.Len(t, parts, 3)

		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var tok endsToken
		require.NoError(t, json.Unmarshal(payload, &tok))
		out = append(out, tok)
	}

	return out
}

// sidsOf are the sign-ins the tokens name.
func sidsOf(tokens []endsToken) []string {
	sids := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		sids = append(sids, tok.Sid)
	}

	return sids
}

// loads reports whether a session still loads.
func (f *signInEnds) loads(t *testing.T, s *session.Session) bool {
	t.Helper()

	_, err := f.sessions.Load(t.Context(), s.ID)
	if err == nil {
		return true
	}

	assert.ErrorIs(t, err, session.ErrNotFound)

	return false
}

// logoutAs posts the chain's logout under the sign-in s.
func (f *signInEnds) logoutAs(t *testing.T, s *session.Session) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+httpsec.DefaultLogoutPath, nil)

	return f.serve(t, r, []flowChange{flowBearer(s.ID)})
}

// TestLogout_EndsProviderGrants pins that the chain's logout ends the sign-in through
// the provider before it deletes the sessions, so that a failure leaves it to retry.
func TestLogout_EndsProviderGrants(t *testing.T) {
	t.Parallel()

	type scene struct {
		s, other      *session.Session
		online, offln endsGrant
		otherGrant    endsGrant
	}

	type testCase struct {
		name    string
		setup   endsSetup
		arrange func(f *signInEnds)
		assert  func(t *testing.T, f *signInEnds, sc scene, a flowAnswer)
	}

	outage := func(mark func(f *signInEnds) *atomic.Bool) func(*testing.T, *signInEnds, scene, flowAnswer) {
		return func(t *testing.T, f *signInEnds, sc scene, a flowAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusInternalServerError, a.status)
			require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
			assert.NotContains(t, a.err.Error(), endsOutageText, "the store's text stays behind fixed text")
			assert.Empty(t, a.header.Get("Clear-Site-Data"))
			assert.True(t, f.loads(t, sc.s), "a failed logout leaves the session to retry from")
			assert.Empty(t, f.events.named(event.SessionLogout), "nothing that did not happen is reported")

			mark(f).Store(false)

			retried := f.logoutAs(t, sc.s)
			assert.Equal(t, http.StatusOK, retried.status, retried.body)
			assert.False(t, f.loads(t, sc.s))
			f.refreshRefused(t, sc.online)
			assert.Equal(t, "login_required", f.silentError(t, sc.online))
			assert.Equal(t, []string{sc.s.FamilyID.String()}, sidsOf(f.toldOf(t)), "told once, whatever it took")
		}
	}

	ended := func(t *testing.T, f *signInEnds, sc scene, a flowAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusOK, a.status, a.body)
		assert.Empty(t, a.body)
		assert.False(t, f.loads(t, sc.s))
		f.refreshRefused(t, sc.online)
		f.refreshWorks(t, sc.offln)
		f.refreshWorks(t, sc.otherGrant)
		assert.True(t, f.loads(t, sc.other), "another sign-in is not this logout's to end")
		assert.Equal(t, "login_required", f.silentError(t, sc.online))
		assert.Empty(t, f.silentError(t, sc.otherGrant), "the other sign-in's browser session stands")

		told := f.toldOf(t)
		require.Len(t, told, 1, "one client, one ended sign-in, one token")
		assert.Equal(t, endsToken{Sub: "u-1", Sid: sc.s.FamilyID.String(), Aud: []string{endsClient}}, told[0])
	}

	cases := []testCase{
		{
			name:   "a logout revokes the online grant, keeps the offline one and tells the client once",
			assert: ended,
		},
		{
			name:   "logout enabled before the provider ends grants all the same",
			setup:  endsSetup{logoutFirst: true},
			assert: ended,
		},
		{
			name:    "a grant store failure answers 500, leaves the session, and a retry succeeds",
			arrange: func(f *signInEnds) { f.grants.failing.Store(true) },
			assert:  outage(func(f *signInEnds) *atomic.Bool { return &f.grants.failing }),
		},
		{
			name:    "logout enabled before the provider still fails on a grant store failure",
			setup:   endsSetup{logoutFirst: true},
			arrange: func(f *signInEnds) { f.grants.failing.Store(true) },
			assert:  outage(func(f *signInEnds) *atomic.Bool { return &f.grants.failing }),
		},
		{
			name:    "a browser store failure answers 500, leaves the session, and a retry succeeds",
			arrange: func(f *signInEnds) { f.browsers.failing.Store(true) },
			assert:  outage(func(f *signInEnds) *atomic.Bool { return &f.browsers.failing }),
		},
		{
			name:    "a failed notification does not fail the logout",
			arrange: func(f *signInEnds) { f.told.refusing.Store(true) },
			assert: func(t *testing.T, f *signInEnds, sc scene, a flowAnswer) {
				t.Helper()

				ended(t, f, sc, a)

				require.Len(t, f.events.named(event.LogoutDeliveryFailed), 1)
				assert.NotContains(t, f.logs.String(), f.told.tokens[0], "no token is logged")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignInEnds(t, tc.setup)
			sc := scene{s: f.signIn(t), other: f.signIn(t)}
			sc.online = f.grantFrom(t, sc.s, endsOnlineScope)
			sc.offln = f.grantFrom(t, sc.s, endsOffline)
			sc.otherGrant = f.grantFrom(t, sc.other, endsOnlineScope)

			if tc.arrange != nil {
				tc.arrange(f)
			}

			tc.assert(t, f, sc, f.logoutAs(t, sc.s))
		})
	}
}

// TestLogout_EndsProviderGrants_RequestShapes pins the edges of what reaches the provider.
func TestLogout_EndsProviderGrants_RequestShapes(t *testing.T) {
	t.Parallel()

	t.Run("a client hanging up during the revocation still ends the sign-in", func(t *testing.T) {
		t.Parallel()

		f := newSignInEnds(t, endsSetup{})
		s := f.signIn(t)
		g := f.grantFrom(t, s, endsOnlineScope)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		hangUp := func() { cancel() }
		f.grants.during.Store(&hangUp)

		r := httptest.NewRequestWithContext(ctx, http.MethodPost, f.issuer+httpsec.DefaultLogoutPath, nil)
		a := f.serve(t, r, []flowChange{flowBearer(s.ID)})

		f.grants.during.Store(nil)

		assert.Equal(t, http.StatusOK, a.status, a.body)
		assert.False(t, f.loads(t, s))
		f.refreshRefused(t, g)
	})

	t.Run("a session with no family stays the manager's to refuse, and the provider is not asked", func(t *testing.T) {
		t.Parallel()

		f := newSignInEnds(t, endsSetup{chain: func(*testing.T, *signInEnds) []httpsec.Option {
			return []httpsec.Option{httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					familyless := *ex.Session
					familyless.FamilyID = id.Nil
					ex.Session = &familyless

					return next(ex)
				}), httpsec.Before(httpsec.OrderLogout))}
		}})
		s := f.signIn(t)

		a := f.logoutAs(t, s)

		assert.Equal(t, http.StatusInternalServerError, a.status)
		require.Error(t, a.err)
		assert.NotErrorIs(t, a.err, oidcprovider.ErrConfig, "a selector of no shape was never built")
		assert.True(t, f.loads(t, s))
	})
}

// endPaths are the ways a sign-in ends other than the chain's logout. Each ends s, and
// says whether the user's other sign-in is spared.
type endPath struct {
	name string
	// spares says that the other sign-in is not ended.
	spares bool
	// end ends s, presenting other where the path needs a presenter.
	end func(t *testing.T, f *signInEnds, s, other *session.Session)
}

func endPaths() []endPath {
	return []endPath{
		{
			name:   "a superseded identifier presented past its window",
			spares: true,
			end: func(t *testing.T, f *signInEnds, s, _ *session.Session) {
				t.Helper()

				_, _, err := f.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
				require.NoError(t, err)
				f.clk.Advance(5 * time.Minute)

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, f.issuer+"/api/orders", nil)
				a := f.serve(t, r, []flowChange{flowBearer(s.ID)})
				require.Equal(t, http.StatusUnauthorized, a.status)
				require.ErrorIs(t, a.err, session.ErrReused)
			},
		},
		{
			name:   "ending one sign-in by its handle",
			spares: true,
			end: func(t *testing.T, f *signInEnds, s, other *session.Session) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
					f.issuer+httpsec.DefaultSessionManagementPrefix+"/"+s.FamilyID.String(), nil)
				a := f.serve(t, r, []flowChange{flowBearer(other.ID)})
				require.Less(t, a.status, http.StatusBadRequest, a.body)
			},
		},
		{
			name:   "ending the user's other sign-ins",
			spares: true,
			end: func(t *testing.T, f *signInEnds, _, other *session.Session) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
					f.issuer+httpsec.DefaultSessionManagementPrefix, nil)
				a := f.serve(t, r, []flowChange{flowBearer(other.ID)})
				require.Less(t, a.status, http.StatusBadRequest, a.body)
			},
		},
		{
			name:   "a passkey removal ending the user's other sessions",
			spares: true,
			end: func(t *testing.T, f *signInEnds, _, other *session.Session) {
				t.Helper()

				cid := must.Must(id.NewV7Generator().NewID())
				require.NoError(t, f.creds.Insert(t.Context(), &passkey.Credential{
					ID: cid, User: other.UserID, CredentialID: []byte("cred"), PublicKey: []byte("cose"),
					Name: "Laptop", CreatedAt: f.clk.Now().Add(-time.Hour), State: passkey.StateActive,
				}))

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					f.issuer+httpsec.DefaultPasskeyCredentialsPrefix+"/remove",
					strings.NewReader(url.Values{"id": {cid.String()}}.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				a := f.serve(t, r, []flowChange{flowBearer(other.ID)})
				require.Equal(t, http.StatusNoContent, a.status, "%s %v", a.body, a.err)
			},
		},
		{
			name: "deleting the user's sessions through the manager",
			end: func(t *testing.T, f *signInEnds, s, _ *session.Session) {
				t.Helper()

				require.NoError(t, f.sessions.DeleteByUser(t.Context(), s.UserID))
			},
		},
		{
			// Delete removes the one session, and its family's grants go with it: the
			// provider cannot tell whether a successor outlives it.
			name:   "deleting one session through the manager",
			spares: true,
			end: func(t *testing.T, f *signInEnds, s, _ *session.Session) {
				t.Helper()

				require.NoError(t, f.sessions.Delete(t.Context(), s.ID))
			},
		},
		{
			// The kept session is another user's, so the report keeps no family, which
			// spares nothing: the safe mistake.
			name: "deleting all but a session the report cannot name",
			end: func(t *testing.T, f *signInEnds, s, _ *session.Session) {
				t.Helper()

				stranger, err := f.sessions.Create(t.Context(), "u-2", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				_, err = f.sessions.DeleteByUserExcept(t.Context(), s.UserID, stranger.ID)
				require.NoError(t, err)
			},
		},
	}
}

// signInEndsChain is every endpoint the paths above reach.
func signInEndsChain(t *testing.T, f *signInEnds) []httpsec.Option {
	t.Helper()

	manager, err := passkey.New(passkey.Deps{
		Verifier:    newPasskeyVerifierStub(t).mock,
		Credentials: f.creds,
		Users:       f.users,
		Sender:      &capturingSender{},
		Sessions:    f.sessions,
	}, passkey.WithRepudiationContact("help@example.com"), passkey.WithOptionalRecoveryCodes(),
		passkey.WithoutCloneGrantRevocation())
	require.NoError(t, err)

	return []httpsec.Option{
		httpsec.EnableSessionManagement(),
		httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: manager, Sessions: f.sessions, Users: f.users}),
	}
}

// TestOIDCProvider_SignInEnds pins that each end through the session manager reaches
// the provider: the online grant ends, the offline one stands, the client is told of
// the sign-in once, and the sign-in's browser session goes.
func TestOIDCProvider_SignInEnds(t *testing.T) {
	t.Parallel()

	for _, path := range endPaths() {
		t.Run(path.name, func(t *testing.T) {
			t.Parallel()

			f := newSignInEnds(t, endsSetup{chain: signInEndsChain})
			s, other := f.signIn(t), f.signIn(t)
			online := f.grantFrom(t, s, endsOnlineScope)
			offline := f.grantFrom(t, s, endsOffline)
			otherGrant := f.grantFrom(t, other, endsOnlineScope)

			path.end(t, f, s, other)

			f.refreshRefused(t, online)
			f.refreshWorks(t, offline)
			assert.Equal(t, "login_required", f.silentError(t, online), "the browser session ended with its sign-in")

			if path.spares {
				f.refreshWorks(t, otherGrant)
				assert.Empty(t, f.silentError(t, otherGrant), "the spared sign-in's browser session stands")
				assert.Equal(t, []string{s.FamilyID.String()}, sidsOf(f.toldOf(t)))

				return
			}

			f.refreshRefused(t, otherGrant)
			assert.Equal(t, "login_required", f.silentError(t, otherGrant))
			assert.ElementsMatch(t, []string{s.FamilyID.String(), other.FamilyID.String()}, sidsOf(f.toldOf(t)))
		})
	}
}

// TestOIDCProvider_SignInEnds_Failures pins that a grant store failing never undoes an
// end: the sessions stay ended, the browser session still goes, and the log says so
// without the store's text.
func TestOIDCProvider_SignInEnds_Failures(t *testing.T) {
	t.Parallel()

	for _, path := range endPaths() {
		t.Run(path.name, func(t *testing.T) {
			t.Parallel()

			f := newSignInEnds(t, endsSetup{chain: signInEndsChain})
			s, other := f.signIn(t), f.signIn(t)
			g := f.grantFrom(t, s, endsOnlineScope)

			f.grants.failing.Store(true)
			path.end(t, f, s, other)
			f.grants.failing.Store(false)

			assert.False(t, f.loads(t, s), "the end stands")
			assert.Equal(t, "login_required", f.silentError(t, g), "the browser session went all the same")

			logs := f.logs.String()
			assert.Contains(t, logs, "level=ERROR")
			assert.Contains(t, logs, "could not be ended")
			assert.NotContains(t, logs, endsOutageText)
			assert.Empty(t, f.toldOf(t), "nothing ended here for a client to be told of")
		})
	}
}

// TestOIDCProvider_SignInEnds_Expiry pins that a sign-in reaching a deadline ends
// nothing at the provider, whether it is read after it or swept.
func TestOIDCProvider_SignInEnds_Expiry(t *testing.T) {
	t.Parallel()

	f := newSignInEnds(t, endsSetup{chain: signInEndsChain})
	s := f.signIn(t)
	f.grantFrom(t, s, endsOnlineScope)

	f.clk.Advance(f.sessions.IdleTimeout() + time.Minute)

	_, err := f.sessions.Load(t.Context(), s.ID)
	require.ErrorIs(t, err, session.ErrExpired)

	_, err = f.sessions.DeleteExpired(t.Context())
	require.NoError(t, err)

	assert.Empty(t, f.toldOf(t), "no logout token is sent")
	assert.Empty(t, f.events.named(event.GrantRevoked), "the grant ends by its own deadline")
}
