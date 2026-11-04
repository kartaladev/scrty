package httpsec_test

// These tests run a real provider, because what they pin is that a client's real
// refresh token stops working. The provider's grants sit over the memory store
// behind a thin decorator, so a row can fail the revocation or see when it ran.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// *oidcprovider.Provider is what every package's own port is declared for.
var (
	_ recovery.GrantRevoker = (*oidcprovider.Provider)(nil)
	_ mfa.GrantRevoker      = (*oidcprovider.Provider)(nil)
	_ passkey.GrantRevoker  = (*oidcprovider.Provider)(nil)
)

// watchedGrants is the provider's grant store with its revocation by user in view.
type watchedGrants struct {
	oidcprovider.GrantStore

	mu    sync.Mutex
	err   error
	order *[]string
	cause []oidcprovider.RevocationCause
}

func (g *watchedGrants) RevokeByUser(
	ctx context.Context, user identity.UserID, cause oidcprovider.RevocationCause, at time.Time,
) ([]oidcprovider.Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.order != nil {
		*g.order = append(*g.order, "revoke")
	}
	if g.err != nil {
		return nil, g.err
	}

	g.cause = append(g.cause, cause)

	return g.GrantStore.RevokeByUser(ctx, user, cause, at)
}

// fail makes the revocation fail with err, or succeed again with nil.
func (g *watchedGrants) fail(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.err = err
}

// causes reports the causes the revocations that succeeded recorded.
func (g *watchedGrants) causes() []oidcprovider.RevocationCause {
	g.mu.Lock()
	defer g.mu.Unlock()

	return append([]oidcprovider.RevocationCause(nil), g.cause...)
}

// grantWorld is a provider holding grants for u-1, its token endpoint on a chain
// of its own, and a session manager reporting to it that a chain under test
// resolves its sign-ins through.
type grantWorld struct {
	*tokenEndpoint

	grants   *watchedGrants
	sessions *session.Sessions
	users    *MockUserLoader
}

func newGrantWorld(t *testing.T) *grantWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	consents := must.Must(oidcprovider.NewMemoryConsentStore())
	grants := &watchedGrants{GrantStore: must.Must(oidcprovider.NewMemoryGrantStore())}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			d := storedUser()
			d.ID = user

			return d, nil
		},
	).AnyTimes()

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: opIssuer,
		Clients: []oidcprovider.Client{{
			ID: tokenWeb, Type: oidcprovider.Confidential, Secret: []byte(tokenSecret),
			RedirectURIs: []string{rpCallback},
			Scopes:       []string{"openid", "profile", "offline_access"},
			GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		}},
		Keys:         tokenKeys(),
		Users:        users,
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout-page",
		LoggedOutURL: opIssuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithoutBrowserSessions(),
	)
	require.NoError(t, err)

	f := &opFixture{keys: tokenKeys()}
	chain, err := httpsec.New(append(f.wired(t, p), httpsec.WithClock(clk), httpsec.EnableOIDCProvider(p))...)
	require.NoError(t, err)

	return &grantWorld{
		tokenEndpoint: &tokenEndpoint{p: p, chain: chain, clk: clk, consents: consents},
		grants:        grants,
		users:         users,
		sessions: must.Must(session.New(
			session.WithClock(clk),
			session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))),
			session.WithIdleTimeout(7*24*time.Hour),
			session.WithAbsoluteTimeout(30*24*time.Hour),
			session.WithEndObserver(p),
		)),
	}
}

// chainWith builds the chain under test, over the world's provider and sessions.
func (w *grantWorld) chainWith(t *testing.T, opts ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	all := []httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(w.p),
	}

	chain, err := httpsec.New(append(all, opts...)...)
	require.NoError(t, err)

	return chain
}

// signIn stores a new sign-in of u-1.
func (w *grantWorld) signIn(t *testing.T) *session.Session {
	t.Helper()

	return must.Must(w.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password)))
}

// refreshToken is a real refresh token a client holds for u-1, offline access
// included.
func (w *grantWorld) refreshToken(t *testing.T) string {
	t.Helper()

	issued := assertTokenIssued(t, w.send(t, exchangeOf(w.issue(t, tokenWeb, nil)), asClient(tokenWeb)), "Bearer")
	refresh, ok := issued["refresh_token"].(string)
	require.True(t, ok, "the client holds offline_access, so a refresh token is issued")

	return refresh
}

// assertGrantWorks proves the client's grant is alive, by using it.
func (w *grantWorld) assertGrantWorks(t *testing.T, refresh string) {
	t.Helper()

	assertTokenIssued(t, w.send(t, refreshOf(refresh), asClient(tokenWeb)), "Bearer")
}

// assertGrantRevoked proves the client's grant is over, by trying it.
func (w *grantWorld) assertGrantRevoked(t *testing.T, refresh string) {
	t.Helper()

	assertTokenRefused(t, w.send(t, refreshOf(refresh), asClient(tokenWeb)), "invalid_grant")
}

// answerOf runs req through chain's net/http middleware, which writes the status
// an error maps to.
func answerOf(chain *httpsec.Chain, req *http.Request) (*httptest.ResponseRecorder, bool) {
	var passedOn bool

	rec := httptest.NewRecorder()
	chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true })).ServeHTTP(rec, req)

	return rec, passedOn
}

// asSignIn is a request carrying s as its session reference.
func asSignIn(t *testing.T, method, path string, s *session.Session, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+s.ID)

	return req
}

func TestPasswordChange_RevokesGrants(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("grant store secret text")

	type world struct {
		*grantWorld

		chain   *httpsec.Chain
		signIn  *session.Session
		refresh string
		order   []string
	}

	type testCase struct {
		name   string
		opts   []httpsec.PasswordChangeOption
		arm    func(w *world)
		change func(w *world) httpsec.ChangePasswordFunc
		assert func(t *testing.T, w *world, rec *httptest.ResponseRecorder)
	}

	writes := func(w *world) httpsec.ChangePasswordFunc {
		return func(ex *httpsec.Exchange) error {
			w.order = append(w.order, "write")
			ex.Writer.WriteHeader(http.StatusNoContent)

			return nil
		}
	}

	revoking := []httpsec.PasswordChangeOption{httpsec.WithPasswordChangeGrantRevocation()}

	cases := []testCase{
		{
			name:   "the default keeps the grants",
			change: writes,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, rec.Code)
				assert.Equal(t, []string{"write"}, w.order, "no revocation ran")
				w.assertGrantWorks(t, w.refresh)
			},
		},
		{
			name:   "the option revokes every grant, offline access included, before the password is written",
			opts:   revoking,
			change: writes,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, rec.Code)
				assert.Equal(t, []string{"revoke", "write"}, w.order)
				assert.Equal(t, []oidcprovider.RevocationCause{oidcprovider.CausePasswordChange}, w.grants.causes())
				w.assertGrantRevoked(t, w.refresh)
			},
		},
		{
			name:   "a revoker failure answers 500 with the password unchanged, and a retry succeeds",
			opts:   revoking,
			arm:    func(w *world) { w.grants.fail(errOutage) },
			change: writes,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusInternalServerError, rec.Code)
				assert.Equal(t, []string{"revoke"}, w.order, "the password was not written")
				assert.NotContains(t, rec.Body.String(), "secret text")

				s, err := w.sessions.Load(t.Context(), w.signIn.ID)
				require.NoError(t, err)
				assert.True(t, s.PasswordChangePending, "the debt is still owed")

				w.grants.fail(nil)
				retry, _ := answerOf(w.chain, asSignIn(t, http.MethodPost, passwordResolvePath, w.signIn, ""))
				assert.Equal(t, http.StatusNoContent, retry.Code)
				w.assertGrantRevoked(t, w.refresh)
			},
		},
		{
			name: "a change the consumer refuses has already revoked: the revocation comes first",
			opts: revoking,
			change: func(*world) httpsec.ChangePasswordFunc {
				return func(*httpsec.Exchange) error { return errChangeRefused }
			},
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.NotEqual(t, http.StatusNoContent, rec.Code)
				w.assertGrantRevoked(t, w.refresh)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := &world{grantWorld: newGrantWorld(t)}
			w.grants.order = &w.order
			w.refresh = w.refreshToken(t)

			w.signIn = w.grantWorld.signIn(t)
			w.signIn.PasswordChangePending = true
			require.NoError(t, w.sessions.Save(t.Context(), w.signIn))

			opts := append([]httpsec.PasswordChangeOption{
				httpsec.WithPasswordChangeEndpoint(passwordResolvePath, tc.change(w)),
			}, tc.opts...)
			w.chain = w.chainWith(t, httpsec.EnablePasswordChangeGate(w.sessions, opts...))

			if tc.arm != nil {
				tc.arm(w)
			}

			rec, _ := answerOf(w.chain, asSignIn(t, http.MethodPost, passwordResolvePath, w.signIn, ""))
			tc.assert(t, w, rec)
		})
	}
}

// TestPasswordChange_GrantRevocationConstruction pins the wirings the option
// refuses, since it could revoke nothing on them.
func TestPasswordChange_GrantRevocationConstruction(t *testing.T) {
	t.Parallel()

	change := func(*httpsec.Exchange) error { return nil }

	type testCase struct {
		name   string
		opts   func() []httpsec.Option
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "no provider on the chain is refused",
			opts: func() []httpsec.Option {
				return []httpsec.Option{httpsec.EnablePasswordChangeGate(must.Must(session.New()),
					httpsec.WithPasswordChangeEndpoint(passwordResolvePath, change),
					httpsec.WithPasswordChangeGrantRevocation())}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnableOIDCProvider")
			},
		},
		{
			name: "no resolve endpoint is refused",
			opts: func() []httpsec.Option {
				return []httpsec.Option{httpsec.EnablePasswordChangeGate(must.Must(session.New()),
					httpsec.WithPasswordChangeGrantRevocation())}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "WithPasswordChangeEndpoint")
			},
		},
		{
			name: "the default needs no provider",
			opts: func() []httpsec.Option {
				return []httpsec.Option{httpsec.EnablePasswordChangeGate(must.Must(session.New()),
					httpsec.WithPasswordChangeEndpoint(passwordResolvePath, change))}
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.opts()...)
			tc.assert(t, err)
		})
	}
}

func TestSessionManagement_RevokeApplicationAccess(t *testing.T) {
	t.Parallel()

	const choice = `{"revoke_application_access":true}`

	errOutage := errors.New("grant store secret text")

	type world struct {
		*grantWorld

		chain   *httpsec.Chain
		current *session.Session
		other   *session.Session
		refresh string
	}

	type testCase struct {
		name string
		path func(w *world) string
		body string
		arm  func(w *world)
		// noFresh leaves the caller's authentication older than the endpoint's window.
		noFresh bool
		assert  func(t *testing.T, w *world, rec *httptest.ResponseRecorder)
	}

	loads := func(t *testing.T, w *world, s *session.Session) bool {
		t.Helper()

		_, err := w.sessions.Load(t.Context(), s.ID)

		return err == nil
	}

	unchosen := func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
		t.Helper()

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.False(t, loads(t, w, w.other), "the other sign-in ended")
		assert.True(t, loads(t, w, w.current), "the current sign-in is kept")
		w.assertGrantWorks(t, w.refresh)
	}

	malformed := func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
		t.Helper()

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.True(t, loads(t, w, w.other), "nothing ended")
		w.assertGrantWorks(t, w.refresh)
	}

	cases := []testCase{
		{
			name: "with the choice every grant ends, offline access included, and the current sign-in is kept",
			body: choice,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, rec.Code)
				assert.False(t, loads(t, w, w.other), "the other sign-in ended")
				assert.True(t, loads(t, w, w.current), "the current sign-in is kept")
				assert.Equal(t, []oidcprovider.RevocationCause{oidcprovider.CauseUserRequest}, w.grants.causes())
				w.assertGrantRevoked(t, w.refresh)
			},
		},
		{name: "with no body, the offline grants survive", assert: unchosen},
		{name: "a choice of false is no choice", body: `{"revoke_application_access":false}`, assert: unchosen},
		{name: "another member is no choice", body: `{"other":true}`, assert: unchosen},
		{name: "a body that is not JSON is refused and ends nothing", body: `{not json`, assert: malformed},
		{name: "a choice that is not a boolean is refused and ends nothing", body: `{"revoke_application_access":"yes"}`, assert: malformed},
		{name: "a body with something after its document is refused", body: choice + `{}`, assert: malformed},
		{
			name: "a body over the limit is refused and ends nothing",
			body: strings.Repeat(" ", 8<<10) + choice,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
				assert.True(t, loads(t, w, w.other), "nothing ended")
				w.assertGrantWorks(t, w.refresh)
			},
		},
		{
			name: "a failure answers 500 with the other sign-ins ended, and a retry revokes",
			body: choice,
			arm:  func(w *world) { w.grants.fail(errOutage) },
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusInternalServerError, rec.Code)
				assert.NotContains(t, rec.Body.String(), "secret text")
				assert.False(t, loads(t, w, w.other), "an outage does not keep the other sign-in alive")

				w.grants.fail(nil)
				retry, _ := answerOf(w.chain, asSignIn(t, http.MethodDelete, httpsec.DefaultSessionManagementPrefix, w.current, choice))
				assert.Equal(t, http.StatusNoContent, retry.Code)
				w.assertGrantRevoked(t, w.refresh)
			},
		},
		{
			name:    "a stale session is refused and revokes nothing",
			body:    choice,
			noFresh: true,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Empty(t, w.grants.causes())
				w.assertGrantWorks(t, w.refresh)
			},
		},
		{
			name: "ending one sign-in by its handle takes no such choice",
			path: func(w *world) string {
				return httpsec.DefaultSessionManagementPrefix + "/" + w.other.FamilyID.String()
			},
			body: choice,
			assert: func(t *testing.T, w *world, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, rec.Code)
				assert.Empty(t, w.grants.causes())
				w.assertGrantWorks(t, w.refresh)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := &world{grantWorld: newGrantWorld(t)}
			w.other = w.signIn(t)
			if tc.noFresh {
				w.clk.Advance(time.Hour)
			}
			w.current = w.signIn(t)
			if tc.noFresh {
				w.clk.Advance(time.Hour)
			}
			w.refresh = w.refreshToken(t)
			w.chain = w.chainWith(t, httpsec.EnableSessionManagement())

			if tc.arm != nil {
				tc.arm(w)
			}

			path := httpsec.DefaultSessionManagementPrefix
			if tc.path != nil {
				path = tc.path(w)
			}

			rec, _ := answerOf(w.chain, asSignIn(t, http.MethodDelete, path, w.current, tc.body))
			tc.assert(t, w, rec)
		})
	}
}

// TestSessionManagement_NoProviderIgnoresTheBody pins that a chain without a
// provider reads no choice: the endpoint answers as it always did, whatever the
// body holds.
func TestSessionManagement_NoProviderIgnoresTheBody(t *testing.T) {
	t.Parallel()

	for _, body := range []string{`{"revoke_application_access":true}`, `{not json`} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()

			f := newManagementFixture(t, nil)
			other, current := f.signIn(t, "u-1"), f.signIn(t, "u-1")

			req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
				httpsec.DefaultSessionManagementPrefix, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+current.ID)

			rec, _ := answerOf(f.chain, req)
			assert.Equal(t, http.StatusNoContent, rec.Code)
			assert.False(t, f.loads(t, other))
			assert.True(t, f.loads(t, current))
		})
	}
}

// consumerRevoker is what a consumer supplies in place of the chain's provider.
type consumerRevoker struct {
	mu    sync.Mutex
	users []identity.UserID
}

func (r *consumerRevoker) RevokeUserGrants(_ context.Context, user identity.UserID, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.users = append(r.users, user)

	return nil
}

// recoveredBySession asserts out is a completed recovery whose credential is the
// stored session's own identifier, as a chain with the session bearer issues.
func recoveredBySession(t *testing.T, h *recoveryHarness, out served) {
	t.Helper()

	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	var doc recoveryDocument
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

	s, err := h.sessions.Load(t.Context(), doc.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, session.MFARecoveryPending, s.MFA)
}

// TestRecovery_RevokesGrantsThroughTheChain pins that the chain hands its provider
// to the recovery it builds, that the consumer's core options still decide, and
// that a chain without a provider revokes nothing.
func TestRecovery_RevokesGrantsThroughTheChain(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("grant store secret text")

	type testCase struct {
		name   string
		core   func(r *consumerRevoker) []recovery.Option
		arm    func(w *grantWorld)
		assert func(t *testing.T, w *grantWorld, r *consumerRevoker, refresh string, h *recoveryHarness, out served)
	}

	cases := []testCase{
		{
			name: "a completed recovery revokes through the chain's provider, offline access included",
			assert: func(t *testing.T, w *grantWorld, _ *consumerRevoker, refresh string, h *recoveryHarness, out served) {
				t.Helper()

				recoveredBySession(t, h, out)
				assert.Equal(t, []oidcprovider.RevocationCause{oidcprovider.CauseRecovery}, w.grants.causes())
				w.assertGrantRevoked(t, refresh)
			},
		},
		{
			name: "the consumer's keep option keeps the grants",
			core: func(*consumerRevoker) []recovery.Option {
				return []recovery.Option{recovery.WithoutRecoveryGrantRevocation()}
			},
			assert: func(t *testing.T, w *grantWorld, _ *consumerRevoker, refresh string, h *recoveryHarness, out served) {
				t.Helper()

				recoveredBySession(t, h, out)
				assert.Empty(t, w.grants.causes())
				w.assertGrantWorks(t, refresh)
			},
		},
		{
			name: "the consumer's own revoker replaces the chain's",
			core: func(r *consumerRevoker) []recovery.Option {
				return []recovery.Option{recovery.WithGrantRevoker(r)}
			},
			assert: func(t *testing.T, w *grantWorld, r *consumerRevoker, refresh string, h *recoveryHarness, out served) {
				t.Helper()

				recoveredBySession(t, h, out)
				assert.Equal(t, []identity.UserID{e2eUser}, r.users)
				w.assertGrantWorks(t, refresh)
			},
		},
		{
			name: "a failure is the provider's dependency failure, a 500",
			arm:  func(w *grantWorld) { w.grants.fail(errOutage) },
			assert: func(t *testing.T, _ *grantWorld, _ *consumerRevoker, _ string, _ *recoveryHarness, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "secret text")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newGrantWorld(t)
			refresh := w.refreshToken(t)
			revoker := &consumerRevoker{}

			h := newRecoveryHarness(t)
			h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
			h.reference = true
			h.sessions = w.sessions
			h.chainOpts = []httpsec.Option{
				httpsec.EnableJWKSEndpoint(tokenKeys()),
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableOIDCProvider(w.p),
			}
			if tc.core != nil {
				h.coreOpts = tc.core(revoker)
			}
			h.build(t)

			if tc.arm != nil {
				tc.arm(w)
			}

			out := h.complete(t, recoveryForm(
				httpsec.RecoverySavedCodeParam, h.saved(t),
				httpsec.RecoveryIssuedCodeParam, h.issued(t),
			))
			tc.assert(t, w, revoker, refresh, h, out)
		})
	}
}

// TestRecovery_NoProviderRevokesNothing pins that a chain with no provider builds
// and recovers as it always did, and the keep option changes nothing there.
func TestRecovery_NoProviderRevokesNothing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		core []recovery.Option
	}{
		{name: "the default"},
		{name: "the keep option", core: []recovery.Option{recovery.WithoutRecoveryGrantRevocation()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
			h.coreOpts = tc.core
			h.build(t)

			recovered(t, h, h.complete(t, recoveryForm(
				httpsec.RecoverySavedCodeParam, h.saved(t),
				httpsec.RecoveryIssuedCodeParam, h.issued(t),
			)))
		})
	}
}

// TestResetEnrolment_RawStoreRevokesGrants pins what the port exists for. A raw
// session.Store ends sessions with no report a provider could see, so the row
// that keeps the grants shows the store alone leaves them alive, and the other
// that the port alone ends them.
func TestResetEnrolment_RawStoreRevokesGrants(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []mfa.ResetOption
		assert func(t *testing.T, w *grantWorld, refresh string)
	}

	cases := []testCase{
		{
			name: "the reset revokes through the port, offline access included",
			assert: func(t *testing.T, w *grantWorld, refresh string) {
				t.Helper()

				assert.Equal(t, []oidcprovider.RevocationCause{oidcprovider.CauseMFAReset}, w.grants.causes())
				w.assertGrantRevoked(t, refresh)
			},
		},
		{
			name: "keeping the grants, the raw store's end reaches no provider",
			opts: []mfa.ResetOption{mfa.WithoutResetGrantRevocation()},
			assert: func(t *testing.T, w *grantWorld, refresh string) {
				t.Helper()

				assert.Empty(t, w.grants.causes())
				w.assertGrantWorks(t, refresh)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newGrantWorld(t)
			refresh := w.refreshToken(t)

			store := must.Must(session.NewMemoryStore())
			s := must.Must(must.Must(session.New(session.WithStore(store))).Create(t.Context(), "u-1"))

			totp := must.Must(mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example"))

			require.NoError(t, mfa.ResetEnrolment(t.Context(), "u-1", mfa.ResetDeps{
				Enrolments: []mfa.EnrolmentRemover{totp},
				Sessions:   store,
				Grants:     w.p,
			}, append(tc.opts, mfa.WithoutResetNotification())...))

			_, err := store.Load(t.Context(), s.ID)
			require.ErrorIs(t, err, session.ErrNotFound, "the raw store ended the session")

			tc.assert(t, w, refresh)
		})
	}
}

// TestPasskey_CloneRevokesGrants pins that a suspended clone ends a client's real
// refresh token through the manager's port. The manager sits over a
// session manager that reports to no provider, so the row that keeps the grants
// shows such a manager alone leaves them alive.
func TestPasskey_CloneRevokesGrants(t *testing.T) {
	t.Parallel()

	type env struct {
		d      *pwlDeployment
		w      *grantWorld
		m      *passkey.Passkeys
		handle []byte
		s      *session.Session
		store  session.Store
	}

	clone := func(t *testing.T, e *env) {
		t.Helper()

		_, err := e.m.BeginLogin(t.Context(), "ceremony")
		require.NoError(t, err)

		body := handleAssertionBody(e.d.verifier.lastRequest(t), "cred-1", e.handle)

		_, err = e.m.Authenticate(t.Context(), []byte(body), "ceremony")
		require.ErrorIs(t, err, passkey.ErrCloneSuspected)
	}

	sessionEnded := func(t *testing.T, e *env) {
		t.Helper()

		_, err := e.store.Load(t.Context(), e.s.ID)
		require.ErrorIs(t, err, session.ErrNotFound, "the raw store ended the session")
	}

	type testCase struct {
		name   string
		opts   func(w *grantWorld) []passkey.Option
		act    func(t *testing.T, e *env)
		assert func(t *testing.T, e *env, refresh string)
	}

	cases := []testCase{
		{
			name: "a suspended clone revokes every grant through the port, offline access included",
			opts: func(w *grantWorld) []passkey.Option { return []passkey.Option{passkey.WithGrantRevoker(w.p)} },
			act:  clone,
			assert: func(t *testing.T, e *env, refresh string) {
				t.Helper()

				sessionEnded(t, e)
				assert.Equal(t, []oidcprovider.RevocationCause{oidcprovider.CausePasskeyClone}, e.w.grants.causes())
				e.w.assertGrantRevoked(t, refresh)
			},
		},
		{
			name: "keeping the grants, a manager reporting to no provider leaves the token working",
			opts: func(w *grantWorld) []passkey.Option {
				return []passkey.Option{passkey.WithGrantRevoker(w.p), passkey.WithoutCloneGrantRevocation()}
			},
			act: clone,
			assert: func(t *testing.T, e *env, refresh string) {
				t.Helper()

				sessionEnded(t, e)
				assert.Empty(t, e.w.grants.causes())
				e.w.assertGrantWorks(t, refresh)
			},
		},
		{
			name: "with neither option the manager alone revokes nothing",
			opts: func(*grantWorld) []passkey.Option { return nil },
			act:  clone,
			assert: func(t *testing.T, e *env, refresh string) {
				t.Helper()

				sessionEnded(t, e)
				e.w.assertGrantWorks(t, refresh)
			},
		},
		{
			name: "removing one's own passkey keeps the grants",
			opts: func(w *grantWorld) []passkey.Option { return []passkey.Option{passkey.WithGrantRevoker(w.p)} },
			act: func(t *testing.T, e *env) {
				t.Helper()

				c, err := e.d.creds.FindByCredentialID(t.Context(), []byte("cred-1"))
				require.NoError(t, err)
				require.NoError(t, e.m.Remove(t.Context(), e.s, c.ID, passkey.RegistrationContext{}))
			},
			assert: func(t *testing.T, e *env, refresh string) {
				t.Helper()

				assert.Empty(t, e.w.grants.causes())
				e.w.assertGrantWorks(t, refresh)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newGrantWorld(t)
			refresh := w.refreshToken(t)

			d := newPwlDeployment(t)
			store := must.Must(session.NewMemoryStore())
			// A manager that reports to no provider: its ends reach the grant port
			// only through the manager's own revoker option.
			sessions := must.Must(session.New(session.WithStore(store)))

			m, err := passkey.New(passkey.Deps{
				Verifier: d.verifier.mock, Credentials: d.creds, Handles: d.handles,
				Users: d.users, Sender: d.notices, Sessions: sessions,
			}, append([]passkey.Option{
				passkey.WithRepudiationContact("help@example.com"), passkey.WithOptionalRecoveryCodes(),
			}, tc.opts(w)...)...)
			require.NoError(t, err)

			e := &env{
				d: d, w: w, m: m, store: store,
				handle: d.seedCounted(t, e2eUser, "cred-1", passkey.StateActive, 5),
				s: must.Must(sessions.Create(
					t.Context(), e2eUser, session.WithFirstFactor(factor.Passkey))),
			}

			tc.act(t, e)
			tc.assert(t, e, refresh)
		})
	}
}

// TestEnablePasskeys_CloneGrantDecision pins that a chain with a provider refuses a
// manager told nothing about a clone's grants, and that a chain with none does not
// care.
func TestEnablePasskeys_CloneGrantDecision(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		opts     func(w *grantWorld) []passkey.Option
		provider bool
		assert   func(t *testing.T, err error)
	}

	built := func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) }

	cases := []testCase{
		{
			name:     "neither option, with a provider, is refused naming what to pass",
			opts:     func(*grantWorld) []passkey.Option { return nil },
			provider: true,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnablePasskeys")
				assert.ErrorContains(t, err, "passkey.WithGrantRevoker")
				assert.ErrorContains(t, err, "passkey.WithoutCloneGrantRevocation")
			},
		},
		{
			name:     "a revoker, with a provider, builds",
			opts:     func(w *grantWorld) []passkey.Option { return []passkey.Option{passkey.WithGrantRevoker(w.p)} },
			provider: true,
			assert:   built,
		},
		{
			name:     "the keep option, with a provider, builds",
			opts:     func(*grantWorld) []passkey.Option { return []passkey.Option{passkey.WithoutCloneGrantRevocation()} },
			provider: true,
			assert:   built,
		},
		{
			name:   "neither option, with no provider, builds as it always did",
			opts:   func(*grantWorld) []passkey.Option { return nil },
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newGrantWorld(t)

			m, err := passkey.New(passkey.Deps{
				Verifier: newPasskeyVerifierStub(t).mock, Users: w.users, Sender: exampleSender{}, Sessions: w.sessions,
			}, append([]passkey.Option{passkey.WithRepudiationContact("help@example.com")}, tc.opts(w)...)...)
			require.NoError(t, err)

			opts := []httpsec.Option{
				httpsec.WithClock(w.clk),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
				httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: w.sessions, Users: w.users}),
			}
			if tc.provider {
				opts = append(opts,
					httpsec.EnableJWKSEndpoint(tokenKeys()),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(w.p),
				)
			}

			_, err = httpsec.New(opts...)
			tc.assert(t, err)
		})
	}
}
