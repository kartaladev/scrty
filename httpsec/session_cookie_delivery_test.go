package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// errBrowserStoreDown is the outage a browserStore fails a write with.
var errBrowserStoreDown = errors.New("delivery_test: the session store is unreachable")

// browserStore forwards to the in-memory store, and fails the creating write
// or the superseding write when a case asks it to, as a store outage does.
// Each case runs its requests one after another, so the switches need no lock.
type browserStore struct {
	session.Store

	failCreate    bool
	failSupersede bool

	// failDeleteFamily fails the write that ends a sign-in. The write also
	// fails when its context has ended, as a real store's does.
	failDeleteFamily bool

	// endBounded is whether the last write that ended a sign-in ran on a
	// context with a deadline.
	endBounded bool

	// onSupersede, when set before any request runs, stands around every
	// superseding write the store does not fail: it is handed the write's
	// context and the write itself, which it may run, hold behind a barrier
	// or skip, and its answer is the write's.
	onSupersede func(ctx context.Context, write func() error) error
}

func (s *browserStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	_, s.endBounded = ctx.Deadline()

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if s.failDeleteFamily {
		return 0, errBrowserStoreDown
	}

	return s.Store.DeleteFamily(ctx, family)
}

func (s *browserStore) Create(ctx context.Context, sess *session.Session) error {
	if s.failCreate {
		return errBrowserStoreDown
	}

	return s.Store.Create(ctx, sess)
}

func (s *browserStore) Supersede(ctx context.Context, sup session.Supersession) error {
	if s.failSupersede {
		return errBrowserStoreDown
	}

	if s.onSupersede != nil {
		return s.onSupersede(ctx, func() error { return s.Store.Supersede(ctx, sup) })
	}

	return s.Store.Supersede(ctx, sup)
}

// browserWorld is a cookie chain wired the way a browser application wires
// it: form login over the real password authenticator, the real TOTP second
// factor behind the real MFA policy, re-authentication, session renewal and
// logout, all over one real session manager on a fake clock. Only the user
// store is a double. CSRF protection is explicitly off, so a case's unsafe
// requests need no token; the cookie suites cover CSRF.
type browserWorld struct {
	clk      *clockwork.FakeClock
	store    *browserStore
	sessions *session.Sessions
	users    *MockUserLoader
	totp     *mfa.TOTP
	secret   string

	// cookieOpts are the cookie session's options, and extra further chain
	// options, both read when the chain is built.
	cookieOpts []httpsec.SessionCookieOption
	extra      []httpsec.Option

	// loginOpts, mfaOpts, reauthOpts and renewalOpts are the issuing
	// endpoints' own options, read when the chain is built.
	loginOpts   []httpsec.LoginOption
	mfaOpts     []httpsec.MFAOption
	reauthOpts  []httpsec.ReauthenticationOption
	renewalOpts []httpsec.SessionRenewalOption

	// policies are registered on the chain's engine after the MFA policy,
	// read when the chain is built.
	policies []policy.Policy

	chain *httpsec.Chain
}

func newBrowserWorld(t *testing.T, opts ...session.Option) *browserWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now().Truncate(time.Minute))
	store := &browserStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}

	sessions, err := session.New(append([]session.Option{session.WithClock(clk), session.WithStore(store)}, opts...)...)
	require.NoError(t, err)

	w := &browserWorld{
		clk:      clk,
		store:    store,
		sessions: sessions,
		users:    NewMockUserLoader(gomock.NewController(t)),
	}

	w.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(clk))
	require.NoError(t, err)

	hash, err := e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Password: hash, Active: true}
	}

	w.users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return details(), nil })
	w.users.EXPECT().LoadByUserID(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return details(), nil })

	return w
}

// build assembles the chain from the world's current configuration.
func (w *browserWorld) build(t *testing.T) *browserWorld {
	t.Helper()

	require.NoError(t, w.tryBuild(t))

	return w
}

// tryBuild is build returning the construction error, for the cases about
// the construction itself.
func (w *browserWorld) tryBuild(t *testing.T) error {
	t.Helper()

	lookups, err := mfa.LookupsFor(w.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	authn, err := authenticate.NewUsernamePasswordAuthenticator(w.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	w.chain, err = httpsec.New(append([]httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.WithPolicyEngine(engineOf(t, append([]policy.Policy{challenge}, w.policies...)...)),
		httpsec.WithoutCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}, w.cookieOpts...),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: w.sessions, Attempts: must.Must(lockout.NewMemoryAttemptStore()),
		}, w.loginOpts...),
		httpsec.EnableMFA([]mfa.Method{w.totp}, w.mfaOpts...),
		httpsec.EnableReauthentication(w.reauthOpts...),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: w.users}, w.renewalOpts...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: w.sessions}),
	}, w.extra...)...)

	return err
}

// enrol enrols the user on TOTP, so a password login is challenged for it.
func (w *browserWorld) enrol(t *testing.T) {
	t.Helper()

	prov, err := w.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)

	code, err := totp.GenerateCode(prov.Secret, w.clk.Now())
	require.NoError(t, err)
	require.NoError(t, w.totp.ConfirmEnrolment(t.Context(), e2eUser, code))

	w.secret = prov.Secret
}

// code is a TOTP code for the next time step, so it is not one already spent.
func (w *browserWorld) code(t *testing.T) string {
	t.Helper()

	w.clk.Advance(w.totp.Period())

	c, err := totp.GenerateCode(w.secret, w.clk.Now())
	require.NoError(t, err)

	return c
}

// post sends values to path, presenting cookie as the session cookie when it
// is not empty, on ctx.
func (w *browserWorld) post(ctx context.Context, t *testing.T, path, cookie string, values url.Values) served {
	t.Helper()

	req := postValues(ctx, path, e2eSource, values)
	if cookie != "" {
		req.Header.Set("Cookie", named(cookie))
	}

	return serveContext(ctx, t, w.chain, req)
}

// login posts the user's password to form login.
func (w *browserWorld) login(t *testing.T) served {
	t.Helper()

	return w.post(t.Context(), t, httpsec.DefaultLoginPath, "", url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	})
}

// signedIn signs the user in and returns the identifier the cookie carries.
func (w *browserWorld) signedIn(t *testing.T) string {
	t.Helper()

	out := w.login(t)
	require.NoError(t, out.err)

	c := cookieNamed(out.rec, httpsec.DefaultSessionCookieName)
	require.NotNil(t, c, "the sign-in set the session cookie")

	return c.Value
}

// active is the number of live sessions the user holds.
func (w *browserWorld) active(t *testing.T) int {
	t.Helper()

	n, err := w.sessions.CountActiveByUser(t.Context(), e2eUser)
	require.NoError(t, err)

	return n
}

// deliveredOnlyInCookie asserts out delivered a session identifier only as
// the session cookie: one Set-Cookie of the default name, HttpOnly, Secure,
// on Path=/ and with no Max-Age, whose value names a stored session, and that
// value nowhere in the body or in any header other than Set-Cookie, Location
// included. The response is no-store. It returns the identifier.
func deliveredOnlyInCookie(t *testing.T, sessions *session.Sessions, out served) string {
	t.Helper()

	var set []*http.Cookie

	for _, c := range out.rec.Result().Cookies() { //nolint:bodyclose // the recorder's result has no body to close
		if c.Name == httpsec.DefaultSessionCookieName {
			set = append(set, c)
		}
	}

	require.Len(t, set, 1, "exactly one session cookie is set")

	c := set[0]
	require.True(t, session.ValidIdentifier(c.Value), "the cookie carries a session identifier")
	assert.True(t, c.HttpOnly, "no script can read the cookie")
	assert.True(t, c.Secure)
	assert.Equal(t, "/", c.Path)
	assert.Zero(t, c.MaxAge, "a sign-in's cookie lasts the browser session unless it persists")

	_, err := sessions.Load(context.WithoutCancel(t.Context()), c.Value)
	require.NoError(t, err, "the cookie names a stored session")

	assert.NotContains(t, out.rec.Body.String(), c.Value, "the body carries no credential")

	for name, values := range out.rec.Header() {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}

		for _, v := range values {
			assert.NotContains(t, v, c.Value, "header %s carries no credential", name)
		}
	}

	assert.Equal(t, []string{"no-store"}, out.rec.Header().Values("Cache-Control"))

	return c.Value
}

// noSessionCookie asserts out set no session cookie at all: none set and
// none expired.
func noSessionCookie(t *testing.T, out served) {
	t.Helper()

	assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultSessionCookieName), "no session cookie is written")
}

// TestSessionCookie_NoCredentialInBody pins that on a cookie chain every
// issuing endpoint hands the credential out as the session cookie alone:
// form login, a password login challenged for a second factor (whose
// challenge carries the pending session and no token), second-factor
// verification, re-authentication, session renewal, magic link redemption,
// passwordless passkey login, recovery completion and the federated
// callback. The body and every header other than Set-Cookie carry no
// identifier, and a rotating endpoint sets the successor's.
func TestSessionCookie_NoCredentialInBody(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// issue runs the issuing request and returns what it answered, the
		// manager its session lives in, and the identifier the request
		// presented ("" for a fresh sign-in).
		issue func(t *testing.T) (out served, sessions *session.Sessions, presented string)

		assert func(t *testing.T, out served, sessions *session.Sessions, presented, delivered string)
	}

	fresh := func(t *testing.T, out served, _ *session.Sessions, _, _ string) {
		t.Helper()
		require.NoError(t, out.err)
	}

	rotated := func(t *testing.T, out served, sessions *session.Sessions, presented, delivered string) {
		t.Helper()
		require.NoError(t, out.err)
		assert.NotEqual(t, presented, delivered, "the cookie names the rotated session")
		assert.NotContains(t, out.rec.Body.String(), presented)

		s, err := sessions.Load(t.Context(), delivered)
		require.NoError(t, err)
		assert.Equal(t, e2eUser, s.UserID)
	}

	cases := []testCase{
		{
			name: "form login",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				w := newBrowserWorld(t).build(t)

				return w.login(t), w.sessions, ""
			},
			assert: fresh,
		},
		{
			name: "password login challenged for a second factor",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				w := newBrowserWorld(t)
				w.enrol(t)
				w.build(t)

				return w.login(t), w.sessions, ""
			},
			assert: func(t *testing.T, out served, _ *session.Sessions, _, delivered string) {
				t.Helper()

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Empty(t, ch.Token, "the challenge carries no credential")
				assert.Empty(t, ch.TokenType, "nor the type of one")
				require.NotNil(t, ch.Session)
				assert.Equal(t, ch.Session.ID, delivered, "the cookie names the pending session")
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
			},
		},
		{
			name: "second-factor verification",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				w := newBrowserWorld(t)
				w.enrol(t)
				w.build(t)

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending, "the challenged login set the pending session's cookie")

				return w.post(t.Context(), t, testMFAVerifyPath, pending.Value,
					url.Values{"code": {w.code(t)}}), w.sessions, pending.Value
			},
			assert: func(t *testing.T, out served, sessions *session.Sessions, presented, delivered string) {
				t.Helper()
				rotated(t, out, sessions, presented, delivered)

				s, err := sessions.Load(t.Context(), delivered)
				require.NoError(t, err)
				assert.Equal(t, session.MFASatisfied, s.MFA)
			},
		},
		{
			name: "re-authentication",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, reauthPasswordPath, id,
					url.Values{"password": {e2ePassword}}), w.sessions, id
			},
			assert: rotated,
		},
		{
			name: "session renewal",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil), w.sessions, id
			},
			assert: rotated,
		},
		{
			name: "magic link redemption",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				h := newMagicLinkHarness(t)
				h.tokens = nil
				h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))

				chain, err := h.build()
				require.NoError(t, err)

				tok, nonce := h.link(t, chain)

				return h.redeem(t, chain, tok, nonce), h.sessions, ""
			},
			assert: fresh,
		},
		{
			name: "passwordless passkey login",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				d := newPwlDeployment(t)
				_ = d.options(t)

				chain, err := httpsec.New(
					httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: d.sessions, Users: d.users}),
					httpsec.EnablePasskeys(
						httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions, Users: d.users},
						httpsec.WithPasskeyPasswordlessLogin()),
				)
				require.NoError(t, err)

				d.chain = chain

				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive)), d.sessions, ""
			},
			assert: fresh,
		},
		{
			name: "recovery completion",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				h := newRecoveryHarness(t)
				h.cookie = true
				h.build(t)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword)), h.sessions, ""
			},
			assert: fresh,
		},
		{
			name: "federated callback",
			issue: func(t *testing.T) (served, *session.Sessions, string) {
				h := newOIDCHarness(t)

				chain, err := oidcCookieChain(h, referenceUsers(t), nil)
				require.NoError(t, err)

				l := startLogin(t, chain, "")

				return serve(t, chain, callbackRequest(t.Context(), l.genuineCallback(), l.handle)), h.sessions, ""
			},
			assert: fresh,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, sessions, presented := tc.issue(t)
			delivered := deliveredOnlyInCookie(t, sessions, out)
			tc.assert(t, out, sessions, presented, delivered)
		})
	}
}

// TestSessionCookie_IssuingPathsPassGetAndHead pins that a GET or a HEAD to an
// issuing endpoint's path on a cookie chain issues nothing: it passes through
// to the application, sets no session cookie and stores no session, whether
// or not it carries a session cookie.
func TestSessionCookie_IssuingPathsPassGetAndHead(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method string
		path   string
		signIn bool

		// endpoint builds a chain other than the browser world's, and returns
		// it, the query a client would send to sign in by GET, and a count of
		// the user's live sessions. Nil serves the browser world.
		endpoint func(t *testing.T) (*httpsec.Chain, url.Values, func() int)

		assert func(t *testing.T, out served, before, after int)
	}

	passedThrough := func(t *testing.T, out served, before, after int) {
		t.Helper()
		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the application answers it")
		noSessionCookie(t, out)
		assert.Equal(t, before, after, "no session was stored")
	}

	var cases []testCase

	for _, path := range []string{
		httpsec.DefaultLoginPath, testMFAVerifyPath, reauthPasswordPath, httpsec.DefaultSessionRenewalPath,
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			cases = append(cases,
				testCase{name: method + " " + path, method: method, path: path, assert: passedThrough},
				testCase{name: method + " " + path + " with a cookie", method: method, path: path, signIn: true,
					assert: passedThrough})
		}
	}

	magicLink := func(t *testing.T) (*httpsec.Chain, url.Values, func() int) {
		h := newMagicLinkHarness(t)
		h.tokens = nil
		h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
			httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))

		chain, err := h.build()
		require.NoError(t, err)

		tok, _ := h.link(t, chain)

		return chain, url.Values{"token": {tok}}, func() int { return h.activeSessions(t) }
	}

	recoveryComplete := func(t *testing.T) (*httpsec.Chain, url.Values, func() int) {
		h := newRecoveryHarness(t)
		h.cookie = true
		h.build(t)

		active := func() int {
			n, err := h.sessions.CountActiveByUser(t.Context(), e2eUser)
			require.NoError(t, err)

			return n
		}

		return h.chain, recoveryForm(
			httpsec.RecoverySavedCodeParam, h.saved(t), httpsec.RecoveryPasswordParam, e2ePassword), active
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		cases = append(cases,
			testCase{
				name: method + " magic link redemption with a live link", method: method,
				path: httpsec.DefaultMagicLinkConsumePath, endpoint: magicLink, assert: passedThrough,
			},
			testCase{
				name: method + " recovery completion with good proofs", method: method,
				path: httpsec.DefaultRecoveryCompletePath, endpoint: recoveryComplete, assert: passedThrough,
			})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				chain  *httpsec.Chain
				query  url.Values
				active func() int
				cookie string
			)

			if tc.endpoint != nil {
				chain, query, active = tc.endpoint(t)
			} else {
				w := newBrowserWorld(t).build(t)
				chain, active = w.chain, func() int { return w.active(t) }
				query = url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				}

				if tc.signIn {
					cookie = w.signedIn(t)
				}
			}

			req := getFrom(t.Context(), tc.path, e2eSource)
			req.Method = tc.method
			req.URL.RawQuery = query.Encode()

			if cookie != "" {
				req.Header.Set("Cookie", named(cookie))
			}

			before := active()
			out := serve(t, chain, req)

			tc.assert(t, out, before, active())
		})
	}
}

// TestSessionCookie_IssuingFailureSetsNoCookie pins that an issuing endpoint
// on a cookie chain whose session could not be stored, or whose request ended
// before it was, sets no session cookie: neither a new one nor one expiring
// the cookie the request presented, and stores nothing.
func TestSessionCookie_IssuingFailureSetsNoCookie(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// signIn signs the user in first, and act is handed the identifier
		// the cookie carries ("" without).
		signIn bool

		// act breaks the world as the case needs, runs the issuing request on
		// ctx and returns what it answered.
		act func(ctx context.Context, t *testing.T, w *browserWorld, id string) served

		ctx func(context.Context) context.Context

		assert func(t *testing.T, w *browserWorld, out served, before int)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	login := func(ctx context.Context, t *testing.T, w *browserWorld, _ string) served {
		return w.post(ctx, t, httpsec.DefaultLoginPath, "", url.Values{
			httpsec.DefaultLoginUsernameParam: {e2eAddress},
			httpsec.DefaultLoginPasswordParam: {e2ePassword},
		})
	}

	rotation := func(path string, values url.Values, breakStore bool) func(context.Context, *testing.T, *browserWorld, string) served {
		return func(ctx context.Context, t *testing.T, w *browserWorld, id string) served {
			w.store.failSupersede = breakStore

			return w.post(ctx, t, path, id, values)
		}
	}

	nothingIssued := func(t *testing.T, w *browserWorld, out served, before int) {
		t.Helper()
		require.Error(t, out.err)
		noSessionCookie(t, out)
		assert.Empty(t, out.rec.Body.String(), "nothing is written")
		assert.Equal(t, before, w.active(t), "nothing more is stored")
	}

	outage := func(t *testing.T, w *browserWorld, out served, before int) {
		t.Helper()
		nothingIssued(t, w, out, before)
		assert.ErrorIs(t, out.err, errBrowserStoreDown)
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
	}

	cases := []testCase{
		{
			name: "a sign-in whose session the store cannot create",
			act: func(ctx context.Context, t *testing.T, w *browserWorld, id string) served {
				w.store.failCreate = true

				return login(ctx, t, w, id)
			},
			assert: outage,
		},
		{
			name:   "a sign-in whose request has ended",
			act:    login,
			ctx:    cancelled,
			assert: nothingIssued,
		},
		{
			name:   "a renewal whose successor the store cannot write",
			signIn: true,
			act:    rotation(httpsec.DefaultSessionRenewalPath, nil, true),
			assert: outage,
		},
		{
			name:   "a re-authentication whose successor the store cannot write",
			signIn: true,
			act:    rotation(reauthPasswordPath, url.Values{"password": {e2ePassword}}, true),
			assert: outage,
		},
		{
			name:   "a re-authentication whose request has ended",
			signIn: true,
			act:    rotation(reauthPasswordPath, url.Values{"password": {e2ePassword}}, false),
			ctx:    cancelled,
			assert: nothingIssued,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t).build(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var id string
			if tc.signIn {
				id = w.signedIn(t)
			}

			before := w.active(t)
			out := tc.act(ctx, t, w, id)

			tc.assert(t, w, out, before)
		})
	}
}

// TestSessionCookie_RenewalUsesTheCookieManager pins that the renewal
// endpoint on a cookie chain rotates through the cookie session's manager:
// it defaults to it, and refuses at construction another one given
// explicitly, since a successor written through a manager the cookie session
// does not read could never be presented.
func TestSessionCookie_RenewalUsesTheCookieManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(w *browserWorld) httpsec.SessionRenewalDeps
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "no manager given defaults to the cookie session's",
			deps: func(w *browserWorld) httpsec.SessionRenewalDeps {
				return httpsec.SessionRenewalDeps{Users: w.users}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "the cookie session's own manager given explicitly builds",
			deps: func(w *browserWorld) httpsec.SessionRenewalDeps {
				return httpsec.SessionRenewalDeps{Sessions: w.sessions, Users: w.users}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "another manager is refused",
			deps: func(w *browserWorld) httpsec.SessionRenewalDeps {
				return httpsec.SessionRenewalDeps{Sessions: must.Must(session.New()), Users: w.users}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "SessionRenewalDeps.Sessions")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)

			_, err := httpsec.New(
				httpsec.WithoutCSRFProtection(),
				httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
				httpsec.EnableSessionRenewal(tc.deps(w)),
			)

			tc.assert(t, err)
		})
	}
}

// TestSessionCookie_IssuingEndpointsTakeNoGenerator pins that an issuing
// endpoint on a cookie chain given a token generator is a configuration
// error naming the cookie session: the chain hands out only the cookie, and
// would refuse every token the generator minted.
func TestSessionCookie_IssuingEndpointsTakeNoGenerator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint func(t *testing.T, w *browserWorld, g *MockGenerator) httpsec.Option
		assert   func(t *testing.T, err error)
	}

	refused := func(field string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), "EnableSessionCookie")
			assert.Contains(t, err.Error(), field)
		}
	}

	cases := []testCase{
		{
			name: "form login",
			endpoint: func(t *testing.T, w *browserWorld, g *MockGenerator) httpsec.Option {
				return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: NewMockAuthenticator(gomock.NewController(t)), Sessions: w.sessions,
					Tokens: g, Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				})
			},
			assert: refused("FormLoginDeps.Tokens"),
		},
		{
			name: "session renewal",
			endpoint: func(_ *testing.T, w *browserWorld, g *MockGenerator) httpsec.Option {
				return httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: w.users, Tokens: g})
			},
			assert: refused("SessionRenewalDeps.Tokens"),
		},
		{
			name: "second factor",
			endpoint: func(_ *testing.T, w *browserWorld, g *MockGenerator) httpsec.Option {
				return httpsec.EnableMFA([]mfa.Method{w.totp}, httpsec.WithMFATokens(g))
			},
			assert: refused("WithMFATokens"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)

			_, err := httpsec.New(
				httpsec.WithoutCSRFProtection(),
				httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
				tc.endpoint(t, w, newMockGenerator(gomock.NewController(t))),
			)

			tc.assert(t, err)
		})
	}
}

// TestSessionCookie_SignInSetsCookieAttributes pins the attributes a real form
// sign-in sets the session cookie with, read as a browser would, from the
// parsed Set-Cookie: under the default and under a consumer's SameSite.
func TestSessionCookie_SignInSetsCookieAttributes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		configure func(w *browserWorld)
		assert    func(t *testing.T, cookies []*http.Cookie)
	}

	attributes := func(sameSite http.SameSite) func(t *testing.T, cookies []*http.Cookie) {
		return func(t *testing.T, cookies []*http.Cookie) {
			t.Helper()

			var named []*http.Cookie

			for _, c := range cookies {
				if c.Name == httpsec.DefaultSessionCookieName {
					named = append(named, c)
				}
			}

			require.Len(t, named, 1, "exactly one session cookie: %v", cookies)

			c := named[0]
			assert.Equal(t, "__Host-scrty-session", c.Name)
			assert.NotEmpty(t, c.Value)
			assert.Equal(t, "/", c.Path)
			assert.True(t, c.Secure)
			assert.True(t, c.HttpOnly)
			assert.Equal(t, sameSite, c.SameSite)
			assert.Empty(t, c.Domain, "a __Host- cookie carries no Domain")
			assert.Zero(t, c.MaxAge, "a session cookie, kept until the browser closes")
			assert.True(t, c.Expires.IsZero(), "no Expires: %v", c.Expires)
		}
	}

	cases := []testCase{
		{
			name:   "default",
			assert: attributes(http.SameSiteLaxMode),
		},
		{
			name: "SameSite=Strict",
			configure: func(w *browserWorld) {
				w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookieSameSite(http.SameSiteStrictMode))
			},
			assert: attributes(http.SameSiteStrictMode),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)
			if tc.configure != nil {
				tc.configure(w)
			}

			out := w.build(t).login(t)
			require.NoError(t, out.err)

			resp := out.rec.Result()
			t.Cleanup(func() { _ = resp.Body.Close() })

			tc.assert(t, resp.Cookies())
		})
	}
}
