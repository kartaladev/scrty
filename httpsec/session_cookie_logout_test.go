package httpsec_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// sessionCookieLines is every Set-Cookie line of out naming name.
func sessionCookieLines(t *testing.T, out served, name string) []string {
	t.Helper()

	var lines []string

	for _, line := range out.rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)

		if c.Name == name {
			lines = append(lines, line)
		}
	}

	return lines
}

// logoutWith posts a logout to w's chain presenting id under the cookie name.
func (w *browserWorld) logoutWith(t *testing.T, name, id string) served {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultLogoutPath, e2eSource, nil)
	if id != "" {
		req.Header.Set("Cookie", name+"="+id)
	}

	return serveContext(t.Context(), t, w.chain, req)
}

// TestSessionCookie_LogoutExpires pins that a successful logout on a cookie
// chain expires the session cookie with exactly the name, path, domain and
// attributes it was set with, Max-Age=0, the session ended; and that a logout
// that fails, or is refused, or runs on a chain without the cookie session,
// writes no session cookie at all.
func TestSessionCookie_LogoutExpires(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	// expiresAs signs in on w, logs out with the cookie named name, and
	// asserts the logout expired it exactly as want and ended the session.
	expiresAs := func(t *testing.T, w *browserWorld, name, want string) {
		t.Helper()

		in := w.login(t)
		require.NoError(t, in.err)

		set := cookieNamed(in.rec, name)
		require.NotNil(t, set, "the sign-in set the cookie under %s", name)

		out := w.logoutWith(t, name, set.Value)
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)
		assert.Equal(t, []string{want}, sessionCookieLines(t, out, name),
			"one expiring cookie, under every attribute the sign-in set it with")

		expired := cookieNamed(out.rec, name)
		require.NotNil(t, expired, "the logout expires the cookie")
		assert.Negative(t, expired.MaxAge, "expired, not re-set")
		assert.Empty(t, expired.Value)
		assert.Equal(t, set.Path, expired.Path, "the path the sign-in set")
		assert.Equal(t, set.Domain, expired.Domain, "the domain the sign-in set")
		assert.Equal(t, set.Secure, expired.Secure)
		assert.Equal(t, set.HttpOnly, expired.HttpOnly)
		assert.Equal(t, set.SameSite, expired.SameSite)

		_, err := w.sessions.Load(t.Context(), set.Value)
		require.Error(t, err, "the session is ended")
	}

	cases := []testCase{
		{
			name: "the default cookie is expired with its default attributes",
			assert: func(t *testing.T) {
				t.Helper()

				expiresAs(t, newBrowserWorld(t).build(t), httpsec.DefaultSessionCookieName,
					"__Host-scrty-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
			},
		},
		{
			name: "a configured name, domain and same-site are expired as configured",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t)
				w.cookieOpts = append(w.cookieOpts,
					httpsec.WithSessionCookieName("__Secure-app"),
					httpsec.WithSessionCookieDomain("example.com"),
					httpsec.WithSessionCookieSameSite(http.SameSiteStrictMode))
				w.build(t)

				expiresAs(t, w, "__Secure-app",
					"__Secure-app=; Path=/; Domain=example.com; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
			},
		},
		{
			name: "a persistent cookie is expired too",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t)
				w.cookieOpts = append(w.cookieOpts,
					httpsec.WithSessionCookiePersistence(func(*httpsec.Exchange) bool { return true }))
				w.build(t)

				expiresAs(t, w, httpsec.DefaultSessionCookieName,
					"__Host-scrty-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
			},
		},
		{
			name: "a logout that cannot end the sign-in keeps the session and the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)
				w.store.failDeleteFamily = true

				out := w.logoutWith(t, httpsec.DefaultSessionCookieName, id)
				require.ErrorIs(t, out.err, errBrowserStoreDown)
				noSessionCookie(t, out)

				w.store.failDeleteFamily = false

				_, err := w.sessions.Load(t.Context(), id)
				require.NoError(t, err, "the session is still there, so the logout can be retried")
			},
		},
		{
			name: "on a chain running the provider, a logout the provider's store fails keeps the session and the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w := newCookieProviderWorld(t)
				w.browsers.failEnd.Store(true)

				a := w.logout(t, w.signIn.ID)
				require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				assert.Nil(t, a.cookie(httpsec.DefaultSessionCookieName), "the cookie is not expired")
				assert.Empty(t, a.header.Values("Set-Cookie"), "the failed logout writes no cookie at all")

				_, err := w.sessions.Load(t.Context(), w.signIn.ID)
				require.NoError(t, err, "the session stays, so the logout can be retried")

				w.browsers.failEnd.Store(false)

				retried := w.logout(t, w.signIn.ID)
				require.NoError(t, retried.err)
				assert.Equal(t, []string{"__Host-scrty-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"},
					retried.header.Values("Set-Cookie"), "the retry ends the sign-in and expires the cookie")
			},
		},
		{
			name: "a logout presenting only a padded twin of the cookie name expires nothing",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				out := w.logoutWith(t, httpsec.DefaultSessionCookieName+"\u2000", id)
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"), "no cookie was presented, so none is expired")

				_, err := w.sessions.Load(t.Context(), id)
				require.NoError(t, err, "the session is untouched")
			},
		},
		{
			name: "a logout with no sign-in is refused and touches no cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t).build(t)

				out := w.logoutWith(t, httpsec.DefaultSessionCookieName, "")
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
			},
		},
		{
			name: "basic-auth logout without the cookie sets no Set-Cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t)
				authn, err := authenticate.NewUsernamePasswordAuthenticator(w.users,
					authenticate.WithPasswordEncoder(e2eEncoder(t)))
				require.NoError(t, err)

				w.extra = append(w.extra, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
					Authenticator: authn, Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				}))
				w.build(t)

				req := postValues(t.Context(), httpsec.DefaultLogoutPath, e2eSource, nil)
				req.SetBasicAuth(e2eAddress, e2ePassword)

				out := serveContext(t.Context(), t, w.chain, req)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"),
					"a request that carried no session cookie has none to expire")
			},
		},
		{
			name: "a chain without the cookie session touches no cookie",
			assert: func(t *testing.T) {
				t.Helper()

				sessions := must.Must(session.New())
				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), testUserID).AnyTimes().
					DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
						return &identity.Details{ID: testUserID, Username: "ada", Active: true}, nil
					})

				chain, err := httpsec.New(
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
				require.NoError(t, err)

				s, err := sessions.Create(t.Context(), testUserID, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				req := postValues(t.Context(), httpsec.DefaultLogoutPath, e2eSource, nil)
				req.Header.Set("Authorization", "Bearer "+s.ID)

				out := serveContext(t.Context(), t, chain, req)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}
