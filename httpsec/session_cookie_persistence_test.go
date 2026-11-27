package httpsec_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// remembered is a persistence decision that persists every sign-in.
func remembered(*httpsec.Exchange) bool { return true }

// persistentDelivery is a consumer's session delivery that sets the cookie
// itself, with the Max-Age it works out from the session's absolute deadline
// and now, or with none when noMaxAge is set. It is a consumer delivery
// implementation whose own logic is the test's subject, so it stays
// hand-written.
type persistentDelivery struct {
	now      func() time.Time
	noMaxAge bool

	// skew is added to the Max-Age of a persistent cookie; maxAgeAlways is the
	// Max-Age a non-persistent cookie is set with, when not zero.
	skew         int
	maxAgeAlways int
}

func (d persistentDelivery) Deliver(ex *httpsec.Exchange, s *session.Session, credential string) (string, error) {
	c := sessionCookieFor(credential) //nolint:gosec // G124: the chain's own Secure, HttpOnly, SameSite=Lax cookie
	if s.PersistentCookie && !d.noMaxAge {
		c.MaxAge = max(1, int((s.AbsoluteExpiresAt.Sub(d.now())+time.Second-1)/time.Second)) + d.skew
	}

	if !s.PersistentCookie {
		c.MaxAge = d.maxAgeAlways
	}

	ex.Writer.SetCookie(c)

	return "", nil
}

// delivering is a world whose cookie chain delivers through d, with now the
// world's clock, and persists the sign-ins decide chooses.
func delivering(d persistentDelivery, decide func(*httpsec.Exchange) bool) func(*testing.T) (*browserWorld, error) {
	return func(t *testing.T) (*browserWorld, error) {
		t.Helper()

		w := newBrowserWorld(t, session.WithAbsoluteTimeout(12*time.Hour), session.WithIdleTimeout(12*time.Hour))
		d.now = w.clk.Now
		w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookiePersistence(decide), httpsec.WithSessionDelivery(d))

		return w, w.tryBuild(t)
	}
}

// assertDeliveryRefused asserts out is an issuing failure that set no session
// cookie and left no sign-in live.
func assertDeliveryRefused(t *testing.T, w *browserWorld, out served) {
	t.Helper()

	require.Error(t, out.err)
	assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err), "an issuing failure")
	noSessionCookie(t, out)
	assert.Zero(t, w.active(t), "the undelivered sign-in is ended")
}

// rawSessionCookie is the Set-Cookie line out set for the default session
// cookie, "" when it set none.
func rawSessionCookie(out served) string {
	for _, line := range out.rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, httpsec.DefaultSessionCookieName+"=") {
			return line
		}
	}

	return ""
}

// persistedFor asserts the session cookie out set persists for exactly the
// seconds left until the stored session's absolute deadline, by now, rounded
// up and at least one, and that the session records the choice. It returns
// the identifier.
func persistedFor(t *testing.T, sessions *session.Sessions, out served, now time.Time) string {
	t.Helper()

	c := cookieNamed(out.rec, httpsec.DefaultSessionCookieName)
	require.NotNil(t, c, "the session cookie is set")

	s, err := sessions.Load(t.Context(), c.Value)
	require.NoError(t, err)
	assert.True(t, s.PersistentCookie, "the session records the persistent cookie")

	left := s.AbsoluteExpiresAt.Sub(now)
	want := max(1, int((left+time.Second-1)/time.Second))

	assert.Equal(t, want, c.MaxAge, "Max-Age is the seconds to the absolute deadline, rounded up")
	assert.Contains(t, rawSessionCookie(out), "Max-Age="+strconv.Itoa(want))
	assert.NotContains(t, rawSessionCookie(out), "Expires=", "Max-Age alone carries the lifetime")

	return c.Value
}

// browserSessionOnly asserts the session cookie out set carries neither
// Max-Age nor Expires, and that the session does not record a persistent
// cookie.
func browserSessionOnly(t *testing.T, sessions *session.Sessions, out served) {
	t.Helper()

	c := cookieNamed(out.rec, httpsec.DefaultSessionCookieName)
	require.NotNil(t, c, "the session cookie is set")
	assert.Zero(t, c.MaxAge)
	assert.NotContains(t, rawSessionCookie(out), "Max-Age")
	assert.NotContains(t, rawSessionCookie(out), "Expires")

	s, err := sessions.Load(t.Context(), c.Value)
	require.NoError(t, err)
	assert.False(t, s.PersistentCookie)
}

// TestSessionCookie_Persistence pins the persistence decision: a sign-in it
// persists is created with the persistent mark and its cookie carries Max-Age,
// the seconds to the session's absolute deadline rounded up and never below
// one, on every rotation of it too; without the option, or when it declines,
// no cookie carries Max-Age or Expires; and a nil decision is a configuration
// error.
func TestSessionCookie_Persistence(t *testing.T) {
	t.Parallel()

	twelveHours := []session.Option{
		session.WithAbsoluteTimeout(12 * time.Hour), session.WithIdleTimeout(12 * time.Hour),
	}

	type testCase struct {
		name string

		// world builds the chain the case runs on.
		world func(t *testing.T) (*browserWorld, error)

		assert func(t *testing.T, w *browserWorld, buildErr error)
	}

	persisting := func(enrol bool, decide func(*httpsec.Exchange) bool) func(*testing.T) (*browserWorld, error) {
		return func(t *testing.T) (*browserWorld, error) {
			t.Helper()

			w := newBrowserWorld(t, twelveHours...)
			if decide != nil {
				w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookiePersistence(decide))
			}

			if enrol {
				w.enrol(t)
			}

			return w, w.tryBuild(t)
		}
	}

	cases := []testCase{
		{
			name:  "a remembered sign-in of 12 hours persists for 43200 seconds",
			world: persisting(false, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				out := w.login(t)
				require.NoError(t, out.err)
				persistedFor(t, w.sessions, out, w.clk.Now())
				assert.Equal(t, 43200, cookieNamed(out.rec, httpsec.DefaultSessionCookieName).MaxAge)
			},
		},
		{
			name:  "persistence survives second-factor verification",
			world: persisting(true, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				challenged := w.login(t)
				require.Error(t, challenged.err)
				pending := persistedFor(t, w.sessions, challenged, w.clk.Now())

				code := w.code(t) // moves the clock on by one TOTP period
				verified := w.post(t.Context(), t, testMFAVerifyPath, pending, url.Values{"code": {code}})
				require.NoError(t, verified.err)

				rotated := persistedFor(t, w.sessions, verified, w.clk.Now())
				assert.NotEqual(t, pending, rotated)
				assert.Less(t, cookieNamed(verified.rec, httpsec.DefaultSessionCookieName).MaxAge, 43200,
					"Max-Age follows the deadline, not the sign-in's original lifetime")
			},
		},
		{
			name:  "persistence survives re-authentication and renewal",
			world: persisting(false, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				id := w.signedIn(t)

				w.clk.Advance(time.Minute)
				reproved := w.post(t.Context(), t, reauthPasswordPath, id, url.Values{"password": {e2ePassword}})
				require.NoError(t, reproved.err)
				id = persistedFor(t, w.sessions, reproved, w.clk.Now())

				w.clk.Advance(time.Minute)
				renewed := w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil)
				require.NoError(t, renewed.err)
				persistedFor(t, w.sessions, renewed, w.clk.Now())
			},
		},
		{
			name:  "a deadline 0.4 seconds away persists for one second",
			world: persisting(false, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				id := w.signedIn(t)

				w.clk.Advance(12*time.Hour - 400*time.Millisecond)

				renewed := w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil)
				require.NoError(t, renewed.err)
				persistedFor(t, w.sessions, renewed, w.clk.Now())
				assert.Equal(t, 1, cookieNamed(renewed.rec, httpsec.DefaultSessionCookieName).MaxAge,
					"never 0, which would expire the cookie it sets")
			},
		},
		{
			name:  "no option: a browser-session cookie",
			world: persisting(true, nil),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				challenged := w.login(t)
				browserSessionOnly(t, w.sessions, challenged)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName).Value
				verified := w.post(t.Context(), t, testMFAVerifyPath, pending, url.Values{"code": {w.code(t)}})
				require.NoError(t, verified.err)
				browserSessionOnly(t, w.sessions, verified)
			},
		},
		{
			name:  "a declined sign-in: a browser-session cookie",
			world: persisting(false, func(*httpsec.Exchange) bool { return false }),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				out := w.login(t)
				require.NoError(t, out.err)
				browserSessionOnly(t, w.sessions, out)
			},
		},
		{
			name:  "the decision reads the sign-in's request",
			world: persisting(false, func(ex *httpsec.Exchange) bool { return ex.Request.Header("X-Remember") == "1" }),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				})
				req.Header.Set("X-Remember", "1")

				out := serve(t, w.chain, req)
				require.NoError(t, out.err)
				persistedFor(t, w.sessions, out, w.clk.Now())

				browserSessionOnly(t, w.sessions, w.login(t))
			},
		},
		{
			name: "a consumer delivery setting the persistent cookie exactly is accepted",
			world: func(t *testing.T) (*browserWorld, error) {
				t.Helper()

				w := newBrowserWorld(t, twelveHours...)
				w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookiePersistence(remembered),
					httpsec.WithSessionDelivery(persistentDelivery{now: w.clk.Now}))

				return w, w.tryBuild(t)
			},
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				out := w.login(t)
				require.NoError(t, out.err)
				persistedFor(t, w.sessions, out, w.clk.Now())
			},
		},
		{
			name: "a consumer delivery dropping Max-Age from a persistent cookie fails the sign-in",
			world: func(t *testing.T) (*browserWorld, error) {
				t.Helper()

				w := newBrowserWorld(t, twelveHours...)
				w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookiePersistence(remembered),
					httpsec.WithSessionDelivery(persistentDelivery{now: w.clk.Now, noMaxAge: true}))

				return w, w.tryBuild(t)
			},
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				out := w.login(t)
				require.Error(t, out.err)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err), "an issuing failure")
				noSessionCookie(t, out)
				assert.Zero(t, w.active(t), "the undelivered sign-in is ended")
			},
		},
		{
			name:  "a delivery's Max-Age one second under the chain's is accepted",
			world: delivering(persistentDelivery{skew: -1}, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				out := w.login(t)
				require.NoError(t, out.err)
				assert.Equal(t, 43199, cookieNamed(out.rec, httpsec.DefaultSessionCookieName).MaxAge,
					"the cookie the delivery set is the one sent")
			},
		},
		{
			name:  "a delivery's Max-Age two seconds under the chain's is refused",
			world: delivering(persistentDelivery{skew: -2}, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)
				assertDeliveryRefused(t, w, w.login(t))
			},
		},
		{
			name:  "a delivery's Max-Age one second over the chain's is refused",
			world: delivering(persistentDelivery{skew: 1}, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)
				assertDeliveryRefused(t, w, w.login(t))
			},
		},
		{
			name:  "a delivery adding Max-Age to a browser-session cookie is refused",
			world: delivering(persistentDelivery{maxAgeAlways: 100}, func(*httpsec.Exchange) bool { return false }),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)
				assertDeliveryRefused(t, w, w.login(t))
			},
		},
		{
			name:  "a delivery one second under a Max-Age of 1 would set none, and is refused",
			world: delivering(persistentDelivery{skew: -1}, remembered),
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				id := w.signedIn(t)

				w.clk.Advance(12*time.Hour - 400*time.Millisecond)

				assertDeliveryRefused(t, w, w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil))
			},
		},
		{
			name: "a recovery-pending persistent sign-in is re-set for the deadline it gets back, not the lowered one",
			world: func(t *testing.T) (*browserWorld, error) {
				t.Helper()

				w := newBrowserWorld(t, twelveHours...)
				w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookiePersistence(remembered))
				w.extra = append(w.extra, httpsec.EnablePasswordChangeGate(w.sessions,
					httpsec.WithPasswordChangeEndpoint(cookiePasswordPath, func(*httpsec.Exchange) error { return nil })))

				return w, w.tryBuild(t)
			},
			assert: func(t *testing.T, w *browserWorld, buildErr error) {
				t.Helper()
				require.NoError(t, buildErr)

				id := w.signedIn(t)

				s, err := w.sessions.Load(t.Context(), id)
				require.NoError(t, err)
				w.sessions.MarkRecoveryPending(s, 10*time.Minute, w.clk.Now())
				require.NoError(t, w.sessions.Save(t.Context(), s))

				out := w.post(t.Context(), t, cookiePasswordPath, id, url.Values{"password": {"n3w-Passw0rd!"}})
				require.NoError(t, out.err)
				assert.Equal(t, 43200, cookieNamed(out.rec, httpsec.DefaultSessionCookieName).MaxAge,
					"the absolute deadline the session has once the change is saved, not the recovery lifetime")

				rotated, err := w.sessions.Load(t.Context(), cookieNamed(out.rec, httpsec.DefaultSessionCookieName).Value)
				require.NoError(t, err)
				assert.Equal(t, w.clk.Now().Add(43200*time.Second), rotated.AbsoluteExpiresAt)
			},
		},
		{
			name: "a nil decision is refused",
			world: func(t *testing.T) (*browserWorld, error) {
				t.Helper()

				w := newBrowserWorld(t)
				w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookiePersistence(nil))

				return w, w.tryBuild(t)
			},
			assert: func(t *testing.T, _ *browserWorld, buildErr error) {
				t.Helper()
				require.ErrorIs(t, buildErr, httpsec.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, err := tc.world(t)
			tc.assert(t, w, err)
		})
	}
}

// TestSessionCookie_PersistenceAtEverySignIn pins that the persistence
// decision is asked once at every path that creates a sign-in on a cookie
// chain, and that each creates its session persistent and sets its cookie
// with Max-Age.
func TestSessionCookie_PersistenceAtEverySignIn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// signIn runs the sign-in on a chain whose cookie session takes opt,
		// and returns what it answered and the manager its session lives in.
		signIn func(t *testing.T, opt httpsec.SessionCookieOption) (served, *session.Sessions)
	}

	cases := []testCase{
		{
			name: "form login",
			signIn: func(t *testing.T, opt httpsec.SessionCookieOption) (served, *session.Sessions) {
				t.Helper()

				w := newBrowserWorld(t)
				w.cookieOpts = append(w.cookieOpts, opt)
				w.build(t)

				return w.login(t), w.sessions
			},
		},
		{
			name: "magic link redemption",
			signIn: func(t *testing.T, opt httpsec.SessionCookieOption) (served, *session.Sessions) {
				t.Helper()

				h := newMagicLinkHarness(t)
				h.tokens = nil
				h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}, opt))

				chain, err := h.build()
				require.NoError(t, err)

				tok, nonce := h.link(t, chain)

				return h.redeem(t, chain, tok, nonce), h.sessions
			},
		},
		{
			name: "passwordless passkey login",
			signIn: func(t *testing.T, opt httpsec.SessionCookieOption) (served, *session.Sessions) {
				t.Helper()

				d := newPwlDeployment(t)
				_ = d.options(t)

				chain, err := httpsec.New(
					httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: d.sessions, Users: d.users}, opt),
					httpsec.EnablePasskeys(
						httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions, Users: d.users},
						httpsec.WithPasskeyPasswordlessLogin()),
				)
				require.NoError(t, err)

				d.chain = chain

				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive)), d.sessions
			},
		},
		{
			name: "recovery completion",
			signIn: func(t *testing.T, opt httpsec.SessionCookieOption) (served, *session.Sessions) {
				t.Helper()

				h := newRecoveryHarness(t)
				h.cookie = true
				h.cookieOpts = []httpsec.SessionCookieOption{opt}
				h.build(t)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword)), h.sessions
			},
		},
		{
			name: "federated callback",
			signIn: func(t *testing.T, opt httpsec.SessionCookieOption) (served, *session.Sessions) {
				t.Helper()

				h := newOIDCHarness(t)

				chain, err := oidcCookieChain(h, referenceUsers(t), []httpsec.SessionCookieOption{opt})
				require.NoError(t, err)

				l := startLogin(t, chain, "")

				return serve(t, chain, callbackRequest(t.Context(), l.genuineCallback(), l.handle)), h.sessions
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var asked atomic.Int32

			out, sessions := tc.signIn(t, httpsec.WithSessionCookiePersistence(func(ex *httpsec.Exchange) bool {
				asked.Add(1)

				assert.NotNil(t, ex.Request, "the decision is asked on the sign-in's request")

				return true
			}))
			require.NoError(t, out.err)

			assert.Equal(t, int32(1), asked.Load(), "the decision is asked once per sign-in")

			c := cookieNamed(out.rec, httpsec.DefaultSessionCookieName)
			require.NotNil(t, c, "the sign-in set the session cookie")
			assert.Positive(t, c.MaxAge, "the cookie persists")

			s, err := sessions.Load(t.Context(), c.Value)
			require.NoError(t, err)
			assert.True(t, s.PersistentCookie, "the session records the persistent cookie")
		})
	}
}
