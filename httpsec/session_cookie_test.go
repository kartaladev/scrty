package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// cookieSource is the client address every cookie request comes from.
const cookieSource = "198.51.100.23"

// cookieStore forwards to the in-memory store, counts the loads it is asked
// for, honours the request's own context as a networked store would, and
// fails every load with fail when it is set.
type cookieStore struct {
	session.Store

	loads atomic.Int64
	fail  error

	// hangUp, when set, ends the request's context as its session loads, as
	// a client hanging up mid-request does.
	hangUp context.CancelFunc
}

func (s *cookieStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	s.loads.Add(1)

	if s.hangUp != nil {
		s.hangUp()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if s.fail != nil {
		return nil, s.fail
	}

	return s.Store.Load(ctx, sid)
}

// cookieFixture is a session manager over a counting in-memory store, on a fake
// clock, with one signed-in session that carries a CSRF token, and the user
// loader, limiter and log a cookie chain is built over.
type cookieFixture struct {
	clk      *clockwork.FakeClock
	store    *cookieStore
	sessions *session.Sessions
	signIn   *session.Session
	limiter  *chargeRecorder
	logs     *capturingHandler

	// user is what the user loader answers; it defaults to the stored user.
	user    func() (*identity.Details, error)
	reloads atomic.Int64
	users   *MockUserLoader

	// hangUpOnLoad ends the request's context as its session loads.
	hangUpOnLoad bool
}

func newCookieFixture(t *testing.T) *cookieFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC))
	store := &cookieStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}

	sessions, err := session.New(session.WithClock(clk), session.WithStore(store),
		session.WithIdleTimeout(30*time.Minute), session.WithAbsoluteTimeout(12*time.Hour))
	require.NoError(t, err)

	f := &cookieFixture{
		clk:      clk,
		store:    store,
		sessions: sessions,
		limiter:  newChargeRecorder(t),
		logs:     &capturingHandler{},
		user:     func() (*identity.Details, error) { return storedUser(), nil },
	}

	f.users = NewMockUserLoader(gomock.NewController(t))
	f.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			f.reloads.Add(1)

			return f.user()
		})

	f.signIn = f.create(t)

	return f
}

// create makes a sign-in for u-1 holding a CSRF token, with opts.
func (f *cookieFixture) create(t *testing.T, opts ...session.CreateOption) *session.Session {
	t.Helper()

	s, err := f.sessions.Create(t.Context(), "u-1",
		append([]session.CreateOption{session.WithFirstFactor(factor.Password), session.WithCSRFToken()}, opts...)...)
	require.NoError(t, err)

	return s
}

func (f *cookieFixture) deps() httpsec.SessionBearerDeps {
	return httpsec.SessionBearerDeps{Sessions: f.sessions, Users: f.users}
}

// chainOptions is a cookie chain at its defaults, over the fixture's limiter.
func (f *cookieFixture) chainOptions(extra ...httpsec.Option) []httpsec.Option {
	return append([]httpsec.Option{
		httpsec.WithLogger(slog.New(f.logs)),
		httpsec.WithClock(f.clk),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableSessionCookie(f.deps(), httpsec.WithSessionCookieLimiter(f.limiter)),
	}, extra...)
}

// cookieRequest is a same-origin request from cookieSource carrying cookie as
// its Cookie header (none when ""), and headers.
func sessionCookieRequest(ctx context.Context, method, cookie string, headers map[string]string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, method, "https://app.example.com/orders", nil)
	req.RemoteAddr = cookieSource + ":51000"
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req
}

// named is the Cookie header pair presenting value under the default name.
func named(value string) string { return httpsec.DefaultSessionCookieName + "=" + value }

// TestSessionCookie_Authenticates pins that the cookie session is off until
// enabled, that a session cookie is judged by the same rules as a session
// reference in the Authorization header (shape before lookup, load, reuse,
// user reload, policy, per-source throttling, refusal versus dependency
// failure), that more than one cookie of the name is refused before any
// lookup, that an unsafe request needs the sign-in's CSRF token, judged before
// the user is reloaded and never charged to the source, and that the cookie
// is never recorded as a presented access token.
func TestSessionCookie_Authenticates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options builds the chain; nil is the fixture's cookie chain.
		options func(t *testing.T, f *cookieFixture) []httpsec.Option

		// request builds the request; it runs after wire.
		request func(t *testing.T, f *cookieFixture) *http.Request

		wire func(t *testing.T, f *cookieFixture)
		ctx  func(ctx context.Context) context.Context

		assert func(t *testing.T, f *cookieFixture, s served)
	}

	errStoreDown := errors.New("sessions: connection refused")

	get := func(cookie func(f *cookieFixture) string) func(t *testing.T, f *cookieFixture) *http.Request {
		return func(t *testing.T, f *cookieFixture) *http.Request {
			return sessionCookieRequest(t.Context(), http.MethodGet, cookie(f), nil)
		}
	}

	signedIn := func(f *cookieFixture) string { return named(f.signIn.ID) }

	authenticated := func(t *testing.T, f *cookieFixture, s served) {
		t.Helper()
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)

		auth, ok := authenticate.AuthenticationFromContext(s.handled.Context())
		require.True(t, ok)
		assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)

		published, ok := httpsec.SessionFromContext(s.handled.Context())
		require.True(t, ok)
		assert.Equal(t, f.signIn.ID, published.ID)

		assert.Empty(t, httpsec.PresentedToken(s.handled),
			"a cookie is not an access token: nothing is recorded for a DPoP proof's ath")
		assert.True(t, httpsec.StreamByCookie(s.handled), "the signal stream reads it as a cookie")
		assert.Empty(t, f.limiter.recorded(), "a live session spends nothing")
	}

	passedThroughUnread := func(t *testing.T, f *cookieFixture, s served) {
		t.Helper()
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)

		_, ok := authenticate.AuthenticationFromContext(s.handled.Context())
		assert.False(t, ok, "nothing was authenticated")
		assert.Zero(t, f.store.loads.Load(), "the cookie was not looked up")
	}

	// refusedCharged is a 401 that never ran the handler and was charged once
	// to the source; looked says whether the store was asked.
	refusedCharged := func(looked bool) func(t *testing.T, f *cookieFixture, s served) {
		return func(t *testing.T, f *cookieFixture, s served) {
			t.Helper()
			require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
			assert.False(t, s.handlerRan)

			charged := f.limiter.recorded()
			require.Len(t, charged, 1, "a refused reference is a failed guess")
			assert.Contains(t, charged[0], cookieSource)

			if !looked {
				assert.Zero(t, f.store.loads.Load(), "refused before any lookup")
			}
		}
	}

	uncharged := func(t *testing.T, f *cookieFixture) {
		t.Helper()
		assert.Empty(t, f.limiter.recorded(), "nothing is charged to the source")
	}

	cases := []testCase{
		{
			name: "not enabled: the cookie is ignored and never looked up",
			options: func(_ *testing.T, f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(slog.New(f.logs)), httpsec.EnableCSRFProtection()}
			},
			request: get(signedIn),
			assert:  passedThroughUnread,
		},
		{
			name:    "enabled: a valid cookie authenticates its session's user",
			request: get(signedIn),
			assert:  authenticated,
		},
		{
			name:    "the cookie among others is found",
			request: get(func(f *cookieFixture) string { return "theme=dark; " + named(f.signIn.ID) + "; lang=en" }),
			assert:  authenticated,
		},
		{
			name:    "no cookie passes through",
			request: get(func(*cookieFixture) string { return "" }),
			assert:  passedThroughUnread,
		},
		{
			name:    "only other cookies pass through",
			request: get(func(*cookieFixture) string { return "theme=dark; __Host-scrty-sessionx=abc" }),
			assert:  passedThroughUnread,
		},
		{
			name:    "an unknown, well-formed value is refused and charged",
			request: get(func(*cookieFixture) string { return named(unknownReference(1)) }),
			assert:  refusedCharged(true),
		},
		{
			name:    "a malformed value is refused before any lookup",
			request: get(func(*cookieFixture) string { return named("not-a-reference") }),
			assert:  refusedCharged(false),
		},
		{
			name:    "an empty value is refused before any lookup",
			request: get(func(*cookieFixture) string { return named("") }),
			assert:  refusedCharged(false),
		},
		{
			name:    "an oversized value is refused before any lookup",
			request: get(func(*cookieFixture) string { return named(strings.Repeat("a", 4000)) }),
			assert:  refusedCharged(false),
		},
		{
			name: "a value with characters no identifier has is refused before any lookup",
			request: get(func(f *cookieFixture) string {
				return named(`"` + f.signIn.ID + `"`)
			}),
			assert: refusedCharged(false),
		},
		{
			name: "two cookies of the name, the same value, are refused before any lookup",
			request: get(func(f *cookieFixture) string {
				return named(f.signIn.ID) + "; " + named(f.signIn.ID)
			}),
			assert: refusedCharged(false),
		},
		{
			name: "two cookies of the name on two header lines are refused before any lookup",
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				req := sessionCookieRequest(t.Context(), http.MethodGet, named(f.signIn.ID), nil)
				req.Header.Add("Cookie", named(unknownReference(2)))

				return req
			},
			assert: refusedCharged(false),
		},
		{
			name: "an expired session is refused and charged",
			wire: func(_ *testing.T, f *cookieFixture) {
				f.clk.Advance(31 * time.Minute)
			},
			request: get(signedIn),
			assert:  refusedCharged(true),
		},
		{
			name: "a superseded identifier after its window is reuse, and the family is revoked",
			wire: func(t *testing.T, f *cookieFixture) {
				successor, _, err := f.sessions.RotateWithGrace(t.Context(), f.signIn, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(31 * time.Second)

				t.Cleanup(func() {
					_, err := f.sessions.Load(context.WithoutCancel(t.Context()), successor.ID)
					assert.ErrorIs(t, err, session.ErrNotFound, "the family is revoked, its successor with it")
				})
			},
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				refusedCharged(true)(t, f, s)
				assert.ErrorIs(t, s.err, session.ErrReused)
			},
		},
		{
			name: "a disabled user is refused and charged",
			wire: func(_ *testing.T, f *cookieFixture) {
				f.user = func() (*identity.Details, error) {
					u := storedUser()
					u.Active = false

					return u, nil
				}
			},
			request: get(signedIn),
			assert:  refusedCharged(true),
		},
		{
			name: "a session bound to a sender key is refused: a cookie carries no proof",
			wire: func(t *testing.T, f *cookieFixture) {
				f.signIn = f.create(t, session.WithKeyBinding(session.KeyBinding{JKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}))
			},
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				refusedCharged(true)(t, f, s)
				assert.Zero(t, f.reloads.Load(), "refused before the user is reloaded")
			},
		},
		{
			name:    "a session store outage is a dependency failure, not a refusal",
			wire:    func(_ *testing.T, f *cookieFixture) { f.store.fail = errStoreDown },
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.ErrorIs(t, s.err, errStoreDown)
				assert.NotErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				uncharged(t, f)
			},
		},
		{
			name: "a user store outage is a dependency failure, not a refusal",
			wire: func(_ *testing.T, f *cookieFixture) {
				f.user = func() (*identity.Details, error) { return nil, errStoreDown }
			},
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.ErrorIs(t, s.err, errStoreDown)
				assert.NotErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, s.handlerRan)
				uncharged(t, f)
			},
		},
		{
			// The limiter is asked on a context that has already ended, which
			// the pipeline answers as a source it could not judge.
			name:    "a request whose context ended before it arrived is not looked up or charged",
			request: get(signedIn),
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.Error(t, s.err)
				assert.False(t, s.handlerRan)
				assert.Zero(t, f.store.loads.Load())
				uncharged(t, f)
			},
		},
		{
			name:    "a request whose context ends while its session loads is neither refused nor charged",
			wire:    func(_ *testing.T, f *cookieFixture) { f.hangUpOnLoad = true },
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.ErrorIs(t, s.err, context.Canceled)
				assert.NotErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, s.handlerRan)
				uncharged(t, f)
			},
		},
		{
			name: "a policy refusal of a valid session is not charged",
			options: func(t *testing.T, f *cookieFixture) []httpsec.Option {
				return f.chainOptions(httpsec.WithPolicyEngine(
					denyingIn(t, policy.PerRequest, httpsec.ErrAuthenticationRequired)))
			},
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, s.handlerRan)
				uncharged(t, f)
			},
		},
		{
			name: "a limiter that cannot answer is logged under the cookie's own flow",
			options: func(t *testing.T, f *cookieFixture) []httpsec.Option {
				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().Return(false, errLimiterDown)

				return []httpsec.Option{
					httpsec.WithLogger(slog.New(f.logs)),
					httpsec.WithClock(f.clk),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableSessionCookie(f.deps(), httpsec.WithSessionCookieLimiter(limiter)),
				}
			},
			request: get(signedIn),
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.Zero(t, f.store.loads.Load())

				rec, ok := recordAt(f.logs.records(), slog.LevelError, "httpsec: the rate limiter could not answer")
				require.True(t, ok)

				flow, ok := attrValue(rec, "flow")
				require.True(t, ok)
				assert.Equal(t, "session-cookie", flow.String(), "apart from the header's session-reference")
			},
		},
		{
			name: "an unsafe request with the sign-in's CSRF token is authenticated",
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID),
					map[string]string{"X-CSRF-Token": f.signIn.CSRFToken})
			},
			assert: authenticated,
		},
		{
			name: "an unsafe request without a CSRF token is refused as cross-site and not charged",
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID), nil)
			},
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				refusedCrossSite(t, s)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(s.err))
				uncharged(t, f)
			},
		},
		{
			name: "an unsafe request with another sign-in's token is refused as cross-site",
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				other := f.create(t)

				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID),
					map[string]string{"X-CSRF-Token": other.CSRFToken})
			},
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				refusedCrossSite(t, s)
				uncharged(t, f)
			},
		},
		{
			name: "CSRF is judged before the user reload: a disabled user without a token is refused as cross-site",
			wire: func(_ *testing.T, f *cookieFixture) {
				f.user = func() (*identity.Details, error) {
					u := storedUser()
					u.Active = false

					return u, nil
				}
			},
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID), nil)
			},
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				refusedCrossSite(t, s)
				assert.Zero(t, f.reloads.Load(), "the user was not reloaded")
				uncharged(t, f)
			},
		},
		{
			name: "a token source answering with the authentication-required error is a cross-site refusal, not charged",
			options: func(_ *testing.T, f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(slog.New(f.logs)),
					httpsec.WithClock(f.clk),
					httpsec.EnableCSRFProtection(httpsec.WithCSRFTokens(authRequiredTokens{})),
					httpsec.EnableSessionCookie(f.deps(), httpsec.WithSessionCookieLimiter(f.limiter)),
				}
			},
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID),
					map[string]string{"X-CSRF-Token": "anything"})
			},
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				refusedCrossSite(t, s)
				assert.NotErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				uncharged(t, f)
			},
		},
		{
			name: "a token source whose outage is joined to the authentication-required error is an outage, not charged, cookie kept",
			options: func(_ *testing.T, f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(slog.New(f.logs)),
					httpsec.WithClock(f.clk),
					httpsec.EnableCSRFProtection(httpsec.WithCSRFTokens(outageTokens{err: errStoreDown})),
					httpsec.EnableSessionCookie(f.deps(), httpsec.WithSessionCookieLimiter(f.limiter)),
				}
			},
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID),
					map[string]string{"X-CSRF-Token": "anything"})
			},
			assert: func(t *testing.T, f *cookieFixture, s served) {
				t.Helper()
				require.ErrorIs(t, s.err, errStoreDown)
				assert.NotErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.NotErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Header().Values("Set-Cookie"), "an outage does not expire the cookie")
				uncharged(t, f)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCookieFixture(t)
			if tc.wire != nil {
				tc.wire(t, f)
			}

			opts := f.chainOptions()
			if tc.options != nil {
				opts = tc.options(t, f)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			req := tc.request(t, f)

			tc.assert(t, f, f.serve(t, chain, req, tc.ctx))
		})
	}
}

// serve runs req through chain on t's context, changed by modify when it is
// not nil, and ended as the session loads when hangUpOnLoad is set.
func (f *cookieFixture) serve(
	t *testing.T, chain *httpsec.Chain, req *http.Request, modify func(context.Context) context.Context,
) served {
	t.Helper()

	ctx := t.Context()
	if modify != nil {
		ctx = modify(ctx)
	}

	if f.hangUpOnLoad {
		var cancel context.CancelFunc

		ctx, cancel = context.WithCancel(ctx)
		defer cancel()

		f.store.hangUp = cancel
	}

	return serveContext(ctx, t, chain, req.WithContext(ctx))
}

// authRequiredTokens is a consumer's CSRF token source that breaks its contract:
// it refuses with the authentication-required error rather than
// ErrCrossSiteRequest.
type authRequiredTokens struct{}

func (authRequiredTokens) Token(context.Context, *session.Session) (string, error) { return "t", nil }

func (authRequiredTokens) Verify(context.Context, *session.Session, string) error {
	return httpsec.ErrAuthenticationRequired
}

// outageTokens is a consumer's CSRF token source that fails with err, joined to
// the authentication-required error.
type outageTokens struct{ err error }

func (outageTokens) Token(context.Context, *session.Session) (string, error) { return "t", nil }

func (o outageTokens) Verify(context.Context, *session.Session, string) error {
	return errors.Join(httpsec.ErrAuthenticationRequired, o.err)
}

// expiredDefaultCookie is the default session cookie expired with the
// attributes it is set with.
const expiredDefaultCookie = "__Host-scrty-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"

// TestSessionCookie_RefusalExpires pins that a cookie the pipeline judged bad
// (malformed, duplicated, unknown, expired, unreadable, reused, its user
// refused, bound to a sender) is expired by the refusal with the attributes it
// is set with, and that every answer reached without judging it (a store,
// user-store or cipher outage, a request whose context ended, a source over
// its allowance or a limiter that cannot answer, a CSRF failure, a policy
// decision about a valid session) leaves it in place. The server's deadlines
// stay authoritative over a persistent cookie.
func TestSessionCookie_RefusalExpires(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options builds the chain; nil is the fixture's cookie chain.
		options func(t *testing.T, f *cookieFixture) []httpsec.Option

		wire    func(t *testing.T, f *cookieFixture)
		request func(t *testing.T, f *cookieFixture) *http.Request
		ctx     func(ctx context.Context) context.Context

		assert func(t *testing.T, s served)
	}

	errStoreDown := errors.New("sessions: connection refused")

	get := func(cookie func(f *cookieFixture) string) func(t *testing.T, f *cookieFixture) *http.Request {
		return func(t *testing.T, f *cookieFixture) *http.Request {
			return sessionCookieRequest(t.Context(), http.MethodGet, cookie(f), nil)
		}
	}

	signedIn := func(f *cookieFixture) string { return named(f.signIn.ID) }

	// expires is a refusal whose response expires the cookie, as want.
	expires := func(want string) func(t *testing.T, s served) {
		return func(t *testing.T, s served) {
			t.Helper()
			require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
			assert.False(t, s.handlerRan)
			assert.Equal(t, []string{want}, s.rec.Header().Values("Set-Cookie"))
		}
	}

	expired := expires(expiredDefaultCookie)

	// untouched is an answer whose response sets no cookie; cause, when not
	// nil, is what it fails with.
	untouched := func(cause error) func(t *testing.T, s served) {
		return func(t *testing.T, s served) {
			t.Helper()
			require.Error(t, s.err)

			if cause != nil {
				require.ErrorIs(t, s.err, cause)
			}

			assert.False(t, s.handlerRan)
			assert.Empty(t, s.rec.Header().Values("Set-Cookie"), "the cookie is left in place")
		}
	}

	// limitedBy is the fixture's cookie chain over a limiter answering
	// exceeded for every source, and recording nothing.
	limitedBy := func(exceeded bool, err error) func(t *testing.T, f *cookieFixture) []httpsec.Option {
		return func(t *testing.T, f *cookieFixture) []httpsec.Option {
			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().Return(exceeded, err)
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

			return []httpsec.Option{
				httpsec.WithLogger(slog.New(f.logs)),
				httpsec.WithClock(f.clk),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableSessionCookie(f.deps(), httpsec.WithSessionCookieLimiter(limiter)),
			}
		}
	}

	disabled := func(_ *testing.T, f *cookieFixture) {
		f.user = func() (*identity.Details, error) {
			u := storedUser()
			u.Active = false

			return u, nil
		}
	}

	cases := []testCase{
		{
			name:    "a malformed value is expired",
			request: get(func(*cookieFixture) string { return named("not-a-reference") }),
			assert:  expired,
		},
		{
			name:    "an empty value is expired",
			request: get(func(*cookieFixture) string { return named("") }),
			assert:  expired,
		},
		{
			name: "two cookies of the name are expired",
			request: get(func(f *cookieFixture) string {
				return named(f.signIn.ID) + "; " + named(unknownReference(3))
			}),
			assert: expired,
		},
		{
			name:    "an unknown value is expired",
			request: get(func(*cookieFixture) string { return named(unknownReference(1)) }),
			assert:  expired,
		},
		{
			name:    "an expired session's cookie is expired",
			wire:    func(_ *testing.T, f *cookieFixture) { f.clk.Advance(31 * time.Minute) },
			request: get(signedIn),
			assert:  expired,
		},
		{
			name: "a persistent cookie presented after its session's idle deadline is refused and expired",
			wire: func(t *testing.T, f *cookieFixture) {
				f.signIn = f.create(t, session.WithPersistentCookie())
				require.True(t, f.signIn.PersistentCookie)
				f.clk.Advance(31 * time.Minute)
			},
			request: get(signedIn),
			assert:  expired,
		},
		{
			name:    "an unreadable session's cookie is expired",
			wire:    func(_ *testing.T, f *cookieFixture) { f.store.fail = session.ErrUnreadable },
			request: get(signedIn),
			assert:  expired,
		},
		{
			name: "a reused identifier's cookie is expired",
			wire: func(t *testing.T, f *cookieFixture) {
				_, _, err := f.sessions.RotateWithGrace(t.Context(), f.signIn, 30*time.Second)
				require.NoError(t, err)
				f.clk.Advance(31 * time.Second)
			},
			request: get(signedIn),
			assert: func(t *testing.T, s served) {
				t.Helper()
				expired(t, s)
				assert.ErrorIs(t, s.err, session.ErrReused)
			},
		},
		{
			name:    "a disabled user's cookie is expired",
			wire:    disabled,
			request: get(signedIn),
			assert:  expired,
		},
		{
			name: "a cookie whose user is gone is expired",
			wire: func(_ *testing.T, f *cookieFixture) {
				f.user = func() (*identity.Details, error) { return nil, identity.ErrUserNotFound }
			},
			request: get(signedIn),
			assert:  expired,
		},
		{
			name: "a sender-bound session's cookie is expired",
			wire: func(t *testing.T, f *cookieFixture) {
				f.signIn = f.create(t, session.WithKeyBinding(session.KeyBinding{X5TS256: "thumb"}))
			},
			request: get(signedIn),
			assert:  expired,
		},
		{
			name: "a consumer's name, domain and same-site are expired as set",
			options: func(_ *testing.T, f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(slog.New(f.logs)),
					httpsec.WithClock(f.clk),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableSessionCookie(f.deps(),
						httpsec.WithSessionCookieLimiter(f.limiter),
						httpsec.WithSessionCookieName("__Secure-app"),
						httpsec.WithSessionCookieDomain("example.com"),
						httpsec.WithSessionCookieSameSite(http.SameSiteStrictMode)),
				}
			},
			request: get(func(*cookieFixture) string { return "__Secure-app=" + unknownReference(4) }),
			assert:  expires("__Secure-app=; Path=/; Domain=example.com; Max-Age=0; HttpOnly; Secure; SameSite=Strict"),
		},
		{
			name:    "a live session's cookie is not set again",
			request: get(signedIn),
			assert: func(t *testing.T, s served) {
				t.Helper()
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
				assert.Empty(t, s.rec.Header().Values("Set-Cookie"))
			},
		},
		{
			name:    "a session store outage leaves the cookie",
			wire:    func(_ *testing.T, f *cookieFixture) { f.store.fail = errStoreDown },
			request: get(signedIn),
			assert:  untouched(errStoreDown),
		},
		{
			name:    "a cipher outage leaves the cookie",
			wire:    func(_ *testing.T, f *cookieFixture) { f.store.fail = session.ErrCipherUnavailable },
			request: get(signedIn),
			assert:  untouched(session.ErrCipherUnavailable),
		},
		{
			name: "a user store outage leaves the cookie",
			wire: func(_ *testing.T, f *cookieFixture) {
				f.user = func() (*identity.Details, error) { return nil, errStoreDown }
			},
			request: get(signedIn),
			assert:  untouched(errStoreDown),
		},
		{
			name:    "a request whose context ends while its session loads leaves the cookie",
			wire:    func(_ *testing.T, f *cookieFixture) { f.hangUpOnLoad = true },
			request: get(signedIn),
			assert:  untouched(context.Canceled),
		},
		{
			name:    "a request whose context ended before it arrived leaves the cookie",
			request: get(signedIn),
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: untouched(nil),
		},
		{
			name:    "a source over its allowance leaves a valid cookie",
			options: limitedBy(true, nil),
			request: get(signedIn),
			assert:  untouched(httpsec.ErrAuthenticationRequired),
		},
		{
			name:    "a source over its allowance leaves even a malformed cookie",
			options: limitedBy(true, nil),
			request: get(func(*cookieFixture) string { return named("not-a-reference") }),
			assert:  untouched(httpsec.ErrAuthenticationRequired),
		},
		{
			name:    "a source over its allowance leaves two cookies of the name",
			options: limitedBy(true, nil),
			request: get(func(f *cookieFixture) string { return named(f.signIn.ID) + "; " + named(f.signIn.ID) }),
			assert:  untouched(httpsec.ErrAuthenticationRequired),
		},
		{
			name:    "a limiter that cannot answer leaves the cookie",
			options: limitedBy(false, errLimiterDown),
			request: get(signedIn),
			assert:  untouched(httpsec.ErrAuthenticationRequired),
		},
		{
			name: "a CSRF failure leaves the cookie",
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID), nil)
			},
			assert: untouched(httpsec.ErrCrossSiteRequest),
		},
		{
			name: "a CSRF failure of a disabled user's cookie leaves it",
			wire: disabled,
			request: func(t *testing.T, f *cookieFixture) *http.Request {
				return sessionCookieRequest(t.Context(), http.MethodPost, named(f.signIn.ID), nil)
			},
			assert: untouched(httpsec.ErrCrossSiteRequest),
		},
		{
			name: "a policy refusal of a valid session leaves the cookie",
			options: func(t *testing.T, f *cookieFixture) []httpsec.Option {
				return f.chainOptions(httpsec.WithPolicyEngine(
					denyingIn(t, policy.PerRequest, httpsec.ErrAuthenticationRequired)))
			},
			request: get(signedIn),
			assert:  untouched(httpsec.ErrAuthenticationRequired),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCookieFixture(t)
			if tc.wire != nil {
				tc.wire(t, f)
			}

			opts := f.chainOptions()
			if tc.options != nil {
				opts = tc.options(t, f)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, f.serve(t, chain, tc.request(t, f), tc.ctx))
		})
	}
}
