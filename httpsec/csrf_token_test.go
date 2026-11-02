package httpsec_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// csrfCookie is the cookie the test cookie authenticator reads.
const csrfCookie = "sid"

// csrfFixture is a session manager over the in-memory store and one sign-in
// made with a CSRF token.
type csrfFixture struct {
	sessions *session.Sessions
	signIn   *session.Session
}

func newCSRFFixture(t *testing.T) *csrfFixture {
	t.Helper()

	sessions, err := session.New()
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithCSRFToken())
	require.NoError(t, err)
	require.NotEmpty(t, s.CSRFToken)

	return &csrfFixture{sessions: sessions, signIn: s}
}

// create makes another sign-in for the fixture's user.
func (f *csrfFixture) create(t *testing.T, opts ...session.CreateOption) *session.Session {
	t.Helper()

	s, err := f.sessions.Create(t.Context(), "u-1", opts...)
	require.NoError(t, err)

	return s
}

// cookieRequest is a same-origin request authenticated by the cookie naming
// sid, carrying headers and, when body is not "", a URL-encoded body.
func cookieRequest(ctx context.Context, method, sid string, headers map[string]string, body string) *http.Request {
	all := map[string]string{"Sec-Fetch-Site": "same-origin"}
	for k, v := range headers {
		all[k] = v
	}

	req := csrfRequest(ctx, method, "https://app.example.com/orders", all, body)
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: sid})

	return req
}

// hmacTokens is a consumer's token source: an HMAC over the sign-in's family
// under the consumer's own key.
type hmacTokens struct{ key []byte }

func (h hmacTokens) Token(_ context.Context, s *session.Session) (string, error) {
	m := hmac.New(sha256.New, h.key)
	m.Write(s.FamilyID[:])

	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func (h hmacTokens) Verify(ctx context.Context, s *session.Session, presented string) error {
	want, err := h.Token(ctx, s)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(want), []byte(presented)) {
		return httpsec.ErrCrossSiteRequest
	}

	return nil
}

func TestCSRF_Token(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		csrf    []httpsec.CSRFOption
		extra   func(t *testing.T, f *csrfFixture) []httpsec.Option
		request func(t *testing.T, f *csrfFixture) *http.Request

		// assert receives New's error, and the request's outcome when New
		// built the chain.
		assert func(t *testing.T, f *csrfFixture, s served, err error)
	}

	passes := func(t *testing.T, _ *csrfFixture, s served, err error) {
		require.NoError(t, err)
		passedCSRF(t, s)
	}

	refused := func(t *testing.T, _ *csrfFixture, s served, err error) {
		require.NoError(t, err)
		refusedCrossSite(t, s)
	}

	misconfigured := func(names ...string) func(t *testing.T, _ *csrfFixture, _ served, err error) {
		return func(t *testing.T, _ *csrfFixture, _ served, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)

			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	posting := func(token func(f *csrfFixture) string) func(t *testing.T, f *csrfFixture) *http.Request {
		return func(t *testing.T, f *csrfFixture) *http.Request {
			return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
				map[string]string{"X-CSRF-Token": token(f)}, "")
		}
	}

	own := func(f *csrfFixture) string { return f.signIn.CSRFToken }
	hmacSource := hmacTokens{key: []byte("the consumer's own key, 32 bytes")}

	cases := []testCase{
		{
			name: "a missing token is refused",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID, nil, "")
			},
			assert: refused,
		},
		{
			name:    "a malformed token is refused",
			request: posting(func(*csrfFixture) string { return "not a token!" }),
			assert:  refused,
		},
		{
			name: "another sign-in's token is refused",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				other := f.create(t, session.WithCSRFToken())

				return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
					map[string]string{"X-CSRF-Token": other.CSRFToken}, "")
			},
			assert: refused,
		},
		{name: "the sign-in's own token in the header passes", request: posting(own), assert: passes},
		{
			name: "the sign-in's own token in the form field passes",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID, nil,
					url.Values{"csrf_token": {f.signIn.CSRFToken}}.Encode())
			},
			assert: passes,
		},
		{
			name: "a token in the query string is not read",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				req := cookieRequest(t.Context(), http.MethodPost, f.signIn.ID, nil, "")
				req.URL.RawQuery = url.Values{"csrf_token": {f.signIn.CSRFToken}}.Encode()

				return req
			},
			assert: refused,
		},
		{
			name: "a safe request needs no token",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodGet, f.signIn.ID, nil, "")
			},
			assert: passes,
		},
		{
			name: "a token read before a renewal passes after it",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				renewed, err := f.sessions.Rotate(t.Context(), f.signIn)
				require.NoError(t, err)
				require.NotEqual(t, f.signIn.ID, renewed.ID)

				return cookieRequest(t.Context(), http.MethodPost, renewed.ID,
					map[string]string{"X-CSRF-Token": f.signIn.CSRFToken}, "")
			},
			assert: passes,
		},
		{
			name: "a token read before logging out is refused after a new sign-in",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				require.NoError(t, f.sessions.Delete(t.Context(), f.signIn.ID))
				again := f.create(t, session.WithCSRFToken())

				return cookieRequest(t.Context(), http.MethodPost, again.ID,
					map[string]string{"X-CSRF-Token": f.signIn.CSRFToken}, "")
			},
			assert: refused,
		},
		{
			name: "a sign-in holding no token is refused",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				bare := f.create(t)
				require.Empty(t, bare.CSRFToken)

				return cookieRequest(t.Context(), http.MethodPost, bare.ID,
					map[string]string{"X-CSRF-Token": f.signIn.CSRFToken}, "")
			},
			assert: refused,
		},
		{
			name: "a sign-in holding no token is refused even with an empty token",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				bare := f.create(t)

				return cookieRequest(t.Context(), http.MethodPost, bare.ID,
					map[string]string{"X-CSRF-Token": ""}, "csrf_token=")
			},
			assert: refused,
		},
		{
			name: "a bearer-only request needs no token",
			extra: func(t *testing.T, f *csrfFixture) []httpsec.Option {
				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(storedUser(), nil).AnyTimes()

				return []httpsec.Option{httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users})}
			},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				req := csrfRequest(t.Context(), http.MethodPost, "https://app.example.com/orders",
					map[string]string{"Sec-Fetch-Site": "same-origin", "Authorization": "Bearer " + f.signIn.ID}, "")

				return req
			},
			assert: func(t *testing.T, f *csrfFixture, s served, err error) {
				require.NoError(t, err)
				passedCSRF(t, s)
				require.NotNil(t, s.handled.Session, "the bearer authenticated the request")
				assert.Equal(t, f.signIn.ID, s.handled.Session.ID)
			},
		},
		{
			name: "the accessor returns the sign-in's token",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodGet, f.signIn.ID, nil, "")
			},
			assert: func(t *testing.T, f *csrfFixture, s served, err error) {
				require.NoError(t, err)
				require.True(t, s.handlerRan)

				tok, ok := httpsec.CSRFToken(s.handled.Context())
				require.True(t, ok)
				assert.Equal(t, f.signIn.CSRFToken, tok)
			},
		},
		{
			name: "the accessor answers nothing without a sign-in",
			request: func(t *testing.T, _ *csrfFixture) *http.Request {
				return csrfRequest(t.Context(), http.MethodGet, "https://app.example.com/orders", nil, "")
			},
			assert: func(t *testing.T, _ *csrfFixture, s served, err error) {
				require.NoError(t, err)
				require.True(t, s.handlerRan)

				tok, ok := httpsec.CSRFToken(s.handled.Context())
				assert.False(t, ok)
				assert.Empty(t, tok)
			},
		},
		{
			name: "the accessor answers nothing for a sign-in holding no token",
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodGet, f.create(t).ID, nil, "")
			},
			assert: func(t *testing.T, _ *csrfFixture, s served, err error) {
				require.NoError(t, err)
				require.True(t, s.handlerRan)

				_, ok := httpsec.CSRFToken(s.handled.Context())
				assert.False(t, ok)
			},
		},
		{
			name: "replaced names: the consumer's header passes",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokenNames("X-XSRF-Token", "_xsrf")},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
					map[string]string{"X-XSRF-Token": f.signIn.CSRFToken}, "")
			},
			assert: passes,
		},
		{
			name: "replaced names: the consumer's field passes",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokenNames("X-XSRF-Token", "_xsrf")},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID, nil,
					url.Values{"_xsrf": {f.signIn.CSRFToken}}.Encode())
			},
			assert: passes,
		},
		{
			name:    "replaced names: the default header is no longer read",
			csrf:    []httpsec.CSRFOption{httpsec.WithCSRFTokenNames("X-XSRF-Token", "_xsrf")},
			request: posting(own),
			assert:  refused,
		},
		{
			name:   "a header name that is not a token is refused",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFTokenNames("X CSRF", "csrf_token")},
			assert: misconfigured("WithCSRFTokenNames", `"X CSRF"`),
		},
		{
			name:   "an empty header name is refused",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFTokenNames("", "csrf_token")},
			assert: misconfigured("WithCSRFTokenNames"),
		},
		{
			name: "the default source compares through the comparison it is handed",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokens(httpsec.SessionCSRFTokensComparingWith(
				func(x, y []byte) int {
					// It refuses whatever the bytes, so a pass would mean the
					// comparison was bypassed.
					return 0
				}))},
			request: posting(own),
			assert:  refused,
		},
		{
			name: "the default source is handed the presented and the stored token",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokens(httpsec.SessionCSRFTokensComparingWith(
				func(x, y []byte) int {
					if string(x) == "presented-value" && string(y) != "" {
						return 1
					}

					return 0
				}))},
			request: posting(func(*csrfFixture) string { return "presented-value" }),
			assert:  passes,
		},
		{
			name: "a consumer's source: its token passes",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokens(hmacSource)},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
					map[string]string{"X-CSRF-Token": must.Must(hmacSource.Token(t.Context(), f.signIn))}, "")
			},
			assert: passes,
		},
		{
			name:    "a consumer's source: the stored token is refused",
			csrf:    []httpsec.CSRFOption{httpsec.WithCSRFTokens(hmacSource)},
			request: posting(own),
			assert:  refused,
		},
		{
			name: "a consumer's source: the accessor returns its token",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokens(hmacSource)},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodGet, f.signIn.ID, nil, "")
			},
			assert: func(t *testing.T, f *csrfFixture, s served, err error) {
				require.NoError(t, err)
				require.True(t, s.handlerRan)

				tok, ok := httpsec.CSRFToken(s.handled.Context())
				require.True(t, ok)
				assert.Equal(t, must.Must(hmacSource.Token(t.Context(), f.signIn)), tok)
				assert.NotEqual(t, f.signIn.CSRFToken, tok)
			},
		},
		{
			name:    "a consumer's source failing is not a refusal",
			csrf:    []httpsec.CSRFOption{httpsec.WithCSRFTokens(failingTokens{})},
			request: posting(own),
			assert: func(t *testing.T, _ *csrfFixture, s served, err error) {
				require.NoError(t, err)
				require.ErrorIs(t, s.err, errTokensDown)
				assert.NotErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "CORS allows the token header",
			extra: func(*testing.T, *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"https://app.example.com"}})}
			},
			request: corsPreflightAsking("x-csrf-token"),
			assert: func(t *testing.T, _ *csrfFixture, s served, err error) {
				require.NoError(t, err)
				assert.Equal(t, "X-CSRF-Token", s.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name: "CORS allows the consumer's token header",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFTokenNames("X-XSRF-Token", "_xsrf")},
			extra: func(*testing.T, *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"https://app.example.com"}})}
			},
			request: corsPreflightAsking("x-xsrf-token"),
			assert: func(t *testing.T, _ *csrfFixture, s served, err error) {
				require.NoError(t, err)
				assert.Equal(t, "X-XSRF-Token", s.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name:   "a nil source is refused",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFTokens(nil)},
			assert: misconfigured("WithCSRFTokens"),
		},
		{
			name:   "a typed-nil source is refused",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFTokens((*hmacTokensPtr)(nil))},
			assert: misconfigured("WithCSRFTokens"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCSRFFixture(t)

			opts := []httpsec.Option{
				httpsec.EnableCSRFProtection(tc.csrf...),
				httpsec.RegisterInterceptor(httpsec.NewTestCookieAuthenticator(f.sessions, csrfCookie), httpsec.OrderBearerToken),
			}
			if tc.extra != nil {
				opts = append(opts, tc.extra(t, f)...)
			}

			chain, err := httpsec.New(opts...)
			if err != nil || tc.request == nil {
				tc.assert(t, f, served{}, err)

				return
			}

			tc.assert(t, f, serve(t, chain, tc.request(t, f)), nil)
		})
	}
}

// corsPreflightAsking is a preflight from https://app.example.com asking to
// send header on a POST to api.example.com.
func corsPreflightAsking(header string) func(t *testing.T, _ *csrfFixture) *http.Request {
	return func(t *testing.T, _ *csrfFixture) *http.Request {
		return csrfRequest(t.Context(), http.MethodOptions, "https://api.example.com/orders", map[string]string{
			"Origin":                         "https://app.example.com",
			"Access-Control-Request-Method":  http.MethodPost,
			"Access-Control-Request-Headers": header,
		}, "")
	}
}

// errTokensDown is the failure failingTokens answers with.
var errTokensDown = errors.New("csrf_test: token source down")

// failingTokens is a consumer's source whose dependency is down.
type failingTokens struct{}

func (failingTokens) Token(context.Context, *session.Session) (string, error) {
	return "", errTokensDown
}

func (failingTokens) Verify(context.Context, *session.Session, string) error { return errTokensDown }

// hmacTokensPtr is a source with a pointer receiver, so a typed nil of it is a
// non-nil interface.
type hmacTokensPtr struct{ hmacTokens }

func TestCSRF_TokenAtSignIn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(f *csrfFixture) []httpsec.Option
		assert func(t *testing.T, signedIn *session.Session)
	}

	cookies := func(f *csrfFixture) httpsec.Option {
		return httpsec.RegisterInterceptor(httpsec.NewTestCookieAuthenticator(f.sessions, csrfCookie), httpsec.OrderBearerToken)
	}

	cases := []testCase{
		{
			name: "with CSRF protection and a cookie authenticator, a sign-in holds a token",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), cookies(f)}
			},
			assert: func(t *testing.T, signedIn *session.Session) {
				assert.NotEmpty(t, signedIn.CSRFToken)
			},
		},
		{
			name: "with a consumer's token source, a sign-in holds none",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableCSRFProtection(httpsec.WithCSRFTokens(hmacTokens{key: []byte("the consumer's own key, 32 bytes")})),
					cookies(f),
				}
			},
			assert: func(t *testing.T, signedIn *session.Session) {
				assert.Empty(t, signedIn.CSRFToken, "a token the consumer's source never reads is not stored")
			},
		},
		{
			name: "without a cookie authenticator, a sign-in holds none",
			opts: func(*csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection()}
			},
			assert: func(t *testing.T, signedIn *session.Session) {
				assert.Empty(t, signedIn.CSRFToken)
			},
		},
		{
			name: "with CSRF protection opted out, a sign-in holds none",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithoutCSRFProtection(), cookies(f)}
			},
			assert: func(t *testing.T, signedIn *session.Session) {
				assert.Empty(t, signedIn.CSRFToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCSRFFixture(t)
			ctrl := gomock.NewController(t)

			authn := NewMockAuthenticator(ctrl)
			authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
				Return(&authenticate.Authentication{Principal: testPrincipal()}, nil)

			attempts := NewMockAttemptStore(ctrl)
			attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil)

			var sid string

			tokens := NewMockGenerator(ctrl)
			tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
					sid = id

					return "issued-token", nil
				})

			opts := append(tc.opts(f), httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: authn, Sessions: f.sessions, Tokens: tokens, Attempts: attempts,
			}))

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			s := serve(t, chain, csrfRequest(t.Context(), http.MethodPost, "https://app.example.com/login",
				map[string]string{"Sec-Fetch-Site": "same-origin"}, "username=ada&password=s3cret"))
			require.NoError(t, s.err)
			require.NotEmpty(t, sid)

			signedIn, err := f.sessions.Load(t.Context(), sid)
			require.NoError(t, err)
			tc.assert(t, signedIn)
		})
	}
}

func TestCSRF_TokenAtFirstFactorLogins(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// csrf is whether the chain has CSRF protection and a cookie
		// authenticator, with the default token source.
		csrf bool

		// signIn makes the login and returns the session it created.
		signIn func(t *testing.T, csrfOpts func(sessions *session.Sessions) []httpsec.Option) *session.Session
		assert func(t *testing.T, signedIn *session.Session)
	}

	magicLinkSignIn := func(t *testing.T, csrfOpts func(*session.Sessions) []httpsec.Option) *session.Session {
		h := newMagicLinkHarness(t)
		h.chainOpts = csrfOpts(h.sessions)

		requesting := h.chain(t)
		token, nonce := h.link(t, requesting)
		require.NoError(t, h.redeem(t, requesting, token, nonce).err)

		return h.openedSession(t)
	}

	passkeySignIn := func(t *testing.T, csrfOpts func(*session.Sessions) []httpsec.Option) *session.Session {
		d := newPwlDeployment(t)
		d.withoutPasskeyMFA = true
		d.required.on.Store(false)
		d.pkOpts = append(d.pkOpts, passkey.WithUserVerification(passkey.UserVerificationPreferred))
		d.verifier.notUserVerified.Store(true)
		d.extra = append(d.extra, csrfOpts(d.sessions)...)
		d.build(t)

		return d.finishedSession(t, d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive)))
	}

	holdsToken := func(t *testing.T, signedIn *session.Session) {
		assert.NotEmpty(t, signedIn.CSRFToken)
	}

	holdsNone := func(t *testing.T, signedIn *session.Session) {
		assert.Empty(t, signedIn.CSRFToken)
	}

	cases := []testCase{
		{name: "a magic-link redemption with CSRF protection holds a token", csrf: true, signIn: magicLinkSignIn, assert: holdsToken},
		{name: "a magic-link redemption without CSRF protection holds none", signIn: magicLinkSignIn, assert: holdsNone},
		{name: "a passwordless passkey login with CSRF protection holds a token", csrf: true, signIn: passkeySignIn, assert: holdsToken},
		{name: "a passwordless passkey login without CSRF protection holds none", signIn: passkeySignIn, assert: holdsNone},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signedIn := tc.signIn(t, func(sessions *session.Sessions) []httpsec.Option {
				if !tc.csrf {
					return nil
				}

				return []httpsec.Option{
					httpsec.EnableCSRFProtection(),
					httpsec.RegisterInterceptor(httpsec.NewTestCookieAuthenticator(sessions, csrfCookie), httpsec.OrderBearerToken),
				}
			})

			tc.assert(t, signedIn)
		})
	}
}

// consumerCookieAuthenticator is a consumer's own interceptor authenticating a
// request by a cookie, written against the exported API alone: it declares
// that it authenticates by a cookie, and checks the request's CSRF token for
// the session it loads before handing it on.
type consumerCookieAuthenticator struct{ sessions *session.Sessions }

func (consumerCookieAuthenticator) AuthenticatesByCookie() {}

func (a consumerCookieAuthenticator) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	id, ok := ex.Request.Cookie(csrfCookie)
	if !ok {
		return next(ex)
	}

	s, err := a.sessions.Load(ex.Context(), id)
	if err != nil {
		return httpsec.ErrAuthenticationRequired
	}

	if err := httpsec.CheckCSRFToken(ex, s); err != nil {
		return err
	}

	ex.Session = s

	return next(ex)
}

func TestCSRF_RequiredWithCookies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(f *csrfFixture) []httpsec.Option
		assert func(t *testing.T, f *csrfFixture, chain *httpsec.Chain, err error)
	}

	cookies := func(f *csrfFixture) httpsec.Option {
		return httpsec.RegisterInterceptor(httpsec.NewTestCookieAuthenticator(f.sessions, csrfCookie), httpsec.OrderBearerToken)
	}

	consumers := func(f *csrfFixture) httpsec.Option {
		return httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderBearerToken)
	}

	builds := func(t *testing.T, _ *csrfFixture, chain *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, chain)
	}

	cases := []testCase{
		{
			name: "a cookie authenticator without CSRF protection fails construction",
			opts: func(f *csrfFixture) []httpsec.Option { return []httpsec.Option{cookies(f)} },
			assert: func(t *testing.T, _ *csrfFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "CSRF protection")
				assert.ErrorContains(t, err, "EnableCSRFProtection")
				assert.ErrorContains(t, err, "WithoutCSRFProtection")
			},
		},
		{
			name: "a consumer's own cookie authenticator without CSRF protection fails construction",
			opts: func(f *csrfFixture) []httpsec.Option { return []httpsec.Option{consumers(f)} },
			assert: func(t *testing.T, _ *csrfFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "CSRF protection")
			},
		},
		{
			name: "a consumer's own cookie authenticator refuses a request without its sign-in's token",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{consumers(f), httpsec.EnableCSRFProtection()}
			},
			assert: func(t *testing.T, f *csrfFixture, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				refusedCrossSite(t, serve(t, chain, cookieRequest(t.Context(), http.MethodPost, f.signIn.ID, nil, "")))
			},
		},
		{
			name: "a consumer's own cookie authenticator passes a request with its sign-in's token",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{consumers(f), httpsec.EnableCSRFProtection()}
			},
			assert: func(t *testing.T, f *csrfFixture, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				passedCSRF(t, serve(t, chain, cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
					map[string]string{"X-CSRF-Token": f.signIn.CSRFToken}, "")))
			},
		},
		{
			name: "the explicit opt-out builds, and judges nothing",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{cookies(f), httpsec.WithoutCSRFProtection()}
			},
			assert: func(t *testing.T, f *csrfFixture, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				s := serve(t, chain, cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
					map[string]string{"Sec-Fetch-Site": "cross-site"}, ""))
				passedCSRF(t, s)
			},
		},
		{
			name: "a cookie authenticator in the CSRF slot fails construction",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderCSRF),
					httpsec.EnableCSRFProtection(),
				}
			},
			assert: func(t *testing.T, _ *csrfFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "CSRF protection")
				assert.ErrorContains(t, err, "OrderCSRF")
			},
		},
		{
			name: "a cookie authenticator ahead of the CSRF slot fails construction",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableCSRFProtection(),
					httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderCORS),
				}
			},
			assert: func(t *testing.T, _ *csrfFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "CSRF protection")
			},
		},
		{
			name: "a cookie authenticator just behind the CSRF slot builds",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableCSRFProtection(),
					httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderCSRF+1),
				}
			},
			assert: builds,
		},
		{
			name: "a cookie authenticator ahead of the CSRF slot builds when protection is opted out",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithoutCSRFProtection(),
					httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderCORS),
				}
			},
			assert: builds,
		},
		{
			name: "a cookie authenticator with CSRF protection builds",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{cookies(f), httpsec.EnableCSRFProtection()}
			},
			assert: builds,
		},
		{
			name:   "a chain without a cookie authenticator needs no CSRF protection",
			opts:   func(*csrfFixture) []httpsec.Option { return nil },
			assert: builds,
		},
		{
			name:   "the opt-out alone builds",
			opts:   func(*csrfFixture) []httpsec.Option { return []httpsec.Option{httpsec.WithoutCSRFProtection()} },
			assert: builds,
		},
		{
			name: "protection and the opt-out together contradict each other",
			opts: func(*csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), httpsec.WithoutCSRFProtection()}
			},
			assert: func(t *testing.T, _ *csrfFixture, _ *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnableCSRFProtection")
				assert.ErrorContains(t, err, "WithoutCSRFProtection")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCSRFFixture(t)
			chain, err := httpsec.New(tc.opts(f)...)
			tc.assert(t, f, chain, err)
		})
	}
}
