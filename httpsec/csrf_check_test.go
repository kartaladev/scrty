package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// unmarkedCookieAuthenticator authenticates by a cookie and checks the token as
// a cookie authenticator does, but does not declare the marker, so
// construction cannot see it and it may run where the CSRF layer never did.
type unmarkedCookieAuthenticator struct{ sessions *session.Sessions }

func (a unmarkedCookieAuthenticator) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	return consumerCookieAuthenticator(a).Intercept(ex, next)
}

func TestCheckCSRFToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    func(f *csrfFixture) []httpsec.Option
		request func(t *testing.T, f *csrfFixture) *http.Request
		assert  func(t *testing.T, f *csrfFixture, s served)
	}

	// ahead is a cookie authenticator running in the CORS slot, ahead of
	// the CSRF layer.
	ahead := func(f *csrfFixture) httpsec.Option {
		return httpsec.RegisterInterceptor(unmarkedCookieAuthenticator{sessions: f.sessions}, httpsec.OrderCORS)
	}

	behind := func(f *csrfFixture) httpsec.Option {
		return httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderBearerToken)
	}

	posting := func(t *testing.T, f *csrfFixture) *http.Request {
		return cookieRequest(t.Context(), http.MethodPost, f.signIn.ID, nil, "")
	}

	misconfigured := func(t *testing.T, _ *csrfFixture, s served) {
		require.ErrorIs(t, s.err, httpsec.ErrConfig)
		assert.ErrorContains(t, s.err, "CSRF protection")
		assert.NotErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err))
		assert.False(t, s.handlerRan, "no session is published")
	}

	published := func(t *testing.T, f *csrfFixture, s served) {
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)
		require.NotNil(t, s.handled.Session)
		assert.Equal(t, f.signIn.ID, s.handled.Session.ID)
	}

	cases := []testCase{
		{
			name: "a check where the CSRF layer never ran fails closed",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), ahead(f)}
			},
			request: posting,
			assert:  misconfigured,
		},
		{
			name: "a safe request where the CSRF layer never ran fails closed too",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), ahead(f)}
			},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodGet, f.signIn.ID, nil, "")
			},
			assert: misconfigured,
		},
		{
			name:    "a check on a chain with no CSRF layer and no opt-out fails closed",
			opts:    func(f *csrfFixture) []httpsec.Option { return []httpsec.Option{ahead(f)} },
			request: posting,
			assert:  misconfigured,
		},
		{
			name: "a check on a chain that opted out passes",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithoutCSRFProtection(), ahead(f)}
			},
			request: posting,
			assert:  published,
		},
		{
			name: "a check on an exempt route passes",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableCSRFProtection(httpsec.WithCSRFExemption(http.MethodPost, "/orders")),
					behind(f),
				}
			},
			request: posting,
			assert:  published,
		},
		{
			name: "a consumer's authenticator: the accessor returns the checked sign-in's token",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), behind(f)}
			},
			request: func(t *testing.T, f *csrfFixture) *http.Request {
				return cookieRequest(t.Context(), http.MethodGet, f.signIn.ID, nil, "")
			},
			assert: func(t *testing.T, f *csrfFixture, s served) {
				published(t, f, s)

				tok, ok := httpsec.CSRFToken(s.handled.Context())
				require.True(t, ok)
				assert.Equal(t, f.signIn.CSRFToken, tok)
			},
		},
		{
			name: "a consumer's authenticator: a refused check publishes no token",
			opts: func(f *csrfFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), behind(f)}
			},
			request: posting,
			assert: func(t *testing.T, _ *csrfFixture, s served) {
				refusedCrossSite(t, s)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCSRFFixture(t)
			chain, err := httpsec.New(tc.opts(f)...)
			require.NoError(t, err)

			tc.assert(t, f, serve(t, chain, tc.request(t, f)))
		})
	}
}

// A check made on an exchange no chain ran has no CSRF layer and no opt-out
// to go by, so it fails closed as a wiring fault. Its setup is no chain at
// all, which is why it is not a row of TestCheckCSRFToken.
func TestCheckCSRFToken_OutsideAnyChain(t *testing.T) {
	t.Parallel()

	f := newCSRFFixture(t)
	req := cookieRequest(t.Context(), http.MethodPost, f.signIn.ID,
		map[string]string{"X-CSRF-Token": f.signIn.CSRFToken}, "")
	ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))

	err := httpsec.CheckCSRFToken(ex, f.signIn)

	require.ErrorIs(t, err, httpsec.ErrConfig)
	assert.ErrorContains(t, err, "CSRF protection")
	assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
}

// detachedRedeemer redeems through handoffs on a context of its own, derived
// from nothing the request carried, as a consumer's redeemer may.
type detachedRedeemer struct{ handoffs *oidc.Handoff }

func (r detachedRedeemer) Redeem(_ context.Context, code string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
	return r.handoffs.Redeem(context.Background(), code, checks...) //nolint:contextcheck // detached on purpose
}

func TestCSRF_TokenAtRedemption(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		redeemer func(h *oidcHarness) httpsec.HandoffRedeemer
		assert   func(t *testing.T, signedIn *session.Session)
	}

	holdsToken := func(t *testing.T, signedIn *session.Session) {
		assert.NotEmpty(t, signedIn.CSRFToken)
	}

	cases := []testCase{
		{
			name:     "a redeemer on the request's context issues the token",
			redeemer: func(h *oidcHarness) httpsec.HandoffRedeemer { return h.handoffs },
			assert:   holdsToken,
		},
		{
			name:     "a redeemer on a context not derived from the request still issues the token",
			redeemer: func(h *oidcHarness) httpsec.HandoffRedeemer { return detachedRedeemer{handoffs: h.handoffs} },
			assert:   holdsToken,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)

			var sid string

			h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
					sid = id

					return "issued-token", nil
				})

			h.chainOpts = []httpsec.Option{
				httpsec.EnableCSRFProtection(),
				httpsec.RegisterInterceptor(httpsec.NewTestCookieAuthenticator(h.sessions, csrfCookie), httpsec.OrderBearerToken),
			}

			chain := h.chain(t, httpsec.WithOIDCHandoffRedeemer(tc.redeemer(h)))
			out := serve(t, chain, handoffRequest(t.Context(), oidcTestSource, h.issueHandoff(t, "")))
			require.NoError(t, out.err)
			require.NotEmpty(t, sid)

			signedIn, err := h.sessions.Load(t.Context(), sid)
			require.NoError(t, err)
			tc.assert(t, signedIn)
		})
	}
}
