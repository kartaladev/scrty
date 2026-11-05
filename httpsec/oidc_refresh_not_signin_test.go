package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// TestRefreshToken_NotASignIn proves that the refresh token a provider issues is never a
// sign-in. Each row presents a real one, issued by the token endpoint, to a chain whose session
// manager sits over a store that has no expectation set, so any lookup it caused fails the row.
func TestRefreshToken_NotASignIn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method string
		path   string
		expect func(store *MockStore)
		bearer func(refresh string) string
		assert func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool)
	}

	refused := func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, handlerRan, "the request reached no handler")
		assert.NotContains(t, rec.Body.String(), "rt.", "the answer does not echo the credential")
	}

	asBearer := func(refresh string) string { return "Bearer " + refresh }

	cases := []testCase{
		{
			name:   "as a session-reference bearer, it is refused and the store is never asked",
			method: http.MethodGet,
			path:   "/api/orders",
			bearer: asBearer,
			assert: refused,
		},
		{
			name:   "to session renewal, it is refused and nothing is rotated",
			method: http.MethodPost,
			path:   httpsec.DefaultSessionRenewalPath,
			bearer: asBearer,
			assert: refused,
		},
		{
			name:   "control: a well-formed session reference the store does not know reaches the store",
			method: http.MethodGet,
			path:   "/api/orders",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, session.ErrNotFound).Times(1)
			},
			bearer: func(string) string { return "Bearer " + strings.Repeat("A", 43) },
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newTokenEndpoint(t, tokenSetup{cert: true})

			issued := assertTokenIssued(t, e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb)), "Bearer")
			refresh, ok := issued["refresh_token"].(string)
			require.True(t, ok, "the client holds offline_access, so a refresh token is issued")
			require.True(t, strings.HasPrefix(refresh, "rt."), "a refresh token is what was issued")

			store := NewMockStore(gomock.NewController(t))
			if tc.expect != nil {
				tc.expect(store)
			}

			sessions := must.Must(session.New(session.WithStore(store), session.WithEndObserver(e.p)))
			f := &opFixture{keys: tokenKeys()}

			chain, err := httpsec.New(
				httpsec.WithClock(e.clk),
				httpsec.EnableCertificateBinding(),
				f.bearer(t, sessions),
				httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: NewMockUserLoader(gomock.NewController(t))}),
				httpsec.EnableJWKSEndpoint(f.keys),
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableOIDCProvider(e.p),
			)
			require.NoError(t, err)

			var handlerRan bool

			h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerRan = true }))

			r := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, strings.NewReader(url.Values{}.Encode()))
			r.RemoteAddr = tokenAddr
			r.Header.Set("Authorization", tc.bearer(refresh))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			tc.assert(t, rec, handlerRan)
		})
	}
}
