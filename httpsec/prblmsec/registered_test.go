package prblmsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/policy/lockout"
)

// TestRegisteredOrNot refuses one unauthenticated request, with no credentials
// at all, at a real net/http chain whose error handler writes through a prblm
// handler, once with the integration registered and once without.
func TestRegisteredOrNot(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// handler builds the prblm handler the chain's error handler writes through.
		handler func(p *prblmsec.Problems) *prblm.Handler
		assert  func(t *testing.T, w *httptest.ResponseRecorder)
	}

	cases := []testCase{
		{
			name: "registered: scrty decides",
			handler: func(p *prblmsec.Problems) *prblm.Handler {
				return prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())
			},
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))
				assert.Equal(t, "/probs/security/authentication-required", decode(t, w).Type)
			},
		},
		{
			name: "not registered: prblm alone decides",
			handler: func(*prblmsec.Problems) *prblm.Handler {
				return prblm.NewHandler(prblm.WithNamespace("/probs"))
			},
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, w.Code)
				doc := decode(t, w)
				assert.Empty(t, doc.Type, "no scrty type without the integration")
				assert.Empty(t, doc.Detail)
				assert.NotContains(t, w.Body.String(), "security/authentication-required")
				assert.NotContains(t, w.Body.String(), httpsec.ErrAuthenticationRequired.Error())
			},
		},
	}

	p := newProblems(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			attempts, err := lockout.NewMemoryAttemptStore()
			require.NoError(t, err)

			chain, err := httpsec.New(
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: refuseAll{}, Attempts: attempts}),
				httpsec.EnableAuthorization(allowAll{},
					authorize.Rule[httpsec.Request]{
						Match:   func(httpsec.Request) bool { return true },
						Require: authorize.Authenticated(),
					}),
				httpsec.WithErrorHandler(tc.handler(p).Write),
			)
			require.NoError(t, err)

			ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records/r-1", nil)
			w := httptest.NewRecorder()
			chain.Middleware()(ok).ServeHTTP(w, req)

			tc.assert(t, w)
		})
	}
}
