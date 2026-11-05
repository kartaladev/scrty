package httpsec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/oidcprovider"
)

// TestHoldToKey_UnknownConfirmation pins that a confirmation the chain cannot honour is refused, never
// taken for a plain bearer token. The provider issues no such token, so no request can carry one.
func TestHoldToKey_UnknownConfirmation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		cnf    map[string]string
		assert func(t *testing.T, answered bool, rec *httptest.ResponseRecorder)
	}

	refused := func(t *testing.T, answered bool, rec *httptest.ResponseRecorder) {
		t.Helper()
		assert.True(t, answered)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get(headerWWWAuthenticate))
	}

	cases := []testCase{
		{name: "a member the chain does not know", cnf: map[string]string{"other": "x"}, assert: refused},
		{name: "both bindings at once", cnf: map[string]string{"jkt": "a", "x5t#S256": "b"}, assert: refused},
		{
			name: "no confirmation at all",
			assert: func(t *testing.T, answered bool, rec *httptest.ResponseRecorder) {
				t.Helper()
				assert.False(t, answered)
				assert.Empty(t, rec.Header().Get(headerWWWAuthenticate))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://id.example.com/oauth2/userinfo", nil)
			rec := httptest.NewRecorder()
			ex := NewExchange(t.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(rec))

			answered, err := holdToKey(ex, nil, false, "tok", &oidcprovider.AccessToken{Confirmation: tc.cnf}, false)
			assert.NoError(t, err)
			tc.assert(t, answered, rec)
		})
	}
}
