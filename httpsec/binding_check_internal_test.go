package httpsec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckBinding_Verdicts pins that the binding check reports a typed verdict for each binding it
// cannot hold, and writes nothing to the response: the caller maps the verdict to its own answer.
func TestCheckBinding_Verdicts(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		cnf    map[string]string
		assert func(t *testing.T, got bindingCheck, err error)
	}

	verdict := func(want bindingVerdict) func(t *testing.T, got bindingCheck, err error) {
		return func(t *testing.T, got bindingCheck, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, got.verdict)
			assert.Nil(t, got.proof, "no proof was presented")
		}
	}

	cases := []testCase{
		{name: "no confirmation is unbound", assert: verdict(bindingUnbound)},
		{name: "a member the chain does not know", cnf: map[string]string{"other": "x"}, assert: verdict(bindingUnknownMethod)},
		{
			name:   "a known member beside an unknown one",
			cnf:    map[string]string{"x5t#S256": "b", "other": "x"},
			assert: verdict(bindingUnknownMethod),
		},
		{name: "both bindings at once", cnf: map[string]string{"jkt": "a", "x5t#S256": "b"}, assert: verdict(bindingUnknownMethod)},
		{name: "a key binding with DPoP off", cnf: map[string]string{"jkt": "a"}, assert: verdict(bindingKeyMismatch)},
		{
			name:   "a certificate binding with certificate binding off",
			cnf:    map[string]string{"x5t#S256": "b"},
			assert: verdict(bindingCertificateMismatch),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/orders", nil)
			rec := httptest.NewRecorder()
			ex := NewExchange(t.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(rec))

			got, err := checkBinding(ex, nil, false, "tok", tc.cnf)
			tc.assert(t, got, err)

			assert.Empty(t, rec.Header(), "the check writes no header")
			assert.False(t, rec.Flushed)
			assert.Equal(t, http.StatusOK, rec.Code, "the check writes no status")
		})
	}
}
