package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/httpsec"
)

// A consumer who turns the automatic headers off states DPoP itself, and still gets no credentials
// at the token endpoint, whatever its policy says.
func TestCORS_OIDCProvider_AutomaticHeadersOffStillAllowsNoCredentials(t *testing.T) {
	t.Parallel()

	policy := httpsec.CORSPolicy{
		AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true,
		AllowedHeaders: []string{"DPoP"},
	}
	e := newTokenEndpoint(t, tokenSetup{
		chain: []httpsec.Option{httpsec.EnableCORS(policy, httpsec.WithoutAutomaticCORSHeaders())},
	})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, opIssuer+"/oauth2/token", nil)
	r.Header.Set("Origin", allowedOrigin)
	r.Header.Set("Access-Control-Request-Method", http.MethodPost)
	r.Header.Set("Access-Control-Request-Headers", "DPoP")

	a := e.serve(t, r)
	assert.Equal(t, http.StatusNoContent, a.status)
	assert.Equal(t, allowedOrigin, a.header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, a.header.Get("Access-Control-Allow-Headers"), "DPoP", "the consumer's own list is what allows it")
	assert.Empty(t, a.header.Get("Access-Control-Allow-Credentials"), "the token endpoint allows no credentials")
}
