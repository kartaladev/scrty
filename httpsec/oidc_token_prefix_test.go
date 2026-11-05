package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// With the prefix set to /op, the token endpoint answers at /op/token and a POST to the old path is
// no business of the provider's: it passes through to the application.
func TestOIDCToken_ConsumerPrefixMovesTheEndpoint(t *testing.T) {
	t.Parallel()

	e := newTokenEndpoint(t, tokenSetup{
		endpoint: func(*testing.T) []httpsec.OIDCProviderOption {
			return []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op")}
		},
	})

	post := func(path, code string) tokenAnswer {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+path,
			strings.NewReader(exchangeOf(code).Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = tokenAddr
		asClient(tokenWeb)(r)

		return e.serve(t, r)
	}

	moved := post("/op/token", e.issue(t, tokenWeb, nil))
	assertTokenIssued(t, moved, "Bearer")

	old := post("/oauth2/token", e.issue(t, tokenWeb, nil))
	require.True(t, old.passedOn, "the old path reaches the application")
	assert.NotContains(t, old.body, "access_token")
}
