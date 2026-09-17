// These tests are white-box, in package token, because what they pin is not
// observable from outside: how many times a rule is registered, and which
// options the verification path is built from.
package token

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpiryRegisteredExactlyOnce catches a duplicate registration of the
// expiry requirement. Registered twice, a later change to the rule would
// silently take effect in only one of the two places.
func TestExpiryRegisteredExactlyOnce(t *testing.T) {
	t.Parallel()

	// jwx renders a required-claim option as WithValidator(<claim>), which
	// distinguishes it both from a requirement on another claim and from the
	// issuer and audience options.
	want := fmt.Sprintf("%v", jwt.WithRequiredClaim(jwt.ExpirationKey))
	require.NotEqual(t, want, fmt.Sprintf("%v", jwt.WithRequiredClaim(jwt.IssuedAtKey)),
		"the rendering must tell one required claim from another, or counting proves nothing")

	type testCase struct {
		name   string
		config func() *config
	}

	cases := []testCase{
		{
			name:   "with nothing else configured",
			config: newConfig,
		},
		{
			name: "with an issuer and an audience configured",
			config: func() *config {
				c := newConfig()
				c.hasIssuer = true
				c.issuer = "https://auth.example"
				c.hasAudience = true
				c.audience = "api"

				return c
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var registered int
			for _, opt := range tc.config().validateOptions() {
				if fmt.Sprintf("%v", opt) == want {
					registered++
				}
			}
			assert.Equal(t, 1, registered, "exp is required exactly once")
		})
	}
}
