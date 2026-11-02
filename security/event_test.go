package security_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/security"
)

// TestSecurityEvents_Names pins the documented list: every OWASP Logging
// Vocabulary name the spec requires, every scrty_ name under its prefix, and
// no name twice.
func TestSecurityEvents_Names(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, names []string)
	}

	cases := []testCase{
		{
			name: "every required OWASP name is listed",
			assert: func(t *testing.T, names []string) {
				for _, want := range []string{
					"authn_login_success", "authn_login_successafterfail", "authn_login_fail",
					"authn_login_fail_max", "authn_login_lock", "authn_password_change",
					"authn_password_change_fail", "authn_token_created", "authn_token_revoked",
					"authn_token_reuse", "session_created", "session_renewed", "session_expired",
					"session_use_after_expire", "session_logout", "authz_fail",
				} {
					assert.Contains(t, names, want)
				}
			},
		},
		{
			name: "every other name is under the scrty_ prefix, and none under it is an OWASP name",
			assert: func(t *testing.T, names []string) {
				scrty := 0
				for _, n := range names {
					if strings.HasPrefix(n, "scrty_") {
						scrty++
					}
				}
				assert.Equal(t, 18, scrty, "the outcomes the vocabulary does not name")
				assert.Len(t, names, 16+18)
			},
		},
		{
			name: "no name is listed twice",
			assert: func(t *testing.T, names []string) {
				seen := map[string]bool{}
				for _, n := range names {
					assert.False(t, seen[n], "%s listed twice", n)
					seen[n] = true
				}
			},
		},
		{
			name: "the slice is the caller's own",
			assert: func(t *testing.T, names []string) {
				names[0] = "changed"
				assert.Equal(t, security.AuthnLoginSuccess, security.Names()[0])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, security.Names())
		})
	}
}
