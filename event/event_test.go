package event_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/event"
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
					"excess_rate_limit_exceeded", "malicious_csrf",
				} {
					assert.Contains(t, names, want)
				}
			},
		},
		{
			name: "every scrty_ name the spec requires is listed",
			assert: func(t *testing.T, names []string) {
				for _, want := range []string{
					"scrty_recovery_started", "scrty_recovery_completed", "scrty_recovery_refused",
				} {
					assert.Contains(t, names, want)
				}
			},
		},
		{
			name: "every scrty_ name the OpenID provider reports is listed",
			assert: func(t *testing.T, names []string) {
				for _, want := range []string{
					"scrty_grant_created", "scrty_consent_given", "scrty_consent_denied",
					"scrty_consent_revoked", "scrty_client_auth_refused", "scrty_code_replayed",
					"scrty_refresh_reused", "scrty_grant_revoked", "scrty_logout_delivery_failed",
					"scrty_grant_end_failed", "scrty_grant_revoke_failed",
				} {
					assert.Contains(t, names, want)
				}
			},
		},
		{
			name: "no scrty_ name stands for an outcome the vocabulary names",
			assert: func(t *testing.T, names []string) {
				for _, gone := range []string{"scrty_rate_limit_refused", "scrty_csrf_refused"} {
					assert.NotContains(t, names, gone)
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
				assert.Equal(t, 39, scrty, "the outcomes the vocabulary does not name")
				assert.Len(t, names, 25+39)
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
				assert.Equal(t, event.AuthnLoginSuccess, event.Names()[0])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, event.Names())
		})
	}
}

// TestNames_IncludesAdministration pins the names the administration services
// report under: the OWASP names for user, privilege and role changes, and the
// scrty_ names for what the vocabulary does not name.
func TestNames_IncludesAdministration(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, names []string)
	}

	contains := func(want ...string) func(t *testing.T, names []string) {
		return func(t *testing.T, names []string) {
			for _, w := range want {
				assert.Contains(t, names, w)
			}
		}
	}

	cases := []testCase{
		{
			name: "OWASP names",
			assert: contains("user_created", "user_updated", "user_archived", "user_deleted",
				"authn_password_change", "privilege_permissions_changed", "authz_change", "authz_admin"),
		},
		{
			name: "scrty_ names",
			assert: contains("scrty_user_reactivated", "scrty_user_imported", "scrty_identifier_conflict",
				"scrty_active_role_switched"),
		},
		{
			name: "the constants carry the names",
			assert: func(t *testing.T, names []string) {
				for _, c := range []string{
					event.UserCreated, event.UserUpdated, event.UserArchived, event.UserDeleted,
					event.PrivilegePermissionsChanged, event.AuthzChange, event.AuthzAdmin,
					event.UserReactivated, event.UserImported, event.IdentifierConflict, event.ActiveRoleSwitched,
				} {
					assert.Contains(t, names, c)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, event.Names())
		})
	}
}
