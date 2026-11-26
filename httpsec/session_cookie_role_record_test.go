package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestSessionCookie_RoleSwitchRecordsRoleInRotation pins that a rotating
// switch records the role in the rotation's own write, with no later selection
// write; that a store which writes the successor back with another role fails
// the switch as a dependency failure, sets no cookie and leaves the role
// unchanged; and that a switch that does not rotate still records the role
// with a selection.
func TestSessionCookie_RoleSwitchRecordsRoleInRotation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		cookieOpts []httpsec.SessionCookieOption
		assert     func(t *testing.T, w *switchCookieWorld)
	}

	cases := []testCase{
		{
			name: "a rotating switch makes no selection write",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)

				rotated := reSetAs(t, w.chain, out, w.signIn.ID)
				s, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err)
				assert.Equal(t, "audit", s.SelectedRole)
				assert.Zero(t, w.hooks.selects.Load(), "the role was recorded by the rotation's write")
			},
		},
		{
			name: "a store that ignores the successor's role fails the switch",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				other := "sales"
				w.hooks.successorRole.Store(&other)

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.ErrorIs(t, err, session.ErrStoreContract)
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err), "a dependency failure")
				noSessionCookie(t, out)
				assert.Zero(t, w.hooks.selects.Load())

				w.hooks.successorRole.Store(nil)

				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "the role is unchanged")
			},
		},
		{
			name:       "a switch that does not rotate records the role with a selection",
			cookieOpts: []httpsec.SessionCookieOption{httpsec.WithoutSessionRotation(httpsec.RotateOnRoleSwitch)},
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)
				noSessionCookie(t, out)
				assert.Equal(t, int32(1), w.hooks.selects.Load())
				assert.Equal(t, "audit", w.activeRole(t, w.signIn.ID))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newSwitchCookieWorldWith(t, nil, nil, tc.cookieOpts,
				func(*session.Sessions) []httpsec.Option { return nil }))
		})
	}
}
