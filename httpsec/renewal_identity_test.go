package httpsec_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestRenewal_RefusesDisabledUser pins that the renewal endpoint renews only
// its own, active user's session, both on a session the chain resolved,
// inside the grace window, and on a late renewal after it, which the endpoint
// judges without the resolution core: the refusal creates no successor and
// recovers nothing, and a re-enabled user renews again.
func TestRenewal_RefusesDisabledUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		recovery bool
		assert   func(t *testing.T, f *renewalFixture, user *switchableUser)
	}

	// renewedWhileActive renews O once while its user is active, and returns
	// the successor's identifier.
	renewedWhileActive := func(t *testing.T, f *renewalFixture) string {
		t.Helper()

		first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
		require.NoError(t, first.err)
		require.Len(t, f.recorded(), 1)

		return f.recorded()[0].Session.ID
	}

	cases := []testCase{
		{
			name: "a disabled user's renewal is refused, and no successor is created",
			assert: func(t *testing.T, f *renewalFixture, user *switchableUser) {
				user.set(userActive(false))

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")

				old, err := f.sessions.Load(t.Context(), f.old)
				require.NoError(t, err, "the refused session is still stored")
				assert.True(t, old.SupersededAt.IsZero(), "the refused session was not rotated")
			},
		},
		{
			name: "inside the grace window: a disabled user's predecessor is not re-rotated",
			assert: func(t *testing.T, f *renewalFixture, user *switchableUser) {
				renewedWhileActive(t, f)

				user.set(userActive(false))

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Len(t, f.recorded(), 1, "no second successor was created")
			},
		},
		{
			name:     "after the grace window: a disabled user's late renewal is refused, and nothing is recovered",
			recovery: true,
			assert: func(t *testing.T, f *renewalFixture, user *switchableUser) {
				successor := renewedWhileActive(t, f)

				user.set(userActive(false))
				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Len(t, f.recorded(), 1, "no successor was recovered")
				f.unpresented(t, successor)
			},
		},
		{
			name:     "after the grace window: a late renewal whose reloaded user is another user is refused",
			recovery: true,
			assert: func(t *testing.T, f *renewalFixture, user *switchableUser) {
				successor := renewedWhileActive(t, f)

				user.set(otherUser())
				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Len(t, f.recorded(), 1, "no successor was recovered")
				f.unpresented(t, successor)
			},
		},
		{
			name: "a loader answering with no user and no error is refused, and no successor is created",
			assert: func(t *testing.T, f *renewalFixture, user *switchableUser) {
				user.set(nil)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")
			},
		},
		{
			name:     "after the grace window: a re-enabled user's late renewal recovers",
			recovery: true,
			assert: func(t *testing.T, f *renewalFixture, user *switchableUser) {
				renewedWhileActive(t, f)

				user.set(userActive(false))
				f.clk.Advance(24 * time.Hour)
				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))

				user.set(userActive(true))

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, out.err)
				require.Len(t, f.recorded(), 2)
				assert.Equal(t, session.RenewalRecovery, f.recorded()[1].Kind)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := &switchableUser{}
			user.set(userActive(true))

			f := newRenewalFixture(t, renewalSetup{recovery: tc.recovery, record: true, users: user.loader(t)})
			tc.assert(t, f, user)
		})
	}
}
