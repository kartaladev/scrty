package oidcprovider_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

func TestAuthorizeDevice_FractionalIntervalRoundsUp(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		assert   func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error)
	}

	// answers asserts the interval the device is told, in whole seconds.
	answers := func(want int) func(*testing.T, *oidcprovider.DeviceAuthorizationResponse, error) {
		return func(t *testing.T, resp *oidcprovider.DeviceAuthorizationResponse, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, resp.Interval)
		}
	}

	cases := []testCase{
		{name: "1.5 s is answered as 2", interval: 1500 * time.Millisecond, assert: answers(2)},
		{name: "2.5 s is answered as 3", interval: 2500 * time.Millisecond, assert: answers(3)},
		{name: "a just-over second is answered as 2", interval: time.Second + time.Nanosecond, assert: answers(2)},
		{name: "a whole number of seconds is answered as it is", interval: 5 * time.Second, assert: answers(5)},
		{name: "the shortest interval is answered as 1", interval: time.Second, assert: answers(1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(deviceNow)
			deps := validDeps(t)
			deps.Clients = deviceClients()
			p, err := oidcprovider.New(deps, oidcprovider.WithClock(clk),
				oidcprovider.WithDeviceAuthorization(issuer+"/activate",
					oidcprovider.WithUserCodeKey(deviceKey), oidcprovider.WithDevicePollInterval(tc.interval)))
			require.NoError(t, err)

			resp, err := p.AuthorizeDevice(t.Context(), oidcprovider.DeviceAuthorizationRequest{
				Form: url.Values{"client_id": {"tv"}, "scope": {"openid"}},
			})
			tc.assert(t, resp, err)
		})
	}
}

// A device that waits the interval it was answered, and 5 s more after every slow_down as
// RFC 8628 asks, is never slowed down when the interval was set to a fraction of a second.
func TestToken_DeviceFollowingAnsweredInterval(t *testing.T) {
	t.Parallel()

	f := newDeviceTokenFixture(t, oidcprovider.WithDevicePollInterval(1500*time.Millisecond))
	resp, err := f.p.AuthorizeDevice(t.Context(), oidcprovider.DeviceAuthorizationRequest{
		Form: url.Values{"client_id": {tvRefresh}, "scope": {"openid"}},
	})
	require.NoError(t, err)
	wait := time.Duration(resp.Interval) * time.Second

	raw, err := base64.RawURLEncoding.DecodeString(resp.DeviceCode)
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	record, err := f.devices.LoadByDeviceCode(t.Context(), digest[:])
	require.NoError(t, err)

	poll := func() (*oidcprovider.TokenResponse, string) {
		res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, resp.DeviceCode))
		if err == nil {
			return res, ""
		}
		var oe *oidcprovider.Error
		require.ErrorAs(t, err, &oe)

		return nil, oe.Code
	}

	for i := range 6 {
		_, got := poll()
		if got == oidcprovider.CodeSlowDown {
			wait += 5 * time.Second
		}
		assert.Equal(t, oidcprovider.CodeAuthorizationPending, got, "poll %d", i+1)
		f.clk.Advance(wait)
	}

	var approval oidcprovider.DeviceAuthorization
	approval.IssuedAt = record.IssuedAt
	approved("openid", "offline_access")(&approval)
	require.NoError(t, f.devices.Claim(t.Context(), record.ID, approval.ClaimFlowDigest, f.clk.Now()))
	require.NoError(t, f.devices.Decide(t.Context(), record.ID, approval.Approval, f.clk.Now()))

	res, got := poll()
	require.Empty(t, got, "the poll after approval")
	assert.NotEmpty(t, res.AccessToken)
}
