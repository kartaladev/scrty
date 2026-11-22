package oidcprovider_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// deviceSignInFixture is a device-grant provider over memory stores the rows can reach, and
// the events it reported.
type deviceSignInFixture struct {
	*deviceTokenFixture
	codes    *oidcprovider.MemoryCodeStore
	consents *oidcprovider.MemoryConsentStore
	events   *eventLog
}

func newDeviceSignInFixture(t *testing.T) *deviceSignInFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(deviceNow)
	grants, err := oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(clk))
	require.NoError(t, err)
	codes, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(clk))
	require.NoError(t, err)
	consents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	registry, err := oidcprovider.NewMemoryRegistry(deviceTokenClients())
	require.NoError(t, err)

	f := &deviceSignInFixture{
		deviceTokenFixture: &deviceTokenFixture{
			clk: clk, devices: oidcprovider.NewMemoryDeviceAuthorizationStore(), grants: grants, registry: registry,
			users: &exchangeUsers{disabled: map[identity.UserID]bool{}, missing: map[identity.UserID]bool{}},
			keys:  newExchangeKeys(t), logs: &syncBuffer{},
		},
		codes: codes, consents: consents, events: &eventLog{},
	}
	f.p, err = f.provider(t, true, oidcprovider.WithSecurityEvents(f.events.sink))
	require.NoError(t, err)

	return f
}

// provider builds a provider over the fixture's grant, code and consent stores, with the
// device grant over its device store when device is true.
func (f *deviceSignInFixture) provider(t *testing.T, device bool, opts ...oidcprovider.Option) (*oidcprovider.Provider, error) {
	t.Helper()

	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return f.users.load(user) },
	).AnyTimes()
	opts = append([]oidcprovider.Option{
		oidcprovider.WithClock(f.clk),
		oidcprovider.WithGrantStore(f.grants),
		oidcprovider.WithCodeStore(f.codes),
		oidcprovider.WithConsentStore(f.consents),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))),
	}, opts...)
	if device {
		opts = append(opts, oidcprovider.WithDeviceAuthorization(issuer+"/activate",
			oidcprovider.WithUserCodeKey(deviceKey),
			oidcprovider.WithDeviceAuthorizationStore(f.devices),
		))
	}

	// A provider without the grant refuses a client registered for it, so it reads the code
	// client alone.
	registry := oidcprovider.ClientRegistry(f.registry)
	if !device {
		web, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{webClient()})
		require.NoError(t, err)
		registry = web
	}

	return oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         f.keys,
		Users:        loader,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, opts...)
}

// revokedEvents is how many grant revocations were reported, with each one's cause.
func (f *deviceSignInFixture) revokedEvents() []string {
	var causes []string
	for _, e := range named(f.events.all(), event.GrantRevoked) {
		causes = append(causes, e.Cause)
	}

	return causes
}

// endSignInOf ends the approving sign-in of record.
func endSignInOf(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization) {
	t.Helper()

	_, err := f.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: record.Approval.SignIn.Family})
	require.NoError(t, err)
}

// outlives makes an approval survive its sign-in's end, as DeviceGrantsOutliveSignIn records it.
func outlives(r *oidcprovider.DeviceAuthorization) { r.Approval.SurvivesSignInEnd = true }

// tiedToSignIn makes an approval end with its sign-in, as EndGrantsWithSignIn records it.
func tiedToSignIn(r *oidcprovider.DeviceAuthorization) { r.Approval.EndsWithSignIn = true }

// TestDeviceGrant_SignInEnd covers an exchanged device grant meeting the end of its sign-in,
// a consent revocation and a user's revocation, and the lifetime it was given (8.1–8.3).
func TestDeviceGrant_SignInEnd(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		seed func(*oidcprovider.DeviceAuthorization)
		// act runs after the exchange.
		act    func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization)
		assert func(t *testing.T, f *deviceSignInFixture, g *oidcprovider.Grant, refresh error)
	}

	lifetime := func(t *testing.T, f *deviceSignInFixture) time.Duration {
		rc, err := f.p.ClientForTest(t.Context(), tvRefresh)
		require.NoError(t, err)

		return rc.GrantAbsoluteLifetime
	}
	deadline := deviceNow.Add(deviceSIValid)
	endedBy := func(cause oidcprovider.RevocationCause, expiresAt func(*testing.T, *deviceSignInFixture) time.Time) func(
		*testing.T, *deviceSignInFixture, *oidcprovider.Grant, error,
	) {
		return func(t *testing.T, f *deviceSignInFixture, g *oidcprovider.Grant, refresh error) {
			assert.True(t, g.Revoked)
			assert.Equal(t, cause, g.RevokeCause)
			assert.Equal(t, expiresAt(t, f), g.ExpiresAt)
			assert.Equal(t, []string{string(cause)}, f.revokedEvents(), "the revocation is reported once")
			assertRefused(t, refresh, oidcprovider.CodeInvalidGrant)
		}
	}
	atDeadline := func(*testing.T, *deviceSignInFixture) time.Time { return deadline }
	ownLifetime := func(t *testing.T, f *deviceSignInFixture) time.Time { return deviceNow.Add(lifetime(t, f)) }
	survives := func(t *testing.T, f *deviceSignInFixture, g *oidcprovider.Grant, refresh error) {
		assert.False(t, g.Revoked, "the grant outlives its sign-in")
		assert.Equal(t, deviceNow, g.SignInEndedAt, "the grant is marked as having outlived its sign-in")
		assert.Equal(t, ownLifetime(t, f), g.ExpiresAt, "a surviving grant lives its own lifetime")
		assert.Empty(t, f.revokedEvents(), "a survivor is no revocation")
		require.NoError(t, refresh)
	}

	cases := []testCase{
		{
			name: "under the default, a grant without offline_access ends with its sign-in, at its deadline",
			seed: approved("openid"), act: endSignInOf,
			assert: endedBy(oidcprovider.CauseSignInEnded, atDeadline),
		},
		{
			name: "under the default, a grant with offline_access survives",
			seed: approved("openid", "offline_access"), act: endSignInOf,
			assert: survives,
		},
		{
			name: "under DeviceGrantsOutliveSignIn, a grant without offline_access survives",
			seed: then(approved("openid"), outlives), act: endSignInOf,
			assert: survives,
		},
		{
			name: "EndGrantsWithSignIn ends an offline grant with its sign-in",
			seed: then(approved("openid", "offline_access"), tiedToSignIn), act: endSignInOf,
			assert: endedBy(oidcprovider.CauseSignInEnded, atDeadline),
		},
		{
			name: "a grant both tied to and surviving its sign-in ends with it, as EndsWithSignIn wins",
			seed: then(approved("openid"), outlives, tiedToSignIn), act: endSignInOf,
			assert: endedBy(oidcprovider.CauseSignInEnded, atDeadline),
		},
		{
			name: "RevokeConsent revokes an offline device grant",
			seed: approved("openid", "offline_access"),
			act: func(t *testing.T, f *deviceSignInFixture, _ *oidcprovider.DeviceAuthorization) {
				require.NoError(t, f.consents.Give(t.Context(), "u-1", tvRefresh, []string{"openid"}, true, deviceNow))
				require.NoError(t, f.p.RevokeConsent(t.Context(), "u-1", tvRefresh))
			},
			assert: endedBy(oidcprovider.CauseConsentRevoked, ownLifetime),
		},
		{
			name: "RevokeUserGrants revokes a device grant that survives its sign-in",
			seed: then(approved("openid"), outlives),
			act: func(t *testing.T, f *deviceSignInFixture, _ *oidcprovider.DeviceAuthorization) {
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseRecovery)))
			},
			assert: endedBy(oidcprovider.CauseRecovery, ownLifetime),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceSignInFixture(t)
			code, record := f.seed(t, tvRefresh, tc.seed)
			res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
			require.NoError(t, err)
			require.NotEmpty(t, res.RefreshToken)

			tc.act(t, f, record)

			g := f.grantRow(t, record.Approval.GrantFamily)
			require.NotNil(t, g)
			_, refresh := f.p.Token(t.Context(), publicRefresh(tvRefresh, res.RefreshToken, ""))
			tc.assert(t, f, g, refresh)
		})
	}
}

// TestDeviceGrant_UnexchangedApproval covers an end or a revocation that comes between the
// approval and the device's poll (8.4): it reaches the approval through the device store
// joined to the grant store, and the poll hands nothing out.
func TestDeviceGrant_UnexchangedApproval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   func(*oidcprovider.DeviceAuthorization)
		act    func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization)
		assert func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error)
	}

	refusedRevoked := func(cause oidcprovider.RevocationCause) func(
		*testing.T, *deviceSignInFixture, *oidcprovider.DeviceAuthorization, *oidcprovider.TokenResponse, error,
	) {
		return func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
			assert.Nil(t, res)
			assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			g := f.grantRow(t, record.Approval.GrantFamily)
			require.NotNil(t, g, "the grant row is stored, revoked")
			assert.True(t, g.Revoked)
			assert.Equal(t, cause, g.RevokeCause)
			assert.Equal(t, 0, f.p.LineageHeldForTest(), "no refresh token is stored")
		}
	}
	exchanged := func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
		require.NoError(t, err)
		assert.NotEmpty(t, res.AccessToken)
		g := f.grantRow(t, record.Approval.GrantFamily)
		require.NotNil(t, g)
		assert.False(t, g.Revoked)
	}
	// approvedAfter seeds the record claimed, ends the sign-in it will be approved under, so that
	// end sweeps before the approval exists, and only then records the approval.
	approvedAfter := func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization) {
		approval := record.Approval
		sel := oidcprovider.SignInSelector{Family: approval.SignIn.Family}
		ended, err := f.p.EndSignIn(t.Context(), sel)
		require.NoError(t, err)
		require.Empty(t, ended, "the first end finds nothing to end")
		require.NoError(t, f.devices.Decide(t.Context(), record.ID, approval, deviceNow))
	}
	claimedOnly := func(r *oidcprovider.DeviceAuthorization) { r.State = oidcprovider.DeviceClaimed }

	cases := []testCase{
		{
			name: "EndSignIn under the default without offline_access", seed: approved("openid"),
			act:    endSignInOf,
			assert: refusedRevoked(oidcprovider.CauseSignInEnded),
		},
		{
			name: "EndSignIn of an approval tied to its sign-in, offline_access or not",
			seed: then(approved("openid", "offline_access"), tiedToSignIn), act: endSignInOf,
			assert: refusedRevoked(oidcprovider.CauseSignInEnded),
		},
		{
			name: "RevokeConsent", seed: approved("openid", "offline_access"),
			act: func(t *testing.T, f *deviceSignInFixture, _ *oidcprovider.DeviceAuthorization) {
				require.NoError(t, f.consents.Give(t.Context(), "u-1", tvRefresh, []string{"openid"}, true, deviceNow))
				require.NoError(t, f.p.RevokeConsent(t.Context(), "u-1", tvRefresh))
			},
			assert: refusedRevoked(oidcprovider.CauseConsentRevoked),
		},
		{
			name: "RevokeUserGrants", seed: then(approved("openid"), outlives),
			act: func(t *testing.T, f *deviceSignInFixture, _ *oidcprovider.DeviceAuthorization) {
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseMFAReset)))
			},
			assert: refusedRevoked(oidcprovider.CauseMFAReset),
		},
		{
			name: "an approval written after the end swept is reached by the end asked again",
			seed: then(approved("openid"), claimedOnly),
			act: func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization) {
				approvedAfter(t, f, record)
				endSignInOf(t, f, record)
			},
			assert: refusedRevoked(oidcprovider.CauseSignInEnded),
		},
		{
			name:   "an approval written after the end swept, with the end not asked again, is exchanged",
			seed:   then(approved("openid"), claimedOnly),
			act:    approvedAfter,
			assert: exchanged,
		},
		{
			name: "EndSignIn leaves an offline approval to be exchanged", seed: approved("openid", "offline_access"),
			act:    endSignInOf,
			assert: exchanged,
		},
		{
			name: "EndSignIn leaves an approval surviving its sign-in to be exchanged", seed: then(approved("openid"), outlives),
			act:    endSignInOf,
			assert: exchanged,
		},
		{
			name: "EndSignIn of another sign-in leaves the approval alone", seed: approved("openid"),
			act: func(t *testing.T, f *deviceSignInFixture, _ *oidcprovider.DeviceAuthorization) {
				other, err := id.NewV7Generator().NewID()
				require.NoError(t, err)
				_, err = f.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: other})
				require.NoError(t, err)
			},
			assert: exchanged,
		},
		{
			name: "a denied record is left denied, with nothing recorded for any family",
			seed: then(approved("openid"), func(r *oidcprovider.DeviceAuthorization) { r.State = oidcprovider.DeviceDenied }),
			act: func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization) {
				endSignInOf(t, f, record)
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseMFAReset)))
			},
			assert: func(t *testing.T, f *deviceSignInFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeAccessDenied)
				assert.Nil(t, f.grantRow(t, record.Approval.GrantFamily), "a denial has no family to revoke")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceSignInFixture(t)
			// A record not yet approved is stored with no approval; the row keeps the one it
			// was seeded with, for its act to record and its assert to look for.
			var approval *oidcprovider.DeviceApproval
			code, record := f.seed(t, tvRefresh, then(tc.seed, func(r *oidcprovider.DeviceAuthorization) {
				if r.State != oidcprovider.DeviceApproved {
					approval, r.Approval = r.Approval, nil
				}
			}))
			if approval != nil {
				record.Approval = approval
			}
			tc.act(t, f, record)
			res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
			tc.assert(t, f, record, res, err)
			f.assertNoDeviceSecret(t, code, err)
		})
	}
}

// TestDeviceGrant_SurvivalRule pins one rule for every combination of the three flags, in the
// grant store's end of a sign-in and in the device store's listing: a grant or an approval ends
// with its sign-in when EndsWithSignIn || (!Offline && !SurvivesSignInEnd).
func TestDeviceGrant_SurvivalRule(t *testing.T) {
	t.Parallel()

	type flags struct{ offline, endsWithSignIn, survives bool }
	type testCase struct {
		name   string
		flags  flags
		origin oidcprovider.GrantOrigin
		assert func(t *testing.T, ends bool, g *oidcprovider.Grant, listed, listedWithOffline bool)
	}

	ruleSays := func(f flags) bool { return f.endsWithSignIn || (!f.offline && !f.survives) }
	originName := map[oidcprovider.GrantOrigin]string{oidcprovider.OriginCode: "code", oidcprovider.OriginDevice: "device"}
	var cases []testCase
	for _, origin := range []oidcprovider.GrantOrigin{oidcprovider.OriginCode, oidcprovider.OriginDevice} {
		for _, f := range []flags{
			{}, {offline: true}, {endsWithSignIn: true}, {offline: true, endsWithSignIn: true},
			{survives: true}, {offline: true, survives: true}, {endsWithSignIn: true, survives: true},
			{offline: true, endsWithSignIn: true, survives: true},
		} {
			if origin == oidcprovider.OriginCode && f.survives {
				continue // a code's grant never survives by the flag
			}
			cases = append(cases, testCase{
				name:   fmt.Sprintf("origin %s, offline=%t endsWithSignIn=%t survives=%t", originName[origin], f.offline, f.endsWithSignIn, f.survives),
				flags:  f,
				origin: origin,
				assert: func(t *testing.T, ends bool, g *oidcprovider.Grant, listed, listedWithOffline bool) {
					assert.Equal(t, ends, g.Revoked, "the grant store's end")
					assert.Equal(t, deviceNow, g.SignInEndedAt, "every selected grant is marked")
					if origin == oidcprovider.OriginDevice {
						assert.Equal(t, ends, listed, "the device store's listing without offline")
						assert.True(t, listedWithOffline, "includeOffline lists every approval")
					}
				},
			})
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(deviceNow)
			grants, err := oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)
			codes, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)
			require.NoError(t, grants.UseCodes(codes))
			devices := oidcprovider.NewMemoryDeviceAuthorizationStore()

			f := &deviceTokenFixture{clk: clk, devices: devices}
			_, record := f.seed(t, tvRefresh, then(approved("openid"), func(r *oidcprovider.DeviceAuthorization) {
				r.Approval.Offline, r.Approval.EndsWithSignIn = tc.flags.offline, tc.flags.endsWithSignIn
				r.Approval.SurvivesSignInEnd = tc.flags.survives
			}))
			a := record.Approval
			sel := oidcprovider.SignInSelector{Family: a.SignIn.Family}
			require.NoError(t, grants.Create(t.Context(), &oidcprovider.Grant{
				Family: a.GrantFamily, User: a.User, ClientID: tvRefresh, SignInFamily: a.SignIn.Family,
				Offline: tc.flags.offline, EndsWithSignIn: tc.flags.endsWithSignIn, SurvivesSignInEnd: tc.flags.survives,
				Origin: tc.origin, CreatedAt: deviceNow, ExpiresAt: deviceNow.Add(time.Hour),
			}))

			_, err = grants.EndSignIns(t.Context(), sel, deviceNow)
			require.NoError(t, err)
			g, err := grants.Load(t.Context(), a.GrantFamily)
			require.NoError(t, err)
			without, err := devices.UnspentBySignIn(t.Context(), sel, false)
			require.NoError(t, err)
			with, err := devices.UnspentBySignIn(t.Context(), sel, true)
			require.NoError(t, err)

			tc.assert(t, ruleSays(tc.flags), g, len(without) == 1, len(with) == 1)
		})
	}
}

// TestUnspentUnion_SecondProviderJoins covers providers sharing one grant store: each must
// join the same code source, or be refused at New.
func TestUnspentUnion_SecondProviderJoins(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// firstDevice and secondDevice say whether each provider has the device grant on.
		firstDevice, secondDevice bool
		assert                    func(t *testing.T, f *deviceSignInFixture, second *oidcprovider.Provider, err error)
	}

	cases := []testCase{
		{
			name:        "a second device provider over the same stores joins, and its end reaches an approval",
			firstDevice: true, secondDevice: true,
			assert: func(t *testing.T, f *deviceSignInFixture, second *oidcprovider.Provider, err error) {
				require.NoError(t, err)
				code, record := f.seed(t, tvRefresh, approved("openid"))
				_, err = second.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: record.Approval.SignIn.Family})
				require.NoError(t, err)
				res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
		},
		{
			name:        "a provider without the device grant over a grant store a device provider joined is refused",
			firstDevice: true, secondDevice: false,
			assert: func(t *testing.T, _ *deviceSignInFixture, _ *oidcprovider.Provider, err error) {
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
		{
			name:        "a device provider over a grant store a provider without the grant joined is refused",
			firstDevice: false, secondDevice: true,
			assert: func(t *testing.T, _ *deviceSignInFixture, _ *oidcprovider.Provider, err error) {
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
		{
			name:        "two providers without the device grant join as before",
			firstDevice: false, secondDevice: false,
			assert: func(t *testing.T, _ *deviceSignInFixture, _ *oidcprovider.Provider, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceSignInFixture(t)
			if !tc.firstDevice {
				// A fresh grant store, so the first provider to join it is one without the grant.
				grants, err := oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(f.clk))
				require.NoError(t, err)
				f.grants = grants
				f.p, err = f.provider(t, false)
				require.NoError(t, err)
			}
			second, err := f.provider(t, tc.secondDevice)
			tc.assert(t, f, second, err)
		})
	}
}

// TestUnspentUnion_ErrorFails covers a side of the union failing: the union fails, with no
// partial answer, and a nil device side answers the code side alone.
func TestUnspentUnion_ErrorFails(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// codesFail and devicesFail fail that side; noDevices leaves the device side nil.
		codesFail, devicesFail, noDevices bool
		assert                            func(t *testing.T, bySignIn, byClient []id.ID, signInErr, clientErr error)
	}

	codeFamily, deviceFamily := suiteFamily(t), suiteFamily(t)
	failed := func(t *testing.T, bySignIn, byClient []id.ID, signInErr, clientErr error) {
		require.ErrorIs(t, signInErr, errDeviceStoreDown)
		require.ErrorIs(t, clientErr, errDeviceStoreDown)
		assert.Empty(t, bySignIn)
		assert.Empty(t, byClient)
	}

	cases := []testCase{
		{
			name: "both sides answer, concatenated",
			assert: func(t *testing.T, bySignIn, byClient []id.ID, signInErr, clientErr error) {
				require.NoError(t, signInErr)
				require.NoError(t, clientErr)
				assert.ElementsMatch(t, []id.ID{codeFamily, deviceFamily}, bySignIn)
				assert.ElementsMatch(t, []id.ID{codeFamily, deviceFamily}, byClient)
			},
		},
		{name: "the code side failing fails the union", codesFail: true, assert: failed},
		{name: "the device side failing fails the union", devicesFail: true, assert: failed},
		{name: "both sides failing fail the union", codesFail: true, devicesFail: true, assert: failed},
		{
			name: "a nil device side answers the code side alone", noDevices: true,
			assert: func(t *testing.T, bySignIn, byClient []id.ID, signInErr, clientErr error) {
				require.NoError(t, signInErr)
				require.NoError(t, clientErr)
				assert.Equal(t, []id.ID{codeFamily}, bySignIn)
				assert.Equal(t, []id.ID{codeFamily}, byClient)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			side := func(family id.ID, fails bool) oidcprovider.UnspentCodes {
				store := NewMockCodeStore(ctrl)
				var err error
				answer := []id.ID{family}
				if fails {
					answer, err = nil, errDeviceStoreDown
				}
				store.EXPECT().UnspentBySignIn(gomock.Any(), gomock.Any(), gomock.Any()).Return(answer, err).AnyTimes()
				store.EXPECT().UnspentByClient(gomock.Any(), gomock.Any(), gomock.Any()).Return(answer, err).AnyTimes()

				return store
			}
			var devices oidcprovider.UnspentCodes
			if !tc.noDevices {
				devices = side(deviceFamily, tc.devicesFail)
			}
			union := oidcprovider.UnspentUnionForTest(side(codeFamily, tc.codesFail), devices)

			bySignIn, signInErr := union.UnspentBySignIn(t.Context(), oidcprovider.SignInSelector{User: "u-1"}, false)
			byClient, clientErr := union.UnspentByClient(t.Context(), "u-1", tvRefresh)
			tc.assert(t, bySignIn, byClient, signInErr, clientErr)
		})
	}
}

// suiteFamily is a fresh grant family.
func suiteFamily(t *testing.T) id.ID {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return family
}

// TestDeviceGrant_EndSignInBeforeGrantWrite covers an end of the sign-in between the spend and
// the grant's write: the end records its revocation for the approval's family first, the store
// keeps it over the row, and the poll is answered invalid_grant with the grant revoked.
func TestDeviceGrant_EndSignInBeforeGrantWrite(t *testing.T) {
	t.Parallel()

	f := newDeviceTokenFixture(t)
	code, record := f.seed(t, tvRefresh, approved("openid"))
	var once sync.Once
	f.grantCreating = func() {
		once.Do(func() {
			_, err := f.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: record.Approval.SignIn.Family})
			assert.NoError(t, err)
		})
	}

	res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
	assert.Nil(t, res)
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)
	g := f.grantRow(t, record.Approval.GrantFamily)
	require.NotNil(t, g)
	assert.True(t, g.Revoked)
	assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
}

// readBackHook is a grant store whose first Load after a Create, the exchange's read-back, runs
// afterRead once the real answer is in hand: an end landing in the window between the read-back
// and the lineage's write.
type readBackHook struct {
	oidcprovider.GrantStore
	created   atomic.Bool
	afterRead func()
}

func (h *readBackHook) Create(ctx context.Context, grant *oidcprovider.Grant) error {
	err := h.GrantStore.Create(ctx, grant)
	h.created.Store(true)

	return err
}

func (h *readBackHook) Load(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
	g, err := h.GrantStore.Load(ctx, family)
	if h.created.CompareAndSwap(true, false) && h.afterRead != nil {
		h.afterRead()
	}

	return g, err
}

// TestDeviceGrant_EndSignInAfterReadBack covers an end of the sign-in after the grant row was
// written and read back unrevoked, and before the lineage is written. The poll gets its tokens,
// but the end revoked the stored grant, so the refresh token it holds is answered invalid_grant.
func TestDeviceGrant_EndSignInAfterReadBack(t *testing.T) {
	t.Parallel()

	f := newDeviceSignInFixture(t)
	code, record := f.seed(t, tvRefresh, approved("openid"))
	hook := &readBackHook{GrantStore: f.grants}
	p, err := f.provider(t, true, oidcprovider.WithGrantStore(hook))
	require.NoError(t, err)
	hook.afterRead = func() {
		_, endErr := p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: record.Approval.SignIn.Family})
		assert.NoError(t, endErr)
	}

	res, err := p.Token(t.Context(), deviceRequest(tvRefresh, code))
	require.NoError(t, err, "the read-back saw the grant live, so the poll is answered")
	require.NotEmpty(t, res.RefreshToken)

	_, err = p.Token(t.Context(), publicRefresh(tvRefresh, res.RefreshToken, ""))
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)
	g := f.grantRow(t, record.Approval.GrantFamily)
	require.NotNil(t, g)
	assert.True(t, g.Revoked)
	assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
}

// TestDeviceGrant_EndSignInRacesExchange runs an end of the sign-in against the exchange
// concurrently. Whichever comes first, no refresh token outlives the end, and the grant ends
// revoked.
func TestDeviceGrant_EndSignInRacesExchange(t *testing.T) {
	t.Parallel()

	for range 20 {
		f := newDeviceSignInFixture(t)
		code, record := f.seed(t, tvRefresh, approved("openid"))
		sel := oidcprovider.SignInSelector{Family: record.Approval.SignIn.Family}

		var (
			wg  sync.WaitGroup
			res *oidcprovider.TokenResponse
			err error
		)
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			res, err = f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
		})
		wg.Go(func() {
			<-start
			_, endErr := f.p.EndSignIn(t.Context(), sel)
			assert.NoError(t, endErr)
		})
		close(start)
		wg.Wait()

		if err != nil {
			assertRefused(t, err, oidcprovider.CodeInvalidGrant)
		} else {
			_, refresh := f.p.Token(t.Context(), publicRefresh(tvRefresh, res.RefreshToken, ""))
			assertRefused(t, refresh, oidcprovider.CodeInvalidGrant)
		}
		g := f.grantRow(t, record.Approval.GrantFamily)
		require.NotNil(t, g, "the end or the exchange wrote the family")
		assert.True(t, g.Revoked, "the grant ends revoked whichever came first")
	}
}
