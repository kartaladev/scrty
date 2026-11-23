package test_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/sqlstore"
)

// deviceUserCodeKey is the user-code key of the providers these tests build, as a durable
// device store needs one shared by every replica.
var deviceUserCodeKey = []byte("device tests user-code key, 32b+")

// TestOIDCProvider_DeviceApprovalsOverSQL holds a provider with the device grant, over the
// sqlstore grant, code and device stores, to reaching an approval the device has not
// exchanged yet: the grant store reads outstanding families from the union of the code and
// device stores, so a sign-in's end, a user's revocation and a consent's revocation each
// record a revocation for the approval's grant family, by the one rule that decides which
// approvals end with their sign-in. A second provider over the same stores joins an equal
// union.
func TestOIDCProvider_DeviceApprovalsOverSQL(t *testing.T) {
	t.Parallel()

	signInFamily := id.MustParse("0192f000-0000-7000-8000-0000000d0001")
	family := func(n int) id.ID { return id.MustParse(fmt.Sprintf("0192f000-0000-7000-8000-0000000d%04d", n)) }

	// approved returns approved device authorization n of the web client, by durUser under
	// the sign-in, whose grant family is family(n).
	approved := func(n byte, offline, tied, survives bool) *oidcprovider.DeviceAuthorization {
		issued := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
		return &oidcprovider.DeviceAuthorization{
			ID: family(int(n) + 50), DeviceCodeDigest: []byte{0xd0, n}, UserCodeDigest: []byte{0xe0, n},
			ClaimFlowDigest: []byte{0xf0, n}, ClientID: durWeb.id, Scopes: []string{"openid"},
			IssuedAt: issued, ExpiresAt: issued.Add(10 * time.Minute), Interval: 5 * time.Second,
			State: oidcprovider.DeviceApproved,
			Approval: &oidcprovider.DeviceApproval{
				User: durUser, GrantedScopes: []string{"openid"}, GrantFamily: family(int(n)),
				SignIn: oidcprovider.SignIn{
					User: durUser, Family: signInFamily, AuthenticatedAt: issued, AMR: []string{"pwd"},
					AbsoluteExpiresAt: issued.Add(time.Hour),
				},
				Offline: offline, EndsWithSignIn: tied, SurvivesSignInEnd: survives,
			},
		}
	}

	// revokedAre asserts, for each approval named by n, whether its family is revoked.
	revokedAre := func(revoked map[int]bool) func(t *testing.T, ctx context.Context, grants oidcprovider.GrantStore) {
		return func(t *testing.T, ctx context.Context, grants oidcprovider.GrantStore) {
			for n, want := range revoked {
				g, err := grants.Load(ctx, family(n))
				if !want {
					require.ErrorIs(t, err, oidcprovider.ErrNotFound, "approval %d: no revocation is recorded", n)
					continue
				}
				require.NoError(t, err, "approval %d: a revocation is recorded for its family", n)
				assert.True(t, g.Revoked, "approval %d", n)
				assert.True(t, g.CreatedAt.IsZero(), "approval %d: no grant is stored yet, only its revocation", n)
			}
		}
	}

	cases := []struct {
		name string
		// revoke ends or revokes what reaches the approvals, on p.
		revoke func(ctx context.Context, t *testing.T, p *oidcprovider.Provider)
		// assert checks, on the grant store, which approvals' families are revoked.
		assert func(t *testing.T, ctx context.Context, grants oidcprovider.GrantStore)
		// gaveConsent stores the user's consent to the client first, as the approvals did.
		gaveConsent bool
	}{
		{
			name: "a sign-in's end reaches the approvals that end with it",
			revoke: func(ctx context.Context, t *testing.T, p *oidcprovider.Provider) {
				_, err := p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: signInFamily})
				require.NoError(t, err)
			},
			assert: revokedAre(map[int]bool{
				1: true,  // neither offline nor surviving
				2: false, // offline
				3: false, // surviving its sign-in
				4: true,  // tied to its sign-in, which wins over offline and survival
			}),
		},
		{
			name: "a revocation of the user's grants reaches every approval",
			revoke: func(ctx context.Context, t *testing.T, p *oidcprovider.Provider) {
				require.NoError(t, p.RevokeUserGrants(ctx, durUser, "test"))
			},
			assert: revokedAre(map[int]bool{1: true, 2: true, 3: true, 4: true}),
		},
		{
			name: "a consent's revocation reaches every approval of its client",
			revoke: func(ctx context.Context, t *testing.T, p *oidcprovider.Provider) {
				require.NoError(t, p.RevokeConsent(ctx, durUser, durWeb.id))
			},
			gaveConsent: true,
			assert:      revokedAre(map[int]bool{1: true, 2: true, 3: true, 4: true}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			e := newDurEnv(t, "sqlstore", opAdapters[0].open)
			require.Equal(t, "sqlstore", opAdapters[0].name)
			st := opAdapters[0].open(t, e.conn, e.cipher, e.clk)
			devices, err := sqlstore.NewDeviceAuthorizationStore(e.conn.DB)
			require.NoError(t, err)

			build := func() *oidcprovider.Provider {
				return e.build(t, nil,
					oidcprovider.WithGrantStore(st.grants), oidcprovider.WithCodeStore(st.codes),
					oidcprovider.WithDeviceAuthorization(opIssuer+"/device",
						oidcprovider.WithUserCodeKey(deviceUserCodeKey), oidcprovider.WithDeviceAuthorizationStore(devices)))
			}
			p := build()
			_ = build() // a second provider over the same stores joins an equal union

			for n := byte(1); n <= 4; n++ {
				r := approved(n, n == 2 || n == 4, n == 4, n == 3 || n == 4)
				require.NoError(t, devices.Create(ctx, r, r.IssuedAt))
			}

			if tc.gaveConsent {
				require.NoError(t, e.consents.Give(ctx, durUser, durWeb.id, []string{"openid"}, true, e.clk.Now()))
			}
			tc.revoke(ctx, t, p)

			tc.assert(t, ctx, st.grants)
		})
	}
}
