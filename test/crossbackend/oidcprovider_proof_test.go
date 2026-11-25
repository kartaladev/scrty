package crossbackend_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/sqlstore"
)

// proofStores are the provider stores of one backend, over the shared database.
type proofStores struct {
	grants  oidcprovider.GrantStore
	codes   oidcprovider.CodeStore
	browser oidcprovider.BrowserSessionStore
	pending oidcprovider.PendingRequestStore
	device  oidcprovider.DeviceAuthorizationStore
}

// proofStoresOf builds the named backend's provider stores.
func (b backends) proofStoresOf(t *testing.T, name string) proofStores {
	t.Helper()

	switch name {
	case "sqlstore":
		return proofStores{
			grants:  must[oidcprovider.GrantStore](t)(sqlstore.NewGrantStore(b.conn.DB)),
			codes:   must[oidcprovider.CodeStore](t)(sqlstore.NewCodeStore(b.conn.DB)),
			browser: must[oidcprovider.BrowserSessionStore](t)(sqlstore.NewBrowserSessionStore(b.conn.DB)),
			pending: must[oidcprovider.PendingRequestStore](t)(sqlstore.NewPendingRequestStore(b.conn.DB)),
			device:  must[oidcprovider.DeviceAuthorizationStore](t)(sqlstore.NewDeviceAuthorizationStore(b.conn.DB)),
		}
	case "pgx":
		return proofStores{
			grants:  must[oidcprovider.GrantStore](t)(pgxstore.NewGrantStore(b.pool)),
			codes:   must[oidcprovider.CodeStore](t)(pgxstore.NewCodeStore(b.pool)),
			browser: must[oidcprovider.BrowserSessionStore](t)(pgxstore.NewBrowserSessionStore(b.pool)),
			pending: must[oidcprovider.PendingRequestStore](t)(pgxstore.NewPendingRequestStore(b.pool)),
			device:  must[oidcprovider.DeviceAuthorizationStore](t)(pgxstore.NewDeviceAuthorizationStore(b.pool)),
		}
	case "gorm":
		return proofStores{
			grants:  must[oidcprovider.GrantStore](t)(gormstore.NewGrantStore(b.gdb)),
			codes:   must[oidcprovider.CodeStore](t)(gormstore.NewCodeStore(b.gdb)),
			browser: must[oidcprovider.BrowserSessionStore](t)(gormstore.NewBrowserSessionStore(b.gdb)),
			pending: must[oidcprovider.PendingRequestStore](t)(gormstore.NewPendingRequestStore(b.gdb)),
			device:  must[oidcprovider.DeviceAuthorizationStore](t)(gormstore.NewDeviceAuthorizationStore(b.gdb)),
		}
	default:
		t.Fatalf("unknown backend %q", name)
		return proofStores{}
	}
}

// must returns a function that requires its constructor's error to be nil.
func must[S any](t *testing.T) func(S, error) S {
	t.Helper()

	return func(s S, err error) S {
		t.Helper()
		require.NoError(t, err)

		return s
	}
}

// digestOf is a stable 32-byte digest for seed.
func digestOf(seed string) []byte {
	sum := sha256.Sum256([]byte("proof-digest-of-" + seed))

	return sum[:]
}

// provenSignInOf is a federated sign-in whose second factor the library verified, with every
// piece of federated evidence set and an upstream amr of two values, so its order shows.
func provenSignInOf(seed string, now time.Time) oidcprovider.SignIn {
	s := localSignInOf(seed, now)
	s.ExternalIssuer, s.ExternalSessionID = "https://idp.example", "x-"+seed
	s.SecondFactorVerified = true
	s.ExternalProvider = "corp"
	s.ExternalAMR = []string{"mfa", "hwk"}
	s.ExternalACR = "urn:corp:loa:2"

	return s
}

// localSignInOf is a local sign-in, with no marker and no evidence.
func localSignInOf(seed string, now time.Time) oidcprovider.SignIn {
	return oidcprovider.SignIn{
		User: identity.UserID("u-" + seed), Family: crossBackendID("family-" + seed), AuthenticatedAt: now,
		AMR: []string{"pwd"}, ACR: "urn:example:loa:1", AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
}

// requireProven requires got to hold provenSignInOf's marker and evidence.
func requireProven(t *testing.T, got oidcprovider.SignIn) {
	t.Helper()

	assert.True(t, got.SecondFactorVerified, "the second-factor marker is kept")
	assert.Equal(t, "corp", got.ExternalProvider)
	assert.Equal(t, "https://idp.example", got.ExternalIssuer)
	assert.Equal(t, []string{"mfa", "hwk"}, got.ExternalAMR, "the upstream amr is kept, in order")
	assert.Equal(t, "urn:corp:loa:2", got.ExternalACR)
}

// requireUnproven requires got to hold no marker and no evidence.
func requireUnproven(t *testing.T, got oidcprovider.SignIn) {
	t.Helper()

	assert.False(t, got.SecondFactorVerified)
	assert.Empty(t, got.ExternalProvider)
	assert.Nil(t, got.ExternalAMR)
	assert.Empty(t, got.ExternalACR)
}

// TestCrossBackendSignInProof proves every record that keeps a sign-in, written through one
// backend and loaded through each other on the same database, keeps the sign-in's
// second-factor marker and federated evidence, and that a record of a local sign-in reads
// back with none.
func TestCrossBackendSignInProof(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// write stores a record of signIn, keyed by seed, through s.
		write func(ctx context.Context, t *testing.T, s proofStores, seed string, signIn oidcprovider.SignIn)
		// read loads that record through s and returns its sign-in.
		read func(ctx context.Context, t *testing.T, s proofStores, seed string) oidcprovider.SignIn
	}

	now := time.Now().UTC().Truncate(time.Microsecond)

	cases := []testCase{
		{
			name: "grant",
			write: func(ctx context.Context, t *testing.T, s proofStores, seed string, in oidcprovider.SignIn) {
				require.NoError(t, s.grants.Create(ctx, &oidcprovider.Grant{
					Family: crossBackendID("grant-" + seed), User: in.User, ClientID: "billing-web",
					Scopes: []string{"openid"}, AuthTime: in.AuthenticatedAt, AMR: in.AMR, ACR: in.ACR,
					CodeID: crossBackendID("grant-code-" + seed), SignInFamily: in.Family,
					ExternalIssuer: in.ExternalIssuer, ExternalSessionID: in.ExternalSessionID, HoldsLineage: true,
					SecondFactorVerified: in.SecondFactorVerified, ExternalProvider: in.ExternalProvider,
					ExternalAMR: in.ExternalAMR, ExternalACR: in.ExternalACR,
					CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
				}))
			},
			read: func(ctx context.Context, t *testing.T, s proofStores, seed string) oidcprovider.SignIn {
				g, err := s.grants.Load(ctx, crossBackendID("grant-"+seed))
				require.NoError(t, err)

				return oidcprovider.SignIn{
					SecondFactorVerified: g.SecondFactorVerified, ExternalProvider: g.ExternalProvider,
					ExternalIssuer: g.ExternalIssuer, ExternalAMR: g.ExternalAMR, ExternalACR: g.ExternalACR,
				}
			},
		},
		{
			name: "code",
			write: func(ctx context.Context, t *testing.T, s proofStores, seed string, in oidcprovider.SignIn) {
				require.NoError(t, s.codes.Create(ctx, &oidcprovider.CodeRecord{
					TokenID: crossBackendID("code-" + seed), ClientID: "billing-web", RedirectURI: "https://rp.example/cb",
					Scopes: []string{"openid"}, SignIn: in, GrantFamily: crossBackendID("code-grant-" + seed),
					ExpiresAt: now.Add(time.Minute),
				}))
			},
			read: func(ctx context.Context, t *testing.T, s proofStores, seed string) oidcprovider.SignIn {
				c, err := s.codes.Load(ctx, crossBackendID("code-"+seed))
				require.NoError(t, err)

				return c.SignIn
			},
		},
		{
			name: "browser session",
			write: func(ctx context.Context, t *testing.T, s proofStores, seed string, in oidcprovider.SignIn) {
				require.NoError(t, s.browser.Put(ctx, &oidcprovider.BrowserSession{
					Digest: digestOf("browser-" + seed), SignIn: in,
					IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
				}))
			},
			read: func(ctx context.Context, t *testing.T, s proofStores, seed string) oidcprovider.SignIn {
				b, err := s.browser.Load(ctx, digestOf("browser-"+seed), now)
				require.NoError(t, err)

				return b.SignIn
			},
		},
		{
			name: "pending request",
			write: func(ctx context.Context, t *testing.T, s proofStores, seed string, in oidcprovider.SignIn) {
				digest := digestOf("pending-" + seed)
				require.NoError(t, s.pending.Create(ctx, &oidcprovider.PendingRequest{
					ID: crossBackendID("pending-" + seed), HandleDigest: digest, FlowDigest: digestOf("flow-" + seed),
					ClientID: "billing-web", RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"},
					ParkedAt: now, ExpiresAt: now.Add(10 * time.Minute), Stage: oidcprovider.StageLogin,
				}))
				require.NoError(t, s.pending.Advance(ctx, digest, oidcprovider.StageLogin, oidcprovider.StageConsent, &in))
			},
			read: func(ctx context.Context, t *testing.T, s proofStores, seed string) oidcprovider.SignIn {
				p, err := s.pending.Load(ctx, digestOf("pending-"+seed))
				require.NoError(t, err)
				require.NotNil(t, p.SignIn)

				return *p.SignIn
			},
		},
		{
			name: "device approval",
			write: func(ctx context.Context, t *testing.T, s proofStores, seed string, in oidcprovider.SignIn) {
				devID := crossBackendID("device-" + seed)
				require.NoError(t, s.device.Create(ctx, &oidcprovider.DeviceAuthorization{
					ID: devID, DeviceCodeDigest: digestOf("device-code-" + seed), UserCodeDigest: digestOf("user-code-" + seed),
					ClaimFlowDigest: digestOf("claim-" + seed), ClientID: "billing-web", Scopes: []string{"openid"},
					IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Interval: 5 * time.Second,
					State: oidcprovider.DeviceClaimed,
				}, now))
				require.NoError(t, s.device.Decide(ctx, devID, &oidcprovider.DeviceApproval{
					User: in.User, GrantedScopes: []string{"openid"}, SignIn: in,
					GrantFamily: crossBackendID("device-grant-" + seed),
				}, now))
			},
			read: func(ctx context.Context, t *testing.T, s proofStores, seed string) oidcprovider.SignIn {
				d, err := s.device.LoadByDeviceCode(ctx, digestOf("device-code-"+seed))
				require.NoError(t, err)
				require.NotNil(t, d.Approval)

				return d.Approval.SignIn
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := migratedConn(t)
			b := backends{conn: conn, pool: openPgxPool(t, conn.DSN), gdb: openGormDB(t, conn.DSN), cipher: testCipher(t)}

			for _, writer := range backendNames {
				for _, reader := range backendNames {
					if writer == reader {
						continue
					}

					t.Run(writer+"_writes_"+reader+"_reads", func(t *testing.T) {
						t.Parallel()

						seed := tc.name + "-" + writer + "-" + reader
						ctx := t.Context()

						tc.write(ctx, t, b.proofStoresOf(t, writer), seed+"-proven", provenSignInOf(seed+"-proven", now))
						tc.write(ctx, t, b.proofStoresOf(t, writer), seed+"-local", localSignInOf(seed+"-local", now))

						requireProven(t, tc.read(ctx, t, b.proofStoresOf(t, reader), seed+"-proven"))
						requireUnproven(t, tc.read(ctx, t, b.proofStoresOf(t, reader), seed+"-local"))
					})
				}
			}
		})
	}
}
