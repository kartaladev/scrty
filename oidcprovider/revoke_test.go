package oidcprovider_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// credsOf returns the credentials clientID authenticates with its secret.
func credsOf(clientID string) oidcprovider.ClientCredentials {
	return oidcprovider.ClientCredentials{Authorization: basic(clientID, exchangeSecret)}
}

// tokenForm is a revocation's or an introspection's form for raw.
func tokenForm(raw string) url.Values { return url.Values{"token": {raw}} }

// hinted is tokenForm with a token_type_hint.
func hinted(raw, hint string) url.Values {
	return url.Values{"token": {raw}, "token_type_hint": {hint}}
}

// otherGrant is a second grant of billing-web, set on the scene.
func otherGrant(t *testing.T, f *refreshFixture, s *refreshScene) *refreshScene {
	t.Helper()

	s.other = startBilling(t, f)

	return s.other
}

// startOpaque is an offline grant of the client whose access tokens are opaque.
func startOpaque(t *testing.T, f *refreshFixture) *refreshScene {
	t.Helper()

	return startClient(opaqueClient, opaqueRedirect)(t, f)
}

// assertAccessTokenWorks checks raw still reads as a live access token.
func assertAccessTokenWorks(t *testing.T, f *refreshFixture, raw string) {
	t.Helper()

	_, err := f.p.VerifyAccessToken(t.Context(), raw)
	require.NoError(t, err)
}

// assertGrantLive checks the scene's grant has no revocation on it.
func assertGrantLive(t *testing.T, f *refreshFixture, s *refreshScene) {
	t.Helper()

	assert.False(t, grantNow(t, f, s).Revoked, "nothing revoked the grant")
}

// assertEndedByClient checks the scene's grant was ended by its client, with no reuse recorded,
// and that its lineage has gone.
func assertEndedByClient(t *testing.T, f *refreshFixture, s *refreshScene) {
	t.Helper()

	grant := grantNow(t, f, s)
	assert.True(t, grant.Revoked)
	assert.Equal(t, oidcprovider.CauseRevokedByClient, grant.RevokeCause)
	assert.Zero(t, f.liveHeads(t), "the lineage went with the grant")
}

// TestProvider_Revoke is the revocation table. Each row starts from a grant, says what is
// presented and by whom, and judges the answer and what it left behind.
func TestProvider_Revoke(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		start func(*testing.T, *refreshFixture) *refreshScene
		ctx   func(context.Context, *refreshFixture) context.Context
		// arrange returns who presents what, by default billing-web and the grant's first token.
		arrange func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values)
		assert  func(*testing.T, *refreshFixture, *refreshScene, error)
	}

	// ended asserts the whole grant has gone, and every token of it with it.
	ended := func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
		t.Helper()

		require.NoError(t, err)
		assertEndedByClient(t, f, s)
		assertRefreshRefused(t, f, s, s.first.RefreshToken)
		if s.newest != "" {
			assertRefreshRefused(t, f, s, s.newest)
		}
	}
	// spared asserts a success that revoked nothing.
	spared := func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
		t.Helper()

		require.NoError(t, err)
		assertUntouched(t, f, s)
		assert.Zero(t, f.lineage.writes.Load(), "nothing was written to the lineage")
		assertRefreshWorks(t, f, s, s.first.RefreshToken)
	}
	refusedAs := func(code string) func(*testing.T, *refreshFixture, *refreshScene, error) {
		return func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
			t.Helper()

			assertRefused(t, err, code)
			assertUntouched(t, f, s)
			assert.Zero(t, f.lineage.writes.Load(), "nothing was written to the lineage")
			assertRefreshWorks(t, f, s, s.first.RefreshToken)
		}
	}
	dependencyFailed := func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
		t.Helper()

		assertDependencyFailure(t, err)
		f.lineage.failLoad.Store(false)
		f.grants.failLoadAt.Store(0)
		assertUntouched(t, f, s)
	}
	valueOf := func(value string) func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
		return func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
			return credsOf("billing-web"), tokenForm(value)
		}
	}
	// rotated rotates the first token, and says the first is being presented again.
	rotated := func(t *testing.T, f *refreshFixture, s *refreshScene) {
		t.Helper()

		s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
		f.lineage.writes.Store(0)
	}

	cases := []testCase{
		{
			name: "a refresh token ends its whole grant, the tokens rotated from it too",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				rotated(t, f, s)

				return credsOf("billing-web"), tokenForm(s.newest)
			},
			assert: ended,
		},
		{
			name:  "a public client revokes by naming its client_id",
			start: startBound,
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				form := tokenForm(s.first.RefreshToken)
				form.Set("client_id", nativeClient)

				return oidcprovider.ClientCredentials{}, form
			},
			assert: ended,
		},
		{
			name: "a hint of access_token on a refresh token still revokes it",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), hinted(s.first.RefreshToken, "access_token")
			},
			assert: ended,
		},
		{
			name: "a hint of no known type is ignored",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), hinted(s.first.RefreshToken, "id_token")
			},
			assert: ended,
		},
		{
			name: "a superseded secret inside its grace ends the grant and is no reuse",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				rotated(t, f, s)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				ended(t, f, s, err)
			},
		},
		{
			name: "a superseded secret past its grace ends the grant and is no reuse, marking nothing presented",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				rotated(t, f, s)
				f.clk.Advance(5 * time.Minute)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, int32(1), f.lineage.writes.Load(), "the family's deletion is the only write to the lineage")
				ended(t, f, s, err)
			},
		},
		{
			name:  "an opaque token ends itself, and the grant and its other tokens live on",
			start: startOpaque,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				next := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				s.newest, s.newestAccess = next.RefreshToken, next.AccessToken

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				_, err = f.p.VerifyAccessToken(t.Context(), s.first.AccessToken)
				assertRefused(t, err, oidcprovider.CodeInvalidToken)
				assertAccessTokenWorks(t, f, s.newestAccess)
				assertGrantLive(t, f, s)
				assertRefreshWorks(t, f, s, s.newest)
			},
		},
		{
			name:  "an opaque token already ended answers success",
			start: startOpaque,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				require.NoError(t, f.p.Revoke(t.Context(), credsOf(opaqueClient), tokenForm(s.first.AccessToken)))

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				assertGrantLive(t, f, s)
			},
		},
		{
			name:  "an expired opaque token answers success and is not marked",
			start: startOpaque,
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.clk.Advance(6 * time.Minute)

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				created := f.access.created.Load()
				require.NotNil(t, created)
				held, err := f.access.Load(t.Context(), created.ID)
				require.NoError(t, err)
				assert.False(t, held.Revoked, "an expired token is left as it was")
			},
		},
		{
			name: "a JWT access token answers success with nothing revoked, and costs no key read",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.keys.failVerifying(func(context.Context) error { return errOutage })

				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				f.keys.failVerifying(nil)
				spared(t, f, s, err)
				assertAccessTokenWorks(t, f, s.first.AccessToken)
			},
		},
		{name: "a value that is no token answers success", arrange: valueOf("not a token"), assert: spared},
		{name: "a refresh token of no shape answers success", arrange: valueOf("rt.nonsense"), assert: spared},
		{name: "an opaque token of no shape answers success", arrange: valueOf("at.nonsense"), assert: spared},
		{
			name: "a refresh token of an unknown family answers success",
			arrange: func(t *testing.T, _ *refreshFixture, _ *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf("billing-web"), tokenForm("rt." + tokenIDText(t) + "." + neverIssued)
			},
			assert: spared,
		},
		{
			name: "an opaque token unknown to the store answers success",
			arrange: func(t *testing.T, _ *refreshFixture, _ *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf("billing-web"), tokenForm("at." + tokenIDText(t) + "." + neverIssued)
			},
			assert: spared,
		},
		{
			name:  "a real opaque identifier with a forged secret answers success and ends nothing",
			start: startOpaque,
			arrange: func(t *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				tokenID, _ := opaqueParts(t, s.first.AccessToken)

				return credsOf(opaqueClient), tokenForm("at." + tokenID.String() + "." + neverIssued)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				assertAccessTokenWorks(t, f, s.first.AccessToken)
			},
		},
		{
			name: "a real family with a forged secret answers success and revokes nothing",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), tokenForm("rt." + s.grant.Family.String() + "." + neverIssued)
			},
			assert: spared,
		},
		{
			name: "another client's family with a forged secret answers success, saying nothing of whose it is",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf(tiedClient), tokenForm("rt." + s.grant.Family.String() + "." + neverIssued)
			},
			assert: spared,
		},
		{
			name: "a client's own family beside another grant's secret ends neither",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				other := otherGrant(t, f, s)
				f.lineage.writes.Store(0)

				return credsOf("billing-web"), tokenForm("rt." + s.grant.Family.String() + "." + other.secretOf(t, other.first.RefreshToken))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				spared(t, f, s, err)
				assertGrantLive(t, f, s.other)
			},
		},
		{
			name: "a refresh token past its idle timeout answers success with nothing revoked",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.clk.Advance(31 * 24 * time.Hour)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				assertGrantLive(t, f, s)
			},
		},
		{
			name: "a refresh token whose grant has expired answers success with nothing revoked",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.rewrite = func(g *oidcprovider.Grant) { g.ExpiresAt = f.clk.Now() }

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				f.grants.rewrite = nil
				assertGrantLive(t, f, s)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "a refresh token whose grant row has gone answers success",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.loads.Store(0)
				f.grants.missingAt.Store(1)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				assertGrantLive(t, f, s)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "another client's refresh token is refused, and keeps working",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf(tiedClient), tokenForm(s.first.RefreshToken)
			},
			assert: refusedAs(oidcprovider.CodeInvalidGrant),
		},
		{
			name:  "another client's opaque token is refused, and keeps working",
			start: startOpaque,
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assertAccessTokenWorks(t, f, s.first.AccessToken)
			},
		},
		{
			name: "no client authentication is refused",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return oidcprovider.ClientCredentials{}, tokenForm(s.first.RefreshToken)
			},
			assert: refusedAs(oidcprovider.CodeInvalidClient),
		},
		{
			name: "a confidential client naming itself with no secret is refused",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				form := tokenForm(s.first.RefreshToken)
				form.Set("client_id", "billing-web")

				return oidcprovider.ClientCredentials{}, form
			},
			assert: refusedAs(oidcprovider.CodeInvalidClient),
		},
		{
			name: "no token is invalid_request",
			arrange: func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), url.Values{}
			},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "an empty token counts as none",
			arrange: func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), tokenForm("")
			},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a repeated parameter is invalid_request",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), url.Values{"token": {s.first.RefreshToken, s.first.RefreshToken}}
			},
			assert: refusedAs(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a lineage that cannot be read is a dependency failure, and no success",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.lineage.failLoad.Store(true)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: dependencyFailed,
		},
		{
			name: "a grant that cannot be read is a dependency failure, and no success",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.loads.Store(0)
				f.grants.failLoadAt.Store(1)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: dependencyFailed,
		},
		{
			name: "a row that cannot be marked leaves the lineage, and presenting the token again ends the grant",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.failRevoke.Store(true)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
				assert.Zero(t, f.lineage.writes.Load(), "the family stays, as the only way back to the row")

				f.grants.failRevoke.Store(false)
				ended(t, f, s, f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)))
			},
		},
		{
			name: "a family that cannot be deleted leaves the row marked, and presenting the token again finishes",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.lineage.failDelete.Store(true)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
				assert.True(t, grantNow(t, f, s).Revoked, "the row is marked first")
				assert.NotZero(t, f.liveHeads(t))

				f.lineage.failDelete.Store(false)
				ended(t, f, s, f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)))
			},
		},
		{
			name:  "an opaque token that cannot be read is a dependency failure",
			start: startOpaque,
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.access.failLoad.Store(true)

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
			},
		},
		{
			name:  "an opaque token that cannot be marked is a dependency failure",
			start: startOpaque,
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.access.failRevoke.Store(true)

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
				f.access.failRevoke.Store(false)
				assertAccessTokenWorks(t, f, s.first.AccessToken)
			},
		},
		{
			name:  "an opaque token swept between its read and its mark answers success (RFC 7009)",
			start: startOpaque,
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.access.goneAtRevoke.Store(true)

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "a caller gone before anything was read matches its own context, and nothing is revoked",
			ctx: func(ctx context.Context, f *refreshFixture) context.Context {
				f.grants.strictContext.Store(true)
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
				f.grants.strictContext.Store(false)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a caller hanging up at the row does not spare the family, and the delete has a deadline",
			ctx: func(ctx context.Context, f *refreshFixture) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				f.grants.beforeRevoke = cancel

				return ctx
			},
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.lineage.sawDelete = func(ctx context.Context) {
					_, bounded := ctx.Deadline()
					s.deleteBudgeted.Store(true)
					s.deleteBounded.Store(bounded)
				}

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				assertEndedByClient(t, f, s)
				assert.True(t, s.deleteBudgeted.Load())
				assert.True(t, s.deleteBounded.Load(), "a revocation's writes are budgeted")
			},
		},
		{
			name:  "a caller hanging up at an opaque token's mark does not spare it",
			start: startOpaque,
			ctx: func(ctx context.Context, f *refreshFixture) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				f.access.beforeRevoke = cancel

				return ctx
			},
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, err error) {
				t.Helper()

				require.NoError(t, err)
				_, err = f.p.VerifyAccessToken(t.Context(), s.first.AccessToken)
				assertRefused(t, err, oidcprovider.CodeInvalidToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			start := tc.start
			if start == nil {
				start = startBilling
			}
			s := start(t, f)
			f.lineage.writes.Store(0)
			s.grant = grantNow(t, f, s)
			f.grants.loads.Store(0)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, f)
			}
			creds, form := tc.arrange(t, f, s)

			tc.assert(t, f, s, f.p.Revoke(ctx, creds, form))
		})
	}
}

// introspected is what a table row judges.
type introspected struct {
	answer map[string]any
	err    error
}

// resourceServer registers a client whose resource identifier is resource, and returns its name.
func resourceServer(t *testing.T, f *refreshFixture, resource string) string {
	t.Helper()

	name := "rs-" + strings.TrimPrefix(resource, "https://")
	require.NoError(t, f.registry.Put(t.Context(), oidcprovider.Client{
		ID: name, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret),
		RedirectURIs: []string{"https://rs.example.com/cb"}, Scopes: []string{"openid"}, ResourceIdentifier: resource,
	}))

	return name
}

// TestProvider_Introspect is the introspection table. Whatever a row presents, the request
// writes nothing, which the runner checks after each.
func TestProvider_Introspect(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		start   func(*testing.T, *refreshFixture) *refreshScene
		ctx     func(context.Context) context.Context
		arrange func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values)
		assert  func(*testing.T, *refreshFixture, *refreshScene, introspected)
	}

	inactive := func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
		t.Helper()

		require.NoError(t, got.err)
		assert.Equal(t, map[string]any{"active": false}, got.answer)
	}
	active := func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
		t.Helper()

		require.NoError(t, got.err)
		assert.Equal(t, true, got.answer["active"])
	}
	refused := func(code string) func(*testing.T, *refreshFixture, *refreshScene, introspected) {
		return func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
			t.Helper()

			assertRefused(t, got.err, code)
			assert.Nil(t, got.answer)
		}
	}
	dependencyFailed := func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
		t.Helper()

		assertDependencyFailure(t, got.err)
		assert.Nil(t, got.answer)
	}
	byBillingOf := func(value func(*refreshScene) string) func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
		return func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
			return credsOf("billing-web"), tokenForm(value(s))
		}
	}
	access := func(s *refreshScene) string { return s.first.AccessToken }
	byOpaqueClient := func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
		return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
	}

	cases := []testCase{
		{
			name: "no credentials are invalid_client",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return oidcprovider.ClientCredentials{}, tokenForm(s.first.AccessToken)
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name:  "a public client naming itself is invalid_client, even for its own token",
			start: startBound,
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				form := tokenForm(s.first.AccessToken)
				form.Set("client_id", nativeClient)

				return oidcprovider.ClientCredentials{}, form
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name: "a public client naming no token is invalid_client, since the client is judged first",
			arrange: func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return oidcprovider.ClientCredentials{}, url.Values{"client_id": {nativeClient}}
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name:  "a client whose resource identifier is the issuer is unknown, and sees no one's token",
			start: startBound,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf(resourceServer(t, f, issuer)), tokenForm(s.first.AccessToken)
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name: "no token is invalid_request",
			arrange: func(*testing.T, *refreshFixture, *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), url.Values{}
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a repeated parameter is invalid_request",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), url.Values{"token": {s.first.AccessToken, s.first.AccessToken}}
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "another client's JWT is inactive and nothing more",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf(tiedClient), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name:  "another client's opaque token is inactive and nothing more",
			start: startOpaque,
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name: "another client's refresh token is inactive and nothing more",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf(tiedClient), tokenForm(s.first.RefreshToken)
			},
			assert: inactive,
		},
		{
			name:  "a resource server in the token's audience sees it",
			start: startResources("https://api.example.com"),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf(resourceServer(t, f, "https://api.example.com")), tokenForm(s.first.AccessToken)
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, true, got.answer["active"])
				assert.Equal(t, "billing-web", got.answer["client_id"])
			},
		},
		{
			name:  "a resource server not in the token's audience does not",
			start: startResources("https://api.example.com"),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf(resourceServer(t, f, "https://data.example.com")), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name:  "a client with no resource identifier does not read one absent from an audience as a match",
			start: startResources("https://api.example.com"),
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name:  "a resource server does not see a refresh token, which has no audience of its",
			start: startResources("https://api.example.com"),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf(resourceServer(t, f, "https://api.example.com")), tokenForm(s.first.RefreshToken)
			},
			assert: inactive,
		},
		{
			name:    "an active opaque token answers the full field list",
			start:   startOpaque,
			arrange: byOpaqueClient,
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, map[string]any{
					"active":     true,
					"scope":      "openid offline_access",
					"client_id":  opaqueClient,
					"sub":        "u-1",
					"iat":        f.clk.Now().Unix(),
					"exp":        f.clk.Now().Add(5 * time.Minute).Unix(),
					"iss":        issuer,
					"aud":        []string{issuer},
					"token_type": "Bearer",
				}, got.answer)
			},
		},
		{
			name:    "an active JWT answers the full field list",
			arrange: byBillingOf(access),
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, map[string]any{
					"active":     true,
					"scope":      "openid profile offline_access",
					"client_id":  "billing-web",
					"sub":        "u-1",
					"iat":        f.clk.Now().Unix(),
					"exp":        f.clk.Now().Add(5 * time.Minute).Unix(),
					"iss":        issuer,
					"aud":        []string{issuer},
					"token_type": "Bearer",
				}, got.answer)
			},
		},
		{
			name: "a token bound to a key says so",
			start: func(t *testing.T, f *refreshFixture) *refreshScene {
				t.Helper()

				c := issueCodeFor(t, f.parkFixture, opaqueClient, func(v url.Values) {
					asClient(v, opaqueClient, opaqueRedirect)
					v.Set("scope", "openid offline_access")
				}, testSignIn(f.parkFixture, "u-1"), "openid", "offline_access")
				req := confidentialExchange(opaqueClient, opaqueRedirect, c, nil)
				req.Binding = oidcprovider.Binding{JKT: keyOne}
				again := func(raw string) oidcprovider.TokenRequest { return refreshRequest(opaqueClient, raw, nil) }

				return sceneOf(t, f, c, req, again)
			},
			arrange: byOpaqueClient,
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, map[string]string{"jkt": keyOne}, got.answer["cnf"])
				assert.Equal(t, "DPoP", got.answer["token_type"])
			},
		},
		{
			name: "a token bound to a certificate is presented as Bearer, and says what it is bound to",
			start: func(t *testing.T, f *refreshFixture) *refreshScene {
				t.Helper()

				c := issueCodeFor(t, f.parkFixture, opaqueClient, func(v url.Values) {
					asClient(v, opaqueClient, opaqueRedirect)
					v.Set("scope", "openid offline_access")
				}, testSignIn(f.parkFixture, "u-1"), "openid", "offline_access")
				req := confidentialExchange(opaqueClient, opaqueRedirect, c, nil)
				req.Binding = oidcprovider.Binding{X5T: keyTwo}
				again := func(raw string) oidcprovider.TokenRequest { return refreshRequest(opaqueClient, raw, nil) }

				return sceneOf(t, f, c, req, again)
			},
			arrange: byOpaqueClient,
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, map[string]string{"x5t#S256": keyTwo}, got.answer["cnf"])
				assert.Equal(t, "Bearer", got.answer["token_type"])
			},
		},
		{
			name: "a JWT of a revoked grant is inactive",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				revokeWhole(t, f, s)
				f.lineage.writes.Store(0)

				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name:  "an opaque token of a revoked grant is inactive",
			start: startOpaque,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				revokeWhole(t, f, s)
				f.lineage.writes.Store(0)

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name: "a JWT naming no expiry was not minted here, and is inactive",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf("billing-web"), tokenForm(signedAccess(t, f.exchangeFixture, s.grant.Family, func(claims map[string]any) {
					delete(claims, "exp")
				}))
			},
			assert: inactive,
		},
		{
			name: "an empty audience value is no resource identifier, for a client registered with none",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				return credsOf(tiedClient), tokenForm(signedAccess(t, f.exchangeFixture, s.grant.Family, func(claims map[string]any) {
					claims["aud"] = []string{""}
				}))
			},
			assert: inactive,
		},
		{
			name: "a JWT whose grant row is missing reads as revoked",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.loads.Store(0)
				f.grants.missingAt.Store(1)

				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name: "an expired JWT is inactive",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.clk.Advance(6 * time.Minute)

				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name:  "an expired opaque token is inactive",
			start: startOpaque,
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.clk.Advance(6 * time.Minute)

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name:  "an opaque token its client has revoked is inactive",
			start: startOpaque,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				require.NoError(t, f.p.Revoke(t.Context(), credsOf(opaqueClient), tokenForm(s.first.AccessToken)))

				return credsOf(opaqueClient), tokenForm(s.first.AccessToken)
			},
			assert: inactive,
		},
		{
			name: "a live refresh token answers the full field list, and writes nothing",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.clk.Advance(10 * time.Minute)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, map[string]any{
					"active":     true,
					"scope":      "openid profile offline_access",
					"client_id":  "billing-web",
					"sub":        "u-1",
					"iat":        f.clk.Now().Add(-10 * time.Minute).Unix(),
					"exp":        s.head(t, f, s.first.RefreshToken).IdleExpiresAt.Unix(),
					"iss":        issuer,
					"aud":        []string{issuer},
					"token_type": "refresh_token",
				}, got.answer)
			},
		},
		{
			name: "a refresh token's exp is no later than its grant's end",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				f.grants.rewrite = func(g *oidcprovider.Grant) { g.ExpiresAt = f.clk.Now().Add(time.Hour) }

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, f.clk.Now().Add(time.Hour).Unix(), got.answer["exp"])
			},
		},
		{
			name: "a refresh token's exp honours an idle timeout the client has shortened since",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = time.Hour })

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				require.Equal(t, true, got.answer["active"])
				assert.Equal(t, f.clk.Now().Add(time.Hour).Unix(), got.answer["exp"])
			},
		},
		{
			name: "a refresh token's exp honours an absolute lifetime the client has shortened since",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				// A refresh an hour in moves the last use on, and only then are both limits made
				// 3 hours, so the idle end is 4 hours out and the absolute one 3.
				f.clk.Advance(time.Hour)
				res := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.GrantIdleTimeout, c.GrantAbsoluteLifetime = 3*time.Hour, 3*time.Hour
				})
				f.lineage.writes.Store(0)

				return credsOf("billing-web"), tokenForm(res.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				require.Equal(t, true, got.answer["active"])
				assert.Equal(t, f.clk.Now().Add(2*time.Hour).Unix(), got.answer["exp"], "three hours from the grant's start")
			},
		},
		{
			name: "a refresh token's exp is its record's own absolute end when that is the first, whatever its idle end",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				// A lineage store of the consumer's need not keep the idle end within the absolute one.
				f.lineage.rewrite = func(r *session.Session) { r.AbsoluteExpiresAt = f.clk.Now().Add(30 * time.Minute) }

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				require.Equal(t, true, got.answer["active"])
				assert.Equal(t, f.clk.Now().Add(30*time.Minute).Unix(), got.answer["exp"])
			},
		},
		{
			name: "a grant bound to a key says so on its refresh token",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.rewrite = func(g *oidcprovider.Grant) { g.KeyBinding = keyOne }

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Equal(t, map[string]string{"jkt": keyOne}, got.answer["cnf"])
			},
		},
		{
			name: "a hint names no type a token is read as",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), hinted(s.first.RefreshToken, "access_token")
			},
			assert: active,
		},
		{
			name: "a superseded secret inside its grace is inactive, and still refreshes",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.lineage.writes.Store(0)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, got introspected) {
				t.Helper()

				inactive(t, f, s, got)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a superseded secret past its grace is inactive, and is no reuse",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(5 * time.Minute)
				f.lineage.writes.Store(0)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, got introspected) {
				t.Helper()

				inactive(t, f, s, got)
				assertGrantLive(t, f, s)
				assertRefreshWorks(t, f, s, s.newest)
			},
		},
		{
			name: "a real family with a forged secret is inactive",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				return credsOf("billing-web"), tokenForm("rt." + s.grant.Family.String() + "." + neverIssued)
			},
			assert: inactive,
		},
		{
			name: "a client's own family beside another grant's secret is inactive",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				other := otherGrant(t, f, s)
				f.lineage.writes.Store(0)

				return credsOf("billing-web"), tokenForm("rt." + s.grant.Family.String() + "." + other.secretOf(t, other.first.RefreshToken))
			},
			assert: inactive,
		},
		{
			name: "a refresh token of a revoked grant whose lineage remains is inactive",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				require.NoError(t, f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now()))

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: inactive,
		},
		{
			name: "a refresh token whose grant has expired is inactive",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.rewrite = func(g *oidcprovider.Grant) { g.ExpiresAt = f.clk.Now() }

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: inactive,
		},
		{
			name: "a refresh token whose grant row is missing is inactive",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.loads.Store(0)
				f.grants.missingAt.Store(1)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: inactive,
		},
		{
			name: "a refresh token past a lifetime its client has since shortened is inactive",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				t.Helper()

				billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = time.Hour })
				f.clk.Advance(time.Hour)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: inactive,
		},
		{
			name:    "a refresh token of no shape is inactive",
			arrange: byBillingOf(func(*refreshScene) string { return "rt.nonsense" }),
			assert:  inactive,
		},
		{
			name:    "a value that is no token is inactive",
			arrange: byBillingOf(func(*refreshScene) string { return "not a token" }),
			assert:  inactive,
		},
		{
			name: "a grant that cannot be read is a dependency failure, for a refresh token",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.failLoadAt.Store(1)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: dependencyFailed,
		},
		{
			name: "a lineage that cannot be read is a dependency failure",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.lineage.failLoad.Store(true)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: dependencyFailed,
		},
		{
			name: "a grant that cannot be read is a dependency failure, for a JWT",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.failLoadAt.Store(1)

				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: dependencyFailed,
		},
		{
			name: "keys that cannot verify are a dependency failure",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.keys.failVerifying(func(context.Context) error { return errOutage })

				return credsOf("billing-web"), tokenForm(s.first.AccessToken)
			},
			assert: dependencyFailed,
		},
		{
			name: "a caller gone matches its own context, and reports no inactive token",
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) (oidcprovider.ClientCredentials, url.Values) {
				f.grants.strictContext.Store(true)

				return credsOf("billing-web"), tokenForm(s.first.RefreshToken)
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, got introspected) {
				t.Helper()

				require.ErrorIs(t, got.err, context.Canceled)
				assert.NotErrorIs(t, got.err, oidcprovider.ErrDependency)
				assert.Nil(t, got.answer)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			start := tc.start
			if start == nil {
				start = startBilling
			}
			s := start(t, f)
			f.lineage.writes.Store(0)
			revocations := f.grants.revokes.Load()
			s.grant = grantNow(t, f, s)
			f.grants.loads.Store(0)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			creds, form := tc.arrange(t, f, s)
			answer, err := f.p.Introspect(ctx, creds, form)

			assert.Zero(t, f.lineage.writes.Load(), "introspection writes nothing to the lineage")
			assert.Equal(t, revocations, f.grants.revokes.Load(), "introspection revokes nothing")
			tc.assert(t, f, s, introspected{answer: answer, err: err})
		})
	}
}

// TestProvider_Revoke_NoSecretReachesALogOrAnError runs revocation and introspection through what
// fails, and looks for what the requests carried.
func TestProvider_Revoke_NoSecretReachesALogOrAnError(t *testing.T) {
	t.Parallel()

	f := newRefreshFixture(t)
	s := startOpaque(t, f)
	refresh, access := s.first.RefreshToken, s.first.AccessToken

	var errs []error
	try := func() {
		for _, raw := range []string{refresh, access} {
			if err := f.p.Revoke(t.Context(), credsOf(opaqueClient), tokenForm(raw)); err != nil {
				errs = append(errs, err)
			}
			if _, err := f.p.Introspect(t.Context(), credsOf(opaqueClient), tokenForm(raw)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	f.lineage.failLoad.Store(true)
	f.access.failLoad.Store(true)
	try()
	f.lineage.failLoad.Store(false)
	f.access.failLoad.Store(false)
	f.grants.failRevoke.Store(true)
	f.access.failRevoke.Store(true)
	try()
	require.NotEmpty(t, errs)

	logs := f.logs.String()
	_, accessSecret := opaqueParts(t, access)
	for _, secret := range []string{s.secretOf(t, refresh), accessSecret, refresh, access} {
		assert.NotContains(t, logs, secret)
		for _, err := range errs {
			assert.NotContains(t, err.Error(), secret)
		}
	}
}

// TestProvider_Revoke_DuringARefresh holds a refresh at the moment its rotation writes, and lands a
// revocation there, so the answer it gets is the one a row read again reaches. It has its own setup
// from the table's, being two requests.
func TestProvider_Revoke_DuringARefresh(t *testing.T) {
	t.Parallel()

	f := newRefreshFixture(t)
	s := startBilling(t, f)
	revoked := make(chan error, 1)
	f.lineage.beforeSupersede = once(func() {
		revoked <- f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken))
	})

	_, err := f.p.Token(t.Context(), s.request)
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)
	require.NoError(t, <-revoked)
	assertEndedByClient(t, f, s)
	assertRefreshRefused(t, f, s, s.first.RefreshToken)
}

// TestProvider_Revoke_Concurrently meets two revocations of one token at the row's write, so neither
// has finished when the other starts. Both answer success, and the grant ends once.
func TestProvider_Revoke_Concurrently(t *testing.T) {
	t.Parallel()

	f := newRefreshFixture(t)
	s := startBilling(t, f)
	f.grants.beforeRevoke = meeting(t, 2)

	answers := make(chan error, 2)
	for range 2 {
		go func() { answers <- f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)) }()
	}
	require.NoError(t, <-answers)
	require.NoError(t, <-answers)
	assertEndedByClient(t, f, s)
}
