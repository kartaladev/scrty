package oidcprovider_test

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

const (
	// keyOne and keyTwo are two DPoP keys' thumbprints.
	keyOne = authzChallenge
	keyTwo = authzVerifier

	// neverIssued has the shape of a refresh token's secret, and no record behind it.
	neverIssued = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// hookedLineage is a real lineage store whose writes are counted, and which runs a row's step
// or fails at the moments a refresh's order rests on.
type hookedLineage struct {
	session.Store

	writes atomic.Int32

	// beforeSupersede and afterSupersede run around each supersession, and are set before the
	// request starts.
	beforeSupersede, afterSupersede func()

	// onLoad runs after each read that found a record, and is set before the request starts.
	onLoad func()

	failLoad, failSupersede, failDelete atomic.Bool
	// answerNothing makes a read answer with neither a record nor an error.
	answerNothing atomic.Bool
	// conflict makes every supersession lose its race.
	conflict atomic.Bool
	// supersedes counts the supersessions that reached the store.
	supersedes atomic.Int32
}

// Load implements session.Store.
func (h *hookedLineage) Load(ctx context.Context, secret string) (*session.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.failLoad.Load() {
		return nil, errOutage
	}
	if h.answerNothing.Load() {
		return nil, nil //nolint:nilnil // the case a manager reads as no session
	}

	record, err := h.Store.Load(ctx, secret)
	if err == nil && h.onLoad != nil {
		h.onLoad()
	}

	return record, err
}

// MarkPresented implements session.Store.
func (h *hookedLineage) MarkPresented(ctx context.Context, secret string, at time.Time) error {
	h.writes.Add(1)

	return h.Store.MarkPresented(ctx, secret, at)
}

// RecordActivity implements session.Store.
func (h *hookedLineage) RecordActivity(ctx context.Context, secret string, at, idle, since time.Time) error {
	h.writes.Add(1)

	return h.Store.RecordActivity(ctx, secret, at, idle, since)
}

// keepAlive moves every record's idle deadline to until, for a row about a later check.
func (h *hookedLineage) keepAlive(t *testing.T, until time.Time) {
	t.Helper()

	heads, err := h.ListByUser(t.Context(), "u-1", until.Add(-time.Nanosecond))
	require.NoError(t, err)
	require.NotEmpty(t, heads)
	for _, head := range heads {
		require.NoError(t, h.Store.RecordActivity(t.Context(), head.ID, head.CreatedAt, until, head.CreatedAt))
	}
}

// Supersede implements session.Store.
func (h *hookedLineage) Supersede(ctx context.Context, op session.Supersession) error {
	h.writes.Add(1)
	h.supersedes.Add(1)
	if h.beforeSupersede != nil {
		h.beforeSupersede()
	}
	if h.failSupersede.Load() {
		return errOutage
	}
	if h.conflict.Load() {
		return session.ErrRenewalConflict
	}
	err := h.Store.Supersede(ctx, op)
	if err == nil && h.afterSupersede != nil {
		h.afterSupersede()
	}

	return err
}

// DeleteFamily implements session.Store.
func (h *hookedLineage) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	h.writes.Add(1)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if h.failDelete.Load() {
		return 0, errOutage
	}

	return h.Store.DeleteFamily(ctx, family)
}

// hookedGrants is a real grant store that refuses work on a context that has ended, as a store
// reaching a database would, and fails or rewrites at a row's request.
type hookedGrants struct {
	oidcprovider.GrantStore

	loads atomic.Int32
	// failLoadAt fails the nth load, counted from one when loads was last zeroed, and 0 fails none.
	failLoadAt atomic.Int32
	// missingAt answers ErrNotFound at the nth load, counted the same way, and 0 at none.
	missingAt atomic.Int32
	// failRevoke fails every revocation.
	failRevoke atomic.Bool
	// rewrite changes what a load answers, and is set before the request starts.
	rewrite func(*oidcprovider.Grant)
	// strictContext makes a load refuse an ended context too.
	strictContext atomic.Bool
}

// Load implements oidcprovider.GrantStore.
func (h *hookedGrants) Load(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
	if h.strictContext.Load() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	nth := h.loads.Add(1)
	if h.failLoadAt.Load() == nth {
		return nil, errOutage
	}
	if h.missingAt.Load() == nth {
		return nil, oidcprovider.ErrNotFound
	}
	grant, err := h.GrantStore.Load(ctx, family)
	if err == nil && h.rewrite != nil {
		h.rewrite(grant)
	}

	return grant, err
}

// Revoke implements oidcprovider.GrantStore.
func (h *hookedGrants) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.failRevoke.Load() {
		return errOutage
	}

	return h.GrantStore.Revoke(ctx, family, cause, at)
}

// hookedAccessTokens is a real access token store that fails its writes at a row's request.
type hookedAccessTokens struct {
	oidcprovider.AccessTokenStore

	failCreate atomic.Bool
	// creates counts what reached the store.
	creates atomic.Int32
}

// Create implements oidcprovider.AccessTokenStore.
func (h *hookedAccessTokens) Create(ctx context.Context, record *oidcprovider.AccessTokenRecord) error {
	h.creates.Add(1)
	if h.failCreate.Load() {
		return errOutage
	}

	return h.AccessTokenStore.Create(ctx, record)
}

// refreshFixture is an exchange fixture whose grant and lineage stores a row can watch.
type refreshFixture struct {
	*exchangeFixture

	grants  *hookedGrants
	lineage *hookedLineage
	access  *hookedAccessTokens
}

func newRefreshFixture(t *testing.T, opts ...oidcprovider.Option) *refreshFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(exchangeFixtureStart)
	memory, err := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	require.NoError(t, err)
	grantStore, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)

	accessStore, err := oidcprovider.NewMemoryAccessTokenStore()
	require.NoError(t, err)

	lineage := &hookedLineage{Store: memory}
	grants := &hookedGrants{GrantStore: grantStore}
	access := &hookedAccessTokens{AccessTokenStore: accessStore}
	x := newExchangeFixtureOn(t, clk, append([]oidcprovider.Option{
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithRefreshTokenStore(oplineage.New(lineage)),
		oidcprovider.WithAccessTokenStore(access),
	}, opts...)...)

	return &refreshFixture{exchangeFixture: x, grants: grants, lineage: lineage, access: access}
}

// liveHeads is how many of u-1's lineage records could still be rotated from.
func (f *refreshFixture) liveHeads(t *testing.T) int {
	t.Helper()

	heads, err := f.lineage.ListByUser(t.Context(), "u-1", f.clk.Now())
	require.NoError(t, err)

	return len(heads)
}

// refreshRequest is a refresh of raw by a confidential client using its secret.
func refreshRequest(clientID, raw string, change func(url.Values)) oidcprovider.TokenRequest {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}
	if change != nil {
		change(form)
	}

	return oidcprovider.TokenRequest{
		Credentials: oidcprovider.ClientCredentials{Authorization: basic(clientID, exchangeSecret)},
		Form:        form,
	}
}

// refreshScene is what a row starts from: a grant, and the request that refreshes it.
type refreshScene struct {
	grant   *oidcprovider.Grant
	first   *oidcprovider.TokenResponse
	request oidcprovider.TokenRequest
	// again is the client's request for another of the grant's tokens.
	again func(raw string) oidcprovider.TokenRequest
	// newest is the token a row's arrange last received.
	newest string
	// racers answers what a row's arrange set racing the request, and background closes when
	// what else it set running has finished.
	racers     []<-chan exchanged
	background <-chan struct{}
	// other is a second grant of the same client.
	other *refreshScene
	// signed counts the signatures made.
	signed atomic.Int32
}

// secretOf is the secret part of a refresh token of the grant.
func (s *refreshScene) secretOf(t *testing.T, raw string) string {
	t.Helper()

	secret, found := strings.CutPrefix(raw, "rt."+s.grant.Family.String()+".")
	require.True(t, found, "a refresh token is rt.<family>.<secret>")

	return secret
}

// head is the stored lineage record of raw.
func (s *refreshScene) head(t *testing.T, f *refreshFixture, raw string) *session.Session {
	t.Helper()

	record, err := f.lineage.Load(t.Context(), s.secretOf(t, raw))
	require.NoError(t, err)

	return record
}

// sceneOf exchanges req, for a client whose refreshes again builds.
func sceneOf(
	t *testing.T, f *refreshFixture, c issuedCode, req oidcprovider.TokenRequest, again func(string) oidcprovider.TokenRequest,
) *refreshScene {
	t.Helper()

	first, err := f.p.Token(t.Context(), req)
	require.NoError(t, err)
	require.NotEmpty(t, first.RefreshToken)

	return &refreshScene{grant: grantOf(t, f.exchangeFixture, c), first: first, request: again(first.RefreshToken), again: again}
}

func byBilling(raw string) oidcprovider.TokenRequest { return refreshRequest("billing-web", raw, nil) }

// startBilling is an offline grant of billing-web, for openid, profile and offline_access.
func startBilling(t *testing.T, f *refreshFixture) *refreshScene {
	t.Helper()

	c := f.issueOffline(t)

	return sceneOf(t, f, c, billingExchange(c, nil), byBilling)
}

// startBillingFor is startBilling for more scopes than a code usually holds.
func startBillingFor(scopes ...string) func(*testing.T, *refreshFixture) *refreshScene {
	return func(t *testing.T, f *refreshFixture) *refreshScene {
		t.Helper()

		c := issueCodeFor(t, f.parkFixture, "billing-web", func(v url.Values) {
			v.Set("scope", strings.Join(scopes, " "))
		}, testSignIn(f.parkFixture, "u-1"), scopes...)

		return sceneOf(t, f, c, billingExchange(c, nil), byBilling)
	}
}

// startOnline is a grant holding no offline_access, which ends by its sign-in's deadline.
func startOnline(t *testing.T, f *refreshFixture) *refreshScene {
	t.Helper()

	c := f.issue(t)

	return sceneOf(t, f, c, billingExchange(c, nil), byBilling)
}

// startClient is an offline grant of a client registered with scopes openid and offline_access.
func startClient(clientID, redirectURI string) func(*testing.T, *refreshFixture) *refreshScene {
	return func(t *testing.T, f *refreshFixture) *refreshScene {
		t.Helper()

		c := issueCodeFor(t, f.parkFixture, clientID, func(v url.Values) {
			asClient(v, clientID, redirectURI)
			v.Set("scope", "openid offline_access")
		}, testSignIn(f.parkFixture, "u-1"), "openid", "offline_access")
		again := func(raw string) oidcprovider.TokenRequest { return refreshRequest(clientID, raw, nil) }

		return sceneOf(t, f, c, confidentialExchange(clientID, redirectURI, c, nil), again)
	}
}

// startBound is a public client's grant, bound to keyOne by its first request's proof.
func startBound(t *testing.T, f *refreshFixture) *refreshScene {
	t.Helper()

	c := issueCodeFor(t, f.parkFixture, nativeClient, func(v url.Values) {
		asClient(v, nativeClient, nativeRedirect)
		v.Set("scope", "openid offline_access")
	}, testSignIn(f.parkFixture, "u-1"), "openid", "offline_access")
	again := func(raw string) oidcprovider.TokenRequest {
		return oidcprovider.TokenRequest{
			Form:    url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {nativeClient}},
			Binding: oidcprovider.Binding{JKT: keyOne},
		}
	}
	first := oidcprovider.TokenRequest{
		Form: exchangeForm(c, nativeRedirect, func(v url.Values) { v.Set("client_id", nativeClient) }),

		Binding: oidcprovider.Binding{JKT: keyOne},
	}

	return sceneOf(t, f, c, first, again)
}

// startResources is a grant of the billing client holding two resources.
func startResources(resources ...string) func(*testing.T, *refreshFixture) *refreshScene {
	return func(t *testing.T, f *refreshFixture) *refreshScene {
		t.Helper()

		c := issueCodeFor(t, f.parkFixture, "billing-web", func(v url.Values) {
			v["resource"] = resources
			v.Set("scope", "openid offline_access")
		}, testSignIn(f.parkFixture, "u-1"), "openid", "offline_access")

		return sceneOf(t, f, c, billingExchange(c, func(v url.Values) { v.Set("resource", resources[0]) }), byBilling)
	}
}

// billingClient is billing-web changed, as a consumer would change it over time.
func billingClient(t *testing.T, f *refreshFixture, change func(*oidcprovider.Client)) {
	t.Helper()

	client := authzClients()[0]
	change(&client)
	require.NoError(t, f.registry.Put(t.Context(), client))
}

// asksScope is a refresh of the scene's token asking for scope.
func asksScope(s *refreshScene, scope string) oidcprovider.TokenRequest {
	req := s.again(s.first.RefreshToken)
	req.Form.Set("scope", scope)

	return req
}

// assertRefreshWorks refreshes raw, and returns the answer.
func assertRefreshWorks(t *testing.T, f *refreshFixture, s *refreshScene, raw string) *oidcprovider.TokenResponse {
	t.Helper()

	res, err := f.p.Token(t.Context(), s.again(raw))
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)

	return res
}

// assertRefreshRefused checks raw is refused as invalid_grant.
func assertRefreshRefused(t *testing.T, f *refreshFixture, s *refreshScene, raw string) {
	t.Helper()

	_, err := f.p.Token(t.Context(), s.again(raw))
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)
}

// grantNow is the grant's record as it stands.
func grantNow(t *testing.T, f *refreshFixture, s *refreshScene) *oidcprovider.Grant {
	t.Helper()

	grant, err := f.grants.GrantStore.Load(t.Context(), s.grant.Family)
	require.NoError(t, err)

	return grant
}

// assertUntouched checks a refused request left the grant and the token as they were, and made
// no write at all when writes says none were allowed.
func assertUntouched(t *testing.T, f *refreshFixture, s *refreshScene) {
	t.Helper()

	assert.Equal(t, s.grant, grantNow(t, f, s), "the grant is as it was")
	assert.True(t, s.head(t, f, s.first.RefreshToken).SupersededAt.IsZero(), "the token was not rotated")
}

// TestProvider_Refresh is the refresh grant's table. Each row starts from a grant, changes
// what it needs, sends one request, and then judges the answer and what it left behind.
func TestProvider_Refresh(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []oidcprovider.Option
		// ctx modifies the request's context, and nil leaves it alone.
		ctx func(context.Context) context.Context
		// start is the grant the row works on, and nil is startBilling.
		start func(*testing.T, *refreshFixture) *refreshScene
		// arrange changes the scene before the request.
		arrange func(*testing.T, *refreshFixture, *refreshScene)
		assert  func(*testing.T, *refreshFixture, *refreshScene, *oidcprovider.TokenResponse, error)
	}

	refusedGrant := func(t *testing.T, _ *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		assertRefused(t, err, oidcprovider.CodeInvalidGrant)
		assert.Nil(t, res)
	}
	// refusedUserRevokes is the row of a user who is no longer good.
	refusedUserRevokes := func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		refusedGrant(t, f, s, res, err)
		grant := grantNow(t, f, s)
		assert.True(t, grant.Revoked)
		assert.Equal(t, oidcprovider.CauseUserDisabled, grant.RevokeCause)
		assert.Equal(t, 0, f.liveHeads(t), "the lineage went with the grant")
	}

	cases := []testCase{
		{
			name: "missing_lineage_reads_revoked",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				_, err := f.lineage.Store.DeleteFamily(t.Context(), s.grant.Family)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, s.grant, grantNow(t, f, s), "reading as revoked writes nothing: a value naming a family must not end it")
				assert.Zero(t, f.lineage.writes.Load())
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a secret never issued for a real family changes nothing",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = s.again("rt." + s.grant.Family.String() + "." + neverIssued)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load(), "not even the real token's presentation is marked")
				assertUntouched(t, f, s)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a family with no grant is refused",
			arrange: func(t *testing.T, _ *refreshFixture, s *refreshScene) {
				t.Helper()
				other, err := id.NewV7Generator().NewID()
				require.NoError(t, err)
				s.request = s.again("rt." + other.String() + "." + neverIssued)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "another client's token is refused, and its owner's keeps working",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = refreshRequest(weekClient, s.first.RefreshToken, nil)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load(), "the grant row was read before anything changed")
				assertUntouched(t, f, s)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a revoked grant is refused, with nothing written to the lineage",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				require.NoError(t, f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now()))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "a grant past its own expiry is refused, whatever its lineage says",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.grants.rewrite = func(g *oidcprovider.Grant) { g.ExpiresAt = f.clk.Now() }
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name:  "a proof from another key is the binding's refusal, and the token keeps working",
			start: startBound,
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Binding = oidcprovider.Binding{JKT: keyTwo}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidDPoPProof)
				assert.Nil(t, res)
				assert.Zero(t, f.lineage.writes.Load(), "the binding is checked before the lineage is read")
				again := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.Equal(t, "DPoP", again.TokenType)
				assert.Equal(t, keyOne, jktOf(t, again.AccessToken))
			},
		},
		{
			name:  "no proof for a bound grant is the binding's refusal",
			start: startBound,
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Binding = oidcprovider.Binding{}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidDPoPProof)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name:  "a stale secret under a bound grant's wrong key is not judged as reuse",
			start: startBound,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(31 * time.Second)
				s.request.Binding = oidcprovider.Binding{JKT: keyTwo}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidDPoPProof)
				assert.Nil(t, res)
				assert.False(t, grantNow(t, f, s).Revoked, "a stolen token without its key ends nothing")
			},
		},
		{
			name:    "a confidential client refreshes with no proof, as Bearer",
			arrange: func(_ *testing.T, _ *refreshFixture, _ *refreshScene) {},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "Bearer", res.TokenType)
				_, claims := decodeJWT(t, res.AccessToken)
				assert.NotContains(t, claims, "cnf")
			},
		},
		{
			name: "a confidential client's proof binds the access token and not the grant",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Binding = oidcprovider.Binding{JKT: keyTwo}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "DPoP", res.TokenType)
				assert.Equal(t, keyTwo, jktOf(t, res.AccessToken))
				assert.Empty(t, grantNow(t, f, s).KeyBinding)
			},
		},
		{
			name: "a binding that is no thumbprint fails before the token rotates",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Binding = oidcprovider.Binding{JKT: "not a thumbprint"}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a disabled user is refused, and the grant revoked",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
			},
			assert: refusedUserRevokes,
		},
		{
			name: "a missing user is refused, and the grant revoked",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.missing["u-1"] = true })
			},
			assert: refusedUserRevokes,
		},
		{
			name: "an answer naming another user is refused, and the grant revoked",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.impostor = true })
			},
			assert: refusedUserRevokes,
		},
		{
			name: "a forged secret for a disabled user revokes nothing",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
				s.request = s.again("rt." + s.grant.Family.String() + "." + neverIssued)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a user's load that fails is no verdict on the user",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.failing = true })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a failed revocation of a disabled user's grant is a dependency failure",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
				f.grants.failRevoke.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assert.Zero(t, f.liveHeads(t), "each write is tried whatever became of the other")
			},
		},
		{
			name:  "a narrowed scope is what the tokens carry, and the grant keeps its own",
			start: startBillingFor("openid", "profile", "email", "offline_access"),
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = asksScope(s, "openid profile")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "openid profile", res.Scope)
				_, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, "openid profile", claims["scope"])
				assert.Equal(t, s.grant.Scopes, grantNow(t, f, s).Scopes)

				wide := assertRefreshWorks(t, f, s, res.RefreshToken)
				assert.Equal(t, "openid profile email offline_access", wide.Scope, "an omitted scope is the grant's own")
			},
		},
		{
			name: "a scope outside the grant is invalid_scope, with the token not rotated",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = asksScope(s, "openid admin")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidScope)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a scope the client may ask for but the grant does not hold is invalid_scope",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = asksScope(s, "openid email")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidScope)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a scope past the request bound is invalid_request",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = asksScope(s, "openid"+strings.Repeat(" ", 4096))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidRequest)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "messy scope values read as a set",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = asksScope(s, "openid  openid profile")
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "openid profile", res.Scope)
			},
		},
		{
			name:  "a scope the client lost is left out and reported, and comes back when allowed again",
			start: startBillingFor("openid", "profile", "email", "offline_access"),
			arrange: func(t *testing.T, f *refreshFixture, _ *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.Scopes = []string{"openid", "profile", "offline_access"} })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "openid profile offline_access", res.Scope)
				_, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, "openid profile offline_access", claims["scope"])
				assert.Contains(t, grantNow(t, f, s).Scopes, "email", "the grant keeps it")

				billingClient(t, f, func(*oidcprovider.Client) {})
				back := assertRefreshWorks(t, f, s, res.RefreshToken)
				assert.Equal(t, "openid profile email offline_access", back.Scope)
			},
		},
		{
			name:  "a refresh naming only what the client lost is invalid_scope",
			start: startBillingFor("openid", "email", "offline_access"),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.Scopes = []string{"openid", "offline_access"} })
				s.request = asksScope(s, "email")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidScope)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a scope narrowed past openid gets no ID token",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request = asksScope(s, "profile")
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, res.IDToken)
				assert.Equal(t, "profile", res.Scope)
			},
		},
		{
			name:  "a resource named narrows to it, and a later refresh may ask for another",
			start: startResources(defaultAudience, "https://data.example.com"),
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Form.Set("resource", "https://data.example.com")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				_, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, []any{"https://data.example.com"}, claims["aud"])

				req := s.again(res.RefreshToken)
				req.Form.Set("resource", defaultAudience)
				next, err := f.p.Token(t.Context(), req)
				require.NoError(t, err, "the refresh token stays bound to the whole grant")
				_, claims = decodeJWT(t, next.AccessToken)
				assert.Equal(t, []any{defaultAudience}, claims["aud"])
			},
		},
		{
			name:  "no resource named when the grant holds several is invalid_target, not rotated",
			start: startResources(defaultAudience, "https://data.example.com"),
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidTarget)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name:  "a resource outside the grant is invalid_target, not rotated",
			start: startResources(defaultAudience),
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Form.Set("resource", "https://data.example.com")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidTarget)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name:  "no resource named when the grant holds one makes it the audience",
			start: startResources(defaultAudience),
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				_, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, []any{defaultAudience}, claims["aud"])
			},
		},
		{
			name: "rotation answers a new token, whose grant is live",
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "openid profile offline_access", res.Scope)
				assert.Equal(t, 300, res.ExpiresIn)
				assert.NotEmpty(t, res.IDToken)
				assert.NotEqual(t, s.first.RefreshToken, res.RefreshToken)
				next := s.head(t, f, res.RefreshToken)
				assert.True(t, next.SupersededAt.IsZero())
				assert.Equal(t, s.grant.Family, next.FamilyID)
				assert.False(t, s.head(t, f, s.first.RefreshToken).SupersededAt.IsZero(), "the presented token is superseded")
				assert.True(t, session.ValidIdentifier(s.secretOf(t, res.RefreshToken)))
				assert.False(t, session.ValidIdentifier(res.RefreshToken), "no sign-in path takes it")
				assert.False(t, grantNow(t, f, s).Revoked)
				at, verifyErr := f.p.VerifyAccessToken(t.Context(), res.AccessToken)
				require.NoError(t, verifyErr)
				assert.Equal(t, s.grant.Family, at.GrantFamily)
			},
		},
		{
			name: "the old token 10 seconds later gets tokens, with the grant live",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(10 * time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
				assertRefreshWorks(t, f, s, res.RefreshToken)
			},
		},
		{
			name: "a client's 2 minute grace accepts the old token at 90 seconds",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = 2 * time.Minute })
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(90 * time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, _ *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "the old token past the grace is reuse, which ends the whole grant",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				s.newest = second.RefreshToken
				f.clk.Advance(30 * time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				grant := grantNow(t, f, s)
				assert.True(t, grant.Revoked, "the observer marked the row")
				assert.Equal(t, oidcprovider.CauseReuse, grant.RevokeCause)
				assert.True(t, grant.RevokedAt.Equal(f.clk.Now()))
				assert.Zero(t, f.liveHeads(t), "the newest token went too: an unused successor is never recovered")
				assertRefreshRefused(t, f, s, s.newest)

				logs := f.logs.String()
				assert.Contains(t, logs, s.grant.Family.String(), "the reuse is logged with the family")
				assert.NotContains(t, logs, s.secretOf(t, s.newest), "and with no secret")
			},
		},
		{
			name: "a client whose refreshes are not rotated gets its own token back",
			arrange: func(t *testing.T, f *refreshFixture, _ *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.DisableRotation = true
					c.RequireBinding = oidcprovider.BindingMTLS
				})
				f.clk.Advance(day)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.first.RefreshToken, res.RefreshToken, "no new token: the same one comes back")
				assert.Zero(t, f.lineage.supersedes.Load())
				head := s.head(t, f, res.RefreshToken)
				assert.True(t, head.IdleExpiresAt.Equal(f.clk.Now().Add(30*day)), "a refresh still counts as use")

				f.clk.Advance(29 * day)
				assertRefreshWorks(t, f, s, res.RefreshToken)
			},
		},
		{
			name: "a token superseded before a client's rotation went off is still rotated",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.DisableRotation = true
					c.RequireBinding = oidcprovider.BindingMTLS
				})
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, s.first.RefreshToken, res.RefreshToken, "the old token never comes back as if it were the head")
				assert.Equal(t, 1, f.liveHeads(t))
			},
		},
		{
			name: "a grant idle for 31 days is refused, under the defaults",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.clk.Advance(31 * day)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.False(t, grantNow(t, f, s).Revoked, "an idle grant ended by its deadline, not by a revocation")
			},
		},
		{
			name: "a client's idle timeout decides, as it now stands",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = day })
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				s.request = s.again(second.RefreshToken)
				f.clk.Advance(day)
			},
			assert: refusedGrant,
		},
		{
			name: "a grant refreshed daily is refused at 90 days",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				raw := s.first.RefreshToken
				for range 89 {
					f.clk.Advance(day)
					raw = assertRefreshWorks(t, f, s, raw).RefreshToken
				}
				s.request = s.again(raw)
				f.clk.Advance(day)
			},
			assert: refusedGrant,
		},
		{
			name:  "a client's absolute lifetime of 7 days ends its grants at 7 days",
			start: startClient(weekClient, weekRedirect),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.clk.Advance(6 * day)
				s.request = s.again(assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken)
				f.clk.Advance(day)
			},
			assert: refusedGrant,
		},
		{
			name:  "a grant with no offline_access ends by its sign-in's deadline",
			start: startOnline,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				require.True(t, s.grant.ExpiresAt.Before(f.clk.Now().Add(30*day)))
				f.clk.Advance(s.grant.ExpiresAt.Sub(f.clk.Now()))
			},
			assert: refusedGrant,
		},
		{
			name: "a refreshed ID token keeps the authentication facts, with no nonce",
			start: func(t *testing.T, f *refreshFixture) *refreshScene {
				t.Helper()
				c := issueCodeFor(t, f.parkFixture, "billing-web", func(v url.Values) {
					v.Set("scope", "openid profile offline_access")
					v.Set("nonce", "n-1")
				}, testSignIn(f.parkFixture, "u-1"), "openid", "profile", "offline_access")

				return sceneOf(t, f, c, billingExchange(c, nil), byBilling)
			},
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) { f.clk.Advance(time.Hour) },
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				_, before := decodeJWT(t, s.first.IDToken)
				_, after := decodeJWT(t, res.IDToken)
				require.Equal(t, "n-1", before["nonce"])
				assert.NotContains(t, after, "nonce")
				for _, claim := range []string{"auth_time", "sub", "aud", "azp", "sid", "amr", "acr"} {
					assert.Equal(t, before[claim], after[claim], claim)
				}
				assert.Greater(t, after["iat"], before["iat"])

				_, access := decodeJWT(t, res.AccessToken)
				assert.Equal(t, before["auth_time"], access["auth_time"])
				assert.Equal(t, s.grant.Family.String(), access["gid"])
				assert.Equal(t, grantNow(t, f, s), s.grant, "the grant's facts did not move")
			},
		},
		{
			name:  "an opaque client's new token is stored, and read through its grant",
			start: startClient(opaqueClient, opaqueRedirect),
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(res.AccessToken, "at."))
				at, verifyErr := f.p.VerifyAccessToken(t.Context(), res.AccessToken)
				require.NoError(t, verifyErr)
				assert.Equal(t, s.grant.Family, at.GrantFamily)
				assert.Equal(t, []string{"openid", "offline_access"}, at.Scopes)
			},
		},
		{
			name: "a signing failure is a dependency failure, and the token is not rotated",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.keys.failSigning(func(context.Context) error { return errOutage })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.ErrorContains(t, err, "sign the access token", "the failure names the step, not the rotation it stopped")
				assert.Nil(t, res)
				assert.Zero(t, f.lineage.supersedes.Load(), "tokens are signed before the rotation")

				f.keys.failSigning(nil)
				f.clk.Advance(time.Hour)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked, "an outage is no theft alarm")
			},
		},
		{
			name: "a removed client is invalid_client, and its grant waits for its deadlines",
			arrange: func(t *testing.T, f *refreshFixture, _ *refreshScene) {
				t.Helper()
				require.NoError(t, f.registry.Delete(t.Context(), "billing-web"))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a client that fails to authenticate leaves the token as it was",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Credentials.Authorization = basic("billing-web", "wrong secret")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "no refresh token at all is invalid_request",
			arrange: func(_ *testing.T, _ *refreshFixture, s *refreshScene) {
				s.request.Form.Del("refresh_token")
			},
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidRequest)
				assert.Nil(t, res)
			},
		},
		{
			name: "a failing grant store is a dependency failure, and no refusal",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.grants.loads.Store(0)
				f.grants.failLoadAt.Store(1)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a caller who left a grant read matches its own context's error",
			ctx: func(ctx context.Context) context.Context {
				ended, cancel := context.WithCancel(ctx)
				cancel()

				return ended
			},
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.grants.strictContext.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a failing lineage store is a dependency failure, and no refusal",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.lineage.failLoad.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.lineage.failLoad.Store(false)
				assertUntouched(t, f, s)
			},
		},
		{
			name: "a rotation that cannot be written is a dependency failure, and the token still works",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.lineage.failSupersede.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
				f.lineage.failSupersede.Store(false)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "signing that outlasts the grace window fails without a verdict",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.keys.failSigning(func(context.Context) error {
					f.keys.failSigning(nil)
					f.clk.Advance(31 * time.Second)

					return nil
				})
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, res)
				assertUntouched(t, f, s)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},

		{
			name: "a superseded secret of another family, under this grant's, revokes neither",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				other := startBilling(t, f)
				newest := assertRefreshWorks(t, f, other, other.first.RefreshToken).RefreshToken
				f.clk.Advance(30 * time.Second)
				s.other, s.newest = other, newest
				s.request = s.again("rt." + s.grant.Family.String() + "." + other.secretOf(t, other.first.RefreshToken))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.False(t, grantNow(t, f, s.other).Revoked, "a family is judged only by a token that names it")
				assert.False(t, grantNow(t, f, s).Revoked)
				assertRefreshWorks(t, f, s.other, s.newest)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a live secret of another family, under this grant's, writes nothing",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				other := startBilling(t, f)
				s.other = other
				s.request = s.again("rt." + s.grant.Family.String() + "." + other.secretOf(t, other.first.RefreshToken))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load())
				assert.True(t, s.other.head(t, f, s.other.first.RefreshToken).FirstPresentedAt.IsZero())
			},
		},
		{
			name: "a store that answers with neither record nor error is a missing lineage",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.lineage.answerNothing.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.writes.Load())
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "reuse whose family cannot be deleted still marks the row, and is a dependency failure",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(30 * time.Second)
				f.lineage.failDelete.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				grant := grantNow(t, f, s)
				assert.True(t, grant.Revoked, "the observer was not told, and the row ends the grant regardless")
				assert.Equal(t, oidcprovider.CauseReuse, grant.RevokeCause)
				assertRefreshRefused(t, f, s, s.newest)
			},
		},
		{
			name: "reuse whose row cannot be marked is logged, and reads as revoked from then on",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(30 * time.Second)
				f.grants.failRevoke.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Contains(t, f.logs.String(), "level=ERROR")
				assert.NotContains(t, f.logs.String(), errOutage.Error())
				assertRefreshRefused(t, f, s, s.newest)
				assert.False(t, grantNow(t, f, s).Revoked, "the missing lineage reads as revoked, and writes nothing")
			},
		},
		func() testCase {
			var cancel context.CancelFunc

			return testCase{
				name: "reuse by a caller who hangs up still ends the grant",
				ctx: func(ctx context.Context) context.Context {
					ended, stop := context.WithCancel(ctx) //nolint:gosec // the row calls it during the request
					cancel = stop

					return ended
				},
				arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
					t.Helper()
					s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
					f.clk.Advance(30 * time.Second)
					// The second read is the manager's, whose verdict the hang-up follows: the
					// first only checks the record names this grant.
					reads := 0
					f.lineage.onLoad = func() {
						if reads++; reads == 2 {
							cancel()
						}
					}
				},
				assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
					t.Helper()
					f.lineage.onLoad = nil
					refusedGrant(t, f, s, res, err)
					assert.True(t, grantNow(t, f, s).Revoked, "a hang-up must not spare what it was evidence against")
					assert.Zero(t, f.liveHeads(t))
				},
			}
		}(),
		func() testCase {
			var cancel context.CancelFunc

			return testCase{
				name: "reuse by a caller who hangs up still marks the row when the family cannot be deleted",
				ctx: func(ctx context.Context) context.Context {
					ended, stop := context.WithCancel(ctx) //nolint:gosec // the row calls it during the request
					cancel = stop

					return ended
				},
				arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
					t.Helper()
					assertRefreshWorks(t, f, s, s.first.RefreshToken)
					f.clk.Advance(30 * time.Second)
					f.lineage.failDelete.Store(true)
					reads := 0
					f.lineage.onLoad = func() {
						if reads++; reads == 2 {
							cancel()
						}
					}
				},
				assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
					t.Helper()
					f.lineage.onLoad = nil
					require.Error(t, err)
					assert.Nil(t, res)
					assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				},
			}
		}(),
		func() testCase {
			var cancel context.CancelFunc

			return testCase{
				name: "a gone user's revocation holds when the caller hangs up",
				ctx: func(ctx context.Context) context.Context {
					ended, stop := context.WithCancel(ctx) //nolint:gosec // the row calls it during the request
					cancel = stop

					return ended
				},
				arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
					f.users.set(func(u *exchangeUsers) {
						u.disabled["u-1"] = true
						u.onLoad = func() { cancel() }
					})
				},
				assert: refusedUserRevokes,
			}
		}(),
		{
			name:  "an opaque token that cannot be stored fails the refresh, and the old token retries",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.access.failCreate.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.access.failCreate.Store(false)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a grant that cannot be read again after the rotation answers no tokens",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.grants.loads.Store(0)
				f.grants.failLoadAt.Store(2)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.grants.failLoadAt.Store(0)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a refresh token issued before a revocation is refused after it",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				newest := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				require.NoError(t, f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now()))
				s.request = s.again(newest)
			},
			assert: refusedGrant,
		},
		{
			name: "a grant gone by the second read answers no tokens",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.grants.loads.Store(0)
				f.grants.missingAt.Store(2)
			},
			assert: refusedGrant,
		},
		{
			name: "a stale token asking a scope outside the grant is still reuse",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(30 * time.Second)
				s.request = asksScope(s, "openid admin")
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
			},
		},
		{
			name: "a gone user asking a scope outside the grant still revokes it",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
				s.request = asksScope(s, "openid admin")
			},
			assert: refusedUserRevokes,
		},
		{
			name: "a family past its client's shortened lifetime cannot rotate",
			arrange: func(t *testing.T, f *refreshFixture, _ *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.GrantIdleTimeout = day
					c.GrantAbsoluteLifetime = day
				})
				f.grants.rewrite = nil
				f.clk.Advance(day)
				f.lineage.keepAlive(t, f.clk.Now().Add(day))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "two_tabs_within_grace",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.beforeSupersede = meeting(t, 2)
				s.racers = []<-chan exchanged{exchangeAsync(t.Context(), f.exchangeFixture, s.request)}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				other := <-s.racers[0]
				require.NoError(t, other.err, "the tab that lost the race gets tokens too")
				assert.NotEqual(t, res.RefreshToken, other.res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t), "exactly one successor is left live")
				for _, answer := range []*oidcprovider.TokenResponse{res, other.res} {
					_, verifyErr := f.p.VerifyAccessToken(t.Context(), answer.AccessToken)
					require.NoError(t, verifyErr)
				}

				live, _ := s.sortByLife(t, f, res.RefreshToken, other.res.RefreshToken)
				assertRefreshWorks(t, f, s, live)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "two_tabs_the_token_knocked_out_is_reuse",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.beforeSupersede = meeting(t, 2)
				s.racers = []<-chan exchanged{exchangeAsync(t.Context(), f.exchangeFixture, s.request)}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				other := <-s.racers[0]
				require.NoError(t, other.err)

				live, out := s.sortByLife(t, f, res.RefreshToken, other.res.RefreshToken)
				assertRefreshRefused(t, f, s, out)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause,
					"presenting the token a re-rotation knocked out says two parties hold the family")
				assertRefreshRefused(t, f, s, live)
			},
		},
		{
			name: "every racer gets tokens, and one head is left",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.beforeSupersede = meeting(t, racersWithinBound)
				for range racersWithinBound - 1 {
					s.racers = append(s.racers, exchangeAsync(t.Context(), f.exchangeFixture, s.request))
				}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				seen := map[string]bool{res.RefreshToken: true}
				for _, racer := range s.racers {
					answer := <-racer
					require.NoError(t, answer.err)
					seen[answer.res.RefreshToken] = true
				}
				assert.Len(t, seen, racersWithinBound, "each rotation has its own successor")
				assert.Equal(t, 1, f.liveHeads(t), "exactly one is left live")
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a rotation that keeps losing fails without a verdict, having signed once",
			arrange: func(_ *testing.T, f *refreshFixture, s *refreshScene) {
				f.lineage.conflict.Store(true)
				f.keys.failSigning(func(context.Context) error {
					s.signed.Add(1)

					return nil
				})
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assert.Equal(t, int32(racersWithinBound), f.lineage.supersedes.Load(), "the attempts are bounded")
				assert.Equal(t, int32(2), s.signed.Load(), "an access and an ID token, however many attempts")
				assert.False(t, grantNow(t, f, s).Revoked)
				f.lineage.conflict.Store(false)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a reuse landing before the rotation's write leaves no successor",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				newest := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(30 * time.Second)
				stale := s.again(s.first.RefreshToken)
				f.lineage.beforeSupersede = once(func() {
					_, err := f.p.Token(t.Context(), stale)
					assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				})
				s.request = s.again(newest)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "a reuse landing after the rotation's write takes its successor with the grant",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				newest := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(30 * time.Second)
				stale := s.again(s.first.RefreshToken)
				f.lineage.afterSupersede = once(func() {
					_, err := f.p.Token(t.Context(), stale)
					assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				})
				s.request = s.again(newest)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t), "the racing refresh's successor went with its family")
			},
		},
		{
			name: "a revocation landing before the rotation's write leaves no successor",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.beforeSupersede = once(func() { revokeWhole(t, f, s) })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "a revocation landing after the rotation's write answers no tokens",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.afterSupersede = once(func() { revokeWhole(t, f, s) })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name:  "a revocation landing after the rotation's write stores no opaque token",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.access.creates.Store(0)
				f.lineage.afterSupersede = once(func() { revokeWhole(t, f, s) })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.access.creates.Load(), "an opaque token is stored last")
			},
		},
		{
			name:  "a sign-in's end landing before the rotation's write answers no tokens, and leaves nothing usable",
			start: startOnline,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.beforeSupersede = once(func() {
					_, err := f.grants.EndSignIns(t.Context(),
						oidcprovider.SignInSelector{Family: s.grant.SignInFamily}, f.clk.Now())
					require.NoError(t, err)
				})
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				grant := grantNow(t, f, s)
				assert.True(t, grant.Revoked)
				assert.Equal(t, oidcprovider.CauseSignInEnded, grant.RevokeCause)
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name:  "a sign-in's end after the tokens were answered refuses them",
			start: startOnline,
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				newest := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				_, err := f.grants.EndSignIns(t.Context(),
					oidcprovider.SignInSelector{Family: s.grant.SignInFamily}, f.clk.Now())
				require.NoError(t, err)
				s.request = s.again(newest)
			},
			assert: refusedGrant,
		},
		{
			name: "racers against a revocation leave nothing usable, in any order",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				for range racersWithinBound - 1 {
					s.racers = append(s.racers, exchangeAsync(t.Context(), f.exchangeFixture, s.request))
				}
				s.background = goDone(func() { revokeWhole(t, f, s) })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				answers := []exchanged{{res: res, err: err}}
				for _, racer := range s.racers {
					answers = append(answers, <-racer)
				}
				<-s.background
				for _, answer := range answers {
					if answer.err != nil {
						assertRefused(t, answer.err, oidcprovider.CodeInvalidGrant)

						continue
					}
					assertRefreshRefused(t, f, s, answer.res.RefreshToken)
				}
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "racers against a reuse leave nothing usable, in any order",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				newest := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(30 * time.Second)
				stale := s.again(s.first.RefreshToken)
				s.request = s.again(newest)
				for range racersWithinBound - 1 {
					s.racers = append(s.racers, exchangeAsync(t.Context(), f.exchangeFixture, s.request))
				}
				s.racers = append(s.racers, exchangeAsync(t.Context(), f.exchangeFixture, stale))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				answers := []exchanged{{res: res, err: err}}
				for _, racer := range s.racers {
					answers = append(answers, <-racer)
				}
				for _, answer := range answers {
					if answer.err != nil {
						assertRefused(t, answer.err, oidcprovider.CodeInvalidGrant)

						continue
					}
					assertRefreshRefused(t, f, s, answer.res.RefreshToken)
				}
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t, tc.opts...)
			start := tc.start
			if start == nil {
				start = startBilling
			}
			scene := start(t, f)
			if tc.arrange != nil {
				tc.arrange(t, f, scene)
			}
			// A row judges only the writes of the request it is about.
			f.lineage.writes.Store(0)
			f.lineage.supersedes.Store(0)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			res, err := f.p.Token(ctx, scene.request)
			tc.assert(t, f, scene, res, err)
		})
	}
}

// racersWithinBound is how many racers a refresh's bounded attempts are sure to serve: each round
// of racers has one winner, so the last racer wins at the last attempt at worst.
const racersWithinBound = 8

// meeting holds the first n callers until all have arrived, so all of them have read the record
// before any writes, and lets every later caller straight through. The timeout is only there to
// fail a broken test rather than hang it, and orders nothing.
func meeting(t *testing.T, n int32) func() {
	t.Helper()

	var arrived atomic.Int32
	met := make(chan struct{})

	return func() {
		if arrived.Add(1) == n {
			close(met)
		}
		select {
		case <-met:
		case <-time.After(30 * time.Second):
			t.Error("the racers never met")
		}
	}
}

// once runs step at the first call alone. A step that calls back in, as a racing request reaching
// the same hook does, passes straight through.
func once(step func()) func() {
	var done atomic.Bool

	return func() {
		if done.CompareAndSwap(false, true) {
			step()
		}
	}
}

// goDone runs step on its own goroutine, and closes the channel when it has returned.
func goDone(step func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		step()
	}()

	return done
}

// revokeWhole ends a grant as a revocation does: its row, then its lineage.
func revokeWhole(t *testing.T, f *refreshFixture, s *refreshScene) {
	t.Helper()

	require.NoError(t, f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now()))
	_, err := f.lineage.Store.DeleteFamily(t.Context(), s.grant.Family)
	require.NoError(t, err)
}

// sortByLife tells the one of two racers' tokens that is the family's head from the one a
// re-rotation knocked out.
func (s *refreshScene) sortByLife(t *testing.T, f *refreshFixture, a, b string) (live, out string) {
	t.Helper()

	if s.head(t, f, a).SupersededAt.IsZero() {
		return a, b
	}

	return b, a
}

// TestProvider_Refresh_MalformedTokens pins that a value of no shape the provider mints is refused
// with no lookup: the mocks expect no call to either store. It has its own table, because its
// fixture holds nothing a grant could be read from.
func TestProvider_Refresh_MalformedTokens(t *testing.T) {
	t.Parallel()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	spelled := family.String()

	type testCase struct {
		name, raw string
		assert    func(*testing.T, *oidcprovider.TokenResponse, error)
	}
	refused := func(t *testing.T, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		assertRefused(t, err, oidcprovider.CodeInvalidGrant)
		assert.Nil(t, res)
	}

	cases := []testCase{
		{name: "no shape", raw: "rt.bad", assert: refused},
		{name: "the prefix alone", raw: "rt.", assert: refused},
		{name: "another credential's prefix", raw: "at." + spelled + "." + neverIssued, assert: refused},
		{name: "no prefix", raw: spelled + "." + neverIssued, assert: refused},
		{name: "a bare session identifier", raw: neverIssued, assert: refused},
		{name: "no secret", raw: "rt." + spelled, assert: refused},
		{name: "an empty secret", raw: "rt." + spelled + ".", assert: refused},
		{name: "a short secret", raw: "rt." + spelled + ".short", assert: refused},
		{name: "a dotted secret", raw: "rt." + spelled + "." + neverIssued + ".x", assert: refused},
		{name: "a family that is no identifier", raw: "rt.nonsense." + neverIssued, assert: refused},
		{name: "the nil family", raw: "rt." + id.Nil.String() + "." + neverIssued, assert: refused},
		{name: "another spelling of the family", raw: "rt." + strings.ToUpper(spelled) + "." + neverIssued, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			grants := NewMockGrantStore(ctrl)
			grants.EXPECT().UseCodes(gomock.Any()).Return(nil).AnyTimes()
			x := newExchangeFixture(t,
				oidcprovider.WithGrantStore(grants),
				oidcprovider.WithRefreshTokenStore(oplineage.New(NewMockLineageSessionStore(ctrl))),
			)

			res, err := x.p.Token(t.Context(), refreshRequest("billing-web", tc.raw, nil))
			tc.assert(t, res, err)
		})
	}
}

// jktOf is the key an access token's confirmation names.
func jktOf(t *testing.T, raw string) string {
	t.Helper()

	_, claims := decodeJWT(t, raw)
	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok, "the token has a confirmation")
	jkt, ok := cnf["jkt"].(string)
	require.True(t, ok, "the confirmation names a key")

	return jkt
}
