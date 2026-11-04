package oidcprovider_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
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

// successorKeyA and successorKeyB are two deployments' successor keys.
var (
	successorKeyA = []byte("successor key A, of 32 bytes, ok")
	successorKeyB = []byte("successor key B, of 32 bytes, ok")
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

	// rewrite changes each record a read found, as a store of its own might hold it, and is set
	// before the request starts.
	rewrite func(*session.Session)

	// sawDelete is told the context of each family's deletion, and afterDelete runs once one has
	// landed. Both are set before the request starts.
	sawDelete   func(context.Context)
	afterDelete func()

	failLoad, failCreate, failSupersede, failDelete atomic.Bool
	// failLoadOf fails a read of the secrets it says, and is set before the request starts.
	failLoadOf func(secret string) bool
	// nothingOf makes a read of the secrets it says answer with neither a record nor an error, and
	// is set before the request starts.
	nothingOf func(secret string) bool
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
	if h.failLoadOf != nil && h.failLoadOf(secret) {
		return nil, errOutage
	}
	if h.answerNothing.Load() || h.nothingOf != nil && h.nothingOf(secret) {
		return nil, nil //nolint:nilnil // the case a manager reads as no session
	}

	record, err := h.Store.Load(ctx, secret)
	if err == nil && record != nil && h.rewrite != nil {
		h.rewrite(record)
	}
	if err == nil && h.onLoad != nil {
		h.onLoad()
	}

	return record, err
}

// Create implements session.Store.
func (h *hookedLineage) Create(ctx context.Context, s *session.Session) error {
	if h.failCreate.Load() {
		return errOutage
	}

	return h.Store.Create(ctx, s)
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
	if h.sawDelete != nil {
		h.sawDelete(ctx)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if h.failDelete.Load() {
		return 0, errOutage
	}

	n, err := h.Store.DeleteFamily(ctx, family)
	if err == nil && h.afterDelete != nil {
		h.afterDelete()
	}

	return n, err
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
	// beforeRevoke runs at each revocation, and is set before the request starts.
	beforeRevoke func()
	// strictContext makes a load refuse an ended context too.
	strictContext atomic.Bool
	// revokes counts the revocations that reached the store.
	revokes atomic.Int32
	// failBulk fails every write selecting grants by sign-in or by user.
	failBulk atomic.Bool
	// sawBulk is told the context of each such write, and is set before the request starts.
	sawBulk func(context.Context)
	// reorderEnded arranges the grants an end of sign-ins answers, and is set before the request starts.
	reorderEnded func([]oidcprovider.Grant)
	// mu guards selectors.
	mu sync.Mutex
	// selectors holds what each end of sign-ins selected, in order.
	selectors []oidcprovider.SignInSelector
}

// bulk runs what every write selecting grants in bulk shares.
func (h *hookedGrants) bulk(ctx context.Context) error {
	if h.sawBulk != nil {
		h.sawBulk(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.failBulk.Load() {
		return errOutage
	}

	return nil
}

// EndSignIns implements oidcprovider.GrantStore.
func (h *hookedGrants) EndSignIns(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
	h.mu.Lock()
	h.selectors = append(h.selectors, sel)
	h.mu.Unlock()
	if err := h.bulk(ctx); err != nil {
		return nil, err
	}

	ended, err := h.GrantStore.EndSignIns(ctx, sel, at)
	if h.reorderEnded != nil {
		h.reorderEnded(ended)
	}

	return ended, err
}

// RevokeByUser implements oidcprovider.GrantStore.
func (h *hookedGrants) RevokeByUser(
	ctx context.Context, user identity.UserID, cause oidcprovider.RevocationCause, at time.Time,
) ([]oidcprovider.Grant, error) {
	if err := h.bulk(ctx); err != nil {
		return nil, err
	}

	return h.GrantStore.RevokeByUser(ctx, user, cause, at)
}

// RevokeByUserAndClient implements oidcprovider.GrantStore.
func (h *hookedGrants) RevokeByUserAndClient(
	ctx context.Context, user identity.UserID, clientID string, cause oidcprovider.RevocationCause, at time.Time,
) ([]oidcprovider.Grant, error) {
	if err := h.bulk(ctx); err != nil {
		return nil, err
	}

	return h.GrantStore.RevokeByUserAndClient(ctx, user, clientID, cause, at)
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
func (h *hookedGrants) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) (bool, error) {
	h.revokes.Add(1)
	if h.beforeRevoke != nil {
		h.beforeRevoke()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if h.failRevoke.Load() {
		return false, errOutage
	}

	return h.GrantStore.Revoke(ctx, family, cause, at)
}

// hookedAccessTokens is a real access token store that fails its writes at a row's request.
type hookedAccessTokens struct {
	oidcprovider.AccessTokenStore

	failCreate, failRevoke, failLoad atomic.Bool
	// goneAtRevoke answers a revocation as a token swept since its read.
	goneAtRevoke atomic.Bool
	// beforeRevoke runs at each revocation, and is set before the request starts.
	beforeRevoke func()
	// creates counts what reached the store.
	creates atomic.Int32
	// created is the record last stored.
	created atomic.Pointer[oidcprovider.AccessTokenRecord]
}

// Create implements oidcprovider.AccessTokenStore.
func (h *hookedAccessTokens) Create(ctx context.Context, record *oidcprovider.AccessTokenRecord) error {
	h.creates.Add(1)
	if h.failCreate.Load() {
		return errOutage
	}

	if err := h.AccessTokenStore.Create(ctx, record); err != nil {
		return err
	}
	h.created.Store(record)

	return nil
}

// Load implements oidcprovider.AccessTokenStore.
func (h *hookedAccessTokens) Load(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
	if h.failLoad.Load() {
		return nil, errOutage
	}

	return h.AccessTokenStore.Load(ctx, tokenID)
}

// Revoke implements oidcprovider.AccessTokenStore.
func (h *hookedAccessTokens) Revoke(ctx context.Context, tokenID id.ID) error {
	if h.beforeRevoke != nil {
		h.beforeRevoke()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.failRevoke.Load() {
		return errOutage
	}
	if h.goneAtRevoke.Load() {
		return oidcprovider.ErrNotFound
	}

	return h.AccessTokenStore.Revoke(ctx, tokenID)
}

// assertLastEnded checks the opaque token last stored was stored once, and cannot be used.
func (h *hookedAccessTokens) assertLastEnded(t *testing.T) {
	t.Helper()

	assert.Equal(t, int32(1), h.creates.Load(), "stored once, however many attempts")
	created := h.created.Load()
	require.NotNil(t, created)
	held, err := h.Load(t.Context(), created.ID)
	require.NoError(t, err)
	assert.True(t, held.Revoked, "a token stored for a rotation that lost must not stay usable")
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

// replicaGrants lets a replica share a grant store without sharing a code store, which a real
// replica would and which no refresh reads.
type replicaGrants struct {
	oidcprovider.GrantStore
}

// UseCodes implements oidcprovider.GrantStore.
func (replicaGrants) UseCodes(oidcprovider.UnspentCodes) error { return nil }

// replica is another provider over the fixture's stores, registry and keys, as a second instance of
// one deployment is.
func (f *refreshFixture) replica(t *testing.T, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	return f.replicaLoading(t, func(_ context.Context, user identity.UserID) (*identity.Details, error) { return f.users.load(user) }, opts...)
}

// replicaLoading is replica, reading its users through load.
func (f *refreshFixture) replicaLoading(
	t *testing.T, load func(context.Context, identity.UserID) (*identity.Details, error), opts ...oidcprovider.Option,
) *oidcprovider.Provider {
	t.Helper()

	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(load).AnyTimes()
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     f.registry,
		Keys:         f.keys,
		Users:        loader,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, append([]oidcprovider.Option{
		oidcprovider.WithClock(f.clk),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))),
		oidcprovider.WithGrantStore(replicaGrants{GrantStore: f.grants}),
		oidcprovider.WithRefreshTokenStore(oplineage.New(f.lineage)),
		oidcprovider.WithAccessTokenStore(f.access),
	}, opts...)...)
	require.NoError(t, err)

	return p
}

// heldAtUserLoad starts req on a replica, and returns once the request is waiting in its user load:
// the moment between the manager's read of the token and the rotation's own. It stays there until
// release is called. The timeouts are only there to fail a broken test rather than hang it, and
// order nothing.
func (f *refreshFixture) heldAtUserLoad(t *testing.T, req oidcprovider.TokenRequest, opts ...oidcprovider.Option) (<-chan exchanged, func()) {
	t.Helper()

	entered, released := make(chan struct{}), make(chan struct{})
	var held atomic.Bool
	tab := f.replicaLoading(t, func(_ context.Context, user identity.UserID) (*identity.Details, error) {
		if held.CompareAndSwap(false, true) {
			close(entered)
			select {
			case <-released:
			case <-time.After(30 * time.Second):
				t.Error("the held request was never released")
			}
		}

		return f.users.load(user)
	}, opts...)

	answer := make(chan exchanged, 1)
	go func() {
		res, err := tab.Token(t.Context(), req)
		answer <- exchanged{res: res, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the held request never reached its user load")
	}
	var release sync.Once
	stop := func() { release.Do(func() { close(released) }) }
	t.Cleanup(stop)

	return answer, stop
}

// chainOf rotates the scene's token n times at this instant, and returns the last token answered.
func chainOf(t *testing.T, f *refreshFixture, s *refreshScene, n int) string {
	t.Helper()

	held := s.first.RefreshToken
	for range n {
		held = assertRefreshWorks(t, f, s, held).RefreshToken
	}

	return held
}

// advanceOnReplica rotates the scene's token twice on a replica holding another key, so the fixture's
// own provider finds no match for it inside its grace, and a successor that has moved on. It returns
// the newest access token.
func advanceOnReplica(t *testing.T, f *refreshFixture, s *refreshScene) string {
	t.Helper()

	other := f.replica(t, oidcprovider.WithRefreshSuccessorKey(successorKeyB))
	second, err := other.Token(t.Context(), s.request)
	require.NoError(t, err)
	third, err := other.Token(t.Context(), s.again(second.RefreshToken))
	require.NoError(t, err)

	return third.AccessToken
}

// successorUnder is the secret HMAC-SHA256(key, family, secret) gives a token's successor.
func successorUnder(key []byte, family id.ID, secret string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(family.String()))
	mac.Write([]byte{0})
	mac.Write([]byte(secret))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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
	// newest is the token a row's arrange last received, and newestAccess the access token with it.
	newest, newestAccess string
	// racers answers what a row's arrange set racing the request, and background closes when
	// what else it set running has finished.
	racers     []<-chan exchanged
	background <-chan struct{}
	// release lets go of a request a row's arrange is holding at its user load.
	release func()
	// other is a second grant of the same client.
	other *refreshScene
	// signed counts the signatures made.
	signed atomic.Int32
	// deleteBudgeted and deleteBounded say a family's deletion was seen, and had a deadline.
	deleteBudgeted, deleteBounded atomic.Bool
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

// presentCertificate has the scene's requests present a certificate from here on, as a client
// required to use one must for its refreshes to be judged at all.
func presentCertificate(s *refreshScene) {
	s.request.Binding.X5T = boundCert

	again := s.again
	s.again = func(raw string) oidcprovider.TokenRequest {
		req := again(raw)
		req.Binding.X5T = boundCert

		return req
	}
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
				require.NoError(t, revokeErr(f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now())))
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
			name: "a loader answering with neither details nor an error is no live user, and the grant is revoked",
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.users.set(func(u *exchangeUsers) { u.answersNothing = true })
			},
			assert: refusedUserRevokes,
		},
		{
			name: "a disabled user's token past its grace is reuse: the lineage is judged before the user",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(30 * time.Second)
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause, "a stated cause: the theft, not the user")
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "a disabled user's token inside its grace is the user's refusal",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(29 * time.Second)
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
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
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assert.NotZero(t, f.liveHeads(t), "the row is marked first, so a failed mark leaves the family to retry through")
				assert.False(t, grantNow(t, f, s).Revoked)

				f.grants.failRevoke.Store(false)
				_, err = f.p.Token(t.Context(), s.request)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grantNow(t, f, s).Revoked, "presenting it again marks the row")
				assert.Equal(t, oidcprovider.CauseUserDisabled, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
				_, verr := f.p.VerifyAccessToken(t.Context(), s.first.AccessToken)
				assertRefused(t, verr, oidcprovider.CodeInvalidToken)
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
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				presentCertificate(s)
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
				presentCertificate(s)
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
			name: "an idle timeout shortened since reaches a grant issued before it",
			arrange: func(t *testing.T, f *refreshFixture, _ *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = day })
				f.clk.Advance(day)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.supersedes.Load(), "nothing rotated")
				assert.False(t, grantNow(t, f, s).Revoked, "ended by its deadline, not by a revocation")
			},
		},
		{
			name: "an idle timeout shortened since reaches a client whose refreshes are not rotated",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				presentCertificate(s)
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.DisableRotation = true
					c.RequireBinding = oidcprovider.BindingMTLS
					c.GrantIdleTimeout = day
				})
				f.clk.Advance(day)
			},
			assert: refusedGrant,
		},
		{
			name: "an absolute lifetime shortened since reaches a client whose refreshes are not rotated",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				presentCertificate(s)
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.DisableRotation = true
					c.RequireBinding = oidcprovider.BindingMTLS
					c.GrantIdleTimeout = day
					c.GrantAbsoluteLifetime = day
				})
				f.clk.Advance(23 * time.Hour)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(time.Hour)
			},
			assert: refusedGrant,
		},
		{
			name: "a lifetime shortened below a disabled user's grant ends it before the user is judged",
			arrange: func(t *testing.T, f *refreshFixture, _ *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = day })
				f.clk.Advance(day)
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a superseded token inside its grace is not judged idle: the rotation that superseded it was the activity",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.clk.Advance(2 * day)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = day })
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, res.AccessToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
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
			name:  "reuse whose row cannot be marked is a dependency failure with the lineage intact, and presenting it again ends the grant",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				s.newest, s.newestAccess = second.RefreshToken, second.AccessToken
				f.clk.Advance(30 * time.Second)
				f.grants.failRevoke.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t), "nothing is deleted that a later presentation could not mark again")

				f.grants.failRevoke.Store(false)
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
				_, verifyErr := f.p.VerifyAccessToken(t.Context(), s.newestAccess)
				assert.Error(t, verifyErr, "the grant's opaque tokens ended with it")
			},
		},
		func() testCase {
			deleted, refreshDone := make(chan struct{}), make(chan struct{})
			var gone atomic.Bool
			var reuse <-chan exchanged

			return testCase{
				name: "a refresh racing a reuse answers no tokens for a family already deleted",
				arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
					t.Helper()
					newest := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
					f.clk.Advance(30 * time.Second)
					f.lineage.afterDelete = func() {
						if gone.CompareAndSwap(false, true) {
							close(deleted)
						}
					}
					// What follows the deletion waits for the refresh, which reads the row again
					// with the family gone.
					f.grants.beforeRevoke = func() {
						if gone.Load() {
							<-refreshDone
						}
					}
					stale := s.again(s.first.RefreshToken)
					f.lineage.afterSupersede = once(func() {
						reuse = exchangeAsync(context.WithoutCancel(t.Context()), f.exchangeFixture, stale)
						<-deleted
					})
					s.request = s.again(newest)
				},
				assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
					t.Helper()
					close(refreshDone)
					got := <-reuse
					assertRefused(t, got.err, oidcprovider.CodeInvalidGrant)
					refusedGrant(t, f, s, res, err)
					assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				},
			}
		}(),
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
				assert.ErrorContains(t, err, "store the access token", "the failure names the step, not the rotation it stopped")
				assert.Nil(t, res)
				assert.Zero(t, f.lineage.supersedes.Load(), "the token is stored before the rotation's write")
				f.access.failCreate.Store(false)
				f.clk.Advance(31 * time.Second)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked, "an outage is no theft alarm, at a retry past the grace")
			},
		},
		{
			name:  "a rotation that lost every attempt leaves no opaque token usable",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.access.creates.Store(0)
				f.lineage.conflict.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.access.assertLastEnded(t)
			},
		},
		{
			name:  "a rotation that could not be written leaves no opaque token usable",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.access.creates.Store(0)
				f.lineage.failSupersede.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.access.assertLastEnded(t)
			},
		},
		{
			name:  "a second read that fails leaves no opaque token usable",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
				f.access.creates.Store(0)
				f.grants.loads.Store(0)
				f.grants.failLoadAt.Store(2)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.access.assertLastEnded(t)
			},
		},
		func() testCase {
			var cancel context.CancelFunc

			return testCase{
				name:  "a discarded opaque token is ended when the caller hangs up, and a failure to end it is logged",
				start: startClient(opaqueClient, opaqueRedirect),
				ctx: func(ctx context.Context) context.Context {
					ended, stop := context.WithCancel(ctx) //nolint:gosec // the row calls it during the request
					cancel = stop

					return ended
				},
				arrange: func(_ *testing.T, f *refreshFixture, _ *refreshScene) {
					f.access.creates.Store(0)
					f.lineage.beforeSupersede = func() { cancel() }
					f.lineage.failSupersede.Store(true)
				},
				assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
					t.Helper()
					require.Error(t, err)
					assert.Nil(t, res)
					f.access.assertLastEnded(t)

					// The token's write stays, unreachable: nobody was given its value, and it
					// expires with its exp. The failure is the operator's to see.
					f.access.failRevoke.Store(true)
					f.access.creates.Store(0)
					f.lineage.beforeSupersede = nil
					_, err = f.p.Token(t.Context(), s.request)
					assertDependencyFailure(t, err)
					assert.Contains(t, f.logs.String(), "level=ERROR")
					assert.NotContains(t, f.logs.String(), errOutage.Error())
				},
			}
		}(),
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
				require.NoError(t, revokeErr(f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now())))
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
			name: "a reuse's deletion of its family has a budget, once it has stopped listening to its caller",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(30 * time.Second)
				f.lineage.sawDelete = func(ctx context.Context) {
					s.deleteBudgeted.Store(true)
					_, bounded := ctx.Deadline()
					s.deleteBounded.Store(bounded)
				}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				require.True(t, s.deleteBudgeted.Load(), "the family was deleted")
				assert.True(t, s.deleteBounded.Load(), "a deletion the caller cannot end needs its own deadline")
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
				assert.False(t, grantNow(t, f, s).Revoked)
				for _, answer := range []*oidcprovider.TokenResponse{res, other.res} {
					_, verifyErr := f.p.VerifyAccessToken(t.Context(), answer.AccessToken)
					require.NoError(t, verifyErr)
				}
			},
		},
		{
			name: "two_tabs_same_successor_raced",
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
				assert.Equal(t, res.RefreshToken, other.res.RefreshToken, "both tabs hold the one successor")
				assert.Equal(t, 1, f.liveHeads(t))
				assert.True(t, s.head(t, f, res.RefreshToken).SupersededAt.IsZero())

				f.clk.Advance(5 * time.Minute)
				assertRefreshWorks(t, f, s, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked, "whichever tab's write lands last holds a live token")
			},
		},
		{
			name: "two_tabs_same_successor_one_second_apart",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.newest, res.RefreshToken, "the same successor")
				assert.Zero(t, f.lineage.writes.Load(), "answered with no write")
				assert.Equal(t, 1, f.liveHeads(t))
				assert.NotEqual(t, s.first.AccessToken, res.AccessToken, "the access token is its own")

				f.clk.Advance(5 * time.Minute)
				assertRefreshWorks(t, f, s, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name:  "a re-presentation's opaque token is stored and usable, with no lineage write",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.newest, res.RefreshToken)
				assert.Zero(t, f.lineage.writes.Load())
				_, verifyErr := f.p.VerifyAccessToken(t.Context(), res.AccessToken)
				require.NoError(t, verifyErr)
			},
		},
		{
			name: "walks_to_the_head",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(time.Second)
				s.newest = assertRefreshWorks(t, f, s, second).RefreshToken
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.newest, res.RefreshToken, "a tab storing this answer last holds a live token")
				assert.Zero(t, f.lineage.writes.Load())
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))

				f.clk.Advance(5 * time.Minute)
				assertRefreshWorks(t, f, s, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a walk of as many links as its bound reaches the head",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = chainOf(t, f, s, successorWalkBound)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.newest, res.RefreshToken)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "a walk past its bound stops, and the token presented is what any moved-on successor makes it: reuse",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				chainOf(t, f, s, successorWalkBound+1)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "a walk stops at a link another key wrote, and the moved-on successor is reuse",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				_, err := f.replica(t, oidcprovider.WithRefreshSuccessorKey(successorKeyB)).Token(t.Context(), s.again(second))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
			},
		},
		{
			name: "a same answer that cannot be signed fails, with nothing written",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.keys.failSigning(func(context.Context) error { return errOutage })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.ErrorContains(t, err, "sign the access token")
				assert.Nil(t, res)
				assert.Zero(t, f.lineage.writes.Load())
				f.keys.failSigning(nil)
				assert.Equal(t, s.newest, assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name:  "a same answer whose opaque token cannot be stored fails, with nothing written",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.access.failCreate.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.ErrorContains(t, err, "store the access token")
				assert.Nil(t, res)
				assert.Zero(t, f.lineage.writes.Load())
				f.access.failCreate.Store(false)
				assert.Equal(t, s.newest, assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken)
			},
		},
		{
			name: "second_read_after_the_first_write",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				answer, release := f.heldAtUserLoad(t, s.request, oidcprovider.WithRefreshSuccessorKey(successorKeyA))
				s.racers, s.release = []<-chan exchanged{answer}, release
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err, "tab one's write lands while tab two is held")
				writes := f.lineage.writes.Load()
				s.release()
				other := <-s.racers[0]
				require.NoError(t, other.err, "tab two read the token live, and is answered regardless")
				assert.Equal(t, res.RefreshToken, other.res.RefreshToken, "both hold the one successor")
				assert.Equal(t, writes, f.lineage.writes.Load(), "tab two wrote nothing")
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))
			},
		},
		{
			name: "second_read_after_the_successor_moved_on is no theft alarm: it answers the head",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				answer, release := f.heldAtUserLoad(t, s.request, oidcprovider.WithRefreshSuccessorKey(successorKeyA))
				s.racers, s.release = []<-chan exchanged{answer}, release
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				newest := assertRefreshWorks(t, f, s, res.RefreshToken).RefreshToken
				s.release()
				other := <-s.racers[0]
				require.NoError(t, other.err)
				assert.Equal(t, newest, other.res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked, "no token past its grace was presented")
				assert.Equal(t, 1, f.liveHeads(t))
			},
		},
		{
			name: "a window closing while a request waits is judged as it stands then: the token rotates again",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				answer, release := f.heldAtUserLoad(t, s.request, oidcprovider.WithRefreshSuccessorKey(successorKeyA))
				s.racers, s.release = []<-chan exchanged{answer}, release
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				f.clk.Advance(defaultSuccessorWindow)
				s.release()
				other := <-s.racers[0]
				require.NoError(t, other.err)
				assert.NotEqual(t, res.RefreshToken, other.res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))
			},
		},
		{
			name: "after_the_window_re_rotates",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(20 * time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err, "inside the grace, it receives tokens")
				assert.NotEqual(t, s.newest, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))
				assert.Equal(t, int32(1), f.lineage.supersedes.Load(), "it is rotated, not answered")

				// Its next rotation stays random too: the derived identifier is stored already, on
				// the record this one knocked out.
				f.clk.Advance(time.Second)
				again := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.NotEqual(t, res.RefreshToken, again.RefreshToken)
				assert.NotEqual(t, s.newest, again.RefreshToken)

				f.clk.Advance(31 * time.Second)
				assertRefreshRefused(t, f, s, s.newest)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
			},
		},
		{
			name: "past the window, a successor that has moved on is reuse, though the token is inside its grace",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				assertRefreshWorks(t, f, s, second)
				f.clk.Advance(defaultSuccessorWindow)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "the window's last moment answers the same successor, measured from the rotation",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.clk.Advance(time.Minute) // the token's own age is no part of it
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(defaultSuccessorWindow - time.Nanosecond)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.newest, res.RefreshToken)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "the window has ended at exactly its length",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(defaultSuccessorWindow)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, s.newest, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a_thief_missing_the_window_is_caught",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				// First cycle: the victim refreshes, and the thief holding r1 refreshes 20 s later.
				victim := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(20 * time.Second)
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				require.NotEqual(t, victim, s.newest, "they diverged")
				require.False(t, grantNow(t, f, s).Revoked)
				// Second cycle: the victim refreshes with what it holds.
				f.clk.Advance(5 * time.Minute)
				s.request = s.again(victim)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause, "within two cycles")
				assert.Zero(t, f.liveHeads(t))
				assertRefreshRefused(t, f, s, s.newest)
			},
		},
		{
			name: "window_set_by_the_consumer: zero turns the same successor off, and nothing derives",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorWindow(0)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				require.NotEqual(t, successorUnder(successorKeyA, s.grant.Family, s.secretOf(t, s.first.RefreshToken)), s.secretOf(t, s.newest),
					"no rotation needs a derived successor")
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, s.newest, res.RefreshToken, "no re-presentation answers the same one")
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))
			},
		},
		{
			name: "window_set_by_the_consumer: a wider one answers the same successor for longer",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorWindow(time.Minute)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = 2 * time.Minute })
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(time.Minute - time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, s.newest, res.RefreshToken)
				f.clk.Advance(time.Second)
				assert.NotEqual(t, s.newest, assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken)
			},
		},
		{
			name: "window_set_by_the_consumer: a shorter one ends the same successor sooner",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorWindow(time.Second)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, _ *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, s.newest, res.RefreshToken)
			},
		},
		{
			name: "window_set_by_the_consumer: zero holds on a clock behind the rotation's, with no key to read",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorWindow(0)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				ahead := f.replica(t, oidcprovider.WithRefreshSuccessorWindow(0),
					oidcprovider.WithClock(clockwork.NewFakeClockAt(f.clk.Now().Add(5*time.Second))))
				res, err := ahead.Token(t.Context(), s.request)
				require.NoError(t, err)
				s.newest = res.RefreshToken
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, s.newest, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a client's grace still bounds the window: past it, the token is reuse",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorWindow(session.MaxRenewalGrace)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(session.DefaultRenewalGrace)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
			},
		},
		{
			name: "a shortened idle timeout reaches a token inside its grace, measured from its rotation",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = 2 * time.Minute })
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.RefreshGrace = 2 * time.Minute
					c.GrantIdleTimeout = 10 * time.Second
				})
				f.clk.Advance(10 * time.Second)
				assertRefreshRefused(t, f, s, s.newest)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Zero(t, f.lineage.supersedes.Load(), "a token no longer good moves nothing")
				assert.False(t, grantNow(t, f, s).Revoked, "an ending, and no revocation")
			},
		},
		{
			name: "diverged_holders_are_caught",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				s.newest = assertRefreshWorks(t, f, s, second).RefreshToken
				f.clk.Advance(31 * time.Second)
				s.request = s.again(second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
				assertRefreshRefused(t, f, s, s.newest)
			},
		},
		{
			name: "a successor past its own grace ends the same answer: the token presented inside its grace is reuse",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = 2 * time.Minute })
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = time.Second })
				assertRefreshWorks(t, f, s, second)
				f.clk.Advance(2 * time.Second) // inside both windows, and past the successor's grace
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
			},
		},
		{
			name: "a successor past its own deadline, inside the window, is rotated past",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				billingClient(t, f, func(c *oidcprovider.Client) {
					c.RefreshGrace = 2 * time.Minute
					c.GrantIdleTimeout = 5 * time.Second
				})
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = 2 * time.Minute })
				f.clk.Advance(6 * time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, s.newest, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
				assertRefreshWorks(t, f, s, res.RefreshToken)
			},
		},
		{
			name: "a successor that cannot be read is no verdict",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				successor := s.secretOf(t, s.newest)
				f.lineage.failLoadOf = func(secret string) bool { return secret == successor }
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				f.lineage.failLoadOf = nil
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Zero(t, f.lineage.supersedes.Load(), "and nothing rotated on the strength of it")
				assert.Equal(t, s.newest, assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken)
			},
		},
		{
			name: "a store answering nothing for the successor is no answer, and the token is rotated past it",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				successor := s.secretOf(t, s.newest)
				f.lineage.nothingOf = func(secret string) bool { return secret == successor }
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				f.lineage.nothingOf = nil
				require.NoError(t, err)
				assert.NotEqual(t, s.newest, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a first rotation reads no successor: it has none yet",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				derived := successorUnder(successorKeyA, s.grant.Family, s.secretOf(t, s.first.RefreshToken))
				f.lineage.failLoadOf = func(secret string) bool { return secret == derived }
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				f.lineage.failLoadOf = nil
				require.NoError(t, err)
				assert.NotEmpty(t, res.RefreshToken)
			},
		},
		{
			name: "a token knocked out by a replica whose clock runs ahead is reuse, whatever window it records",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				knockedOut := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				ahead := f.replica(t, oidcprovider.WithRefreshSuccessorKey(successorKeyB),
					oidcprovider.WithClock(clockwork.NewFakeClockAt(f.clk.Now().Add(5*time.Second))))
				_, err := ahead.Token(t.Context(), s.request)
				require.NoError(t, err)
				s.request = s.again(knockedOut)
				f.grants.failRevoke.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, _ *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assert.Equal(t, 1, f.liveHeads(t), "judged reuse before anything was deleted: the row could not be marked")
			},
		},
		func() testCase {
			var cancel context.CancelFunc

			return testCase{
				name: "a reuse's row is marked though the caller hangs up before the manager's read",
				ctx: func(ctx context.Context) context.Context {
					ended, stop := context.WithCancel(ctx) //nolint:gosec // the row calls it during the request
					cancel = stop

					return ended
				},
				arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
					t.Helper()
					assertRefreshWorks(t, f, s, s.first.RefreshToken)
					f.clk.Advance(30 * time.Second)
					f.lineage.onLoad = func() { cancel() }
				},
				assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
					t.Helper()
					f.lineage.onLoad = nil
					require.ErrorIs(t, err, context.Canceled)
					assert.Nil(t, res)
					assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause, "a hang-up must not spare what it was evidence against")
				},
			}
		}(),
		{
			name: "no_key_no_successor",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				// What anyone holding the token could compute with no key at all.
				s.request = s.again("rt." + s.grant.Family.String() + "." + successorUnder(nil, s.grant.Family, s.secretOf(t, s.first.RefreshToken)))
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assertRefreshRefused(t, f, s, "rt."+s.grant.Family.String()+"."+successorUnder(successorKeyB, s.grant.Family, s.secretOf(t, s.first.RefreshToken)))
				assert.Zero(t, f.lineage.writes.Load(), "a successor computed under any other key is no record")
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.True(t, s.head(t, f, s.newest).SupersededAt.IsZero(), "the real one is the head still")
				assertRefreshWorks(t, f, s, s.newest)
			},
		},
		{
			name: "another_key_re_rotates",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				other := f.replica(t, oidcprovider.WithRefreshSuccessorKey(successorKeyB))
				res, err := other.Token(t.Context(), s.request)
				require.NoError(t, err)
				s.newest = res.RefreshToken
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err, "a key that differs is no reason to refuse")
				assert.NotEqual(t, s.newest, res.RefreshToken, "it finds no match, and rotates again")
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))
				live := s.head(t, f, res.RefreshToken)
				assert.True(t, live.SupersededAt.IsZero())
				assertRefreshWorks(t, f, s, res.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a digest another key wrote costs no read of what this key derives",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				_, err := f.replica(t, oidcprovider.WithRefreshSuccessorKey(successorKeyB)).Token(t.Context(), s.request)
				require.NoError(t, err)
				derived := successorUnder(successorKeyA, s.grant.Family, s.secretOf(t, s.first.RefreshToken))
				f.lineage.failLoadOf = func(secret string) bool { return secret == derived }
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, _ *oidcprovider.TokenResponse, err error) {
				t.Helper()
				f.lineage.failLoadOf = nil
				require.NoError(t, err)
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "replicas holding different keys keep re-rotating one token, in turn, with no failure",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				other := f.replica(t, oidcprovider.WithRefreshSuccessorKey(successorKeyB))
				for _, p := range []*oidcprovider.Provider{f.p, other, f.p, other} {
					_, err := p.Token(t.Context(), s.request)
					require.NoError(t, err, "a replica returning to a token must not collide with what it derived before")
					f.clk.Advance(time.Second)
				}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Equal(t, 1, f.liveHeads(t))
				assertRefreshWorks(t, f, s, res.RefreshToken)
			},
		},
		{
			name:  "a re-rotation refused because the successor moved on is reuse, which the observer marks",
			start: startClient(opaqueClient, opaqueRedirect),
			opts:  []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newestAccess = advanceOnReplica(t, f, s)
				f.clk.Advance(time.Second)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
				_, verifyErr := f.p.VerifyAccessToken(t.Context(), s.newestAccess)
				assert.Error(t, verifyErr)
			},
		},
		func() testCase {
			var cancel context.CancelFunc

			return testCase{
				name: "a re-rotation's reuse by a caller who hangs up still marks the row",
				opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
				ctx: func(ctx context.Context) context.Context {
					ended, stop := context.WithCancel(ctx) //nolint:gosec // the row calls it during the request
					cancel = stop

					return ended
				},
				arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
					t.Helper()
					advanceOnReplica(t, f, s)
					f.lineage.beforeSupersede = func() { cancel() }
				},
				assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
					t.Helper()
					refusedGrant(t, f, s, res, err)
					assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause, "a hang-up must not spare what it was evidence against")
				},
			}
		}(),
		{
			name: "a re-rotation's reuse whose family cannot be deleted marks the row, and is a dependency failure",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				advanceOnReplica(t, f, s)
				f.lineage.failDelete.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause, "no observer was told, and the row ends the grant regardless")
			},
		},
		{
			name:  "a re-rotation's reuse whose row cannot be marked is logged, and reads as revoked at a refresh from then on",
			start: startClient(opaqueClient, opaqueRedirect),
			opts:  []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				s.newestAccess = advanceOnReplica(t, f, s)
				f.grants.failRevoke.Store(true)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				assert.False(t, grantNow(t, f, s).Revoked)
				assert.Contains(t, f.logs.String(), "level=ERROR")
				assert.NotContains(t, f.logs.String(), errOutage.Error())
				assert.Zero(t, f.liveHeads(t))

				f.grants.failRevoke.Store(false)
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
				assert.False(t, grantNow(t, f, s).Revoked, "the missing lineage reads as revoked, and writes nothing")
				// The stated limit of this one path: nothing is left to present that could mark
				// the row, so this token lives until its own expiry.
				_, verifyErr := f.p.VerifyAccessToken(t.Context(), s.newestAccess)
				require.NoError(t, verifyErr)
			},
		},
		{
			name: "every racer gets the one successor, and one head is left",
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
				assert.Len(t, seen, 1, "each one derives the same successor")
				assert.Equal(t, 1, f.liveHeads(t), "exactly one is left live")
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "more racers than a rotation's attempts are all served: a loser needs one more read, not a win",
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.lineage.beforeSupersede = meeting(t, 2*racersWithinBound)
				for range 2*racersWithinBound - 1 {
					s.racers = append(s.racers, exchangeAsync(t.Context(), f.exchangeFixture, s.request))
				}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				for _, racer := range s.racers {
					answer := <-racer
					require.NoError(t, answer.err)
					assert.Equal(t, res.RefreshToken, answer.res.RefreshToken)
				}
				assert.Equal(t, 1, f.liveHeads(t))
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
			name:  "a revocation landing after the rotation's write leaves no opaque token usable",
			start: startClient(opaqueClient, opaqueRedirect),
			arrange: func(t *testing.T, f *refreshFixture, s *refreshScene) {
				t.Helper()
				f.access.creates.Store(0)
				f.lineage.afterSupersede = once(func() { revokeWhole(t, f, s) })
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				refusedGrant(t, f, s, res, err)
				f.access.assertLastEnded(t)
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

// defaultSuccessorWindow and successorWalkBound state WithRefreshSuccessorWindow's default, and how
// many links one walk to the head may read.
const (
	defaultSuccessorWindow = 10 * time.Second
	successorWalkBound     = 8
)

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

	require.NoError(t, revokeErr(f.grants.GrantStore.Revoke(t.Context(), s.grant.Family, oidcprovider.CauseUserRequest, f.clk.Now())))
	_, err := f.lineage.Store.DeleteFamily(t.Context(), s.grant.Family)
	require.NoError(t, err)
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

// TestProvider_RefreshSuccessorKey is WithRefreshSuccessorKey's table: what it takes, what it
// replaces, and how the successor it derives comes out.
func TestProvider_RefreshSuccessorKey(t *testing.T) {
	t.Parallel()

	// seed is what a row's provider reads from when it draws its key from its random source.
	seed := [32]byte{7, 7, 7}

	type testCase struct {
		name   string
		opts   func(key []byte) []oidcprovider.Option
		key    []byte
		assert func(t *testing.T, f *refreshFixture, s *refreshScene, key []byte)
	}
	withKey := func(key []byte) []oidcprovider.Option {
		return []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(key)}
	}
	derivedUnder := func(want []byte) func(*testing.T, *refreshFixture, *refreshScene, []byte) {
		return func(t *testing.T, f *refreshFixture, s *refreshScene, _ []byte) {
			t.Helper()
			res := assertRefreshWorks(t, f, s, s.first.RefreshToken)
			secret := s.secretOf(t, res.RefreshToken)
			assert.Equal(t, successorUnder(want, s.grant.Family, s.secretOf(t, s.first.RefreshToken)), secret)
			assert.True(t, session.ValidIdentifier(secret))
			raw, err := base64.RawURLEncoding.DecodeString(secret)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(raw)*8, 128, "a successor carries at least 128 bits")
		}
	}

	cases := []testCase{
		{name: "a consumer's key of 32 bytes derives the successor", opts: withKey, key: successorKeyA, assert: derivedUnder(successorKeyA)},
		{
			name: "a replica holding the same key answers the successor another derived, with no write",
			opts: withKey,
			key:  successorKeyA,
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, key []byte) {
				t.Helper()
				first := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.lineage.writes.Store(0)
				res, err := f.replica(t, oidcprovider.WithRefreshSuccessorKey(key)).Token(t.Context(), s.request)
				require.NoError(t, err)
				assert.Equal(t, first.RefreshToken, res.RefreshToken)
				assert.Zero(t, f.lineage.writes.Load())
			},
		},
		{
			name: "a key changed by its caller afterwards changes nothing: it was copied",
			opts: withKey,
			key:  slices.Clone(successorKeyA),
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, key []byte) {
				t.Helper()
				clear(key)
				derivedUnder(successorKeyA)(t, f, s, nil)
			},
		},
		{
			name: "with no key, 32 bytes drawn once from the provider's random source derive it",
			opts: func([]byte) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithRandom(rand.NewChaCha8(seed))}
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, _ []byte) {
				t.Helper()
				drawn := make([]byte, 32)
				_, err := rand.NewChaCha8(seed).Read(drawn)
				require.NoError(t, err)
				derivedUnder(drawn)(t, f, s, nil)
				f.clk.Advance(time.Second)
				again := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.Equal(t, successorUnder(drawn, s.grant.Family, s.secretOf(t, s.first.RefreshToken)), s.secretOf(t, again.RefreshToken),
					"later reads of the source, which issued this very grant, do not move the key")
			},
		},
		{
			name: "two providers drawing their own keys derive different successors",
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, _ []byte) {
				t.Helper()
				res := assertRefreshWorks(t, f, s, s.first.RefreshToken)
				assert.NotEqual(t, successorUnder(make([]byte, 32), s.grant.Family, s.secretOf(t, s.first.RefreshToken)), s.secretOf(t, res.RefreshToken))
				other, err := f.replica(t).Token(t.Context(), s.request)
				require.NoError(t, err)
				assert.NotEqual(t, res.RefreshToken, other.RefreshToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(tc.key)
			}
			f := newRefreshFixture(t, opts...)
			tc.assert(t, f, startBilling(t, f), tc.key)
		})
	}
}

// TestProvider_RefreshSuccessorKey_Refused is what New makes of a key that cannot do its job.
func TestProvider_RefreshSuccessorKey_Refused(t *testing.T) {
	t.Parallel()

	short := []byte("a key one byte short of 32 bytes")[:31]
	cases := []struct {
		name string
		key  []byte
	}{
		{name: "nil", key: nil},
		{name: "empty", key: []byte{}},
		{name: "one byte short", key: short},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcprovider.New(validDeps(t), oidcprovider.WithRefreshSuccessorKey(tc.key))
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "WithRefreshSuccessorKey")
			if len(tc.key) > 0 {
				assert.NotContains(t, err.Error(), string(tc.key), "an error never holds the key")
			}
		})
	}
}

// TestProvider_RefreshSuccessorKey_DrawFails is what New makes of a random source that cannot supply
// the key: no provider, where one is needed, since a provider must not degrade silently.
func TestProvider_RefreshSuccessorKey_DrawFails(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, err error)
	}{
		{
			name: "with the default key to draw, New fails, and repeats nothing of the source's",
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.NotErrorIs(t, err, errOutage)
				assert.NotContains(t, err.Error(), errOutage.Error())
			},
		},
		{
			name: "a consumer's key draws nothing",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorKey(successorKeyA)},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "a window of zero needs no key, so it draws nothing",
			opts: []oidcprovider.Option{oidcprovider.WithRefreshSuccessorWindow(0)},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]oidcprovider.Option{oidcprovider.WithRandom(iotest.ErrReader(errOutage))}, tc.opts...)
			_, err := oidcprovider.New(validDeps(t), opts...)
			tc.assert(t, err)
		})
	}
}

// TestProvider_RefreshSuccessorWindow_Limits is window_set_by_the_consumer's bound, which New states.
func TestProvider_RefreshSuccessorWindow_Limits(t *testing.T) {
	t.Parallel()

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.ErrorContains(t, err, "WithRefreshSuccessorWindow")
	}
	built := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}
	cases := []struct {
		name   string
		window time.Duration
		assert func(t *testing.T, err error)
	}{
		{name: "negative", window: -time.Nanosecond, assert: refused},
		{name: "one over session.MaxRenewalGrace", window: session.MaxRenewalGrace + time.Nanosecond, assert: refused},
		{name: "session.MaxRenewalGrace itself", window: session.MaxRenewalGrace, assert: built},
		{name: "zero", window: 0, assert: built},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcprovider.New(validDeps(t), oidcprovider.WithRefreshSuccessorWindow(tc.window))
			tc.assert(t, err)
		})
	}
}

// TestProvider_RefreshSuccessorKey_WithWindowZero is the contradiction New refuses: a key, which a
// window of zero has no use for, in either order of the options.
func TestProvider_RefreshSuccessorKey_WithWindowZero(t *testing.T) {
	t.Parallel()

	key, off := oidcprovider.WithRefreshSuccessorKey(successorKeyA), oidcprovider.WithRefreshSuccessorWindow(0)
	cases := []struct {
		name string
		opts []oidcprovider.Option
	}{
		{name: "key then window", opts: []oidcprovider.Option{key, off}},
		{name: "window then key", opts: []oidcprovider.Option{off, key}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcprovider.New(validDeps(t), tc.opts...)
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "WithRefreshSuccessorKey")
			assert.ErrorContains(t, err, "WithRefreshSuccessorWindow")
			assert.NotContains(t, err.Error(), string(successorKeyA), "an error never holds the key")
		})
	}
}

// onNthRead is a fault for hookedLineage that fires at the nth read of secret, and at no other. A
// refresh reads its token three times before the rotation writes: the family check, the manager, and
// the re-read before rotating, which is the third.
func onNthRead(secret string, n int32) func(string) bool {
	var reads atomic.Int32

	return func(read string) bool { return read == secret && reads.Add(1) == n }
}

// TestProvider_Refresh_SlowUserLoad is what a request is answered when its user load outlasts the
// grace of the token it presented in time. It has its own table, because each row holds a request at
// its user load, which the main table's single call cannot.
func TestProvider_Refresh_SlowUserLoad(t *testing.T) {
	t.Parallel()

	withKey := oidcprovider.WithRefreshSuccessorKey(successorKeyA)
	type testCase struct {
		name string
		// grace is the client's RefreshGrace, and zero leaves the default.
		grace time.Duration
		act   func(*testing.T, *refreshFixture, *refreshScene) (*oidcprovider.TokenResponse, error)
		// assert gets the token the other tab holds, if the row had one.
		assert func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error)
	}
	noVerdict := func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		assertDependencyFailure(t, err)
		assert.Nil(t, res)
		assert.False(t, grantNow(t, f, s).Revoked, "a token presented in time is no reuse")
		assert.Equal(t, 1, f.liveHeads(t))
	}

	cases := []testCase{
		{
			name: "a live copy whose load outlasts the grace gets no verdict, and the other tab's token works",
			act: func(t *testing.T, f *refreshFixture, s *refreshScene) (*oidcprovider.TokenResponse, error) {
				t.Helper()
				answer, release := f.heldAtUserLoad(t, s.request, withKey)
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(session.DefaultRenewalGrace)
				release()
				got := <-answer

				return got.res, got.err
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				noVerdict(t, f, s, res, err)
				assertRefreshWorks(t, f, s, s.newest)
			},
		},
		{
			name:  "a superseded copy inside its window, answered past its grace, gets no verdict and not the successor",
			grace: 5 * time.Second,
			act: func(t *testing.T, f *refreshFixture, s *refreshScene) (*oidcprovider.TokenResponse, error) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(4 * time.Second)
				answer, release := f.heldAtUserLoad(t, s.request, withKey)
				f.clk.Advance(3 * time.Second)
				release()
				got := <-answer

				return got.res, got.err
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				noVerdict(t, f, s, res, err)
				assertRefreshWorks(t, f, s, s.newest)
			},
		},
		{
			name: "a store failure on the re-read alone is a dependency failure, and nothing is rotated",
			act: func(t *testing.T, f *refreshFixture, s *refreshScene) (*oidcprovider.TokenResponse, error) {
				t.Helper()
				f.lineage.failLoadOf = onNthRead(s.secretOf(t, s.first.RefreshToken), 3)
				answer, release := f.heldAtUserLoad(t, s.request, withKey)
				release()
				got := <-answer

				return got.res, got.err
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				noVerdict(t, f, s, res, err)
				assert.Zero(t, f.lineage.supersedes.Load(), "the token was not rotated on a read that failed")
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
			},
		},
		{
			name: "a re-read that finds the record gone is refused, and nothing is rotated",
			act: func(t *testing.T, f *refreshFixture, s *refreshScene) (*oidcprovider.TokenResponse, error) {
				t.Helper()
				f.lineage.nothingOf = onNthRead(s.secretOf(t, s.first.RefreshToken), 3)
				answer, release := f.heldAtUserLoad(t, s.request, withKey)
				release()
				got := <-answer

				return got.res, got.err
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Nil(t, res)
				assert.Zero(t, f.lineage.supersedes.Load())
				assert.False(t, grantNow(t, f, s).Revoked)
			},
		},
		{
			name: "a presentation already past its grace still revokes",
			act: func(t *testing.T, f *refreshFixture, s *refreshScene) (*oidcprovider.TokenResponse, error) {
				t.Helper()
				s.newest = assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				f.clk.Advance(session.DefaultRenewalGrace)

				return f.p.Token(t.Context(), s.request)
			},
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Nil(t, res)
				assert.Equal(t, oidcprovider.CauseReuse, grantNow(t, f, s).RevokeCause)
				assert.Zero(t, f.liveHeads(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t, withKey)
			if tc.grace != 0 {
				billingClient(t, f, func(c *oidcprovider.Client) { c.RefreshGrace = tc.grace })
			}
			s := startBilling(t, f)
			res, err := tc.act(t, f, s)
			tc.assert(t, f, s, res, err)
		})
	}
}

// TestProvider_Refresh_ReplicaClocks is what a replica whose clock is off from the one that rotated
// answers a token presented again. It has its own table, because the request goes to a replica the
// row builds, where the main table's goes to the fixture's provider.
func TestProvider_Refresh_ReplicaClocks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// behind is how far the replica's clock lags the rotating one's, and after how long it is
		// presented again, on both clocks.
		behind, after time.Duration
		assert        func(t *testing.T, f *refreshFixture, s *refreshScene, r2 string, res *oidcprovider.TokenResponse, err error)
	}
	rotatesAgain := func(t *testing.T, f *refreshFixture, s *refreshScene, r2 string, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotEqual(t, r2, res.RefreshToken, "a lag does not stretch the window")
		assert.False(t, grantNow(t, f, s).Revoked)
	}

	cases := []testCase{
		{name: "a replica behind by 20 seconds", behind: time.Hour, after: 20 * time.Second, assert: rotatesAgain},
		{name: "a replica behind by exactly the window", behind: 10 * time.Second, assert: rotatesAgain},
		{name: "a replica behind by 59 minutes", behind: time.Hour, after: 59 * time.Minute, assert: rotatesAgain},
		{
			name: "replicas 2 seconds apart converge on the same successor", behind: 2 * time.Second,
			assert: func(t *testing.T, _ *refreshFixture, _ *refreshScene, r2 string, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, r2, res.RefreshToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			withKey := oidcprovider.WithRefreshSuccessorKey(successorKeyA)
			f := newRefreshFixture(t, withKey)
			billingClient(t, f, func(c *oidcprovider.Client) { c.GrantIdleTimeout = 24 * time.Hour })
			s := startBilling(t, f)
			r2 := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken

			lagging := clockwork.NewFakeClockAt(f.clk.Now().Add(-tc.behind))
			tab := f.replica(t, withKey, oidcprovider.WithClock(lagging))
			f.clk.Advance(tc.after)
			lagging.Advance(tc.after)

			res, err := tab.Token(t.Context(), s.request)
			tc.assert(t, f, s, r2, res, err)
		})
	}
}

// TestProvider_Refresh_NoSecretReachesALogOrAnError runs the failing and refusing paths, and
// looks for the key and every secret in what they leave.
func TestProvider_Refresh_NoSecretReachesALogOrAnError(t *testing.T) {
	t.Parallel()

	f := newRefreshFixture(t, oidcprovider.WithRefreshSuccessorKey(successorKeyA))
	s := startBilling(t, f)
	first := s.first.RefreshToken

	var errs []error
	try := func(raw string) {
		if _, err := f.p.Token(t.Context(), s.again(raw)); err != nil {
			errs = append(errs, err)
		}
	}
	f.lineage.failLoad.Store(true)
	try(first)
	f.lineage.failLoad.Store(false)
	f.lineage.failSupersede.Store(true)
	try(first)
	f.lineage.failSupersede.Store(false)

	second := assertRefreshWorks(t, f, s, first)
	f.lineage.failLoadOf = func(string) bool { return true }
	try(first)
	f.lineage.failLoadOf = nil

	f.clk.Advance(30 * time.Second)
	f.grants.failRevoke.Store(true)
	try(first)
	f.grants.failRevoke.Store(false)
	f.lineage.failDelete.Store(true)
	try(first)
	f.lineage.failDelete.Store(false)
	require.NotEmpty(t, errs)

	logs := f.logs.String()
	for _, secret := range []string{
		s.secretOf(t, first),
		s.secretOf(t, second.RefreshToken),
		second.AccessToken,
		string(successorKeyA),
		base64.RawURLEncoding.EncodeToString(successorKeyA),
		base64.StdEncoding.EncodeToString(successorKeyA),
	} {
		assert.NotContains(t, logs, secret)
		for _, err := range errs {
			assert.NotContains(t, err.Error(), secret)
		}
	}

	for _, printed := range []string{fmt.Sprintf("%v", f.p), fmt.Sprintf("%+v", f.p)} {
		assert.NotContains(t, printed, fmt.Sprintf("%d", successorKeyA), "a provider printed does not print its key")
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
