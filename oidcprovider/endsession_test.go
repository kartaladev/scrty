package oidcprovider_test

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The rows here are the failures of what the provider asks of its dependencies, which an endpoint
// cannot arrange. httpsec's TestOIDCEndSession and TestOIDCLogoutConfirm hold the behaviour.

// logoutSigningKeys are one set for every row, because generating them is the slow part.
var logoutSigningKeys = sync.OnceValue(func() *signingkey.Keys {
	keys, err := signingkey.New(context.Background(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	if err != nil {
		panic(err)
	}

	return keys
})

// logoutRegistry is a registry a row can take down.
type logoutRegistry struct {
	*oidcprovider.MemoryRegistry

	down atomic.Bool
}

func (r *logoutRegistry) Client(ctx context.Context, clientID string) (*oidcprovider.RegisteredClient, error) {
	if r.down.Load() {
		return nil, errOutage
	}

	return r.MemoryRegistry.Client(ctx, clientID)
}

// logoutPendingStore is a pending-request store whose writes a row can fail, each with its own error.
type logoutPendingStore struct {
	*oidcprovider.MemoryPendingRequestStore

	createFails atomic.Bool
	loadFails   atomic.Bool
	advanceErr  atomic.Pointer[error]
}

func (s *logoutPendingStore) Create(ctx context.Context, r *oidcprovider.PendingRequest) error {
	if s.createFails.Load() {
		return errOutage
	}

	return s.MemoryPendingRequestStore.Create(ctx, r)
}

func (s *logoutPendingStore) Load(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
	if s.loadFails.Load() {
		return nil, errOutage
	}

	return s.MemoryPendingRequestStore.Load(ctx, digest)
}

func (s *logoutPendingStore) Advance(
	ctx context.Context, digest []byte, from, to oidcprovider.Stage, in *oidcprovider.SignIn,
) error {
	if err := s.advanceErr.Load(); err != nil {
		return *err
	}

	return s.MemoryPendingRequestStore.Advance(ctx, digest, from, to, in)
}

// logoutBrowsers is a browser-session store whose reads a row can fail.
type logoutBrowsers struct {
	*oidcprovider.MemoryBrowserSessionStore

	loadFails atomic.Bool
}

func (s *logoutBrowsers) Load(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.BrowserSession, error) {
	if s.loadFails.Load() {
		return nil, errOutage
	}

	return s.MemoryBrowserSessionStore.Load(ctx, digest, now)
}

// logoutKeys is a key source whose verification keys a row can take away.
type logoutKeys struct {
	signingkey.KeySource

	down atomic.Bool
}

func (k *logoutKeys) VerificationKeys(ctx context.Context) ([]signingkey.PublicKey, error) {
	if k.down.Load() {
		return nil, errOutage
	}

	return k.KeySource.VerificationKeys(ctx)
}

type logoutFixture struct {
	p        *oidcprovider.Provider
	clk      *clockwork.FakeClock
	keys     *logoutKeys
	registry *logoutRegistry
	pending  *logoutPendingStore
	browsers *logoutBrowsers
	grants   *oidcprovider.MemoryGrantStore
	family   id.ID
	secret   string
	grant    id.ID
}

const logoutFixtureURI = "https://rp.example.com/bye"

func newLogoutFixture(t *testing.T) *logoutFixture {
	t.Helper()

	f := &logoutFixture{
		clk:    clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)),
		keys:   &logoutKeys{KeySource: logoutSigningKeys()},
		family: id.MustParse("00000000-0000-7000-8000-00000000000a"),
		grant:  id.MustParse("00000000-0000-7000-8000-00000000000b"),
		secret: base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 7)),
	}

	clients := authzClients()
	clients[0].PostLogoutRedirectURIs = []string{logoutFixtureURI}

	registry, err := oidcprovider.NewMemoryRegistry(clients)
	require.NoError(t, err)
	f.registry = &logoutRegistry{MemoryRegistry: registry}

	pending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	f.pending = &logoutPendingStore{MemoryPendingRequestStore: pending}

	browsers, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	f.browsers = &logoutBrowsers{MemoryBrowserSessionStore: browsers}

	f.grants, err = oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)

	f.p, err = oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     f.registry,
		Keys:         f.keys,
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(f.clk),
		oidcprovider.WithPendingRequestStore(f.pending),
		oidcprovider.WithBrowserSessionStore(f.browsers),
		oidcprovider.WithGrantStore(f.grants),
	)
	require.NoError(t, err)

	now := f.clk.Now()
	require.NoError(t, f.browsers.Put(t.Context(), &oidcprovider.BrowserSession{
		Digest:            digestOf(t, f.secret),
		SignIn:            oidcprovider.SignIn{User: "u-1", Family: f.family, AuthenticatedAt: now, AbsoluteExpiresAt: now.Add(time.Hour)},
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, f.grants.Create(t.Context(), &oidcprovider.Grant{
		Family: f.grant, User: "u-1", ClientID: authzClients()[0].ID, Scopes: []string{"openid"},
		SignInFamily: f.family, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AuthTime: now,
	}))

	return f
}

// hint is an ID token naming the fixture's sign-in.
func (f *logoutFixture) hint(t *testing.T) string {
	t.Helper()

	made, err := token.NewIssuer(f.keys.KeySource, signingkey.RS256, issuer, token.WithClock(f.clk))
	require.NoError(t, err)

	raw, err := made.Issue(t.Context(), token.Issue{
		Type: token.TypeIDToken, Subject: "u-1", ID: "j-1", Audience: []string{authzClients()[0].ID},
		Lifetime: 5 * time.Minute, Claims: map[string]any{"sid": f.family.String()},
	})
	require.NoError(t, err)

	return raw
}

// matching is a request ending the fixture's sign-in without asking.
func (f *logoutFixture) matching(t *testing.T) oidcprovider.EndSessionInput {
	t.Helper()

	return oidcprovider.EndSessionInput{
		Params: url.Values{
			"id_token_hint":            {f.hint(t)},
			"post_logout_redirect_uri": {logoutFixtureURI},
		},
		BrowserSessionSecret: f.secret,
	}
}

// parked parks a request and returns its handle and flow secret.
func (f *logoutFixture) parked(t *testing.T, params url.Values) (string, string) {
	t.Helper()

	res, err := f.p.EndSession(t.Context(), oidcprovider.EndSessionInput{Params: params})
	require.NoError(t, err)

	loc, err := url.Parse(res.Location)
	require.NoError(t, err)

	return loc.Query().Get(oidcprovider.HandleParam), res.FlowSecret
}

func (f *logoutFixture) assertStands(t *testing.T) {
	t.Helper()

	_, err := f.browsers.MemoryBrowserSessionStore.Load(t.Context(), digestOf(t, f.secret), f.clk.Now())
	require.NoError(t, err, "the browser session stands")

	grant, err := f.grants.Load(t.Context(), f.grant)
	require.NoError(t, err)
	assert.False(t, grant.Revoked, "the grant stands")
}

func TestProvider_EndSession_Dependencies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		fail  func(f *logoutFixture)
		input func(f *logoutFixture, t *testing.T) oidcprovider.EndSessionInput
	}

	cases := []testCase{
		{
			name:  "a registry down leaves everything as it was",
			fail:  func(f *logoutFixture) { f.registry.down.Store(true) },
			input: (*logoutFixture).matching,
		},
		{
			name:  "a browser store down leaves everything as it was",
			fail:  func(f *logoutFixture) { f.browsers.loadFails.Store(true) },
			input: (*logoutFixture).matching,
		},
		{
			name:  "keys that cannot be read are an outage, and never a refused hint",
			fail:  func(f *logoutFixture) { f.keys.down.Store(true) },
			input: (*logoutFixture).matching,
		},
		{
			name: "a pending store that cannot park is an outage",
			fail: func(f *logoutFixture) { f.pending.createFails.Store(true) },
			input: func(*logoutFixture, *testing.T) oidcprovider.EndSessionInput {
				return oidcprovider.EndSessionInput{Params: url.Values{}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLogoutFixture(t)
			in := tc.input(f, t)
			tc.fail(f)

			res, err := f.p.EndSession(t.Context(), in)
			require.ErrorIs(t, err, oidcprovider.ErrDependency)
			require.NotErrorIs(t, err, oidcprovider.ErrInvalidEndSession)
			assert.Nil(t, res)
			assert.NotContains(t, err.Error(), errOutage.Error())
			f.browsers.loadFails.Store(false)
			f.assertStands(t)
		})
	}
}

func TestProvider_ConfirmLogout_Dependencies(t *testing.T) {
	t.Parallel()

	gone, down := error(oidcprovider.ErrNotFound), error(errOutage)

	type testCase struct {
		name      string
		confirmed bool
		fail      func(f *logoutFixture)
		assert    func(t *testing.T, f *logoutFixture, res *oidcprovider.LogoutResult, err error)
	}

	outage := func(t *testing.T, f *logoutFixture, res *oidcprovider.LogoutResult, err error) {
		t.Helper()

		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assert.Nil(t, res)
		assert.NotContains(t, err.Error(), errOutage.Error())
		f.browsers.loadFails.Store(false)
		f.assertStands(t)
	}

	answered := func(t *testing.T, f *logoutFixture, res *oidcprovider.LogoutResult, err error) {
		t.Helper()

		require.NoError(t, err)
		require.NotNil(t, res.Ended, "the sign-in ended, so the caller still owes its sessions")
		assert.Equal(t, f.family, res.Ended.Family)
		assert.Equal(t, "u-1", string(res.User))
	}

	cases := []testCase{
		{
			name:      "a registry down leaves the sign-in and the handle as they were",
			confirmed: true,
			fail:      func(f *logoutFixture) { f.registry.down.Store(true) },
			assert:    outage,
		},
		{
			name:      "a browser store down leaves the sign-in and the handle as they were",
			confirmed: true,
			fail:      func(f *logoutFixture) { f.browsers.loadFails.Store(true) },
			assert:    outage,
		},
		{
			name:      "a pending store that cannot load is an outage",
			confirmed: true,
			fail:      func(f *logoutFixture) { f.pending.loadFails.Store(true) },
			assert:    outage,
		},
		{
			name:   "a decline that cannot be spent is an outage",
			fail:   func(f *logoutFixture) { f.pending.advanceErr.Store(&down) },
			assert: outage,
		},
		{
			name:      "a sign-in that ended is still answered when its handle cannot be spent",
			confirmed: true,
			fail:      func(f *logoutFixture) { f.pending.advanceErr.Store(&down) },
			assert:    answered,
		},
		{
			name:      "a sign-in that ended is still answered when a racing answer spent its handle",
			confirmed: true,
			fail:      func(f *logoutFixture) { f.pending.advanceErr.Store(&gone) },
			assert:    answered,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLogoutFixture(t)
			handle, flow := f.parked(t, url.Values{
				"id_token_hint":            {f.hint(t)},
				"post_logout_redirect_uri": {logoutFixtureURI},
			})
			tc.fail(f)

			res, err := f.p.ConfirmLogout(t.Context(), handle, flow, f.secret, tc.confirmed)
			tc.assert(t, f, res, err)
		})
	}
}

// TestProvider_EndSession_ParksNoHint pins that nothing a browser holds reaches the record: a
// parked request keeps digests and what was checked, and never the hint.
func TestProvider_EndSession_ParksNoHint(t *testing.T) {
	t.Parallel()

	f := newLogoutFixture(t)
	hint := f.hint(t)
	handle, _ := f.parked(t, url.Values{"id_token_hint": {hint}, "logout_hint": {"someone@example.com"}})

	parts := strings.Split(handle, ".")
	require.Len(t, parts, 3)

	r, err := f.pending.Load(t.Context(), digestOf(t, parts[2]))
	require.NoError(t, err)
	assert.Equal(t, oidcprovider.StageLogout, r.Stage)
	assert.Equal(t, "u-1", r.IDTokenHintSubject)
	assert.Equal(t, f.family, r.SignIn.Family)
	assert.Empty(t, r.LoginHint, "logout_hint is not acted on, so it is not kept")
	assert.NotContains(t, []string{r.State, r.Nonce, r.RedirectURI, r.Challenge}, hint)
}
