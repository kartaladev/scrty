package oidcprovider_test

// The device consent tests build a fixture of their own, over entryFixture: each store a
// resume writes sits behind a generated mock that delegates to a memory store until a row
// arms a failure, the code store is a strict mock no device request may write, and the
// code-entry URL may carry a query.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
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

// deviceExpiresAt is when a seeded device authorization expires.
var deviceExpiresAt = deviceNow.Add(9 * time.Minute)

// deviceConsentSetup is what a row changes in the device consent fixture.
type deviceConsentSetup struct {
	// entry is the code-entry URL, issuer+"/activate" when empty.
	entry string
	// client changes the tv client before the registry is built.
	client func(tv *oidcprovider.Client)
	// scopes are what the seeded authorization asks for, openid and profile when nil.
	scopes []string
	// lifetime is the provider's WithDeviceLifetime, and the seeded authorization's, which
	// expires at deviceExpiresAt when it is zero.
	lifetime time.Duration
}

// deviceConsentFixture is a provider with the device grant on, whose stores a row may fail.
type deviceConsentFixture struct {
	*entryFixture
	registry *oidcprovider.MemoryRegistry
	consents *oidcprovider.MemoryConsentStore
	grants   *oidcprovider.MemoryGrantStore
	events   *eventLog
	logs     *syncBuffer
	ids      *idsDown
	entry    string
	record   *oidcprovider.DeviceAuthorization

	// lookup, once armed, answers the device store's user-code lookups in place of memory's.
	lookup func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error)
	// decide, once armed, runs before each Decide, and answers in its place when it fails.
	decide func() error
	armed  atomic.Bool
	// decides counts the Decide calls, and decided those memory applied.
	decides, decided atomic.Int32

	// advanceFails fails the consent stage's spend, touchGone the browser session's touch
	// as a session gone, touchFails it as a store failing, giveFails remembering a consent,
	// and revokeFails recording a grant revocation.
	advanceFails, touchGone, touchFails, giveFails, revokeFails atomic.Bool
}

// errGrantStoreDown is a grant store's failure, whose text must never leave the provider.
var errGrantStoreDown = errors.New("grant-store-dsn-postgres://secret@db")

// failableGrants is the memory grant store, whose revocations fail while the fixture says.
type failableGrants struct {
	*oidcprovider.MemoryGrantStore

	f *deviceConsentFixture
}

func (g failableGrants) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) (bool, error) {
	if g.f.revokeFails.Load() {
		return false, errGrantStoreDown
	}

	return g.MemoryGrantStore.Revoke(ctx, family, cause, at)
}

func newDeviceConsentFixture(t *testing.T, s deviceConsentSetup) *deviceConsentFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(deviceNow)
	pending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	devices := oidcprovider.NewMemoryDeviceAuthorizationStore()
	consents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	sessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	grants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	clients := entryClients()
	if s.client != nil {
		s.client(&clients[0])
	}
	registry, err := oidcprovider.NewMemoryRegistry(clients)
	require.NoError(t, err)
	entry := s.entry
	if entry == "" {
		entry = issuer + "/activate"
	}

	f := &deviceConsentFixture{
		entryFixture: &entryFixture{clk: clk, pending: pending, devices: devices},
		logs:         &syncBuffer{},
		registry:     registry,
		consents:     consents,
		grants:       grants,
		events:       &eventLog{},
		ids:          &idsDown{next: id.NewV7Generator()},
		entry:        entry,
	}
	ctrl := gomock.NewController(t)
	deviceOpts := []oidcprovider.DeviceOption{
		oidcprovider.WithUserCodeKey(deviceKey),
		oidcprovider.WithDeviceAuthorizationStore(f.hookDevices(ctrl, devices)),
	}
	expiresAt := deviceExpiresAt
	if s.lifetime > 0 {
		deviceOpts = append(deviceOpts, oidcprovider.WithDeviceLifetime(s.lifetime))
		expiresAt = deviceNow.Add(s.lifetime)
	}

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         plainKeys(t),
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithIDGenerator(f.ids),
		oidcprovider.WithPendingRequestStore(f.hookPending(ctrl, pending)),
		oidcprovider.WithConsentStore(f.hookConsents(ctrl, consents)),
		oidcprovider.WithBrowserSessionStore(f.hookSessions(ctrl, sessions)),
		oidcprovider.WithGrantStore(failableGrants{MemoryGrantStore: grants, f: f}),
		// A device request never writes a code: any call fails the row.
		oidcprovider.WithCodeStore(NewMockCodeStore(ctrl)),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))),
		oidcprovider.WithSecurityEvents(f.events.sink),
		oidcprovider.WithDeviceAuthorization(entry, deviceOpts...),
	)
	require.NoError(t, err)
	f.p = p
	f.record = f.seed(t, entryCode, func(r *oidcprovider.DeviceAuthorization) {
		r.ExpiresAt = expiresAt
		if s.scopes != nil {
			r.Scopes = s.scopes
		}
	})

	return f
}

func (f *deviceConsentFixture) hookPending(ctrl *gomock.Controller, memory *oidcprovider.MemoryPendingRequestStore) oidcprovider.PendingRequestStore {
	store := NewMockPendingRequestStore(ctrl)
	store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()
	store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memory.Load).AnyTimes()
	store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memory.DeleteExpired).AnyTimes()
	store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, from, to oidcprovider.Stage, s *oidcprovider.SignIn) error {
			if f.advanceFails.Load() && from == oidcprovider.StageConsent {
				return errOutage
			}

			return memory.Advance(ctx, digest, from, to, s)
		}).AnyTimes()

	return store
}

func (f *deviceConsentFixture) hookConsents(ctrl *gomock.Controller, memory *oidcprovider.MemoryConsentStore) oidcprovider.ConsentStore {
	store := NewMockConsentStore(ctrl)
	store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Load).AnyTimes()
	store.EXPECT().ListByUser(gomock.Any(), gomock.Any()).DoAndReturn(memory.ListByUser).AnyTimes()
	store.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Revoke).AnyTimes()
	store.EXPECT().Give(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time) error {
			if f.giveFails.Load() {
				return errOutage
			}

			return memory.Give(ctx, user, clientID, scopes, offline, at)
		}).AnyTimes()

	return store
}

func (f *deviceConsentFixture) hookSessions(ctrl *gomock.Controller, memory *oidcprovider.MemoryBrowserSessionStore) oidcprovider.BrowserSessionStore {
	store := NewMockBrowserSessionStore(ctrl)
	store.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(memory.Put).AnyTimes()
	store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Load).AnyTimes()
	store.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memory.Delete).AnyTimes()
	store.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memory.DeleteBySignIn).AnyTimes()
	store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memory.DeleteExpired).AnyTimes()
	store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, until time.Time) error {
			if f.touchGone.Load() {
				return oidcprovider.ErrNotFound
			}
			if f.touchFails.Load() {
				return errOutage
			}

			return memory.Touch(ctx, digest, until)
		}).AnyTimes()

	return store
}

func (f *deviceConsentFixture) hookDevices(ctrl *gomock.Controller, memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
	store := NewMockDeviceAuthorizationStore(ctrl)
	store.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()
	store.EXPECT().LoadByDeviceCode(gomock.Any(), gomock.Any()).DoAndReturn(memory.LoadByDeviceCode).AnyTimes()
	store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Claim).AnyTimes()
	store.EXPECT().RecordPoll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.RecordPoll).AnyTimes()
	store.EXPECT().Spend(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Spend).AnyTimes()
	store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memory.DeleteExpired).AnyTimes()
	store.EXPECT().UnspentBySignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.UnspentBySignIn).AnyTimes()
	store.EXPECT().UnspentByClient(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.UnspentByClient).AnyTimes()
	store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
			if f.armed.Load() && f.lookup != nil {
				return f.lookup(ctx, digest, now)
			}

			return memory.LoadByUserCode(ctx, digest, now)
		}).AnyTimes()
	store.EXPECT().Decide(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, deviceID id.ID, approval *oidcprovider.DeviceApproval, now time.Time) error {
			f.decides.Add(1)
			if f.armed.Load() && f.decide != nil {
				if err := f.decide(); err != nil {
					return err
				}
			}
			err := memory.Decide(ctx, deviceID, approval, now)
			if err == nil {
				f.decided.Add(1)
			}

			return err
		}).AnyTimes()

	return store
}

// syncBuffer is a log sink safe for the goroutines a race row starts.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)

	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return string(b.buf)
}

// atLogin enters the seeded code from a browser with no session, and returns the login
// stage's handle and the flow secret.
func (f *deviceConsentFixture) atLogin(t *testing.T) (string, string) {
	t.Helper()

	res, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource})
	require.NoError(t, err)
	require.Equal(t, issuer+"/login", pagePath(t, res.Location))

	return handleOf(t, res.Location), res.FlowSecret
}

// atConsent enters the seeded code from a browser whose session answers the login stage,
// and returns the consent stage's handle, the flow secret and the browser-session secret.
// A flow secret given is the browser's, so the request parked is a sibling of its others.
func (f *deviceConsentFixture) atConsent(t *testing.T, flow, session string) (string, string, string) {
	t.Helper()

	if session == "" {
		session = f.browserSession(t)
	}
	res, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{
		UserCode: entryDisplay, FlowSecret: flow, BrowserSessionSecret: session, Source: entrySource,
	})
	require.NoError(t, err)
	require.Equal(t, issuer+"/consent", pagePath(t, res.Location))

	return handleOf(t, res.Location), res.FlowSecret, session
}

// answer answers the consent stage as u-1, signed in now, and returns the sign-in.
func (f *deviceConsentFixture) answer(t *testing.T, handle, flow string, answer oidcprovider.ConsentAnswer) (oidcprovider.SignIn, oidcprovider.ResumeResult, error) {
	t.Helper()

	s := f.signIn(t, "u-1")
	res, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{Handle: handle, FlowSecret: flow, SignIn: &s, Answer: &answer})

	return s, res, err
}

// stage reads the stage of the request a handle names.
func (f *deviceConsentFixture) stage(t *testing.T, handle string) oidcprovider.Stage {
	t.Helper()

	r, err := f.pending.Load(t.Context(), handleDigestOf(t, handle))
	require.NoError(t, err)

	return r.Stage
}

// state reads the seeded record's state back.
func (f *deviceConsentFixture) state(t *testing.T) *oidcprovider.DeviceAuthorization {
	t.Helper()

	return f.stored(t, f.record)
}

// consentsOf lists what u-1 has given.
func (f *deviceConsentFixture) consentsOf(t *testing.T) []oidcprovider.ConsentView {
	t.Helper()

	got, err := f.p.Consents(t.Context(), "u-1")
	require.NoError(t, err)

	return got
}

// putTV replaces the tv client after a request was parked.
func (f *deviceConsentFixture) putTV(t *testing.T, change func(*oidcprovider.Client)) {
	t.Helper()

	tv := entryClients()[0]
	change(&tv)
	require.NoError(t, f.registry.Put(t.Context(), tv))
}

// entryResult asserts that a redirect is the code-entry URL with its own query kept and
// result added, nothing else, and returns result.
func (f *deviceConsentFixture) entryResult(t *testing.T, redirect string) string {
	t.Helper()

	got, err := url.Parse(redirect)
	require.NoError(t, err)
	want, err := url.Parse(f.entry)
	require.NoError(t, err)
	assert.Equal(t, want.Scheme+"://"+want.Host+want.Path, got.Scheme+"://"+got.Host+got.Path, "the code-entry page")
	query := got.Query()
	require.Len(t, query[oidcprovider.DeviceResultParam], 1, redirect)
	result := query.Get(oidcprovider.DeviceResultParam)
	query.Del(oidcprovider.DeviceResultParam)
	assert.Equal(t, want.Query(), query, "the entry URL's own query is kept, and nothing else added")

	return result
}

// expired asserts the answer of a device authorization that expired before it was decided.
func expired(t *testing.T, f *deviceConsentFixture, res oidcprovider.ResumeResult, err error) {
	t.Helper()

	require.NoError(t, err)
	assert.Equal(t, oidcprovider.DeviceResultExpired, f.entryResult(t, res.RedirectTo))
	assert.Equal(t, oidcprovider.ResumeOutcomeDeviceEntry, res.Outcome)
	assert.Empty(t, res.BrowserSessionSecret)
	assert.Nil(t, f.state(t).Approval, "nothing is approved")
	assert.Zero(t, f.decided.Load(), "nothing is decided")
	assert.Empty(t, f.consentsOf(t), "no consent is remembered")
}

// TestConsentNeeded_Device pins that a device request always asks, where the same request
// from a code flow would not.
func TestConsentNeeded_Device(t *testing.T) {
	t.Parallel()

	const clientID = "tv"
	deviceID, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	type testCase struct {
		name       string
		client     oidcprovider.Client
		scopes     []string
		remembered *oidcprovider.Consent
		assert     func(t *testing.T, device, code bool)
	}

	asksOnlyForDevice := func(t *testing.T, device, code bool) {
		t.Helper()
		assert.True(t, device, "a device request is always asked")
		assert.False(t, code, "the same code-flow request is not")
	}

	cases := []testCase{
		{
			name:   "first-party",
			client: oidcprovider.Client{ID: clientID, ApplicationType: oidcprovider.Native, FirstParty: true},
			scopes: []string{"openid", "profile"},
			assert: asksOnlyForDevice,
		},
		{
			name: "offline access pre-authorized, native",
			client: oidcprovider.Client{
				ID: clientID, ApplicationType: oidcprovider.Native, FirstParty: true, OfflineAccess: oidcprovider.OfflinePreAuthorized,
			},
			scopes: []string{"openid", "offline_access"},
			assert: asksOnlyForDevice,
		},
		{
			name:       "consent remembered for every scope",
			client:     oidcprovider.Client{ID: clientID, ApplicationType: oidcprovider.Native},
			scopes:     []string{"openid", "profile", "offline_access"},
			remembered: &oidcprovider.Consent{ClientID: clientID, Scopes: []string{"openid", "profile"}, Offline: true},
			assert:     asksOnlyForDevice,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rc := &oidcprovider.RegisteredClient{Client: tc.client}
			code := &oidcprovider.PendingRequest{ClientID: clientID, Scopes: tc.scopes}
			device := &oidcprovider.PendingRequest{ClientID: clientID, Scopes: tc.scopes, DeviceAuthorizationID: deviceID, DeviceUserCode: entryDisplay}
			tc.assert(t, oidcprovider.ConsentNeededForTest(rc, device, tc.remembered), oidcprovider.ConsentNeededForTest(rc, code, tc.remembered))
		})
	}
}

// TestResume_DeviceLoginStage pins that a device request's login stage resumes to the
// consent page, whatever would let a code-flow request skip it, and writes no code.
func TestResume_DeviceLoginStage(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup deviceConsentSetup
		// before runs once the request is parked.
		before func(t *testing.T, f *deviceConsentFixture)
		assert func(t *testing.T, f *deviceConsentFixture, handle string, s oidcprovider.SignIn, res oidcprovider.ResumeResult, err error)
	}

	toConsent := func(t *testing.T, f *deviceConsentFixture, handle string, s oidcprovider.SignIn, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, issuer+"/consent", pagePath(t, res.RedirectTo))
		assert.Equal(t, handle, queryOf(t, res.RedirectTo).Get(oidcprovider.HandleParam))
		r, err := f.pending.Load(t.Context(), handleDigestOf(t, handle))
		require.NoError(t, err)
		assert.Equal(t, oidcprovider.StageConsent, r.Stage)
		require.NotNil(t, r.SignIn)
		assert.Equal(t, s.Family, r.SignIn.Family)
		assert.Equal(t, oidcprovider.DeviceClaimed, f.state(t).State, "nothing is decided at the login stage")
		assert.Zero(t, f.decides.Load())
	}

	cases := []testCase{
		{name: "the login stage resumes to the consent page", assert: toConsent},
		{
			name:   "a first-party client is still asked",
			setup:  deviceConsentSetup{client: func(tv *oidcprovider.Client) { tv.FirstParty = true }},
			assert: toConsent,
		},
		{
			name: "consent remembered for every scope is still asked",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				require.NoError(t, f.consents.Give(t.Context(), "u-1", "tv", []string{"openid", "profile"}, true, f.clk.Now()))
			},
			assert: toConsent,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceConsentFixture(t, tc.setup)
			handle, flow := f.atLogin(t)
			if tc.before != nil {
				tc.before(t, f)
			}
			s := f.signIn(t, "u-1")
			res, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{Handle: handle, FlowSecret: flow, SignIn: &s})
			tc.assert(t, f, handle, s, res, err)
		})
	}
}

// TestResume_DeviceApprove pins what an approval records on the device authorization, in
// order: the record is decided, the stage spent, the consent remembered, and the browser sent
// back to the code-entry page with result=approved.
func TestResume_DeviceApprove(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  deviceConsentSetup
		before func(t *testing.T, f *deviceConsentFixture)
		scopes []string
		assert func(t *testing.T, f *deviceConsentFixture, s oidcprovider.SignIn, approval *oidcprovider.DeviceApproval)
	}

	withRefresh := func(tv *oidcprovider.Client) {
		tv.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantDeviceCode, oidcprovider.GrantRefreshToken}
	}
	offline := []string{"openid", "offline_access"}

	cases := []testCase{
		{
			name:   "openid of openid and offline_access, from a client without the refresh grant",
			setup:  deviceConsentSetup{scopes: offline},
			scopes: []string{"openid"},
			assert: func(t *testing.T, f *deviceConsentFixture, s oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.Equal(t, identity.UserID("u-1"), a.User)
				assert.Equal(t, []string{"openid"}, a.GrantedScopes)
				assert.False(t, a.Offline)
				assert.NotEqual(t, id.Nil, a.GrantFamily)
				assert.Equal(t, s.Family, a.SignIn.Family, "the approving sign-in")
				assert.True(t, s.AuthenticatedAt.Equal(a.SignIn.AuthenticatedAt))
				assert.False(t, a.EndsWithSignIn)
				assert.False(t, a.SurvivesSignInEnd)
				consents := f.consentsOf(t)
				require.Len(t, consents, 1)
				assert.Equal(t, "tv", consents[0].ClientID)
				assert.Equal(t, []string{"openid"}, consents[0].Scopes)
				assert.False(t, consents[0].Offline)
			},
		},
		{
			name:   "offline_access granted by a client with the refresh grant",
			setup:  deviceConsentSetup{scopes: offline, client: withRefresh},
			scopes: offline,
			assert: func(t *testing.T, f *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.Equal(t, offline, a.GrantedScopes)
				assert.True(t, a.Offline)
				assert.False(t, a.SurvivesSignInEnd, "an offline grant survives by Offline, not by the flag")
				consents := f.consentsOf(t)
				require.Len(t, consents, 1)
				assert.True(t, consents[0].Offline)
			},
		},
		{
			name:   "DeviceGrantsOutliveSignIn, without offline_access",
			setup:  deviceConsentSetup{client: func(tv *oidcprovider.Client) { tv.DeviceGrantsOutliveSignIn = true }},
			scopes: []string{"openid", "profile"},
			assert: func(t *testing.T, _ *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.False(t, a.Offline)
				assert.True(t, a.SurvivesSignInEnd)
				assert.False(t, a.EndsWithSignIn)
			},
		},
		{
			name: "DeviceGrantsOutliveSignIn, with offline_access",
			setup: deviceConsentSetup{scopes: offline, client: func(tv *oidcprovider.Client) {
				withRefresh(tv)
				tv.DeviceGrantsOutliveSignIn = true
			}},
			scopes: offline,
			assert: func(t *testing.T, _ *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.True(t, a.Offline)
				assert.False(t, a.SurvivesSignInEnd)
			},
		},
		{
			name:   "EndGrantsWithSignIn ties the approval to its sign-in",
			setup:  deviceConsentSetup{scopes: offline, client: func(tv *oidcprovider.Client) { withRefresh(tv); tv.EndGrantsWithSignIn = true }},
			scopes: offline,
			assert: func(t *testing.T, _ *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.True(t, a.EndsWithSignIn)
				assert.False(t, a.SurvivesSignInEnd)
			},
		},
		{
			name:   "a public web client's default ties the approval to its sign-in",
			setup:  deviceConsentSetup{client: func(tv *oidcprovider.Client) { tv.ApplicationType = oidcprovider.Web }},
			scopes: []string{"openid"},
			assert: func(t *testing.T, _ *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.True(t, a.EndsWithSignIn)
			},
		},
		{
			name:   "the code-entry URL's own query is kept",
			setup:  deviceConsentSetup{entry: issuer + "/activate?lang=en&theme=dark"},
			scopes: []string{"openid"},
			assert: func(t *testing.T, _ *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.Equal(t, []string{"openid"}, a.GrantedScopes)
			},
		},
		{
			name: "a scope the client withdrew after the entry is left out",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.putTV(t, func(tv *oidcprovider.Client) { tv.Scopes = []string{"openid"} })
			},
			scopes: []string{"openid", "profile"},
			assert: func(t *testing.T, _ *deviceConsentFixture, _ oidcprovider.SignIn, a *oidcprovider.DeviceApproval) {
				t.Helper()
				assert.Equal(t, []string{"openid"}, a.GrantedScopes)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceConsentFixture(t, tc.setup)
			handle, flow, _ := f.atConsent(t, "", "")
			if tc.before != nil {
				tc.before(t, f)
			}
			s, res, err := f.answer(t, handle, flow, oidcprovider.ConsentAnswer{Scopes: tc.scopes})
			require.NoError(t, err)
			assert.Equal(t, oidcprovider.DeviceResultApproved, f.entryResult(t, res.RedirectTo))
			assert.Equal(t, oidcprovider.ResumeOutcomeDeviceEntry, res.Outcome)
			assert.Empty(t, res.BrowserSessionSecret)
			stored := f.state(t)
			assert.Equal(t, oidcprovider.DeviceApproved, stored.State)
			require.NotNil(t, stored.Approval)
			assert.Equal(t, oidcprovider.StageDone, f.stage(t, handle), "the stage is spent")
			assert.Equal(t, int32(1), f.decided.Load())
			awaitEvent(t, f.events, event.ConsentGiven, 1)
			tc.assert(t, f, s, stored.Approval)
		})
	}
}

// TestResume_DeviceDeny pins that a denial decides the record denied, remembers nothing,
// and sends the browser back with result=denied, and that a malformed denial decides nothing.
func TestResume_DeviceDeny(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		answer oidcprovider.ConsentAnswer
		assert func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error)
	}

	cases := []testCase{
		{
			name:   "a denial",
			answer: oidcprovider.ConsentAnswer{Deny: true},
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.DeviceResultDenied, f.entryResult(t, res.RedirectTo))
				assert.Equal(t, oidcprovider.ResumeOutcomeDeviceEntry, res.Outcome)
				stored := f.state(t)
				assert.Equal(t, oidcprovider.DeviceDenied, stored.State)
				assert.Nil(t, stored.Approval)
				assert.Equal(t, oidcprovider.StageDone, f.stage(t, handle))
				assert.Empty(t, f.consentsOf(t), "no consent is remembered")
				awaitEvent(t, f.events, event.ConsentDenied, 1)
				reportsOf(t, named(f.events.all(), event.ConsentDenied)[0], "tv", "u-1", event.OutcomeFailure)
			},
		},
		{
			name:   "a denial naming scopes is malformed, and decides nothing",
			answer: oidcprovider.ConsentAnswer{Deny: true, Scopes: []string{"openid"}},
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConsentMalformed)
				assert.Empty(t, res.RedirectTo)
				assert.Equal(t, oidcprovider.DeviceClaimed, f.state(t).State)
				assert.Equal(t, oidcprovider.StageConsent, f.stage(t, handle))
				assert.Zero(t, f.decides.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceConsentFixture(t, deviceConsentSetup{})
			handle, flow, _ := f.atConsent(t, "", "")
			_, res, err := f.answer(t, handle, flow, tc.answer)
			tc.assert(t, f, handle, res, err)
		})
	}
}

// TestResume_DeviceExpired pins expiry by the provider's clock, at the consent stage and the
// login stage: an answer at ExpiresAt or later approves nothing and redirects with
// result=expired.
func TestResume_DeviceExpired(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// login resumes the login stage, and otherwise the consent stage is answered.
		login  bool
		at     time.Time
		answer oidcprovider.ConsentAnswer
		// before runs once the request is parked and the clock set.
		before func(t *testing.T, f *deviceConsentFixture)
		assert func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error)
	}

	approve := oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}

	cases := []testCase{
		{
			name:   "an approval a nanosecond before ExpiresAt is approved",
			at:     deviceExpiresAt.Add(-time.Nanosecond),
			answer: approve,
			assert: func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.DeviceResultApproved, f.entryResult(t, res.RedirectTo))
				assert.Equal(t, oidcprovider.DeviceApproved, f.state(t).State)
			},
		},
		{
			name:   "an approval at ExpiresAt",
			at:     deviceExpiresAt,
			answer: approve,
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
				assert.Equal(t, oidcprovider.StageConsent, f.stage(t, handle))
			},
		},
		{
			name:   "an approval after ExpiresAt",
			at:     deviceExpiresAt.Add(30 * time.Second),
			answer: approve,
			assert: func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
			},
		},
		{
			name:   "a denial at ExpiresAt",
			at:     deviceExpiresAt,
			answer: oidcprovider.ConsentAnswer{Deny: true},
			assert: func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
				assert.Equal(t, oidcprovider.DeviceClaimed, f.stored(t, f.record).State, "not denied either")
			},
		},
		{
			name:   "expiry reached between the lookup and the decision",
			at:     deviceExpiresAt.Add(-time.Second),
			answer: approve,
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.lookup = func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
					record, err := f.devices.LoadByUserCode(ctx, digest, now)
					f.clk.Advance(time.Second)

					return record, err
				}
				f.armed.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
				assert.Equal(t, int32(1), f.decides.Load(), "the decision refused it")
			},
		},
		{
			name:  "the login stage resumed after ExpiresAt",
			login: true,
			at:    deviceExpiresAt,
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle), "nothing moves to consent")
				assert.Equal(t, 1, f.pendingHeld(t), "nothing else is parked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceConsentFixture(t, deviceConsentSetup{})
			var handle, flow string
			if tc.login {
				handle, flow = f.atLogin(t)
			} else {
				handle, flow, _ = f.atConsent(t, "", "")
			}
			f.clk.Advance(tc.at.Sub(f.clk.Now()))
			if tc.before != nil {
				tc.before(t, f)
			}

			var res oidcprovider.ResumeResult
			var err error
			if tc.login {
				s := f.signIn(t, "u-1")
				res, err = f.p.Resume(t.Context(), oidcprovider.ResumeInput{Handle: handle, FlowSecret: flow, SignIn: &s})
			} else {
				_, res, err = f.answer(t, handle, flow, tc.answer)
			}
			tc.assert(t, f, handle, res, err)
		})
	}
}

// TestResume_DeviceAdvanceFailsAfterDecide pins the half-applied answer: the record is
// decided and the stage cannot be spent. The decision stands, the answer is a dependency
// failure, the code's re-entry is refused, and a second resume decides nothing and remembers
// nothing.
func TestResume_DeviceAdvanceFailsAfterDecide(t *testing.T) {
	t.Parallel()

	f := newDeviceConsentFixture(t, deviceConsentSetup{})
	handle, flow, _ := f.atConsent(t, "", "")
	f.advanceFails.Store(true)

	_, res, err := f.answer(t, handle, flow, oidcprovider.ConsentAnswer{Scopes: []string{"openid"}})
	require.ErrorIs(t, err, oidcprovider.ErrDependency)
	assert.NotContains(t, err.Error(), errOutage.Error())
	assert.NotContains(t, f.logs.String(), errOutage.Error())
	assert.Empty(t, res.RedirectTo)
	assert.Equal(t, oidcprovider.DeviceApproved, f.state(t).State, "the decision stands")
	assert.Equal(t, oidcprovider.StageConsent, f.stage(t, handle))
	assert.Empty(t, f.consentsOf(t), "nothing is remembered before the stage is spent")

	_, err = f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: flow, Source: entrySource})
	require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode, "the code's re-entry is refused")

	f.advanceFails.Store(false)
	_, res, err = f.answer(t, handle, flow, oidcprovider.ConsentAnswer{Scopes: []string{"openid"}})
	require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
	assert.Empty(t, res.RedirectTo)
	assert.Equal(t, int32(1), f.decided.Load(), "decided once")
	assert.Empty(t, f.consentsOf(t), "nothing remembered by the second resume")
	assert.Empty(t, named(f.events.all(), event.ConsentGiven))
}

// TestResume_DeviceRefused pins what an answer of a device request is refused for, at either
// stage, with nothing decided unless the row says so.
func TestResume_DeviceRefused(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// login resumes the login stage, and otherwise the consent stage is answered.
		login bool
		// bySession answers the consent stage on the browser session, with no sign-in.
		bySession bool
		before    func(t *testing.T, f *deviceConsentFixture)
		assert    func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error)
	}

	unknown := func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.Empty(t, res.RedirectTo)
		assert.Zero(t, f.decided.Load(), "nothing is decided")
		assert.Empty(t, f.consentsOf(t))
	}
	dependency := func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assert.NotContains(t, err.Error(), errStoreBoom.Error())
		assert.NotContains(t, err.Error(), errIDsBoom.Error())
		assert.NotContains(t, f.logs.String(), errStoreBoom.Error())
		assert.NotContains(t, f.logs.String(), errIDsBoom.Error())
		assert.Empty(t, res.RedirectTo)
		assert.Zero(t, f.decided.Load(), "nothing is decided")
		assert.Equal(t, oidcprovider.DeviceClaimed, f.state(t).State)
		assert.Empty(t, f.consentsOf(t))
		assert.NotEqual(t, oidcprovider.StageDone, f.stage(t, handle))
	}
	lostGrant := func(t *testing.T, f *deviceConsentFixture) {
		t.Helper()
		f.putTV(t, func(tv *oidcprovider.Client) {
			tv.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode}
			tv.RedirectURIs = []string{"https://tv.example.com/cb"}
		})
	}
	removed := func(t *testing.T, f *deviceConsentFixture) {
		t.Helper()
		require.NoError(t, f.registry.Delete(t.Context(), "tv"))
	}
	answered := func(t *testing.T, f *deviceConsentFixture) {
		t.Helper()
		f.lookup = func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
			record, err := f.devices.LoadByUserCode(ctx, digest, now)
			if err == nil {
				record.State = oidcprovider.DeviceApproved
			}

			return record, err
		}
		f.armed.Store(true)
	}
	otherFlow := func(t *testing.T, f *deviceConsentFixture) {
		t.Helper()
		f.lookup = func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
			record, err := f.devices.LoadByUserCode(ctx, digest, now)
			if err == nil {
				record.ClaimFlowDigest = digestOf(t, newFlow(t))
			}

			return record, err
		}
		f.armed.Store(true)
	}
	lookupFails := func(t *testing.T, f *deviceConsentFixture) {
		t.Helper()
		f.lookup = func(context.Context, []byte, time.Time) (*oidcprovider.DeviceAuthorization, error) {
			return nil, errStoreBoom
		}
		f.armed.Store(true)
	}

	cases := []testCase{
		{name: "login: a client that lost the device grant", login: true, before: lostGrant, assert: unknown},
		{name: "consent: a client that lost the device grant", before: lostGrant, assert: unknown},
		{name: "login: a client since removed", login: true, before: removed, assert: unknown},
		{name: "consent: a client since removed", before: removed, assert: unknown},
		{name: "login: an authorization already answered through a sibling request", login: true, before: answered, assert: unknown},
		{
			name:   "consent: an authorization already answered through a sibling request is not decided again",
			before: answered,
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				unknown(t, f, handle, res, err)
				assert.Zero(t, f.decides.Load())
			},
		},
		{name: "login: an authorization claimed by another flow", login: true, before: otherFlow, assert: unknown},
		{name: "consent: an authorization claimed by another flow", before: otherFlow, assert: unknown},
		{
			name: "consent: an authorization replaced by another holding its code has expired",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.lookup = func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
					record, err := f.devices.LoadByUserCode(ctx, digest, now)
					if err != nil {
						return nil, err
					}
					record.ID, err = id.NewV7Generator().NewID()

					return record, err
				}
				f.armed.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
			},
		},
		{
			name: "consent: an authorization swept away has expired",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.lookup = func(context.Context, []byte, time.Time) (*oidcprovider.DeviceAuthorization, error) {
					return nil, oidcprovider.ErrNotFound
				}
				f.armed.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, _ string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				expired(t, f, res, err)
			},
		},
		{name: "login: the device store failing the lookup", login: true, before: lookupFails, assert: dependency},
		{name: "consent: the device store failing the lookup", before: lookupFails, assert: dependency},
		{
			name: "consent: the device store failing the decision",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.decide = func() error { return errStoreBoom }
				f.armed.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				dependency(t, f, handle, res, err)
				assert.Equal(t, int32(1), f.decides.Load())
			},
		},
		{
			name: "consent: the identifier generator failing decides nothing",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.ids.armed.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				dependency(t, f, handle, res, err)
				assert.Zero(t, f.decides.Load(), "Decide is never asked")
			},
		},
		{
			name: "consent: remembering the consent failing still answers approved",
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.giveFails.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.DeviceResultApproved, f.entryResult(t, res.RedirectTo))
				assert.Equal(t, oidcprovider.DeviceApproved, f.state(t).State)
				assert.Equal(t, oidcprovider.StageDone, f.stage(t, handle))
				assert.Empty(t, f.consentsOf(t))
				assert.NotContains(t, f.logs.String(), errOutage.Error())
				assert.Contains(t, f.logs.String(), "could not be remembered")
			},
		},
		{
			name:      "consent: a browser session gone by the look after the decision revokes the approval's family",
			bySession: true,
			before: func(t *testing.T, f *deviceConsentFixture) {
				t.Helper()
				f.touchGone.Store(true)
			},
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Empty(t, res.RedirectTo)
				stored := f.state(t)
				require.NotNil(t, stored.Approval)
				g, err := f.grants.Load(t.Context(), stored.Approval.GrantFamily)
				require.NoError(t, err, "a revocation is recorded for the family the exchange will create")
				assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
				assert.Equal(t, oidcprovider.StageConsent, f.stage(t, handle))
				assert.Empty(t, f.consentsOf(t))
			},
		},
		{
			name:      "consent: an approval on the browser session alone",
			bySession: true,
			assert: func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.DeviceResultApproved, f.entryResult(t, res.RedirectTo))
				stored := f.state(t)
				require.NotNil(t, stored.Approval)
				_, err = f.grants.Load(t.Context(), stored.Approval.GrantFamily)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "nothing is revoked")
				assert.Equal(t, oidcprovider.StageDone, f.stage(t, handle))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceConsentFixture(t, deviceConsentSetup{})
			var handle, flow, session string
			if tc.login {
				handle, flow = f.atLogin(t)
			} else {
				handle, flow, session = f.atConsent(t, "", "")
			}
			if tc.before != nil {
				tc.before(t, f)
			}

			in := oidcprovider.ResumeInput{Handle: handle, FlowSecret: flow}
			s := f.signIn(t, "u-1")
			switch {
			case tc.login:
				in.SignIn = &s
			case tc.bySession:
				in.BrowserSessionSecret = session
				in.Answer = &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
			default:
				in.SignIn = &s
				in.Answer = &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
			}
			res, err := f.p.Resume(t.Context(), in)
			tc.assert(t, f, handle, res, err)
		})
	}
}

// TestResume_DeviceSiblingsRace pins that two sibling requests of one browser, one approving
// and one denying at the same moment, decide the record once: one is answered, and the other
// is an unknown handle.
func TestResume_DeviceSiblingsRace(t *testing.T) {
	t.Parallel()

	for round := range 8 {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			t.Parallel()

			f := newDeviceConsentFixture(t, deviceConsentSetup{})
			approveHandle, flow, session := f.atConsent(t, "", "")
			denyHandle, again, _ := f.atConsent(t, flow, session)
			require.Equal(t, flow, again)

			// Both resumes reach Decide before either is let through.
			arrived := make(chan struct{}, 2)
			release := make(chan struct{})
			f.decide = func() error {
				arrived <- struct{}{}
				select {
				case <-release:
					return nil
				case <-time.After(10 * time.Second):
					return errors.New("the sibling never reached the decision")
				}
			}
			f.armed.Store(true)

			type outcome struct {
				res oidcprovider.ResumeResult
				err error
			}
			results := make(chan outcome, 2)
			for _, a := range []struct {
				handle string
				answer oidcprovider.ConsentAnswer
			}{
				{approveHandle, oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}},
				{denyHandle, oidcprovider.ConsentAnswer{Deny: true}},
			} {
				s := f.signIn(t, "u-1")
				go func() {
					res, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{Handle: a.handle, FlowSecret: flow, SignIn: &s, Answer: &a.answer})
					results <- outcome{res, err}
				}()
			}
			for range 2 {
				select {
				case <-arrived:
				case <-time.After(10 * time.Second):
					t.Fatal("both resumes did not reach the decision")
				}
			}
			close(release)

			var won []string
			var lost int
			for range 2 {
				o := <-results
				if o.err != nil {
					require.ErrorIs(t, o.err, oidcprovider.ErrUnknownHandle)
					lost++

					continue
				}
				won = append(won, f.entryResult(t, o.res.RedirectTo))
			}
			require.Len(t, won, 1, "exactly one answer")
			assert.Equal(t, 1, lost)
			assert.Equal(t, int32(1), f.decided.Load(), "decided once")

			stored := f.state(t)
			switch won[0] {
			case oidcprovider.DeviceResultApproved:
				assert.Equal(t, oidcprovider.DeviceApproved, stored.State)
				assert.True(t, slices.ContainsFunc(f.consentsOf(t), func(c oidcprovider.ConsentView) bool { return c.ClientID == "tv" }))
			case oidcprovider.DeviceResultDenied:
				assert.Equal(t, oidcprovider.DeviceDenied, stored.State)
				assert.Empty(t, f.consentsOf(t))
			default:
				t.Fatalf("unexpected result %q", won[0])
			}
		})
	}
}

// TestResume_DeviceWithdrawalOutlivesGrantSweep pins that the revocation recorded when an
// approval is withdrawn lasts as long as the approved authorization can still be exchanged:
// under the longest device lifetime, the grants sweep run well past the longest code
// lifetime keeps it.
func TestResume_DeviceWithdrawalOutlivesGrantSweep(t *testing.T) {
	t.Parallel()

	f := newDeviceConsentFixture(t, deviceConsentSetup{lifetime: 30 * time.Minute})
	handle, flow, session := f.atConsent(t, "", "")
	f.touchGone.Store(true)

	_, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle: handle, FlowSecret: flow, BrowserSessionSecret: session,
		Answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}},
	})
	require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
	approved := f.state(t)
	require.Equal(t, oidcprovider.DeviceApproved, approved.State)
	family := approved.Approval.GrantFamily

	f.clk.Advance(12 * time.Minute)
	require.True(t, f.clk.Now().Before(approved.ExpiresAt), "the approval can still be exchanged")
	ran := false
	for _, task := range oidcprovider.ExpiryTasks(f.p) {
		if task.Name != "oidc-provider.grants" {
			continue
		}
		_, err := task.Run(t.Context())
		require.NoError(t, err)
		ran = true
	}
	require.True(t, ran, "the grants task runs")

	g, err := f.grants.Load(t.Context(), family)
	require.NoError(t, err, "the withdrawal outlives every exchange the approval still allows")
	assert.True(t, g.Revoked)
}

// TestResume_DeviceTouchFailsAfterDecide pins an approval whose browser session cannot be
// confirmed because its store fails after the decision: the approval is withdrawn, and the
// answer is a dependency failure carrying no store text.
func TestResume_DeviceTouchFailsAfterDecide(t *testing.T) {
	t.Parallel()

	f := newDeviceConsentFixture(t, deviceConsentSetup{})
	handle, flow, session := f.atConsent(t, "", "")
	f.touchFails.Store(true)

	res, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle: handle, FlowSecret: flow, BrowserSessionSecret: session,
		Answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}},
	})
	require.ErrorIs(t, err, oidcprovider.ErrDependency)
	assert.NotErrorIs(t, err, oidcprovider.ErrReauthenticate)
	assert.NotContains(t, err.Error(), errOutage.Error())
	assert.NotContains(t, f.logs.String(), errOutage.Error())
	assert.Empty(t, res.RedirectTo)
	stored := f.state(t)
	require.NotNil(t, stored.Approval)
	g, err := f.grants.Load(t.Context(), stored.Approval.GrantFamily)
	require.NoError(t, err, "the approval is withdrawn: a revocation is recorded for its family")
	assert.True(t, g.Revoked)
	assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
	assert.Equal(t, oidcprovider.StageConsent, f.stage(t, handle))
	assert.Empty(t, f.consentsOf(t), "no consent is remembered")
}

// TestResume_DeviceWithdrawalFails pins a withdrawal the grant store cannot record: the
// failure is logged by its type alone, with no store text, and the caller's answer is the
// one the session's confirmation gave, unchanged by the failed withdrawal.
func TestResume_DeviceWithdrawalFails(t *testing.T) {
	t.Parallel()

	f := newDeviceConsentFixture(t, deviceConsentSetup{})
	handle, flow, session := f.atConsent(t, "", "")
	f.touchGone.Store(true)
	f.revokeFails.Store(true)

	res, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle: handle, FlowSecret: flow, BrowserSessionSecret: session,
		Answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}},
	})
	require.ErrorIs(t, err, oidcprovider.ErrReauthenticate, "the answer is the confirmation's")
	assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
	assert.NotContains(t, err.Error(), errGrantStoreDown.Error())
	assert.Empty(t, res.RedirectTo)

	logs := f.logs.String()
	assert.Contains(t, logs, "could not be withdrawn")
	assert.Contains(t, logs, "error_type=")
	assert.NotContains(t, logs, errGrantStoreDown.Error())
	assert.NotContains(t, logs, flow)
	assert.NotContains(t, logs, session)
	assert.NotContains(t, logs, entryCode)

	stored := f.state(t)
	require.NotNil(t, stored.Approval)
	_, err = f.grants.Load(t.Context(), stored.Approval.GrantFamily)
	require.ErrorIs(t, err, oidcprovider.ErrNotFound, "no revocation could be recorded")
	assert.Empty(t, f.consentsOf(t))
}

// TestResume_DeviceDenyAdvanceFailsAfterDecide pins the half-applied denial: the record is
// denied and the stage cannot be spent. The denial stands, the answer is a dependency
// failure, the code's re-entry is refused, a second resume finds no handle, and no consent is
// remembered.
func TestResume_DeviceDenyAdvanceFailsAfterDecide(t *testing.T) {
	t.Parallel()

	f := newDeviceConsentFixture(t, deviceConsentSetup{})
	handle, flow, _ := f.atConsent(t, "", "")
	f.advanceFails.Store(true)

	_, res, err := f.answer(t, handle, flow, oidcprovider.ConsentAnswer{Deny: true})
	require.ErrorIs(t, err, oidcprovider.ErrDependency)
	assert.NotContains(t, err.Error(), errOutage.Error())
	assert.NotContains(t, f.logs.String(), errOutage.Error())
	assert.Empty(t, res.RedirectTo)
	assert.Equal(t, oidcprovider.DeviceDenied, f.state(t).State, "the denial stands")
	assert.Nil(t, f.state(t).Approval)
	assert.Equal(t, oidcprovider.StageConsent, f.stage(t, handle))

	_, err = f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: flow, Source: entrySource})
	require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode, "the code's re-entry is refused")

	f.advanceFails.Store(false)
	_, res, err = f.answer(t, handle, flow, oidcprovider.ConsentAnswer{Deny: true})
	require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
	assert.Empty(t, res.RedirectTo)
	assert.Equal(t, int32(1), f.decided.Load(), "decided once")
	assert.Empty(t, f.consentsOf(t), "no consent is remembered")
	assert.Empty(t, named(f.events.all(), event.ConsentDenied))
	assert.Empty(t, named(f.events.all(), event.ConsentGiven))
}
