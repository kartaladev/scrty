package oidcprovider_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// The device token rows' clients: tv may not refresh, tv-refresh may, tv-dpop must prove a
// key, and cli is confidential. billing-web holds the code grant alone.
const (
	tvClient      = "tv"
	tvRefresh     = "tv-refresh"
	tvDPoP        = "tv-dpop"
	cliClient     = "cli"
	deviceAPI     = "https://api.example.com"
	deviceACR     = "urn:example:acr:silver"
	deviceSIValid = 8 * time.Hour
)

// deviceJKT is a well-formed RFC 7638 thumbprint, for the rows that prove a key.
var deviceJKT = func() string {
	sum := sha256.Sum256([]byte("device-key"))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}()

// errDeviceStoreDown is a device store's failure, whose text must never leave the provider.
var errDeviceStoreDown = errors.New("device-store-dsn-postgres://hunter2@db")

// deviceTokenFixture is a provider with the device grant on, over memory stores, whose
// device store a row may fail or watch.
type deviceTokenFixture struct {
	p        *oidcprovider.Provider
	clk      *clockwork.FakeClock
	devices  *oidcprovider.MemoryDeviceAuthorizationStore
	grants   *oidcprovider.MemoryGrantStore
	registry *oidcprovider.MemoryRegistry
	users    *exchangeUsers
	keys     *exchangeKeys
	logs     *syncBuffer

	// loads and polls count LoadByDeviceCode and RecordPoll calls.
	loads, polls atomic.Int32
	// loadFails, pollFails and spendFails fail those calls as a store failing, and spendLost
	// answers Spend's lost compare.
	loadFails, pollFails, spendFails, spendLost atomic.Bool
	// loadsNothing makes LoadByDeviceCode answer neither a record nor an error.
	loadsNothing atomic.Bool
	// barrier, when set, is waited on after each load, so concurrent polls read one version.
	barrier *sync.WaitGroup
}

func deviceTokenClients() []oidcprovider.Client {
	device := func(clientID string, grants ...oidcprovider.GrantType) oidcprovider.Client {
		return oidcprovider.Client{
			ID: clientID, Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
			GrantTypes: append([]oidcprovider.GrantType{oidcprovider.GrantDeviceCode}, grants...),
			Scopes:     []string{"openid", "profile", "offline_access"},
			Resources:  []string{deviceAPI},
		}
	}
	dpop := device(tvDPoP, oidcprovider.GrantRefreshToken)
	dpop.RequireBinding = oidcprovider.BindingDPoP
	web := webClient()
	web.Scopes = []string{"openid"}

	return []oidcprovider.Client{
		device(tvClient),
		device(tvRefresh, oidcprovider.GrantRefreshToken),
		dpop,
		{
			ID: cliClient, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret),
			AuthMethod: oidcprovider.ClientSecretPost, GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantDeviceCode},
			Scopes: []string{"openid"},
		},
		web,
	}
}

func newDeviceTokenFixture(t *testing.T) *deviceTokenFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(deviceNow)
	devices := oidcprovider.NewMemoryDeviceAuthorizationStore()
	grants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	registry, err := oidcprovider.NewMemoryRegistry(deviceTokenClients())
	require.NoError(t, err)

	users := &exchangeUsers{disabled: map[identity.UserID]bool{}, missing: map[identity.UserID]bool{}}
	ctrl := gomock.NewController(t)
	loader := NewMockUserLoader(ctrl)
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return users.load(user) },
	).AnyTimes()

	f := &deviceTokenFixture{
		clk: clk, devices: devices, grants: grants, registry: registry, users: users,
		keys: newExchangeKeys(t), logs: &syncBuffer{},
	}
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         f.keys,
		Users:        loader,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))),
		oidcprovider.WithDeviceAuthorization(issuer+"/activate",
			oidcprovider.WithUserCodeKey(deviceKey),
			oidcprovider.WithDeviceAuthorizationStore(f.hookDevices(ctrl)),
		),
	)
	require.NoError(t, err)
	f.p = p

	return f
}

// hookDevices is the memory device store behind a generated mock, failing or watching what
// a row asks.
func (f *deviceTokenFixture) hookDevices(ctrl *gomock.Controller) oidcprovider.DeviceAuthorizationStore {
	memory := f.devices
	store := NewMockDeviceAuthorizationStore(ctrl)
	store.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()
	store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.LoadByUserCode).AnyTimes()
	store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Claim).AnyTimes()
	store.EXPECT().Decide(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Decide).AnyTimes()
	store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memory.DeleteExpired).AnyTimes()
	store.EXPECT().UnspentBySignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.UnspentBySignIn).AnyTimes()
	store.EXPECT().UnspentByClient(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.UnspentByClient).AnyTimes()
	store.EXPECT().LoadByDeviceCode(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte) (*oidcprovider.DeviceAuthorization, error) {
			f.loads.Add(1)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if f.loadFails.Load() {
				return nil, errDeviceStoreDown
			}
			if f.loadsNothing.Load() {
				return nil, nil //nolint:nilnil // a store breaking its contract
			}
			record, err := memory.LoadByDeviceCode(ctx, digest)
			if f.barrier != nil {
				f.barrier.Done()
				f.barrier.Wait()
			}

			return record, err
		}).AnyTimes()
	store.EXPECT().RecordPoll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, deviceID id.ID, seen int, at time.Time, interval time.Duration) error {
			f.polls.Add(1)
			if f.pollFails.Load() {
				return errDeviceStoreDown
			}

			return memory.RecordPoll(ctx, deviceID, seen, at, interval)
		}).AnyTimes()
	store.EXPECT().Spend(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, deviceID id.ID, now time.Time) error {
			switch {
			case f.spendFails.Load():
				return errDeviceStoreDown
			case f.spendLost.Load():
				return oidcprovider.ErrNotFound
			}

			return memory.Spend(ctx, deviceID, now)
		}).AnyTimes()

	return store
}

// seed stores a device authorization for clientID, issued now and living ten minutes, with a
// five-second interval, as change leaves it, and returns its device code.
func (f *deviceTokenFixture) seed(t *testing.T, clientID string, change func(*oidcprovider.DeviceAuthorization)) (string, *oidcprovider.DeviceAuthorization) {
	t.Helper()

	code, digest, err := oidcprovider.MintDeviceCodeForTest(rand.Reader)
	require.NoError(t, err)
	recordID, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	userDigest := sha256.Sum256([]byte("user-code-" + recordID.String()))
	now := f.clk.Now()
	record := &oidcprovider.DeviceAuthorization{
		ID:               recordID,
		DeviceCodeDigest: digest,
		UserCodeDigest:   userDigest[:],
		ClientID:         clientID,
		Scopes:           []string{"openid", "profile", "offline_access"},
		Resources:        []string{deviceAPI},
		IssuedAt:         now,
		ExpiresAt:        now.Add(10 * time.Minute),
		Interval:         5 * time.Second,
		State:            oidcprovider.DeviceIssued,
	}
	if change != nil {
		change(record)
	}
	require.NoError(t, f.devices.Create(t.Context(), record, now))

	return code, record
}

// stored reads a record back.
func (f *deviceTokenFixture) stored(t *testing.T, record *oidcprovider.DeviceAuthorization) *oidcprovider.DeviceAuthorization {
	t.Helper()

	got, err := f.devices.LoadByDeviceCode(t.Context(), record.DeviceCodeDigest)
	require.NoError(t, err)

	return got
}

// approved makes a record approved by u-1 for scopes, under a sign-in that authenticated a
// minute ago and lasts eight hours, with offline_access granted when scopes hold it.
func approved(scopes ...string) func(*oidcprovider.DeviceAuthorization) {
	return func(r *oidcprovider.DeviceAuthorization) {
		family, err := id.NewV7Generator().NewID()
		if err != nil {
			panic(err)
		}
		signInFamily, err := id.NewV7Generator().NewID()
		if err != nil {
			panic(err)
		}
		offline := false
		for _, s := range scopes {
			offline = offline || s == "offline_access"
		}
		r.State = oidcprovider.DeviceApproved
		r.ClaimFlowDigest = []byte("flow-digest")
		r.Approval = &oidcprovider.DeviceApproval{
			User:          "u-1",
			GrantedScopes: scopes,
			SignIn: oidcprovider.SignIn{
				User:              "u-1",
				Family:            signInFamily,
				AuthenticatedAt:   r.IssuedAt.Add(-time.Minute),
				AMR:               []string{"pwd", "otp"},
				ACR:               deviceACR,
				AbsoluteExpiresAt: r.IssuedAt.Add(deviceSIValid),
			},
			GrantFamily: family,
			Offline:     offline,
		}
	}
}

// then applies changes in order.
func then(changes ...func(*oidcprovider.DeviceAuthorization)) func(*oidcprovider.DeviceAuthorization) {
	return func(r *oidcprovider.DeviceAuthorization) {
		for _, change := range changes {
			change(r)
		}
	}
}

// deviceRequest is a poll by clientID with code, as the client authenticates.
func deviceRequest(clientID, code string) oidcprovider.TokenRequest {
	form := url.Values{
		"grant_type": {string(oidcprovider.GrantDeviceCode)},
		"client_id":  {clientID},
	}
	if code != "" {
		form.Set("device_code", code)
	}
	switch clientID {
	case cliClient:
		form.Set("client_secret", exchangeSecret)
	case "billing-web":
		form.Del("client_id")

		return oidcprovider.TokenRequest{
			Credentials: oidcprovider.ClientCredentials{Authorization: basic(clientID, exchangeSecret)},
			Form:        form,
		}
	}

	return oidcprovider.TokenRequest{Form: form}
}

// grantRow is the grant stored under family, or nil when there is none.
func (f *deviceTokenFixture) grantRow(t *testing.T, family id.ID) *oidcprovider.Grant {
	t.Helper()

	g, err := f.grants.Load(t.Context(), family)
	if errors.Is(err, oidcprovider.ErrNotFound) {
		return nil
	}
	require.NoError(t, err)

	return g
}

// assertNoDeviceSecret checks that an error and the logs repeat neither the device code
// nor the store's own text.
func (f *deviceTokenFixture) assertNoDeviceSecret(t *testing.T, code string, err error) {
	t.Helper()

	if err != nil {
		assert.NotContains(t, err.Error(), code)
		assert.NotContains(t, err.Error(), errDeviceStoreDown.Error())
	}
	assert.NotContains(t, f.logs.String(), code)
	assert.NotContains(t, f.logs.String(), errDeviceStoreDown.Error())
}

// assertNotPolling checks that err tells the client nothing that would keep it polling.
func assertNotPolling(t *testing.T, err error) {
	t.Helper()

	var refusal *oidcprovider.Error
	assert.False(t, errors.As(err, &refusal), "a failure is no protocol answer, got %v", err)
}

func TestToken_DeviceDispatch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// request builds the provider and the request a row sends.
		request func(t *testing.T, f *deviceTokenFixture) (*oidcprovider.Provider, oidcprovider.TokenRequest)
		assert  func(t *testing.T, f *deviceTokenFixture, res *oidcprovider.TokenResponse, err error)
	}

	refusedUnread := func(code string) func(*testing.T, *deviceTokenFixture, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, f *deviceTokenFixture, res *oidcprovider.TokenResponse, err error) {
			assert.Nil(t, res)
			assertRefused(t, err, code)
			assert.Zero(t, f.loads.Load(), "no device record is read")
		}
	}
	poll := func(clientID string, change func(*oidcprovider.DeviceAuthorization)) func(*testing.T, *deviceTokenFixture) (*oidcprovider.Provider, oidcprovider.TokenRequest) {
		return func(t *testing.T, f *deviceTokenFixture) (*oidcprovider.Provider, oidcprovider.TokenRequest) {
			code, _ := f.seed(t, clientID, change)

			return f.p, deviceRequest(clientID, code)
		}
	}
	withForm := func(clientID string, form func(code string, v url.Values)) func(*testing.T, *deviceTokenFixture) (*oidcprovider.Provider, oidcprovider.TokenRequest) {
		return func(t *testing.T, f *deviceTokenFixture) (*oidcprovider.Provider, oidcprovider.TokenRequest) {
			code, _ := f.seed(t, clientID, nil)
			r := deviceRequest(clientID, code)
			form(code, r.Form)

			return f.p, r
		}
	}

	cases := []testCase{
		{
			name: "a provider without the grant answers unsupported_grant_type",
			request: func(t *testing.T, _ *deviceTokenFixture) (*oidcprovider.Provider, oidcprovider.TokenRequest) {
				return newExchangeFixture(t).p, deviceRequest("billing-web", "anything")
			},
			assert: refusedUnread(oidcprovider.CodeUnsupportedGrantType),
		},
		{
			name:    "a client without the grant answers unauthorized_client",
			request: poll("billing-web", nil),
			assert:  refusedUnread(oidcprovider.CodeUnauthorizedClient),
		},
		{
			name:    "a client required to prove a key, without a proof, answers invalid_dpop_proof and reads nothing",
			request: poll(tvDPoP, approved("openid")),
			assert:  refusedUnread(oidcprovider.CodeInvalidDPoPProof),
		},
		{
			name:    "a missing device_code answers invalid_request",
			request: withForm(tvClient, func(_ string, v url.Values) { v.Del("device_code") }),
			assert:  refusedUnread(oidcprovider.CodeInvalidRequest),
		},
		{
			name:    "an empty device_code answers invalid_request",
			request: withForm(tvClient, func(_ string, v url.Values) { v.Set("device_code", "") }),
			assert:  refusedUnread(oidcprovider.CodeInvalidRequest),
		},
		{
			name:    "a repeated device_code answers invalid_request",
			request: withForm(tvClient, func(code string, v url.Values) { v.Add("device_code", code) }),
			assert:  refusedUnread(oidcprovider.CodeInvalidRequest),
		},
		{
			name:    "a device_code the provider could not have minted answers invalid_grant unread",
			request: withForm(tvClient, func(_ string, v url.Values) { v.Set("device_code", "not a code!") }),
			assert:  refusedUnread(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "an oversized device_code answers invalid_grant unread",
			request: withForm(tvClient, func(code string, v url.Values) {
				v.Set("device_code", code+code+code)
			}),
			assert: refusedUnread(oidcprovider.CodeInvalidGrant),
		},
		{
			name:    "the device grant is dispatched for a client holding it",
			request: poll(tvClient, nil),
			assert: func(t *testing.T, f *deviceTokenFixture, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeAuthorizationPending)
				assert.EqualValues(t, 1, f.loads.Load())
			},
		},
		{
			name:    "a confidential client authenticates and is dispatched",
			request: poll(cliClient, nil),
			assert: func(t *testing.T, _ *deviceTokenFixture, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeAuthorizationPending)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceTokenFixture(t)
			p, r := tc.request(t, f)
			res, err := p.Token(t.Context(), r)
			tc.assert(t, f, res, err)
		})
	}
}

func TestToken_DeviceStates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		client string
		seed   func(*oidcprovider.DeviceAuthorization)
		// arrange runs after seeding, and may replace the code polled with.
		arrange func(t *testing.T, f *deviceTokenFixture, code string) string
		// after is how long after issue the poll comes.
		after  time.Duration
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, f *deviceTokenFixture, before *oidcprovider.DeviceAuthorization, code string, res *oidcprovider.TokenResponse, err error)
	}

	answered := func(code string) func(*testing.T, *deviceTokenFixture, *oidcprovider.DeviceAuthorization, string, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, _ *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization, _ string, res *oidcprovider.TokenResponse, err error) {
			assert.Nil(t, res)
			assertRefused(t, err, code)
		}
	}
	unchanged := func(code string) func(*testing.T, *deviceTokenFixture, *oidcprovider.DeviceAuthorization, string, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, f *deviceTokenFixture, before *oidcprovider.DeviceAuthorization, _ string, res *oidcprovider.TokenResponse, err error) {
			assert.Nil(t, res)
			assertRefused(t, err, code)
			assert.Equal(t, before, f.stored(t, before), "the record is as it was")
			assert.Zero(t, f.polls.Load(), "no poll is recorded")
			if before.Approval != nil {
				assert.Nil(t, f.grantRow(t, before.Approval.GrantFamily), "no grant is recorded")
			}
		}
	}
	dependency := func(t *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization, code string, res *oidcprovider.TokenResponse, err error) {
		assert.Nil(t, res)
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assertNotPolling(t, err)
		f.assertNoDeviceSecret(t, code, err)
	}
	claimed := func(r *oidcprovider.DeviceAuthorization) {
		r.State, r.ClaimFlowDigest = oidcprovider.DeviceClaimed, []byte("flow-digest")
	}
	denied := func(r *oidcprovider.DeviceAuthorization) {
		r.State, r.ClaimFlowDigest = oidcprovider.DeviceDenied, []byte("flow-digest")
	}
	spent := func(r *oidcprovider.DeviceAuthorization) { r.State = oidcprovider.DeviceSpent }

	cases := []testCase{
		{
			name: "issued answers authorization_pending and records the poll", client: tvClient,
			assert: func(t *testing.T, f *deviceTokenFixture, before *oidcprovider.DeviceAuthorization, _ string, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeAuthorizationPending)
				got := f.stored(t, before)
				assert.Equal(t, 1, got.PollCount)
				assert.Equal(t, deviceNow, got.LastPolledAt)
				assert.Equal(t, 5*time.Second, got.Interval)
			},
		},
		{name: "claimed answers authorization_pending", client: tvClient, seed: claimed, assert: answered(oidcprovider.CodeAuthorizationPending)},
		{name: "denied answers access_denied, unchanged", client: tvClient, seed: denied, assert: unchanged(oidcprovider.CodeAccessDenied)},
		{
			name: "issued at exactly ExpiresAt answers expired_token", client: tvClient, after: 10 * time.Minute,
			assert: unchanged(oidcprovider.CodeExpiredToken),
		},
		{
			name: "issued a nanosecond before ExpiresAt is still pending", client: tvClient, after: 10*time.Minute - time.Nanosecond,
			assert: answered(oidcprovider.CodeAuthorizationPending),
		},
		{
			name: "claimed after ExpiresAt answers expired_token", client: tvClient, seed: claimed, after: time.Hour,
			assert: unchanged(oidcprovider.CodeExpiredToken),
		},
		{
			name: "denied after ExpiresAt answers expired_token", client: tvClient, seed: denied, after: 10 * time.Minute,
			assert: unchanged(oidcprovider.CodeExpiredToken),
		},
		{
			name: "approved at exactly ExpiresAt answers expired_token, unspent", client: tvClient, seed: approved("openid"),
			after: 10 * time.Minute, assert: unchanged(oidcprovider.CodeExpiredToken),
		},
		{
			name: "an unknown code answers invalid_grant", client: tvClient,
			arrange: func(t *testing.T, _ *deviceTokenFixture, _ string) string {
				code, _, err := oidcprovider.MintDeviceCodeForTest(rand.Reader)
				require.NoError(t, err)

				return code
			},
			assert: unchanged(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "another client's pending code answers invalid_grant, unchanged", client: tvRefresh,
			arrange: func(t *testing.T, f *deviceTokenFixture, _ string) string {
				code, _ := f.seed(t, tvClient, nil)

				return code
			},
			assert: func(t *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization, _ string, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Zero(t, f.polls.Load(), "no poll is recorded")
			},
		},
		{
			name: "another client's approved code answers invalid_grant, unspent", client: tvRefresh,
			arrange: func(t *testing.T, f *deviceTokenFixture, _ string) string {
				code, record := f.seed(t, tvClient, approved("openid"))
				t.Cleanup(func() {
					assert.Equal(t, oidcprovider.DeviceApproved, f.stored(t, record).State, "the record stays unspent")
					assert.Nil(t, f.grantRow(t, record.Approval.GrantFamily))
				})

				return code
			},
			assert: answered(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a spent code answers invalid_grant", client: tvClient, seed: then(approved("openid"), spent),
			assert: unchanged(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a spent code after expiry answers invalid_grant, not expired_token", client: tvClient,
			seed: then(approved("openid"), spent), after: 10 * time.Minute,
			assert: unchanged(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a failing load is a dependency failure, never pending", client: tvClient,
			arrange: func(_ *testing.T, f *deviceTokenFixture, code string) string { f.loadFails.Store(true); return code },
			assert:  dependency,
		},
		{
			name: "a load answering nothing is a dependency failure", client: tvClient,
			arrange: func(_ *testing.T, f *deviceTokenFixture, code string) string { f.loadsNothing.Store(true); return code },
			assert:  dependency,
		},
		{
			name: "a failing poll write is a dependency failure, never pending", client: tvClient,
			arrange: func(_ *testing.T, f *deviceTokenFixture, code string) string { f.pollFails.Store(true); return code },
			assert:  dependency,
		},
		{
			name: "a failing poll write inside the interval is a dependency failure, never slow_down", client: tvClient,
			seed:    func(r *oidcprovider.DeviceAuthorization) { r.LastPolledAt = r.IssuedAt },
			arrange: func(_ *testing.T, f *deviceTokenFixture, code string) string { f.pollFails.Store(true); return code },
			after:   time.Second, assert: dependency,
		},
		{
			name: "an approved record without its approval is a dependency failure, unspent", client: tvClient,
			seed: func(r *oidcprovider.DeviceAuthorization) { r.State = oidcprovider.DeviceApproved },
			assert: func(t *testing.T, f *deviceTokenFixture, before *oidcprovider.DeviceAuthorization, code string, res *oidcprovider.TokenResponse, err error) {
				dependency(t, f, before, code, res, err)
				assert.Equal(t, oidcprovider.DeviceApproved, f.stored(t, before).State)
			},
		},
		{
			name: "an approval naming the nil grant family is a dependency failure, unspent", client: tvClient,
			seed: then(approved("openid"), func(r *oidcprovider.DeviceAuthorization) { r.Approval.GrantFamily = id.Nil }),
			assert: func(t *testing.T, f *deviceTokenFixture, before *oidcprovider.DeviceAuthorization, code string, res *oidcprovider.TokenResponse, err error) {
				dependency(t, f, before, code, res, err)
				assert.Equal(t, oidcprovider.DeviceApproved, f.stored(t, before).State)
			},
		},
		{
			name: "a caller who left gets its own error, never pending", client: tvClient,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, f *deviceTokenFixture, before *oidcprovider.DeviceAuthorization, _ string, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				require.ErrorIs(t, err, context.Canceled)
				assertNotPolling(t, err)
				assert.Equal(t, before, f.stored(t, before))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceTokenFixture(t)
			code, record := f.seed(t, tvClient, tc.seed)
			if tc.arrange != nil {
				code = tc.arrange(t, f, code)
			}
			before := f.stored(t, record)
			f.clk.Advance(tc.after)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			res, err := f.p.Token(ctx, deviceRequest(tc.client, code))
			tc.assert(t, f, before, code, res, err)
		})
	}
}

func TestToken_DeviceSlowDown(t *testing.T) {
	t.Parallel()

	// step is one poll, at an offset from issue, and the error code it is answered with, or ""
	// for tokens.
	type step struct {
		at   time.Duration
		want string
	}
	type testCase struct {
		name   string
		seed   func(*oidcprovider.DeviceAuthorization)
		steps  []step
		assert func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization)
	}

	pending, slow := oidcprovider.CodeAuthorizationPending, oidcprovider.CodeSlowDown
	justPolled := func(r *oidcprovider.DeviceAuthorization) { r.LastPolledAt, r.PollCount = r.IssuedAt, 1 }
	noPace := func(t *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
		assert.Zero(t, f.polls.Load(), "no RecordPoll for a record answered by its state")
	}

	cases := []testCase{
		{
			name: "a poll inside the interval grows it by 5 s, and it stays grown",
			// 2 s after the first poll is too soon: 10 s. 6 s after that is still too soon: 15 s.
			// 15 s after that, at 23 s, is pending again.
			steps: []step{{0, pending}, {2 * time.Second, slow}, {8 * time.Second, slow}, {23 * time.Second, pending}},
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization) {
				got := f.stored(t, record)
				assert.Equal(t, 15*time.Second, got.Interval)
				assert.Equal(t, 4, got.PollCount)
				assert.Equal(t, deviceNow.Add(23*time.Second), got.LastPolledAt)
			},
		},
		{
			name:  "a poll a nanosecond short of the interval is slowed down, and one at it is not",
			seed:  justPolled,
			steps: []step{{5*time.Second - time.Nanosecond, slow}, {15*time.Second - time.Nanosecond, pending}},
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization) {
				assert.Equal(t, 10*time.Second, f.stored(t, record).Interval)
			},
		},
		{
			name: "a clock behind the last poll counts as too soon and leaves the last poll where it was",
			seed: func(r *oidcprovider.DeviceAuthorization) {
				r.LastPolledAt, r.PollCount = r.IssuedAt.Add(time.Minute), 1
			},
			steps: []step{{0, slow}},
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization) {
				got := f.stored(t, record)
				assert.Equal(t, 10*time.Second, got.Interval)
				assert.Equal(t, record.IssuedAt.Add(time.Minute), got.LastPolledAt)
			},
		},
		{
			name: "a poll from a slow clock does not let the next poll on a true clock in early",
			seed: func(r *oidcprovider.DeviceAuthorization) {
				r.LastPolledAt, r.PollCount = r.IssuedAt.Add(10*time.Second), 1
			},
			steps: []step{{time.Second, slow}, {12 * time.Second, slow}},
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization) {
				got := f.stored(t, record)
				assert.Equal(t, 15*time.Second, got.Interval)
				assert.Equal(t, record.IssuedAt.Add(12*time.Second), got.LastPolledAt)
			},
		},
		{
			name:   "an approved record polled too soon gets its tokens",
			seed:   then(justPolled, approved("openid")),
			steps:  []step{{time.Second, ""}},
			assert: noPace,
		},
		{
			name:   "a denied record polled each second answers access_denied",
			seed:   then(justPolled, func(r *oidcprovider.DeviceAuthorization) { r.State = oidcprovider.DeviceDenied }),
			steps:  []step{{time.Second, oidcprovider.CodeAccessDenied}, {2 * time.Second, oidcprovider.CodeAccessDenied}},
			assert: noPace,
		},
		{
			name: "an expired record polled each second answers expired_token",
			seed: then(justPolled, func(r *oidcprovider.DeviceAuthorization) { r.ExpiresAt = r.IssuedAt.Add(time.Second) }),
			steps: []step{
				{time.Second, oidcprovider.CodeExpiredToken}, {2 * time.Second, oidcprovider.CodeExpiredToken},
			},
			assert: noPace,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceTokenFixture(t)
			code, record := f.seed(t, tvClient, tc.seed)
			for _, s := range tc.steps {
				f.clk.Advance(deviceNow.Add(s.at).Sub(f.clk.Now()))
				res, err := f.p.Token(t.Context(), deviceRequest(tvClient, code))
				if s.want == "" {
					require.NoError(t, err, "at %v", s.at)
					assert.NotEmpty(t, res.AccessToken)

					continue
				}
				assert.Nil(t, res)
				assertRefused(t, err, s.want)
			}
			tc.assert(t, f, record)
		})
	}
}

func TestToken_DeviceConcurrentPolls(t *testing.T) {
	t.Parallel()

	f := newDeviceTokenFixture(t)
	code, record := f.seed(t, tvClient, func(r *oidcprovider.DeviceAuthorization) {
		r.LastPolledAt, r.PollCount = r.IssuedAt.Add(-time.Minute), 1
	})
	// Both polls read the same version before either writes, so both pass the pace check.
	const polls = 2
	f.barrier = &sync.WaitGroup{}
	f.barrier.Add(polls)

	answers := make(chan error, polls)
	var wg sync.WaitGroup
	for range polls {
		wg.Go(func() {
			_, err := f.p.Token(t.Context(), deviceRequest(tvClient, code))
			answers <- err
		})
	}
	wg.Wait()
	close(answers)

	got := map[string]int{}
	for err := range answers {
		var refusal *oidcprovider.Error
		require.ErrorAs(t, err, &refusal)
		got[refusal.Code]++
	}
	assert.Equal(t, map[string]int{oidcprovider.CodeAuthorizationPending: 1, oidcprovider.CodeSlowDown: 1}, got)
	stored := f.stored(t, record)
	assert.Equal(t, 2, stored.PollCount, "only the winner's write landed")
	assert.Equal(t, 5*time.Second, stored.Interval, "the loser's lost write grew nothing")
}

func TestToken_DeviceExchange(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		client string
		seed   func(*oidcprovider.DeviceAuthorization)
		// arrange runs after seeding, before the poll.
		arrange func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization)
		// request changes the poll.
		request func(r *oidcprovider.TokenRequest)
		assert  func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error)
	}

	lifetimeOf := func(t *testing.T, f *deviceTokenFixture, clientID string) time.Duration {
		rc, err := f.p.ClientForTest(t.Context(), clientID)
		require.NoError(t, err)

		return rc.GrantAbsoluteLifetime
	}
	// refusedNothingRecorded is a refusal that spent nothing and recorded no grant.
	refusedNothingRecorded := func(code string) func(*testing.T, *deviceTokenFixture, *oidcprovider.DeviceAuthorization, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
			assert.Nil(t, res)
			assertRefused(t, err, code)
			assert.Equal(t, oidcprovider.DeviceApproved, f.stored(t, record).State, "the record stays unspent")
			assert.Nil(t, f.grantRow(t, record.Approval.GrantFamily), "no grant is recorded")
		}
	}
	dependencyUnspent := func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
		assert.Nil(t, res)
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assertNotPolling(t, err)
		assert.Equal(t, oidcprovider.DeviceApproved, f.stored(t, record).State, "the record stays unspent")
		assert.Nil(t, f.grantRow(t, record.Approval.GrantFamily), "no grant is recorded")
	}
	deadlinePassed := func(r *oidcprovider.DeviceAuthorization) {
		r.Approval.SignIn.AbsoluteExpiresAt = r.IssuedAt
	}

	cases := []testCase{
		{
			name: "openid offline_access for a refresh client gives access, ID and refresh tokens", client: tvRefresh,
			seed: approved("openid", "offline_access"),
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, res.AccessToken)
				assert.Equal(t, "Bearer", res.TokenType)
				assert.Equal(t, "openid offline_access", res.Scope)
				assert.NotEmpty(t, res.RefreshToken)
				require.NotEmpty(t, res.IDToken)

				claims := rawClaims(t, res.IDToken)
				assert.NotContains(t, claims, "nonce")
				a := record.Approval
				assert.JSONEq(t, mustJSON(t, a.SignIn.AuthenticatedAt.Unix()), string(claims["auth_time"]))
				assert.JSONEq(t, mustJSON(t, deviceACR), string(claims["acr"]))
				assert.JSONEq(t, mustJSON(t, []string{"pwd", "otp"}), string(claims["amr"]))
				assert.JSONEq(t, mustJSON(t, a.SignIn.Family.String()), string(claims["sid"]))
				assert.JSONEq(t, mustJSON(t, "u-1"), string(claims["sub"]))
				assert.JSONEq(t, mustJSON(t, []string{deviceAPI}), string(rawClaims(t, res.AccessToken)["aud"]))

				g := f.grantRow(t, a.GrantFamily)
				require.NotNil(t, g)
				assert.Equal(t, oidcprovider.OriginDevice, g.Origin)
				assert.Equal(t, record.ID, g.CodeID)
				assert.Equal(t, a.GrantFamily, g.Family)
				assert.Equal(t, a.SignIn.Family, g.SignInFamily)
				assert.Equal(t, identity.UserID("u-1"), g.User)
				assert.Equal(t, tvRefresh, g.ClientID)
				assert.Equal(t, []string{"openid", "offline_access"}, g.Scopes)
				assert.Equal(t, []string{deviceAPI}, g.Resources)
				assert.True(t, g.Offline)
				assert.True(t, g.HoldsLineage)
				assert.False(t, g.Revoked)
				assert.Equal(t, deviceNow.Add(lifetimeOf(t, f, tvRefresh)), g.ExpiresAt, "an offline grant outlives its sign-in")
				assert.Equal(t, oidcprovider.DeviceSpent, f.stored(t, record).State)
			},
		},
		{
			name: "a client not registered for refresh gets no refresh token", client: tvClient,
			seed: approved("openid", "offline_access"),
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				assert.Empty(t, res.RefreshToken)
				assert.NotEmpty(t, res.IDToken)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.False(t, g.HoldsLineage)
				assert.Equal(t, record.Approval.SignIn.AbsoluteExpiresAt, g.ExpiresAt, "a grant with no lineage ends at its sign-in's deadline")
			},
		},
		{
			name: "no openid gives no ID token", client: tvRefresh, seed: approved("profile"),
			assert: func(t *testing.T, _ *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				assert.Empty(t, res.IDToken)
				assert.Equal(t, "profile", res.Scope)
			},
		},
		{
			name: "under the default without offline_access, the grant ends at the sign-in's deadline", client: tvRefresh,
			seed: approved("openid"),
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, _ *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.Equal(t, record.Approval.SignIn.AbsoluteExpiresAt, g.ExpiresAt)
				assert.False(t, g.SurvivesSignInEnd)
			},
		},
		{
			name: "a confidential client's exchange works, and binds nothing", client: cliClient,
			seed:    then(approved("openid"), func(r *oidcprovider.DeviceAuthorization) { r.Resources = nil }),
			request: func(r *oidcprovider.TokenRequest) { r.Binding = oidcprovider.Binding{JKT: deviceJKT} },
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				assert.Equal(t, "DPoP", res.TokenType)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.Empty(t, g.KeyBinding, "a confidential client's grant is bound by its authentication")
			},
		},
		{
			name: "a public client's proof binds its grant", client: tvDPoP, seed: approved("openid", "offline_access"),
			request: func(r *oidcprovider.TokenRequest) { r.Binding = oidcprovider.Binding{JKT: deviceJKT} },
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				assert.Equal(t, "DPoP", res.TokenType)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.Equal(t, deviceJKT, g.KeyBinding)
			},
		},
		{
			name: "a user disabled after approval answers invalid_grant, unspent, with no grant", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
			},
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a user deleted after approval answers invalid_grant, unspent, with no grant", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.users.set(func(u *exchangeUsers) { u.missing["u-1"] = true })
			},
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a user loader naming someone else answers invalid_grant", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.users.set(func(u *exchangeUsers) { u.impostor = true })
			},
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a failing user loader is a dependency failure, unspent", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.users.set(func(u *exchangeUsers) { u.failing = true })
			},
			assert: dependencyUnspent,
		},
		{
			name: "a user loader answering nothing is a dependency failure, unspent", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.users.set(func(u *exchangeUsers) { u.answersNothing = true })
			},
			assert: dependencyUnspent,
		},
		{
			name: "a sign-in past its deadline under the default without offline_access answers invalid_grant", client: tvRefresh,
			seed:   then(approved("openid"), deadlinePassed),
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "an offline grant tied to its sign-in, past the deadline, answers invalid_grant", client: tvRefresh,
			seed: then(approved("openid", "offline_access"), deadlinePassed, func(r *oidcprovider.DeviceAuthorization) {
				r.Approval.EndsWithSignIn = true
			}),
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "an offline grant past its sign-in's deadline is exchanged", client: tvRefresh,
			seed: then(approved("openid", "offline_access"), deadlinePassed),
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, res.RefreshToken)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.Equal(t, deviceNow.Add(lifetimeOf(t, f, tvRefresh)), g.ExpiresAt)
			},
		},
		{
			name: "a grant surviving its sign-in's end, past the deadline, is exchanged and outlives it", client: tvRefresh,
			seed: then(approved("openid"), deadlinePassed, func(r *oidcprovider.DeviceAuthorization) {
				r.Approval.SurvivesSignInEnd = true
			}),
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, _ *oidcprovider.TokenResponse, err error) {
				require.NoError(t, err)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.True(t, g.SurvivesSignInEnd)
				assert.False(t, g.Offline)
				assert.Equal(t, deviceNow.Add(lifetimeOf(t, f, tvRefresh)), g.ExpiresAt)
			},
		},
		{
			name: "a revocation recorded before the poll answers invalid_grant, with no token, and spends the record", client: tvRefresh,
			seed: approved("openid", "offline_access"),
			arrange: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization) {
				_, err := f.grants.Revoke(t.Context(), record.Approval.GrantFamily, oidcprovider.CauseSignInEnded, deviceNow)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, f *deviceTokenFixture, record *oidcprovider.DeviceAuthorization, res *oidcprovider.TokenResponse, err error) {
				assert.Nil(t, res)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Equal(t, oidcprovider.DeviceSpent, f.stored(t, record).State)
				g := f.grantRow(t, record.Approval.GrantFamily)
				require.NotNil(t, g)
				assert.True(t, g.Revoked)
				assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
				assert.Equal(t, 0, f.p.LineageHeldForTest(), "no refresh token is stored")
			},
		},
		{
			name: "a resource the client may no longer ask for answers invalid_target, unspent", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(t *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				changed := deviceTokenClients()[1]
				changed.Resources = []string{"https://elsewhere.example.com"}
				require.NoError(t, f.registry.Put(t.Context(), changed))
			},
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidTarget),
		},
		{
			name: "a resource outside the authorization answers invalid_target, unspent", client: tvRefresh,
			seed:    approved("openid"),
			request: func(r *oidcprovider.TokenRequest) { r.Form.Set("resource", "https://elsewhere.example.com") },
			assert:  refusedNothingRecorded(oidcprovider.CodeInvalidTarget),
		},
		{
			name: "a failing signer is a dependency failure, unspent", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.keys.failSigning(func(context.Context) error { return errOutage })
			},
			assert: dependencyUnspent,
		},
		{
			name: "a failing spend is a dependency failure with no grant", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.spendFails.Store(true)
			},
			assert: dependencyUnspent,
		},
		{
			name: "a lost spend answers invalid_grant with no grant", client: tvRefresh,
			seed: approved("openid"),
			arrange: func(_ *testing.T, f *deviceTokenFixture, _ *oidcprovider.DeviceAuthorization) {
				f.spendLost.Store(true)
			},
			assert: refusedNothingRecorded(oidcprovider.CodeInvalidGrant),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newDeviceTokenFixture(t)
			code, record := f.seed(t, tc.client, tc.seed)
			if tc.arrange != nil {
				tc.arrange(t, f, record)
			}
			r := deviceRequest(tc.client, code)
			if tc.request != nil {
				tc.request(&r)
			}
			res, err := f.p.Token(t.Context(), r)
			tc.assert(t, f, record, res, err)
			f.assertNoDeviceSecret(t, code, err)
		})
	}
}

// mustJSON is v as JSON.
func mustJSON(t *testing.T, v any) string {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	return string(raw)
}
