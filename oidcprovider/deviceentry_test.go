package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
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
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	// entryCode is the raw user code a row seeds, and entryDisplay how it is shown.
	entryCode    = "BCDFGHJK"
	entryDisplay = "BCDF-GHJK"
	// otherCode is a well-formed code no row seeds.
	otherCode = "LMNP-QRST"
	// entrySource is the address a row enters codes from, and entryKey the limiter key the
	// guard counts it under.
	entrySource = "198.51.100.7"
	entryKey    = "oidc-device-entry:" + entrySource
)

// errLimiterBoom is a limiter's failure, whose text must never leave the provider.
var errLimiterBoom = errors.New("redis-password-limiter-on-fire")

// taggedLimiter is a limiter of a comparable struct type whose tag holds a value of a type
// that is not, so comparing two of them with == panics at run time.
type taggedLimiter struct {
	ratelimit.Limiter
	tag any
}

// entryFixture is a provider with the device grant on, over memory stores a row can read.
type entryFixture struct {
	p       *oidcprovider.Provider
	clk     *clockwork.FakeClock
	pending *oidcprovider.MemoryPendingRequestStore
	devices *oidcprovider.MemoryDeviceAuthorizationStore
	logs    *bytes.Buffer
}

// entrySetup is what a row replaces in the fixture.
type entrySetup struct {
	// pending wraps the memory pending store, and nil keeps it.
	pending func(memory *oidcprovider.MemoryPendingRequestStore) oidcprovider.PendingRequestStore
	// devices wraps the memory device store, and nil keeps it.
	devices func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore
	// registry wraps the memory registry, and nil keeps it.
	registry func(memory *oidcprovider.MemoryRegistry) oidcprovider.ClientRegistry
	// deviceOpts are added to WithDeviceAuthorization's.
	deviceOpts []oidcprovider.DeviceOption
	// opts are added to New's.
	opts []oidcprovider.Option
}

// entryClients are the device clients, the tv one named for the consent page.
func entryClients() []oidcprovider.Client {
	clients := deviceClients()
	clients[0].Name = "Living-room TV"

	return clients
}

func newEntryFixture(t *testing.T, s entrySetup) *entryFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(deviceNow)
	pending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	devices := oidcprovider.NewMemoryDeviceAuthorizationStore()
	registry, err := oidcprovider.NewMemoryRegistry(entryClients())
	require.NoError(t, err)
	logs := &bytes.Buffer{}
	var clients oidcprovider.ClientRegistry = registry
	if s.registry != nil {
		clients = s.registry(registry)
	}

	var pendingStore oidcprovider.PendingRequestStore = pending
	if s.pending != nil {
		pendingStore = s.pending(pending)
	}
	var deviceStore oidcprovider.DeviceAuthorizationStore = devices
	if s.devices != nil {
		deviceStore = s.devices(devices)
	}
	deviceOpts := append([]oidcprovider.DeviceOption{
		oidcprovider.WithUserCodeKey(deviceKey),
		oidcprovider.WithDeviceAuthorizationStore(deviceStore),
	}, s.deviceOpts...)

	opts := append([]oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(pendingStore),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
		oidcprovider.WithDeviceAuthorization(issuer+"/activate", deviceOpts...),
	}, s.opts...)
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     clients,
		Keys:         plainKeys(t),
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, opts...)
	require.NoError(t, err)

	return &entryFixture{p: p, clk: clk, pending: pending, devices: devices, logs: logs}
}

// userCodeDigestOf is the digest a provider keyed with deviceKey keeps for a raw code.
func userCodeDigestOf(raw string) []byte {
	mac := hmac.New(sha256.New, deviceKey)
	mac.Write([]byte(raw))

	return mac.Sum(nil)
}

// newFlow is a flow secret the provider could have minted.
func newFlow(t *testing.T) string {
	t.Helper()

	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// seed stores a device authorization for the tv client holding raw, issued now and
// living ten minutes, as change leaves it.
func (f *entryFixture) seed(t *testing.T, raw string, change func(*oidcprovider.DeviceAuthorization)) *oidcprovider.DeviceAuthorization {
	t.Helper()

	recordID, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	deviceDigest := sha256.Sum256([]byte("device-code-" + recordID.String()))
	now := f.clk.Now()
	record := &oidcprovider.DeviceAuthorization{
		ID:               recordID,
		DeviceCodeDigest: deviceDigest[:],
		UserCodeDigest:   userCodeDigestOf(raw),
		ClientID:         "tv",
		Scopes:           []string{"openid", "profile"},
		Resources:        []string{"https://api.example.com"},
		IssuedAt:         now.Add(-time.Minute),
		ExpiresAt:        now.Add(9 * time.Minute),
		Interval:         5 * time.Second,
		State:            oidcprovider.DeviceIssued,
	}
	if change != nil {
		change(record)
	}
	require.NoError(t, f.devices.Create(t.Context(), record, now.Add(-time.Minute)))

	return record
}

// stored reads a seeded record back, whatever its state and expiry.
func (f *entryFixture) stored(t *testing.T, record *oidcprovider.DeviceAuthorization) *oidcprovider.DeviceAuthorization {
	t.Helper()

	got, err := f.devices.LoadByDeviceCode(t.Context(), record.DeviceCodeDigest)
	require.NoError(t, err)

	return got
}

// parkedBy reads the pending request a login or consent Location names.
func (f *entryFixture) parkedBy(t *testing.T, location string) *oidcprovider.PendingRequest {
	t.Helper()

	r, err := f.pending.Load(t.Context(), handleDigestOf(t, handleOf(t, location)))
	require.NoError(t, err)

	return r
}

// pendingHeld counts the pending requests held, and forgets them, so it is a row's last
// question.
func (f *entryFixture) pendingHeld(t *testing.T) int {
	t.Helper()

	held, err := f.pending.DeleteExpired(t.Context(), f.clk.Now().Add(1000*time.Hour))
	require.NoError(t, err)

	return held
}

// signIn is a complete sign-in of user at the fixture's present.
func (f *entryFixture) signIn(t *testing.T, user identity.UserID) oidcprovider.SignIn {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return oidcprovider.SignIn{
		User:              user,
		Family:            family,
		AuthenticatedAt:   f.clk.Now(),
		AMR:               []string{"pwd"},
		AbsoluteExpiresAt: f.clk.Now().Add(8 * time.Hour),
	}
}

// browserSession signs u-1 in at the login stage of a code-flow request, as a page would,
// and returns the browser-session secret that leaves behind. A device request's own login
// stage is answered through Resume's device branch, which is not this test's.
func (f *entryFixture) browserSession(t *testing.T) string {
	t.Helper()

	params := authzParams()
	asClient(params, "billing-web", "https://rp.example.com/cb")
	params.Set("scope", "openid")
	res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: params})
	require.NoError(t, err)
	s := f.signIn(t, "u-1")
	resumed, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle: handleOf(t, res.Location), FlowSecret: res.FlowSecret, SignIn: &s, IdleTimeout: 15 * time.Minute,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resumed.BrowserSessionSecret)

	return resumed.BrowserSessionSecret
}

// pagePath is the path of a Location, which says which page it is.
func pagePath(t *testing.T, location string) string {
	t.Helper()

	u, err := url.Parse(location)
	require.NoError(t, err)

	return u.Scheme + "://" + u.Host + u.Path
}

// isThrottled asserts the refusal a throttled entry gets, with no text of the limiter's.
func isThrottled(t *testing.T, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()

	require.ErrorIs(t, err, oidcprovider.ErrUserCodeThrottled)
	require.ErrorIs(t, err, ratelimit.ErrThrottled)
	assert.Equal(t, oidcprovider.ErrUserCodeThrottled.Error(), err.Error())
	assert.Empty(t, res.Location)
	assert.Empty(t, res.FlowSecret)
}

// entryReceipt is the receipt a mock limiter answers a charge of entrySource with, and
// laterReceipt the one it answers a second charge with, when a row tells them apart.
var (
	entryReceipt = ratelimit.NewReceipt(entryKey, deviceNow)
	laterReceipt = ratelimit.NewReceipt(entryKey, deviceNow.Add(time.Second))
)

// refundingLimiter is a limiter that passes every check and accepts every charge, each with a
// receipt of its own, and requires, when the test ends, that every charge was refunded exactly
// once: the entries it serves are charged nothing in the end.
func refundingLimiter(t *testing.T) *MockLimiter {
	t.Helper()

	var (
		mu       sync.Mutex
		charged  int
		refunded = map[ratelimit.Receipt]int{}
	)
	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).AnyTimes()
	l.EXPECT().Charge(gomock.Any(), entryKey).DoAndReturn(func(context.Context, string) (ratelimit.Receipt, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		charged++

		return ratelimit.NewReceipt(entryKey, deviceNow.Add(time.Duration(charged))), false, nil
	}).AnyTimes()
	l.EXPECT().Refund(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, r ratelimit.Receipt) error {
		mu.Lock()
		defer mu.Unlock()
		refunded[r]++

		return nil
	}).AnyTimes()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		assert.Len(t, refunded, charged, "every charge is refunded")
		for r, n := range refunded {
			assert.Equal(t, 1, n, "a receipt is refunded once: %v", r.Stamp())
		}
	})

	return l
}

// TestEnterUserCode_Throttle pins that the throttle runs before any lookup, fails closed,
// and is the consumer's limiter when one is given. Each row states how many lookups the
// store may see in all; it sees none past that.
func TestEnterUserCode_Throttle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// limiter is the consumer's limiter, and nil keeps the default.
		limiter func(t *testing.T) ratelimit.Limiter
		// before runs before the entry under test.
		before func(t *testing.T, f *entryFixture)
		// source is the entry's source, entrySource when empty.
		source  string
		lookups int
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error)
	}

	fiveFailures := func(t *testing.T, f *entryFixture) {
		t.Helper()
		for range 5 {
			_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: otherCode, Source: entrySource})
			require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
		}
	}
	untouched := func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		isThrottled(t, res, err)
		assert.Equal(t, oidcprovider.DeviceIssued, f.stored(t, record).State, "a throttled entry claims nothing")
		assert.Zero(t, f.pendingHeld(t), "a throttled entry parks nothing")
	}

	cases := []testCase{
		{
			name:    "the sixth entry from a source that failed 5 times is refused before its valid code is looked up",
			before:  fiveFailures,
			lookups: 5,
			assert:  untouched,
		},
		{
			name:    "another source is unaffected by the first one's failures",
			before:  fiveFailures,
			source:  "198.51.100.8",
			lookups: 6,
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/login", pagePath(t, res.Location))
				assert.Equal(t, oidcprovider.DeviceClaimed, f.stored(t, record).State)
			},
		},
		{
			name: "a limiter that cannot answer fails closed, behind fixed text",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(true, errLimiterBoom)

				return l
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				untouched(t, f, record, res, err)
				assert.NotContains(t, err.Error(), errLimiterBoom.Error())
				assert.NotContains(t, f.logs.String(), errLimiterBoom.Error())
			},
		},
		{
			name: "the consumer's limiter is the one consulted, and charged for a failure",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).Times(2)
				gomock.InOrder(
					l.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil),
					l.EXPECT().Charge(gomock.Any(), entryKey).Return(laterReceipt, false, nil),
				)
				// The failure keeps its charge; the success has its own refunded.
				l.EXPECT().Refund(gomock.Any(), laterReceipt).Return(nil).Times(1)

				return l
			},
			before: func(t *testing.T, f *entryFixture) {
				t.Helper()
				_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: otherCode, Source: entrySource})
				require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
			},
			lookups: 2,
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, _ oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err, "a success is refunded its charge")
				assert.Equal(t, oidcprovider.DeviceClaimed, f.stored(t, record).State)
			},
		},
		{
			name: "the consumer's limiter saying the source is over its limit refuses it",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(true, nil)

				return l
			},
			assert: untouched,
		},
		{
			name: "a charge the consumer's limiter refuses is throttled before a lookup",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil)
				l.EXPECT().Charge(gomock.Any(), entryKey).Return(ratelimit.Receipt{}, true, nil)

				return l
			},
			assert: untouched,
		},
		{
			name: "a charge the limiter cannot decide fails closed, behind fixed text, logged by type",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil)
				l.EXPECT().Charge(gomock.Any(), entryKey).Return(ratelimit.Receipt{}, true, errLimiterBoom)

				return l
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				untouched(t, f, record, res, err)
				assert.ErrorIs(t, err, errLimiterBoom, "the limiter's own failure stays reachable")
				assert.NotContains(t, err.Error(), errLimiterBoom.Error())
				assert.NotContains(t, f.logs.String(), errLimiterBoom.Error())
				assert.Contains(t, f.logs.String(), "could not charge")
			},
		},
		{
			name: "a successful claim refunds its charge",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil)
				l.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil)
				l.EXPECT().Refund(gomock.Any(), entryReceipt).Return(nil).Times(1)

				return l
			},
			lookups: 1,
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/login", pagePath(t, res.Location))
				assert.Equal(t, oidcprovider.DeviceClaimed, f.stored(t, record).State)
			},
		},
		{
			name: "a refund the limiter cannot make is logged by type and changes no answer",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil)
				l.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil)
				l.EXPECT().Refund(gomock.Any(), entryReceipt).Return(errLimiterBoom).Times(1)

				return l
			},
			lookups: 1,
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/login", pagePath(t, res.Location))
				assert.Equal(t, oidcprovider.DeviceClaimed, f.stored(t, record).State)
				assert.Contains(t, f.logs.String(), "could not refund")
				assert.NotContains(t, f.logs.String(), errLimiterBoom.Error())
				assert.NotContains(t, f.logs.String(), entryCode)
			},
		},
		{
			name:   "a source naming no single address is refused before a lookup",
			source: "not-an-address",
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				untouched(t, f, record, res, err)
				assert.ErrorIs(t, err, ratelimit.ErrSourceUnattributable)
			},
		},
		{
			name:   "an empty source is refused before a lookup",
			source: " ",
			assert: untouched,
		},
		{
			name: "a caller who left is refused before a lookup, and its own error stays reachable",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
					return true, ctx.Err()
				})

				return l
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				untouched(t, f, record, res, err)
				assert.ErrorIs(t, err, context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.DeviceOption
			if tc.limiter != nil {
				opts = append(opts, oidcprovider.WithUserCodeEntryLimiter(tc.limiter(t)))
			}
			f := newEntryFixture(t, entrySetup{
				deviceOpts: opts,
				devices: func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
					store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
					store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.LoadByUserCode).Times(tc.lookups)
					store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Claim).AnyTimes()

					return store
				},
			})
			record := f.seed(t, entryCode, nil)
			if tc.before != nil {
				tc.before(t, f)
			}
			source := tc.source
			if source == "" {
				source = entrySource
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			res, err := f.p.EnterUserCode(ctx, oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: source})
			tc.assert(t, f, record, res, err)
		})
	}
}

// TestUseUserCodeEntryLimiter pins how the chain's limiter is handed over: it replaces the
// default once, never a consumer's, and a second, different one is a wiring mistake.
func TestUseUserCodeEntryLimiter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// consumer is a limiter given with WithUserCodeEntryLimiter, nil for none.
		consumer func(t *testing.T) ratelimit.Limiter
		// noDevice builds the provider without the device grant.
		noDevice bool
		// use is what UseUserCodeEntryLimiter is called with, in order.
		use    func(t *testing.T) []ratelimit.Limiter
		assert func(t *testing.T, f *entryFixture, errs []error)
	}

	// consulted is a limiter that expects to be asked about entrySource once.
	consulted := func(t *testing.T) *MockLimiter {
		t.Helper()
		l := NewMockLimiter(gomock.NewController(t))
		l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).Times(1)
		l.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil).Times(1)
		l.EXPECT().Refund(gomock.Any(), gomock.Any()).Times(0)

		return l
	}
	// silent is a limiter no call may reach.
	silent := func(t *testing.T) *MockLimiter {
		t.Helper()

		return NewMockLimiter(gomock.NewController(t))
	}
	enter := func(t *testing.T, f *entryFixture) {
		t.Helper()
		_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: otherCode, Source: entrySource})
		require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
	}
	var typedNil *ratelimit.MemoryLimiter

	cases := []testCase{
		{
			name: "it replaces the default, which is then the limiter consulted",
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()

				return []ratelimit.Limiter{consulted(t)}
			},
			assert: func(t *testing.T, f *entryFixture, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				enter(t, f)
			},
		},
		{
			name: "it never replaces the consumer's limiter, and says nothing of it",
			consumer: func(t *testing.T) ratelimit.Limiter {
				t.Helper()

				return consulted(t)
			},
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()

				return []ratelimit.Limiter{silent(t)}
			},
			assert: func(t *testing.T, f *entryFixture, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				enter(t, f)
			},
		},
		{
			name: "the same limiter twice changes nothing",
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()
				l := consulted(t)

				return []ratelimit.Limiter{l, l}
			},
			assert: func(t *testing.T, f *entryFixture, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
				enter(t, f)
			},
		},
		{
			name: "a different second limiter is refused, and the first stays",
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()

				return []ratelimit.Limiter{consulted(t), silent(t)}
			},
			assert: func(t *testing.T, f *entryFixture, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				require.ErrorIs(t, errs[1], oidcprovider.ErrConfig)
				assert.ErrorContains(t, errs[1], "UseUserCodeEntryLimiter")
				enter(t, f)
			},
		},
		{
			name: "a limiter whose comparable type holds an uncomparable value is refused as different, without a panic",
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()
				l := consulted(t)

				return []ratelimit.Limiter{
					taggedLimiter{Limiter: l, tag: map[string]int{}},
					taggedLimiter{Limiter: l, tag: map[string]int{}},
				}
			},
			assert: func(t *testing.T, f *entryFixture, errs []error) {
				t.Helper()
				require.NoError(t, errs[0])
				require.ErrorIs(t, errs[1], oidcprovider.ErrConfig)
				enter(t, f)
			},
		},
		{
			name: "nil is refused",
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()

				return []ratelimit.Limiter{nil}
			},
			assert: func(t *testing.T, _ *entryFixture, errs []error) {
				t.Helper()
				require.ErrorIs(t, errs[0], oidcprovider.ErrConfig)
				assert.ErrorContains(t, errs[0], "UseUserCodeEntryLimiter")
			},
		},
		{
			name: "a typed nil is refused",
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()

				return []ratelimit.Limiter{typedNil}
			},
			assert: func(t *testing.T, _ *entryFixture, errs []error) {
				t.Helper()
				require.ErrorIs(t, errs[0], oidcprovider.ErrConfig)
			},
		},
		{
			name:     "a provider without the device grant refuses it",
			noDevice: true,
			use: func(t *testing.T) []ratelimit.Limiter {
				t.Helper()

				return []ratelimit.Limiter{silent(t)}
			},
			assert: func(t *testing.T, _ *entryFixture, errs []error) {
				t.Helper()
				require.ErrorIs(t, errs[0], oidcprovider.ErrConfig)
				assert.ErrorContains(t, errs[0], "WithDeviceAuthorization")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var f *entryFixture
			if tc.noDevice {
				p, err := oidcprovider.New(validDeps(t))
				require.NoError(t, err)
				f = &entryFixture{p: p}
			} else {
				var opts []oidcprovider.DeviceOption
				if tc.consumer != nil {
					opts = append(opts, oidcprovider.WithUserCodeEntryLimiter(tc.consumer(t)))
				}
				f = newEntryFixture(t, entrySetup{deviceOpts: opts})
			}

			var errs []error
			for _, l := range tc.use(t) {
				errs = append(errs, f.p.UseUserCodeEntryLimiter(l))
			}
			tc.assert(t, f, errs)
		})
	}
}

// TestUseUserCodeEntryLimiter_Concurrent pins that of concurrent hand-overs exactly one
// wins, and that a hand-over racing entries is safe. Run it with -race.
func TestUseUserCodeEntryLimiter_Concurrent(t *testing.T) {
	t.Parallel()

	const callers = 8
	f := newEntryFixture(t, entrySetup{})
	limiters := make([]ratelimit.Limiter, callers)
	for i := range limiters {
		l, err := ratelimit.NewMemoryLimiter(oidcprovider.DefaultUserCodeEntryLimit, oidcprovider.DefaultUserCodeEntryWindow)
		require.NoError(t, err)
		limiters[i] = l
	}

	start := make(chan struct{})
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			<-start
			errs[i] = f.p.UseUserCodeEntryLimiter(limiters[i])
		})
		wg.Go(func() {
			<-start
			_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{
				UserCode: otherCode, Source: fmt.Sprintf("198.51.100.%d", 10+i),
			})
			assert.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
		})
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range errs {
		if err == nil {
			won++

			continue
		}
		assert.ErrorIs(t, err, oidcprovider.ErrConfig)
	}
	assert.Equal(t, 1, won, "exactly one hand-over wins")
}

// TestWithUserCodeEntryLimiter_Nil pins that a nil limiter is a wiring mistake.
func TestWithUserCodeEntryLimiter_Nil(t *testing.T) {
	t.Parallel()

	var typedNil *ratelimit.MemoryLimiter
	cases := []struct {
		name    string
		limiter ratelimit.Limiter
		assert  func(t *testing.T, p *oidcprovider.Provider, err error)
	}{
		{
			name: "nil",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "WithUserCodeEntryLimiter")
				assert.Nil(t, p)
			},
		},
		{
			name:    "typed nil",
			limiter: typedNil,
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "WithUserCodeEntryLimiter")
				assert.Nil(t, p)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := validDeps(t)
			p, err := oidcprovider.New(deps, oidcprovider.WithDeviceAuthorization(issuer+"/activate",
				oidcprovider.WithUserCodeEntryLimiter(tc.limiter)))
			tc.assert(t, p, err)
		})
	}
}

// TestEnterUserCode_SingleRefusal pins one answer, with one text, for every code that
// cannot be entered, each charged to the throttle and each leaving the record as it was.
func TestEnterUserCode_SingleRefusal(t *testing.T) {
	t.Parallel()

	otherFlow := sha256.Sum256([]byte("another browser's flow secret"))
	approval := &oidcprovider.DeviceApproval{User: "u-1", GrantedScopes: []string{"openid"}}
	cases := []struct {
		name string
		// change makes the seeded record what the row needs, and nil seeds it as issued.
		change func(f *entryFixture, r *oidcprovider.DeviceAuthorization)
		// entered is what the user typed, entryDisplay when empty.
		entered string
		// flow is the browser's flow secret.
		flow string
	}{
		{name: "an unknown code", entered: otherCode},
		{name: "an expired code", change: func(f *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.ExpiresAt = f.clk.Now().Add(-time.Second)
		}},
		{name: "a code at exactly its expiry", change: func(f *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.ExpiresAt = f.clk.Now()
		}},
		{name: "a code another browser claimed", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest = oidcprovider.DeviceClaimed, otherFlow[:]
		}},
		{name: "a code another browser claimed, entered with no flow secret", flow: "-", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest = oidcprovider.DeviceClaimed, otherFlow[:]
		}},
		{name: "an approved code", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest, r.Approval = oidcprovider.DeviceApproved, otherFlow[:], approval
		}},
		{name: "a denied code", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest = oidcprovider.DeviceDenied, otherFlow[:]
		}},
		{name: "a spent code", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest, r.Approval = oidcprovider.DeviceSpent, otherFlow[:], approval
		}},
		{name: "a code for a client no longer registered", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.ClientID = "gone"
		}},
		{name: "a code for a client no longer registered for the grant", change: func(_ *entryFixture, r *oidcprovider.DeviceAuthorization) {
			r.ClientID = "billing-web"
		}},
		{name: "a character outside the alphabet", entered: "BCDF-GHJA"},
		{name: "too short", entered: "BCDF-GHJ"},
		{name: "too long", entered: "BCDF-GHJKL"},
		{name: "empty", entered: "-"},
		{name: "a NUL byte", entered: "BCDF\x00GHJK"},
		{name: "invalid UTF-8", entered: "BCDF\xffGHJK"},
		{name: "a non-ASCII letter that folds to one of the alphabet", entered: "BCDF-GHJK"},
		{name: "oversized, though its characters would normalise to the code", entered: entryDisplay + strings.Repeat(" ", 1<<20)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).Times(1)
			limiter.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil).Times(1)
			limiter.EXPECT().Refund(gomock.Any(), gomock.Any()).Times(0)
			f := newEntryFixture(t, entrySetup{deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(limiter)}})
			record := f.seed(t, entryCode, func(r *oidcprovider.DeviceAuthorization) {
				if tc.change != nil {
					tc.change(f, r)
				}
			})
			before := f.stored(t, record)
			entered := tc.entered
			if entered == "" {
				entered = entryDisplay
			}
			flow := newFlow(t)
			if tc.flow == "-" {
				flow = ""
			}

			res, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entered, FlowSecret: flow, Source: entrySource})

			// Every refusal is the one sentinel, by identity and by text, leaves the record
			// as it was, parks nothing, and was charged once (the limiter's Times(1)).
			require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
			assert.Equal(t, oidcprovider.ErrInvalidUserCode.Error(), err.Error())
			assert.Empty(t, res.Location)
			assert.Empty(t, res.FlowSecret)
			assert.Equal(t, before, f.stored(t, record), "the record is unchanged")
			assert.Zero(t, f.pendingHeld(t), "nothing is parked")
		})
	}
}

// TestEnterUserCode_RefusesBeforeRegistry pins that a code refused for its own state, or for
// its claim, is refused without reading the client registry, so it answers no slower than an
// unknown code. Each is still the one refusal, charged once.
func TestEnterUserCode_RefusesBeforeRegistry(t *testing.T) {
	t.Parallel()

	otherFlow := sha256.Sum256([]byte("another browser's flow secret"))
	approval := &oidcprovider.DeviceApproval{User: "u-1", GrantedScopes: []string{"openid"}}
	cases := []struct {
		name string
		// change makes the seeded record what the row needs.
		change  func(r *oidcprovider.DeviceAuthorization)
		entered string
	}{
		{name: "an unknown code", entered: otherCode},
		{name: "a code another browser claimed", change: func(r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest = oidcprovider.DeviceClaimed, otherFlow[:]
		}},
		{name: "an approved code", change: func(r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest, r.Approval = oidcprovider.DeviceApproved, otherFlow[:], approval
		}},
		{name: "a denied code", change: func(r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest = oidcprovider.DeviceDenied, otherFlow[:]
		}},
		{name: "a spent code", change: func(r *oidcprovider.DeviceAuthorization) {
			r.State, r.ClaimFlowDigest, r.Approval = oidcprovider.DeviceSpent, otherFlow[:], approval
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).Times(1)
			limiter.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil).Times(1)
			limiter.EXPECT().Refund(gomock.Any(), gomock.Any()).Times(0)
			f := newEntryFixture(t, entrySetup{
				deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(limiter)},
				registry: func(*oidcprovider.MemoryRegistry) oidcprovider.ClientRegistry {
					registry := NewMockClientRegistry(gomock.NewController(t))
					registry.EXPECT().Client(gomock.Any(), gomock.Any()).Times(0)

					return registry
				},
			})
			f.seed(t, entryCode, tc.change)
			entered := tc.entered
			if entered == "" {
				entered = entryDisplay
			}

			// Every row is the one refusal, with no registry call (the registry's Times(0)),
			// charged once (the limiter's Times(1)).
			res, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entered, FlowSecret: newFlow(t), Source: entrySource})
			require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
			assert.Equal(t, oidcprovider.ErrInvalidUserCode.Error(), err.Error())
			assert.Empty(t, res.FlowSecret)
		})
	}
}

// TestEnterUserCode_ClaimAndPark pins the claim, the request parked for it, and where the
// browser goes: the login page, or the consent page when a browser session answers.
func TestEnterUserCode_ClaimAndPark(t *testing.T) {
	t.Parallel()

	type entered struct {
		res oidcprovider.AuthorizeResult
		err error
		in  oidcprovider.DeviceEntryInput
	}
	type testCase struct {
		name string
		// in is the entry, given the fixture.
		in     func(t *testing.T, f *entryFixture) oidcprovider.DeviceEntryInput
		assert func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered)
	}

	claimedFor := func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, flow string) {
		t.Helper()
		stored := f.stored(t, record)
		assert.Equal(t, oidcprovider.DeviceClaimed, stored.State)
		assert.Equal(t, digestOf(t, flow), stored.ClaimFlowDigest)
	}
	parkedFor := func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, location string, stage oidcprovider.Stage) {
		t.Helper()
		r := f.parkedBy(t, location)
		assert.Equal(t, record.ID, r.DeviceAuthorizationID)
		assert.Equal(t, entryDisplay, r.DeviceUserCode)
		assert.Equal(t, "tv", r.ClientID)
		assert.Equal(t, record.Scopes, r.Scopes)
		assert.Equal(t, record.Resources, r.Resources)
		assert.Empty(t, r.RedirectURI, "a device request is answered at the device, never at a redirect URI")
		assert.Equal(t, stage, r.Stage)
	}

	cases := []testCase{
		{
			name: "no flow secret: one is minted, and the browser goes to the login page with the handle",
			in: func(_ *testing.T, _ *entryFixture) oidcprovider.DeviceEntryInput {
				return oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)
				require.NotEmpty(t, e.res.FlowSecret)
				assert.Equal(t, issuer+"/login", pagePath(t, e.res.Location))
				assert.NotEmpty(t, handleOf(t, e.res.Location))
				claimedFor(t, f, record, e.res.FlowSecret)
				parkedFor(t, f, record, e.res.Location, oidcprovider.StageLogin)
			},
		},
		{
			name: "the browser's flow secret is kept",
			in: func(t *testing.T, _ *entryFixture) oidcprovider.DeviceEntryInput {
				t.Helper()

				return oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: newFlow(t), Source: entrySource}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)
				assert.Equal(t, e.in.FlowSecret, e.res.FlowSecret)
				claimedFor(t, f, record, e.in.FlowSecret)
			},
		},
		{
			name: "a flow secret the provider could not have minted is replaced",
			in: func(_ *testing.T, _ *entryFixture) oidcprovider.DeviceEntryInput {
				return oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: "forged", Source: entrySource}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)
				require.NotEqual(t, "forged", e.res.FlowSecret)
				claimedFor(t, f, record, e.res.FlowSecret)
			},
		},
		{
			name: "a code typed in lower case with a space is read back to the one issued",
			in: func(_ *testing.T, _ *entryFixture) oidcprovider.DeviceEntryInput {
				return oidcprovider.DeviceEntryInput{UserCode: " bcdf ghjk ", Source: entrySource}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)
				parkedFor(t, f, record, e.res.Location, oidcprovider.StageLogin)
			},
		},
		{
			name: "a browser session sends the browser to the consent page, the login stage answered",
			in: func(t *testing.T, f *entryFixture) oidcprovider.DeviceEntryInput {
				t.Helper()

				return oidcprovider.DeviceEntryInput{
					UserCode: entryDisplay, FlowSecret: newFlow(t), BrowserSessionSecret: f.browserSession(t),
					Source: entrySource, IdleTimeout: 15 * time.Minute,
				}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)
				assert.Equal(t, issuer+"/consent", pagePath(t, e.res.Location))
				claimedFor(t, f, record, e.in.FlowSecret)
				parkedFor(t, f, record, e.res.Location, oidcprovider.StageConsent)
				r := f.parkedBy(t, e.res.Location)
				require.NotNil(t, r.SignIn)
				assert.Equal(t, identity.UserID("u-1"), r.SignIn.User)
			},
		},
		{
			name: "a browser-session secret the provider could not have minted counts as none",
			in: func(t *testing.T, _ *entryFixture) oidcprovider.DeviceEntryInput {
				t.Helper()

				return oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: newFlow(t), BrowserSessionSecret: "forged", Source: entrySource}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)
				assert.Equal(t, issuer+"/login", pagePath(t, e.res.Location))
				parkedFor(t, f, record, e.res.Location, oidcprovider.StageLogin)
			},
		},
		{
			name: "the claiming browser's re-entry parks again at login, and once it has signed in at consent",
			in: func(t *testing.T, _ *entryFixture) oidcprovider.DeviceEntryInput {
				t.Helper()

				return oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: newFlow(t), Source: entrySource, IdleTimeout: 15 * time.Minute}
			},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, e entered) {
				t.Helper()
				require.NoError(t, e.err)

				again, err := f.p.EnterUserCode(t.Context(), e.in)
				require.NoError(t, err, "the claiming browser may enter its code again")
				assert.Equal(t, issuer+"/login", pagePath(t, again.Location))
				assert.Equal(t, e.in.FlowSecret, again.FlowSecret)
				assert.NotEqual(t, handleOf(t, e.res.Location), handleOf(t, again.Location))
				parkedFor(t, f, record, again.Location, oidcprovider.StageLogin)

				// The browser signs in, which leaves it a browser session.
				in := e.in
				in.BrowserSessionSecret = f.browserSession(t)
				third, err := f.p.EnterUserCode(t.Context(), in)
				require.NoError(t, err)
				assert.Equal(t, issuer+"/consent", pagePath(t, third.Location), "re-entry reaches the stage the browser reached")
				parkedFor(t, f, record, third.Location, oidcprovider.StageConsent)
				claimedFor(t, f, record, e.in.FlowSecret)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEntryFixture(t, entrySetup{})
			record := f.seed(t, entryCode, nil)
			in := tc.in(t, f)

			res, err := f.p.EnterUserCode(t.Context(), in)
			tc.assert(t, f, record, entered{res: res, err: err, in: in})
		})
	}
}

// TestEnterUserCode_ConcurrentClaims pins that of browsers entering one code at once
// exactly one claims it, and every other is refused.
func TestEnterUserCode_ConcurrentClaims(t *testing.T) {
	t.Parallel()

	const browsers = 8
	f := newEntryFixture(t, entrySetup{})
	record := f.seed(t, entryCode, nil)

	start := make(chan struct{})
	results := make([]oidcprovider.AuthorizeResult, browsers)
	errs := make([]error, browsers)
	flows := make([]string, browsers)
	for i := range flows {
		flows[i] = newFlow(t)
	}
	var wg sync.WaitGroup
	for i := range browsers {
		wg.Go(func() {
			<-start
			results[i], errs[i] = f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{
				UserCode: entryDisplay, FlowSecret: flows[i], Source: fmt.Sprintf("198.51.100.%d", 20+i),
			})
		})
	}
	close(start)
	wg.Wait()

	winner := -1
	for i, err := range errs {
		if err == nil {
			require.Equal(t, -1, winner, "only one browser claims the code")
			winner = i

			continue
		}
		assert.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
		assert.Empty(t, results[i].Location)
	}
	require.NotEqual(t, -1, winner, "one browser claims the code")
	assert.Equal(t, digestOf(t, flows[winner]), f.stored(t, record).ClaimFlowDigest)
	assert.Equal(t, 1, f.pendingHeld(t), "one request is parked")
}

// TestEnterUserCode_SameBrowserTwiceAtOnce pins that one browser submitting its code twice at
// once is handed off both times and charged nothing: the entry that loses the claim finds the
// claim is its own. The store holds both first lookups until both are made, so both entries
// see the code issued and both try to claim it.
func TestEnterUserCode_SameBrowserTwiceAtOnce(t *testing.T) {
	t.Parallel()

	const entries = 2
	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).Times(entries)
	limiter.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil).Times(entries)
	limiter.EXPECT().Refund(gomock.Any(), entryReceipt).Return(nil).Times(entries)
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

	var lookups sync.WaitGroup
	lookups.Add(entries)
	f := newEntryFixture(t, entrySetup{
		deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(limiter)},
		devices: func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
			store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
			first := store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
					record, err := memory.LoadByUserCode(ctx, digest, now)
					lookups.Done()
					lookups.Wait()

					return record, err
				}).Times(entries)
			store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.LoadByUserCode).After(first).AnyTimes()
			store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Claim).Times(entries)

			return store
		},
	})
	record := f.seed(t, entryCode, nil)
	flow := newFlow(t)

	start := make(chan struct{})
	results := make([]oidcprovider.AuthorizeResult, entries)
	errs := make([]error, entries)
	var wg sync.WaitGroup
	for i := range entries {
		wg.Go(func() {
			<-start
			results[i], errs[i] = f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{
				UserCode: entryDisplay, FlowSecret: flow, Source: entrySource,
			})
		})
	}
	close(start)
	wg.Wait()

	for i := range entries {
		require.NoError(t, errs[i], "neither entry is refused")
		assert.Equal(t, issuer+"/login", pagePath(t, results[i].Location))
		assert.Equal(t, flow, results[i].FlowSecret)
		assert.Equal(t, record.ID, f.parkedBy(t, results[i].Location).DeviceAuthorizationID)
	}
	assert.Equal(t, digestOf(t, flow), f.stored(t, record).ClaimFlowDigest)
	assert.Equal(t, entries, f.pendingHeld(t), "each entry parks a request")
}

// TestEnterUserCode_ParkFailsAfterClaim pins the half-applied entry: the claim stands, the
// entry fails as a dependency, and only the claiming browser can recover it.
func TestEnterUserCode_ParkFailsAfterClaim(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// flow is the browser's flow secret, and empty sends none.
		flow func(t *testing.T) string
	}{
		{name: "a browser with a flow secret", flow: newFlow},
		{name: "a browser without one keeps the secret minted for it", flow: func(*testing.T) string { return "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Only the last entry, another browser's, keeps its charge: the failed entry and
			// the recovering one are refunded theirs.
			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil).Times(3)
			gomock.InOrder(
				limiter.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil),
				limiter.EXPECT().Charge(gomock.Any(), entryKey).Return(laterReceipt, false, nil),
				limiter.EXPECT().Charge(gomock.Any(), entryKey).Return(ratelimit.NewReceipt(entryKey, deviceNow.Add(time.Minute)), false, nil),
			)
			limiter.EXPECT().Refund(gomock.Any(), entryReceipt).Return(nil).Times(1)
			limiter.EXPECT().Refund(gomock.Any(), laterReceipt).Return(nil).Times(1)
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)
			f := newEntryFixture(t, entrySetup{
				deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(limiter)},
				pending: func(memory *oidcprovider.MemoryPendingRequestStore) oidcprovider.PendingRequestStore {
					store := NewMockPendingRequestStore(gomock.NewController(t))
					store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage).Times(1)
					store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()
					store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memory.Load).AnyTimes()
					store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Advance).AnyTimes()

					return store
				},
			})
			record := f.seed(t, entryCode, nil)
			in := oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: tc.flow(t), Source: entrySource}

			res, err := f.p.EnterUserCode(t.Context(), in)
			require.ErrorIs(t, err, oidcprovider.ErrDependency)
			assert.NotErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
			assert.NotContains(t, err.Error(), errOutage.Error())
			assert.NotContains(t, f.logs.String(), errOutage.Error())
			assert.Empty(t, res.Location, "the browser goes nowhere")
			require.NotEmpty(t, res.FlowSecret, "the browser keeps the flow secret its claim is bound to")
			if in.FlowSecret != "" {
				assert.Equal(t, in.FlowSecret, res.FlowSecret)
			}
			stored := f.stored(t, record)
			assert.Equal(t, oidcprovider.DeviceClaimed, stored.State, "the claim stands")
			assert.Equal(t, digestOf(t, res.FlowSecret), stored.ClaimFlowDigest)

			in.FlowSecret = res.FlowSecret
			again, err := f.p.EnterUserCode(t.Context(), in)
			require.NoError(t, err, "the claiming browser recovers")
			assert.Equal(t, issuer+"/login", pagePath(t, again.Location))
			assert.Equal(t, record.ID, f.parkedBy(t, again.Location).DeviceAuthorizationID)

			_, err = f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: newFlow(t), Source: entrySource})
			require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode, "every other browser is still refused")
		})
	}
}

// TestEnterUserCode_ClaimAppliedButReportedFailed pins the claim a store writes and then
// reports as failed: the entry fails as a dependency, still carrying the flow secret the claim
// is bound to, so the browser's re-entry reaches its claim. Its store double differs from
// TestEnterUserCode_ParkFailsAfterClaim's, which fails the pending store instead.
func TestEnterUserCode_ClaimAppliedButReportedFailed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// flow is the browser's flow secret, and empty sends none.
		flow func(t *testing.T) string
	}{
		{name: "a browser with a flow secret keeps it", flow: newFlow},
		{name: "a browser without one keeps the secret minted for it", flow: func(*testing.T) string { return "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limiter := refundingLimiter(t)
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)
			f := newEntryFixture(t, entrySetup{
				deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(limiter)},
				devices: func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
					store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
					store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.LoadByUserCode).AnyTimes()
					store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
						func(ctx context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error {
							require.NoError(t, memory.Claim(ctx, deviceID, flowDigest, now))

							return errOutage
						}).Times(1)

					return store
				},
			})
			record := f.seed(t, entryCode, nil)
			in := oidcprovider.DeviceEntryInput{UserCode: entryDisplay, FlowSecret: tc.flow(t), Source: entrySource}

			res, err := f.p.EnterUserCode(t.Context(), in)
			require.ErrorIs(t, err, oidcprovider.ErrDependency)
			assert.NotErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
			assert.NotContains(t, err.Error(), errOutage.Error())
			assert.NotContains(t, f.logs.String(), errOutage.Error())
			assert.Empty(t, res.Location, "the browser goes nowhere")
			require.NotEmpty(t, res.FlowSecret, "the browser keeps the flow secret its claim is bound to")
			if in.FlowSecret != "" {
				assert.Equal(t, in.FlowSecret, res.FlowSecret)
			}
			assert.Equal(t, digestOf(t, res.FlowSecret), f.stored(t, record).ClaimFlowDigest)

			in.FlowSecret = res.FlowSecret
			again, err := f.p.EnterUserCode(t.Context(), in)
			require.NoError(t, err, "the claiming browser's re-entry reaches its claim")
			assert.Equal(t, issuer+"/login", pagePath(t, again.Location))
			assert.Equal(t, record.ID, f.parkedBy(t, again.Location).DeviceAuthorizationID)
		})
	}
}

// TestEnterUserCode_Failures pins what a failing dependency, a wiring mistake and a caller
// who left get: never a verdict on the code, and every charge made for it refunded.
func TestEnterUserCode_Failures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) entrySetup
		in     oidcprovider.DeviceEntryInput
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error)
	}

	// uncharged is a limiter that is asked, and whose every charge is refunded, so the entry
	// is charged nothing in the end.
	uncharged := func(t *testing.T) oidcprovider.DeviceOption {
		t.Helper()

		return oidcprovider.WithUserCodeEntryLimiter(refundingLimiter(t))
	}
	dependency := func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assert.NotErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
		assert.NotContains(t, err.Error(), errStoreBoom.Error())
		assert.NotContains(t, f.logs.String(), errStoreBoom.Error())
		assert.Empty(t, res.Location)
		assert.Equal(t, oidcprovider.DeviceIssued, f.stored(t, record).State, "nothing is claimed")
	}
	valid := oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource}

	cases := []testCase{
		{
			name: "the device store failing a lookup",
			setup: func(t *testing.T) entrySetup {
				t.Helper()

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{uncharged(t)},
					devices: func(*oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
						store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
						store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errStoreBoom)

						return store
					},
				}
			},
			in:     valid,
			assert: dependency,
		},
		{
			name: "the device store answering neither a record nor an error",
			setup: func(t *testing.T) entrySetup {
				t.Helper()

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{uncharged(t)},
					devices: func(*oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
						store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
						store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

						return store
					},
				}
			},
			in:     valid,
			assert: dependency,
		},
		{
			name: "the device store failing the claim",
			setup: func(t *testing.T) entrySetup {
				t.Helper()

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{uncharged(t)},
					devices: func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
						store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
						store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.LoadByUserCode)
						store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errStoreBoom)

						return store
					},
				}
			},
			in:     valid,
			assert: dependency,
		},
		{
			name: "the client registry failing",
			setup: func(t *testing.T) entrySetup {
				t.Helper()

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{uncharged(t)},
					registry: func(*oidcprovider.MemoryRegistry) oidcprovider.ClientRegistry {
						registry := NewMockClientRegistry(gomock.NewController(t))
						registry.EXPECT().Client(gomock.Any(), "tv").Return(nil, errStoreBoom)

						return registry
					},
				}
			},
			in:     valid,
			assert: dependency,
		},
		{
			name: "a store answering another record than the code's",
			setup: func(t *testing.T) entrySetup {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), entryKey).Return(false, nil)
				l.EXPECT().Charge(gomock.Any(), entryKey).Return(entryReceipt, false, nil)

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(l)},
					devices: func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
						store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
						store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
							func(ctx context.Context, _ []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
								return memory.LoadByUserCode(ctx, userCodeDigestOf(entryCode), now)
							})

						return store
					},
				}
			},
			in: oidcprovider.DeviceEntryInput{UserCode: otherCode, Source: entrySource},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, _ oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
				assert.Equal(t, oidcprovider.DeviceIssued, f.stored(t, record).State)
			},
		},
		{
			name: "the browser-session store failing",
			setup: func(t *testing.T) entrySetup {
				t.Helper()
				sessions := NewMockBrowserSessionStore(gomock.NewController(t))
				sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errStoreBoom)

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{uncharged(t)},
					opts:       []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(sessions)},
				}
			},
			in: oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource, BrowserSessionSecret: "session"},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				// The runner replaces the row's BrowserSessionSecret with a well-formed one, so
				// the failing store is asked.
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotContains(t, err.Error(), errStoreBoom.Error())
				assert.Empty(t, res.Location)
				assert.Equal(t, oidcprovider.DeviceClaimed, f.stored(t, record).State, "the claim stands, for the browser's re-entry")
				assert.Equal(t, digestOf(t, res.FlowSecret), f.stored(t, record).ClaimFlowDigest)
			},
		},
		{
			name: "a caller who left during the lookup is refunded its charge, and its own error stays reachable",
			setup: func(t *testing.T) entrySetup {
				t.Helper()

				return entrySetup{
					deviceOpts: []oidcprovider.DeviceOption{uncharged(t)},
					devices: func(*oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
						store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
						store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
							func(ctx context.Context, _ []byte, _ time.Time) (*oidcprovider.DeviceAuthorization, error) {
								return nil, ctx.Err()
							})

						return store
					},
				}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			in: oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
				assert.NotErrorIs(t, err, oidcprovider.ErrUserCodeThrottled)
				assert.Empty(t, res.Location)
				assert.Equal(t, oidcprovider.DeviceIssued, f.stored(t, record).State)
			},
		},
		{
			name: "a negative idle timeout is a wiring mistake",
			setup: func(t *testing.T) entrySetup {
				t.Helper()

				return entrySetup{deviceOpts: []oidcprovider.DeviceOption{oidcprovider.WithUserCodeEntryLimiter(NewMockLimiter(gomock.NewController(t)))}}
			},
			in: oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource, IdleTimeout: -time.Second},
			assert: func(t *testing.T, f *entryFixture, record *oidcprovider.DeviceAuthorization, _ oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "IdleTimeout")
				assert.Equal(t, oidcprovider.DeviceIssued, f.stored(t, record).State)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := tc.in
			if in.BrowserSessionSecret != "" {
				in.BrowserSessionSecret = newFlow(t)
			}
			f := newEntryFixture(t, tc.setup(t))
			record := f.seed(t, entryCode, nil)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			res, err := f.p.EnterUserCode(ctx, in)
			tc.assert(t, f, record, res, err)
		})
	}
}

// TestEnterUserCode_WithoutTheGrant pins that a provider without the device grant refuses
// the entry as a wiring mistake.
func TestEnterUserCode_WithoutTheGrant(t *testing.T) {
	t.Parallel()

	p, err := oidcprovider.New(validDeps(t))
	require.NoError(t, err)

	_, err = p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource})
	require.ErrorIs(t, err, oidcprovider.ErrConfig)
	assert.ErrorContains(t, err, "WithDeviceAuthorization")
}

// TestPendingRequest_DeviceView pins what the consumer's pages see of a device request,
// and that a request of the code flow shows no device part.
func TestPendingRequest_DeviceView(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// park parks a request, and returns its Location and flow secret.
		park func(t *testing.T, f *entryFixture) (string, string)
		// lookup, when set, answers the device store's user-code lookups once the request is
		// parked, in place of the memory store.
		lookup func(ctx context.Context, memory *oidcprovider.MemoryDeviceAuthorizationStore, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error)
		assert func(t *testing.T, f *entryFixture, view *oidcprovider.PendingView, err error, handle, flow string)
	}

	enterCode := func(t *testing.T, f *entryFixture) (string, string) {
		t.Helper()
		res, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: "bcdfghjk", Source: entrySource})
		require.NoError(t, err)

		return res.Location, res.FlowSecret
	}

	cases := []testCase{
		{
			name: "a device request shows its user code as issued, when the device asked, and its client",
			park: enterCode,
			assert: func(t *testing.T, _ *entryFixture, view *oidcprovider.PendingView, err error, handle, flow string) {
				t.Helper()
				require.NoError(t, err)
				require.NotNil(t, view.Device)
				assert.Equal(t, entryDisplay, view.Device.UserCode)
				assert.True(t, deviceNow.Add(-time.Minute).Equal(view.Device.RequestedAt), "RequestedAt is the record's IssuedAt")
				assert.Equal(t, "tv", view.ClientID)
				assert.Equal(t, "Living-room TV", view.ClientName)
				assert.Equal(t, []string{"openid", "profile"}, view.Scopes)
				assert.Equal(t, oidcprovider.StageLogin, view.Stage)
				for _, printed := range []string{fmt.Sprintf("%+v", view), fmt.Sprintf("%+v", *view), fmt.Sprintf("%+v", *view.Device)} {
					assert.NotContains(t, printed, handle)
					assert.NotContains(t, printed, flow)
					assert.NotContains(t, printed, "device-code-")
				}
			},
		},
		{
			name: "a device request whose authorization has expired is gone",
			park: func(t *testing.T, f *entryFixture) (string, string) {
				t.Helper()
				location, flow := enterCode(t, f)
				f.clk.Advance(9 * time.Minute)

				return location, flow
			},
			assert: func(t *testing.T, _ *entryFixture, view *oidcprovider.PendingView, err error, _, _ string) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Nil(t, view)
			},
		},
		{
			name: "a device request whose authorization was replaced by another holding its code is gone",
			park: enterCode,
			lookup: func(ctx context.Context, memory *oidcprovider.MemoryDeviceAuthorizationStore, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
				record, err := memory.LoadByUserCode(ctx, digest, now)
				if err != nil {
					return nil, err
				}
				replaced := *record
				replaced.ID, err = id.NewV7Generator().NewID()

				return &replaced, err
			},
			assert: func(t *testing.T, _ *entryFixture, view *oidcprovider.PendingView, err error, _, _ string) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Nil(t, view)
			},
		},
		{
			name: "a device store failing the lookup is a dependency failure, behind fixed text",
			park: enterCode,
			lookup: func(context.Context, *oidcprovider.MemoryDeviceAuthorizationStore, []byte, time.Time) (*oidcprovider.DeviceAuthorization, error) {
				return nil, errStoreBoom
			},
			assert: func(t *testing.T, f *entryFixture, view *oidcprovider.PendingView, err error, _, _ string) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.NotContains(t, err.Error(), errStoreBoom.Error())
				assert.NotContains(t, f.logs.String(), errStoreBoom.Error())
				assert.Nil(t, view)
			},
		},
		{
			name: "a request of the code flow shows no device part",
			park: func(t *testing.T, f *entryFixture) (string, string) {
				t.Helper()
				params := authzParams()
				asClient(params, "billing-web", "https://rp.example.com/cb")
				params.Set("scope", "openid")
				res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: params})
				require.NoError(t, err)

				return res.Location, res.FlowSecret
			},
			assert: func(t *testing.T, _ *entryFixture, view *oidcprovider.PendingView, err error, _, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Nil(t, view.Device)
				assert.Equal(t, "billing-web", view.ClientID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var parked atomic.Bool
			setup := entrySetup{}
			if tc.lookup != nil {
				setup.devices = func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
					store := NewMockDeviceAuthorizationStore(gomock.NewController(t))
					store.EXPECT().LoadByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
						func(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
							if parked.Load() {
								return tc.lookup(ctx, memory, digest, now)
							}

							return memory.LoadByUserCode(ctx, digest, now)
						}).AnyTimes()
					store.EXPECT().Claim(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memory.Claim).AnyTimes()

					return store
				}
			}
			f := newEntryFixture(t, setup)
			f.seed(t, entryCode, nil)
			location, flow := tc.park(t, f)
			parked.Store(true)
			handle := handleOf(t, location)

			view, err := f.p.PendingRequest(t.Context(), handle, flow)
			tc.assert(t, f, view, err, handle, flow)
		})
	}
}

// TestMemoryPendingRequestStore_DeviceFields pins that the device fields round-trip.
func TestMemoryPendingRequestStore_DeviceFields(t *testing.T) {
	t.Parallel()

	store, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	deviceID, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	r := &oidcprovider.PendingRequest{
		ID: deviceID, HandleDigest: []byte("handle-digest"), FlowDigest: []byte("flow"),
		ExpiresAt: deviceNow.Add(time.Hour), DeviceAuthorizationID: deviceID, DeviceUserCode: entryDisplay,
	}
	require.NoError(t, store.Create(t.Context(), r))

	got, err := store.Load(t.Context(), []byte("handle-digest"))
	require.NoError(t, err)
	assert.Equal(t, deviceID, got.DeviceAuthorizationID)
	assert.Equal(t, entryDisplay, got.DeviceUserCode)
}

// gatedLookups is a device store whose user-code lookups are held at a gate until every one of
// a burst of entries has either reached a lookup or been answered, so no entry of the burst
// can see a failure another one recorded. It counts the lookups that reach it.
type gatedLookups struct {
	*oidcprovider.MemoryDeviceAuthorizationStore

	burst   int64
	arrived atomic.Int64
	lookups atomic.Int64
	gate    chan struct{}
	once    sync.Once
}

func newGatedLookups(memory *oidcprovider.MemoryDeviceAuthorizationStore, burst int) *gatedLookups {
	return &gatedLookups{MemoryDeviceAuthorizationStore: memory, burst: int64(burst), gate: make(chan struct{})}
}

// arrive counts one entry of the burst as having got as far as it will before the gate, and
// opens the gate once all of them have.
func (g *gatedLookups) arrive() {
	if g.arrived.Add(1) == g.burst {
		g.once.Do(func() { close(g.gate) })
	}
}

func (g *gatedLookups) LoadByUserCode(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.DeviceAuthorization, error) {
	g.lookups.Add(1)
	g.arrive()
	select {
	case <-g.gate:
	case <-time.After(10 * time.Second):
		return nil, errors.New("gatedLookups: the burst never all arrived")
	}

	return g.MemoryDeviceAuthorizationStore.LoadByUserCode(ctx, digest, now)
}

// TestEnterUserCode_BurstIsBounded pins that a concurrent burst of wrong codes from one source
// is looked up no more often than the limit allows: each entry is charged before its lookup,
// so the entries past the limit are refused as throttled however the burst interleaves.
func TestEnterUserCode_BurstIsBounded(t *testing.T) {
	t.Parallel()

	const burst = 16
	var gated *gatedLookups
	f := newEntryFixture(t, entrySetup{
		devices: func(memory *oidcprovider.MemoryDeviceAuthorizationStore) oidcprovider.DeviceAuthorizationStore {
			gated = newGatedLookups(memory, burst)

			return gated
		},
	})

	start := make(chan struct{})
	errs := make([]error, burst)
	var wg sync.WaitGroup
	for i := range burst {
		wg.Go(func() {
			<-start
			_, errs[i] = f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: otherCode, Source: entrySource})
			if !errors.Is(errs[i], oidcprovider.ErrInvalidUserCode) {
				gated.arrive()
			}
		})
	}
	close(start)
	wg.Wait()

	assert.LessOrEqual(t, gated.lookups.Load(), int64(oidcprovider.DefaultUserCodeEntryLimit),
		"no more codes are looked up than the limit allows")
	var invalid, throttled int
	for _, err := range errs {
		switch {
		case errors.Is(err, oidcprovider.ErrInvalidUserCode):
			invalid++
		case errors.Is(err, oidcprovider.ErrUserCodeThrottled):
			assert.ErrorIs(t, err, ratelimit.ErrThrottled)
			throttled++
		default:
			t.Errorf("an entry of the burst answered %v", err)
		}
	}
	assert.Equal(t, int(oidcprovider.DefaultUserCodeEntryLimit), invalid)
	assert.Equal(t, burst-int(oidcprovider.DefaultUserCodeEntryLimit), throttled)
}
