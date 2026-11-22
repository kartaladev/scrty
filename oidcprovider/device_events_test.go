package oidcprovider_test

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
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

// deviceEventNames are the seven outcomes of the device grant.
var deviceEventNames = []string{
	event.DeviceAuthorizationIssued, event.DeviceAuthorizationClaimed, event.DeviceAuthorizationApproved,
	event.DeviceAuthorizationDenied, event.DeviceCodeExchanged, event.DeviceCodeReplayed,
	event.UserCodeEntryThrottled,
}

// base64urlRun is 43 base64url characters, the length of a 32-byte secret.
var base64urlRun = regexp.MustCompile(`[A-Za-z0-9_-]{43}`)

// loseSpend is a device store whose spend loses the compare while lost is set.
type loseSpend struct {
	oidcprovider.DeviceAuthorizationStore

	lost     bool
	sweepErr error
}

func (s *loseSpend) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	if s.sweepErr != nil {
		return 0, s.sweepErr
	}

	return s.DeviceAuthorizationStore.DeleteExpired(ctx, now)
}

func (s *loseSpend) Spend(ctx context.Context, deviceID id.ID, now time.Time) error {
	if s.lost {
		return oidcprovider.ErrNotFound
	}

	return s.DeviceAuthorizationStore.Spend(ctx, deviceID, now)
}

// first is the first event of name, and fails the row when there is none.
func first(t *testing.T, got []event.Event, name string) event.Event {
	t.Helper()

	events := named(got, name)
	require.NotEmpty(t, events, "%s", name)

	return events[0]
}

// eventScene is a device-grant provider over memory stores whose events it records, for the
// rows that issue or exchange a code.
type eventScene struct {
	p      *oidcprovider.Provider
	tf     *deviceTokenFixture
	store  *loseSpend
	grants *oidcprovider.MemoryGrantStore
	events *eventLog
}

func newEventScene(t *testing.T) *eventScene {
	t.Helper()

	clk := clockwork.NewFakeClockAt(deviceNow)
	memory := oidcprovider.NewMemoryDeviceAuthorizationStore()
	grants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	registry, err := oidcprovider.NewMemoryRegistry(deviceTokenClients())
	require.NoError(t, err)
	users := &exchangeUsers{disabled: map[identity.UserID]bool{}, missing: map[identity.UserID]bool{}}
	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return users.load(user) },
	).AnyTimes()

	s := &eventScene{
		tf:     &deviceTokenFixture{clk: clk, devices: memory, grants: grants, registry: registry, users: users},
		store:  &loseSpend{DeviceAuthorizationStore: memory},
		grants: grants,
		events: &eventLog{},
	}
	s.p, err = oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         newExchangeKeys(t),
		Users:        loader,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithSecurityEvents(s.events.sink),
		oidcprovider.WithDeviceAuthorization(issuer+"/activate",
			oidcprovider.WithUserCodeKey(deviceKey),
			oidcprovider.WithDeviceAuthorizationStore(s.store),
		),
	)
	require.NoError(t, err)

	return s
}

// approvedCode seeds an approved authorization of tvRefresh and returns its device code.
func (s *eventScene) approvedCode(t *testing.T) (string, *oidcprovider.DeviceAuthorization) {
	t.Helper()

	return s.tf.seed(t, tvRefresh, approved("openid"))
}

// TestDeviceEvents pins one event per device outcome, what each names, and that a failed,
// repeated or lost outcome reports none. Every event's JSON is also checked for a code, a
// handle, a flow secret or any run of 43 base64url characters.
func TestDeviceEvents(t *testing.T) {
	t.Parallel()

	// scene is what a row did: the events its sink saw, and the secrets none may carry.
	type scene struct {
		events  []event.Event
		secrets []string
	}
	type testCase struct {
		name string
		run  func(t *testing.T) scene
		// want is how many of each named event the row reports, and zero for those left out.
		want   map[string]int
		assert func(t *testing.T, got []event.Event)
	}

	approveAsks := oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
	denies := oidcprovider.ConsentAnswer{Deny: true}
	// consentRow answers the consent stage, with the stage's spend failing when failSpend is set.
	consentRow := func(answer oidcprovider.ConsentAnswer, failSpend bool) func(t *testing.T) scene {
		return func(t *testing.T) scene {
			f := newDeviceConsentFixture(t, deviceConsentSetup{})
			handle, flow, session := f.atConsent(t, "", "")
			f.advanceFails.Store(failSpend)
			_, _, _ = f.answer(t, handle, flow, answer)

			return scene{events: f.events.all(), secrets: []string{entryCode, entryDisplay, handle, flow, session}}
		}
	}
	// exchangeRow exchanges an approved code after arrange, and presents it again replays times.
	exchangeRow := func(arrange func(*testing.T, *eventScene, *oidcprovider.DeviceAuthorization), replays int) func(t *testing.T) scene {
		return func(t *testing.T) scene {
			s := newEventScene(t)
			code, record := s.approvedCode(t)
			if arrange != nil {
				arrange(t, s, record)
			}
			_, _ = s.p.Token(t.Context(), deviceRequest(tvRefresh, code))
			for range replays {
				_, _ = s.p.Token(t.Context(), deviceRequest(tvRefresh, code))
			}

			return scene{events: s.events.all(), secrets: []string{code}}
		}
	}
	// clientAndUser asserts every event of name names the client and the user.
	clientAndUser := func(name, client string) func(*testing.T, []event.Event) {
		return func(t *testing.T, got []event.Event) {
			t.Helper()
			require.NotEmpty(t, named(got, name))
			for _, e := range named(got, name) {
				assert.Equal(t, client, e.Client, "%s: client", name)
				assert.Equal(t, identity.UserID("u-1"), e.User, "%s: user", name)
				assert.False(t, e.At.IsZero(), "%s: when", name)
			}
		}
	}

	cases := []testCase{
		{
			name: "an authorization issued names the client and no user",
			run: func(t *testing.T) scene {
				s := newEventScene(t)
				resp, err := s.p.AuthorizeDevice(t.Context(), oidcprovider.DeviceAuthorizationRequest{
					Form: url.Values{"client_id": {tvClient}, "scope": {"openid"}},
				})
				require.NoError(t, err)

				return scene{events: s.events.all(), secrets: []string{resp.DeviceCode, resp.UserCode}}
			},
			want: map[string]int{event.DeviceAuthorizationIssued: 1},
			assert: func(t *testing.T, got []event.Event) {
				reportsOf(t, first(t, got, event.DeviceAuthorizationIssued), tvClient, "", event.OutcomeSuccess)
			},
		},
		{
			name: "a first entry claims, and the same browser's re-entry claims nothing more",
			run: func(t *testing.T) scene {
				f := newDeviceConsentFixture(t, deviceConsentSetup{})
				_, flow := f.atLogin(t)
				_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{
					UserCode: entryDisplay, FlowSecret: flow, Source: entrySource,
				})
				require.NoError(t, err)

				return scene{events: f.events.all(), secrets: []string{entryCode, entryDisplay, flow}}
			},
			want: map[string]int{event.DeviceAuthorizationClaimed: 1},
			assert: func(t *testing.T, got []event.Event) {
				reportsOf(t, first(t, got, event.DeviceAuthorizationClaimed), "tv", "", event.OutcomeSuccess)
			},
		},
		{
			name: "an approval names the client and the user",
			run:  consentRow(approveAsks, false),
			want: map[string]int{event.DeviceAuthorizationClaimed: 1, event.DeviceAuthorizationApproved: 1},
			assert: func(t *testing.T, got []event.Event) {
				clientAndUser(event.DeviceAuthorizationApproved, "tv")(t, got)
				assert.Equal(t, event.OutcomeSuccess, first(t, got, event.DeviceAuthorizationApproved).Outcome)
			},
		},
		{
			name: "a denial names the client and the user, as a failure",
			run:  consentRow(denies, false),
			want: map[string]int{event.DeviceAuthorizationClaimed: 1, event.DeviceAuthorizationDenied: 1},
			assert: func(t *testing.T, got []event.Event) {
				clientAndUser(event.DeviceAuthorizationDenied, "tv")(t, got)
				assert.Equal(t, event.OutcomeFailure, first(t, got, event.DeviceAuthorizationDenied).Outcome)
			},
		},
		{
			name: "an approval whose stage spend fails is reported once, without the consent event",
			run:  consentRow(approveAsks, true),
			want: map[string]int{event.DeviceAuthorizationClaimed: 1, event.DeviceAuthorizationApproved: 1},
			assert: func(t *testing.T, got []event.Event) {
				assert.Empty(t, named(got, event.ConsentGiven))
			},
		},
		{
			name: "a denial whose stage spend fails is reported once, without the consent event",
			run:  consentRow(denies, true),
			want: map[string]int{event.DeviceAuthorizationClaimed: 1, event.DeviceAuthorizationDenied: 1},
			assert: func(t *testing.T, got []event.Event) {
				assert.Empty(t, named(got, event.ConsentDenied))
			},
		},
		{
			name: "a resume retried after the failed spend reports no second decision",
			run: func(t *testing.T) scene {
				f := newDeviceConsentFixture(t, deviceConsentSetup{})
				handle, flow, session := f.atConsent(t, "", "")
				f.advanceFails.Store(true)
				_, _, _ = f.answer(t, handle, flow, approveAsks)
				f.advanceFails.Store(false)
				_, _, err := f.answer(t, handle, flow, approveAsks)
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)

				return scene{events: f.events.all(), secrets: []string{entryCode, entryDisplay, handle, flow, session}}
			},
			want: map[string]int{event.DeviceAuthorizationClaimed: 1, event.DeviceAuthorizationApproved: 1},
			assert: func(t *testing.T, got []event.Event) {
				assert.Empty(t, named(got, event.ConsentGiven))
			},
		},
		{
			name: "an approval withdrawn for a session gone is reported approved, with no consent event",
			run: func(t *testing.T) scene {
				f := newDeviceConsentFixture(t, deviceConsentSetup{})
				handle, flow, session := f.atConsent(t, "", "")
				f.touchGone.Store(true)
				_, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
					Handle: handle, FlowSecret: flow, BrowserSessionSecret: session, Answer: &approveAsks,
				})
				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)

				return scene{events: f.events.all(), secrets: []string{entryCode, entryDisplay, handle, flow, session}}
			},
			want: map[string]int{event.DeviceAuthorizationClaimed: 1, event.DeviceAuthorizationApproved: 1},
			assert: func(t *testing.T, got []event.Event) {
				assert.Empty(t, named(got, event.ConsentGiven))
			},
		},
		{
			name: "an exchange that returns tokens names the client and the user",
			run:  exchangeRow(nil, 0),
			want: map[string]int{event.DeviceCodeExchanged: 1},
			assert: func(t *testing.T, got []event.Event) {
				clientAndUser(event.DeviceCodeExchanged, tvRefresh)(t, got)
				assert.Len(t, named(got, event.GrantCreated), 1)
			},
		},
		{
			name: "an exchange that lost the spend reports no exchange",
			run: exchangeRow(func(_ *testing.T, s *eventScene, _ *oidcprovider.DeviceAuthorization) {
				s.store.lost = true
			}, 0),
			want: map[string]int{},
		},
		{
			name: "a grant created over a revocation reports no exchange",
			run: exchangeRow(func(t *testing.T, s *eventScene, r *oidcprovider.DeviceAuthorization) {
				_, err := s.grants.Revoke(t.Context(), r.Approval.GrantFamily, oidcprovider.CauseConsentRevoked, deviceNow)
				require.NoError(t, err)
			}, 0),
			want: map[string]int{},
		},
		{
			name: "a replay names the client and the user, beside the one grant revocation",
			run:  exchangeRow(nil, 1),
			want: map[string]int{event.DeviceCodeExchanged: 1, event.DeviceCodeReplayed: 1, event.GrantRevoked: 1},
			assert: func(t *testing.T, got []event.Event) {
				clientAndUser(event.DeviceCodeReplayed, tvRefresh)(t, got)
				assert.Equal(t, event.OutcomeFailure, first(t, got, event.DeviceCodeReplayed).Outcome)
				assert.Equal(t, string(oidcprovider.CauseCodeReplay), first(t, got, event.GrantRevoked).Cause)
			},
		},
		{
			name: "each further replay is reported, and the grant is not revoked again",
			run:  exchangeRow(nil, 2),
			want: map[string]int{event.DeviceCodeExchanged: 1, event.DeviceCodeReplayed: 2, event.GrantRevoked: 1},
		},
		{
			name: "a sixth entry from a source that failed five times is reported throttled",
			run: func(t *testing.T) scene {
				events := &eventLog{}
				f := newEntryFixture(t, entrySetup{opts: []oidcprovider.Option{oidcprovider.WithSecurityEvents(events.sink)}})
				f.seed(t, entryCode, nil)
				for range 5 {
					_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: otherCode, Source: entrySource})
					require.ErrorIs(t, err, oidcprovider.ErrInvalidUserCode)
				}
				_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource})
				isThrottled(t, oidcprovider.AuthorizeResult{}, err)

				return scene{events: events.all(), secrets: []string{entryCode, entryDisplay, otherCode}}
			},
			want: map[string]int{event.UserCodeEntryThrottled: 1},
			assert: func(t *testing.T, got []event.Event) {
				reportsOf(t, first(t, got, event.UserCodeEntryThrottled), "", "", event.OutcomeFailure)
			},
		},
		{
			name: "an entry from an unattributable source is refused but not reported throttled",
			run: func(t *testing.T) scene {
				events := &eventLog{}
				f := newEntryFixture(t, entrySetup{opts: []oidcprovider.Option{oidcprovider.WithSecurityEvents(events.sink)}})
				_, err := f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: "not-an-address"})
				isThrottled(t, oidcprovider.AuthorizeResult{}, err)

				return scene{events: events.all(), secrets: []string{entryCode, entryDisplay}}
			},
			want: map[string]int{},
		},
		{
			name: "an entry whose caller left is refused but not reported throttled",
			run: func(t *testing.T) scene {
				events := &eventLog{}
				f := newEntryFixture(t, entrySetup{opts: []oidcprovider.Option{oidcprovider.WithSecurityEvents(events.sink)}})
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_, err := f.p.EnterUserCode(ctx, oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource})
				isThrottled(t, oidcprovider.AuthorizeResult{}, err)

				return scene{events: events.all(), secrets: []string{entryCode, entryDisplay}}
			},
			want: map[string]int{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := tc.run(t)

			for _, name := range append(deviceEventNames, event.GrantRevoked) {
				assert.Len(t, named(s.events, name), tc.want[name], "%s", name)
			}
			for _, e := range s.events {
				raw, err := json.Marshal(e)
				require.NoError(t, err)
				assert.False(t, base64urlRun.Match(raw), "%s carries a 43-character run: %s", e.Name, raw)
				for _, secret := range s.secrets {
					assert.NotContains(t, string(raw), secret, "%s carries a secret", e.Name)
				}
			}
			if tc.assert != nil {
				tc.assert(t, s.events)
			}
		})
	}
}
