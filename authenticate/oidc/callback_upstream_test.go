package oidc_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// upstreamCallbackEnv is one login in progress at provider (corp or partner,
// which share one test issuer), whose token endpoint answers the flow's code
// with a valid ID token beside whatever tokenFields adds, and whose relying
// party resolves through broker.
type upstreamCallbackEnv struct {
	provider string
	broker   oidc.IdentityBroker
	m        *oidc.RelyingParty
	p        *testProvider
	auth     oidc.Authorization
	flow     oidc.Flow
	logs     *bytes.Buffer
}

// newUpstreamCallbackEnv begins a flow at provider, corp or partner, and makes
// the token endpoint answer with tokenFields (JSON members, each followed by a
// comma, or empty) and a valid ID token for subject-1. broker is built once
// the test issuer is known.
func newUpstreamCallbackEnv(t *testing.T, provider string, broker func(issuer string) oidc.IdentityBroker, tokenFields string) *upstreamCallbackEnv {
	t.Helper()

	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)

	e := &upstreamCallbackEnv{provider: provider, p: p, logs: &bytes.Buffer{}}
	e.broker = broker(p.Issuer())
	e.m, err = oidc.NewRelyingParty(reg, e.broker,
		oidc.WithOutboundClient(p.Outbound(t)),
		oidc.WithClock(clockwork.NewFakeClockAt(now)),
		oidc.WithLogger(testTextLogger(e.logs)))
	require.NoError(t, err)

	e.auth, err = e.m.Authorize(t.Context(), provider, "/after")
	require.NoError(t, err)
	e.flow = authorizeFlow(t, e.m, e.auth.Handle)

	idTok := p.Sign(t, map[string]any{
		"iss": p.Issuer(), "aud": "client-" + provider, "sub": "subject-1",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"nonce": e.flow.Nonce, "email": "alice@corp.example", "email_verified": true,
	})
	p.SetTokenResponse(func(*http.Request) (int, string) {
		return http.StatusOK, `{` + tokenFields + `"token_type":"Bearer","id_token":"` + idTok + `"}`
	})

	return e
}

func (e *upstreamCallbackEnv) callback(t *testing.T) (oidc.CallbackResult, error) {
	t.Helper()
	return e.m.Callback(t.Context(), e.provider, "the-code", e.flow.State, e.auth.Handle)
}

// recordingHandoffStore is the memory handoff store, keeping every record it
// was asked to insert.
type recordingHandoffStore struct {
	*oidc.MemoryHandoffStore
	inserted []oidc.HandoffRecord
}

func (s *recordingHandoffStore) Insert(ctx context.Context, rec oidc.HandoffRecord) error {
	s.inserted = append(s.inserted, rec)
	return s.MemoryHandoffStore.Insert(ctx, rec)
}

// upstreamAndPlainBroker is a broker that accepts upstream access: the plain
// method fails the test if called, the upstream one is the mock's.
type upstreamAndPlainBroker struct {
	*MockIdentityBroker
	*MockUpstreamBroker
}

// refusingWrapper is a consumer's broker that embeds the library broker and
// overrides Broker to refuse subject-1, counting each call. The library
// broker under it hooks corp only and links (partner, subject-1) to
// user-alice, so without the override partner's subject-1 would sign in.
//
// A struct that embeds *oidc.Broker directly has a field named Broker and so
// cannot declare a Broker method; a consumer embeds it under another name,
// here through an alias, which still promotes AcceptsUpstream and
// BrokerUpstream.
type refusingWrapper struct {
	*libraryBroker
	calls *atomic.Int32
}

// libraryBroker names the library broker for embedding.
type libraryBroker = oidc.Broker

func (w *refusingWrapper) Broker(ctx context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
	w.calls.Add(1)
	if ext.Subject == "subject-1" {
		return nil, oidc.ErrNoLinkedAccount
	}
	return w.libraryBroker.Broker(ctx, ext)
}

func newRefusingWrapper(t *testing.T, issuer string) *refusingWrapper {
	t.Helper()

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider: "partner", Issuer: issuer, Subject: "subject-1", UserID: "user-alice", Username: "alice",
	}))
	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, u identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: u, Username: "alice", Active: true}, nil
		}).AnyTimes()
	b, err := oidc.NewBroker(links, users, oidc.WithBrokerSignInHook("corp", noopHook))
	require.NoError(t, err)
	return &refusingWrapper{libraryBroker: b, calls: &atomic.Int32{}}
}

const (
	upstreamAccessToken  = "at-secret"
	upstreamRefreshToken = "rt-secret"
	bothUpstreamTokens   = `"access_token":"` + upstreamAccessToken + `","refresh_token":"` + upstreamRefreshToken + `",`
)

func TestCallback_Upstream(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		provider    string // empty means corp
		tokenFields string
		// plainBroker builds the broker; broker, when set, builds it instead,
		// given the test issuer.
		plainBroker func(t *testing.T) oidc.IdentityBroker
		broker      func(t *testing.T, issuer string) oidc.IdentityBroker
		assert      func(t *testing.T, e *upstreamCallbackEnv, got oidc.CallbackResult, err error)
	}

	cases := []testCase{
		{
			name:        "DropsUpstreamTokensFromResults",
			tokenFields: bothUpstreamTokens,
			plainBroker: func(t *testing.T) oidc.IdentityBroker {
				b := NewMockIdentityBroker(gomock.NewController(t))
				b.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(alice(), nil)
				return b
			},
			assert: func(t *testing.T, e *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)

				store := &recordingHandoffStore{MemoryHandoffStore: oidc.NewMemoryHandoffStore()}
				h, err := oidc.NewHandoff(store, NewMockUserLoader(gomock.NewController(t)))
				require.NoError(t, err)
				_, err = h.Issue(t.Context(), got)
				require.NoError(t, err)
				require.Len(t, store.inserted, 1)

				stored, _ := oidc.FlowForTest(oidc.WiringOf(e.m).Flows.(*oidc.MemoryFlowStore), e.auth.Handle)
				for what, text := range map[string]string{
					"callback result": fmt.Sprintf("%#v %#v", got, *got.Principal),
					"flow":            fmt.Sprintf("%#v %#v", e.flow, stored),
					"handoff record":  fmt.Sprintf("%#v", store.inserted[0]),
					"logs":            e.logs.String(),
				} {
					assert.NotContains(t, text, upstreamAccessToken, "the %s must not hold the access token", what)
					assert.NotContains(t, text, upstreamRefreshToken, "the %s must not hold the refresh token", what)
				}
			},
		},
		{
			name:        "UpstreamBrokerReceivesToken",
			tokenFields: bothUpstreamTokens,
			plainBroker: func(t *testing.T) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
				up.EXPECT().AcceptsUpstream("corp").Return(true)
				up.EXPECT().BrokerUpstream(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity, u oidc.Upstream) (*identity.Principal, error) {
						assert.Equal(t, "subject-1", ext.Subject)
						assert.True(t, u.HasAccessToken())
						assert.Equal(t, upstreamAccessToken, u.AccessToken())
						return alice(), nil
					})
				return upstreamAndPlainBroker{MockIdentityBroker: NewMockIdentityBroker(ctrl), MockUpstreamBroker: up}
			},
			assert: func(t *testing.T, e *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
				assert.NotContains(t, fmt.Sprintf("%#v", got), upstreamAccessToken)
				assert.NotContains(t, e.logs.String(), upstreamAccessToken)
			},
		},
		{
			name:        "PlainBrokerUnchanged",
			tokenFields: bothUpstreamTokens,
			plainBroker: func(t *testing.T) oidc.IdentityBroker {
				b := NewMockIdentityBroker(gomock.NewController(t))
				b.EXPECT().Broker(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
						assert.Equal(t, "subject-1", ext.Subject)
						assert.NotContains(t, fmt.Sprintf("%#v", ext), upstreamAccessToken,
							"the verified identity carries no upstream access")
						return alice(), nil
					})
				return b
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
			},
		},
		{
			name:        "NoAccessTokenStillLogsIn",
			tokenFields: "",
			plainBroker: func(t *testing.T) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
				up.EXPECT().AcceptsUpstream("corp").Return(true)
				up.EXPECT().BrokerUpstream(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ oidc.ExternalIdentity, u oidc.Upstream) (*identity.Principal, error) {
						assert.False(t, u.HasAccessToken())
						assert.Empty(t, u.AccessToken())
						_, err := u.UserInfo(ctx)
						assert.ErrorIs(t, err, oidc.ErrUserInfoFailed)
						return alice(), nil
					})
				return upstreamAndPlainBroker{MockIdentityBroker: NewMockIdentityBroker(ctrl), MockUpstreamBroker: up}
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err, "a token response without an access token still logs in")
				assert.Equal(t, alice(), got.Principal)
			},
		},
		{
			name:        "NonStringAccessTokenIsAbsentForPlainBroker",
			tokenFields: `"access_token":{"v":1},`,
			plainBroker: func(t *testing.T) oidc.IdentityBroker {
				b := NewMockIdentityBroker(gomock.NewController(t))
				b.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(alice(), nil)
				return b
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err, "a non-string access_token still logs in")
				assert.Equal(t, alice(), got.Principal)
			},
		},
		{
			// F54: an unhooked provider reaches the wrapper's own Broker, so its
			// refusal is the login's outcome.
			name:     "WrapperOfLibraryBrokerRefusesOnUnhookedProvider",
			provider: "partner",
			broker: func(t *testing.T, issuer string) oidc.IdentityBroker {
				return newRefusingWrapper(t, issuer)
			},
			assert: func(t *testing.T, e *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount,
					"the wrapper's Broker override refuses subject-1 on unhooked partner")
				assert.Nil(t, got.Principal)
				w, ok := e.broker.(*refusingWrapper)
				require.True(t, ok)
				assert.Equal(t, int32(1), w.calls.Load(), "the override is called once")
			},
		},
		{
			name:     "ConsumerBrokerScopedToCorpIsIdentityOnlyThroughPartner",
			provider: "partner",
			broker: func(t *testing.T, _ string) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
				up.EXPECT().AcceptsUpstream(gomock.Any()).
					DoAndReturn(func(provider string) bool { return provider == "corp" }).AnyTimes()
				plain := NewMockIdentityBroker(ctrl)
				plain.EXPECT().Broker(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
						assert.Equal(t, "partner", ext.Provider)
						return alice(), nil
					})
				return upstreamAndPlainBroker{MockIdentityBroker: plain, MockUpstreamBroker: up}
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
			},
		},
		{
			name:        "ConsumerBrokerScopedToCorpGetsUpstreamThroughCorp",
			provider:    "corp",
			tokenFields: bothUpstreamTokens,
			broker: func(t *testing.T, _ string) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
				up.EXPECT().AcceptsUpstream(gomock.Any()).
					DoAndReturn(func(provider string) bool { return provider == "corp" }).AnyTimes()
				up.EXPECT().BrokerUpstream(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity, u oidc.Upstream) (*identity.Principal, error) {
						assert.Equal(t, "corp", ext.Provider)
						assert.Equal(t, upstreamAccessToken, u.AccessToken())
						return alice(), nil
					})
				return upstreamAndPlainBroker{MockIdentityBroker: NewMockIdentityBroker(ctrl), MockUpstreamBroker: up}
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
			},
		},
	}
	for _, v := range []string{`{"v":1}`, `12`, `null`, `[1]`, `true`} {
		cases = append(cases, testCase{
			name:        "NonStringAccessTokenIsAbsent/" + v,
			tokenFields: `"access_token":` + v + `,`,
			plainBroker: func(t *testing.T) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
				up.EXPECT().AcceptsUpstream("corp").Return(true)
				up.EXPECT().BrokerUpstream(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ oidc.ExternalIdentity, u oidc.Upstream) (*identity.Principal, error) {
						assert.False(t, u.HasAccessToken())
						assert.Empty(t, u.AccessToken())
						return alice(), nil
					})
				return upstreamAndPlainBroker{MockIdentityBroker: NewMockIdentityBroker(ctrl), MockUpstreamBroker: up}
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := tc.provider
			if provider == "" {
				provider = "corp"
			}
			broker := tc.broker
			if broker == nil {
				broker = func(t *testing.T, _ string) oidc.IdentityBroker { return tc.plainBroker(t) }
			}
			e := newUpstreamCallbackEnv(t, provider, func(issuer string) oidc.IdentityBroker { return broker(t, issuer) }, tc.tokenFields)
			got, err := e.callback(t)
			tc.assert(t, e, got, err)
		})
	}
}
