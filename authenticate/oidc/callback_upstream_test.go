package oidc_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// upstreamCallbackEnv is one login in progress at provider corp, whose token
// endpoint answers the flow's code with a valid ID token beside whatever
// tokenFields adds, and whose relying party resolves through broker.
type upstreamCallbackEnv struct {
	m    *oidc.RelyingParty
	p    *testProvider
	auth oidc.Authorization
	flow oidc.Flow
	logs *bytes.Buffer
}

// newUpstreamCallbackEnv begins a flow at corp and makes its token endpoint
// answer with tokenFields (JSON members, each followed by a comma, or empty)
// and a valid ID token for subject-1.
func newUpstreamCallbackEnv(t *testing.T, broker oidc.IdentityBroker, tokenFields string) *upstreamCallbackEnv {
	t.Helper()

	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)

	e := &upstreamCallbackEnv{p: p, logs: &bytes.Buffer{}}
	e.m, err = oidc.NewRelyingParty(reg, broker,
		oidc.WithOutboundClient(p.Outbound(t)),
		oidc.WithClock(clockwork.NewFakeClockAt(now)),
		oidc.WithLogger(testTextLogger(e.logs)))
	require.NoError(t, err)

	e.auth, err = e.m.Authorize(t.Context(), "corp", "/after")
	require.NoError(t, err)
	e.flow = authorizeFlow(t, e.m, e.auth.Handle)

	idTok := p.Sign(t, map[string]any{
		"iss": p.Issuer(), "aud": "client-corp", "sub": "subject-1",
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
	return e.m.Callback(t.Context(), "corp", "the-code", e.flow.State, e.auth.Handle)
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

const (
	upstreamAccessToken  = "at-secret"
	upstreamRefreshToken = "rt-secret"
	bothUpstreamTokens   = `"access_token":"` + upstreamAccessToken + `","refresh_token":"` + upstreamRefreshToken + `",`
)

func TestCallback_Upstream(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		tokenFields string
		broker      func(t *testing.T) oidc.IdentityBroker
		assert      func(t *testing.T, e *upstreamCallbackEnv, got oidc.CallbackResult, err error)
	}

	cases := []testCase{
		{
			name:        "DropsUpstreamTokensFromResults",
			tokenFields: bothUpstreamTokens,
			broker: func(t *testing.T) oidc.IdentityBroker {
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
			broker: func(t *testing.T) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
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
			broker: func(t *testing.T) oidc.IdentityBroker {
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
			broker: func(t *testing.T) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
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
			broker: func(t *testing.T) oidc.IdentityBroker {
				b := NewMockIdentityBroker(gomock.NewController(t))
				b.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(alice(), nil)
				return b
			},
			assert: func(t *testing.T, _ *upstreamCallbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err, "a non-string access_token still logs in")
				assert.Equal(t, alice(), got.Principal)
			},
		},
	}
	for _, v := range []string{`{"v":1}`, `12`, `null`, `[1]`, `true`} {
		cases = append(cases, testCase{
			name:        "NonStringAccessTokenIsAbsent/" + v,
			tokenFields: `"access_token":` + v + `,`,
			broker: func(t *testing.T) oidc.IdentityBroker {
				ctrl := gomock.NewController(t)
				up := NewMockUpstreamBroker(ctrl)
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

			e := newUpstreamCallbackEnv(t, tc.broker(t), tc.tokenFields)
			got, err := e.callback(t)
			tc.assert(t, e, got, err)
		})
	}
}
