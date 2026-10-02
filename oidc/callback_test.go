package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// callbackEnv is one login in progress: a provider, a manager whose default
// store holds a flow begun by Authorize, and a token endpoint that answers
// that flow's code with a valid ID token.
type callbackEnv struct {
	m      *oidc.Manager
	p      *testProvider
	broker *MockIdentityBroker
	auth   oidc.Authorization
	flow   oidc.Flow
	idTok  string
	logs   *bytes.Buffer
	now    time.Time
}

// genuine is the callback the provider's real redirect produces.
func (e *callbackEnv) genuine(t *testing.T) (oidc.CallbackResult, error) {
	t.Helper()
	return e.m.Callback(t.Context(), "corp", "the-code", e.flow.State, e.auth.Handle)
}

// expectBroker makes the broker resolve exactly one identity to alice.
func (e *callbackEnv) expectBroker(times int) {
	e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(alice(), nil).Times(times)
}

func alice() *identity.Principal { return &identity.Principal{ID: "user-alice", Username: "alice"} }

func TestManagerCallback(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbDown := errors.New("db down")

	type testCase struct {
		name string
		// flows, when set, replaces the default store; no flow is begun then.
		flows  func(t *testing.T) oidc.FlowStore
		setup  func(t *testing.T, e *callbackEnv)
		act    func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error)
		assert func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error)
	}

	spentByLater := func(t *testing.T, e *callbackEnv) {
		t.Helper()
		_, err := e.genuine(t)
		require.ErrorIs(t, err, oidc.ErrInvalidState, "the flow must be spent")
	}
	stillCompletable := func(t *testing.T, e *callbackEnv) {
		t.Helper()
		got, err := e.genuine(t)
		require.NoError(t, err, "the victim's genuine callback must still complete")
		assert.Equal(t, alice(), got.Principal)
	}

	cases := []testCase{
		{
			name: "a successful callback returns the brokered principal and the provider session",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
						assert.Equal(t, "corp", ext.Provider)
						assert.Equal(t, e.p.Issuer(), ext.Issuer)
						assert.Equal(t, "subject-1", ext.Subject)
						assert.Equal(t, "alice@corp.example", ext.Email)
						assert.True(t, ext.EmailVerified)
						assert.Equal(t, "provider-session", ext.Claims["sid"])
						return alice(), nil
					})
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.CallbackResult{
					Principal: alice(),
					Provider:  "corp",
					Issuer:    e.p.Issuer(),
					SessionID: "provider-session",
					IDToken:   e.idTok,
					Next:      "/after",
				}, got)
				spentByLater(t, e)
			},
		},
		{
			name: "a forged callback leaves the victim's flow completable",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "attacker-code", "attacker", e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load(), "nothing is exchanged")
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "a callback through another provider's path leaves the flow completable",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "partner", "the-code", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "an empty code is refused without touching the flow",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load())
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "an unknown provider",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "nope", "the-code", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				e.expectBroker(1)
				stillCompletable(t, e)
			},
		},
		{
			name: "a store fault propagates as itself",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, dbDown)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, dbDown)
				require.ErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
				assert.Contains(t, e.logs.String(), "level=ERROR")
			},
		},
		{
			name: "an exchange failure spends the flow",
			setup: func(_ *testing.T, e *callbackEnv) {
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusBadRequest, `{"error":"invalid_grant"}`
				})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) { return e.genuine(t) },
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
				spentByLater(t, e)
			},
		},
		{
			name: "an invalid ID token spends the flow and reaches no broker",
			setup: func(t *testing.T, e *callbackEnv) {
				bad := e.p.Sign(t, map[string]any{
					"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
					"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nonce": "an-earlier-flow",
				})
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusOK, `{"id_token":"` + bad + `"}`
				})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) { return e.genuine(t) },
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Contains(t, e.logs.String(), "nonce", "the cause reaches the log")
				spentByLater(t, e)
			},
		},
		{
			name: "a refused ID token's claim values never reach the log or the error",
			setup: func(t *testing.T, e *callbackEnv) {
				bad := e.p.Sign(t, map[string]any{
					"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
					"exp": now.Add(time.Minute).Unix(), "iat": "alice@corp.example", "nonce": e.flow.Nonce,
				})
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusOK, `{"id_token":"` + bad + `"}`
				})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) { return e.genuine(t) },
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
				require.Contains(t, e.logs.String(), "invalid-id-token", "the refusal is logged")
				assert.NotContains(t, e.logs.String(), "alice@corp.example")
				assert.NotContains(t, err.Error(), "alice@corp.example")
			},
		},
		{
			name: "a store that completes another provider's flow has still spent it",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "partner", State: "s", Nonce: "n", Verifier: "v"}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent, "the store consumed the flow")
				assert.Equal(t, oidc.CallbackResult{}, got)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load(), "no code is exchanged")
			},
		},
		{
			name: "a broker refusal is returned as itself",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(nil, oidc.ErrNoLinkedAccount)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
				spentByLater(t, e)
			},
		},
		{
			name: "a malformed amr is warned about by provider and claim, never its value, and the login proceeds",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": "mfa"})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err, "a malformed claim never fails the login")
				assert.Equal(t, alice(), got.Principal)
				assert.Empty(t, got.AMR, "a malformed amr asserts nothing")
				out := e.logs.String()
				assert.Contains(t, out, "level=WARN")
				assert.Contains(t, out, "reason=malformed-assurance-claim")
				assert.Contains(t, out, "provider=corp")
				assert.Contains(t, out, "claim=amr")
				assert.NotContains(t, out, "mfa", "the claim's value never reaches a log")
			},
		},
		{
			name: "a malformed acr is warned about without its value",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"acr": map[string]any{"level": "gold-marker"}})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, alice(), got.Principal)
				out := e.logs.String()
				assert.Contains(t, out, "provider=corp")
				assert.Contains(t, out, "claim=acr")
				assert.NotContains(t, out, "gold-marker")
			},
		},
		{
			name: "malformed assurance warnings are sampled under the provider's callback key",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"mfa", 1}, "acr": 2})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, strings.Count(e.logs.String(), "reason=malformed-assurance-claim"),
					"the second warning in the window is held back")
				require.NoError(t, e.m.FlushRefusalLogs())
				out := e.logs.String()
				assert.Contains(t, out, "reason=oidc.callback:malformed-assurance-claim:corp suppressed=1")
				assert.NotContains(t, out, "mfa")
			},
		},
		{
			name: "well-formed assurance claims write no warning",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"pwd", "mfa"}, "acr": "urn:corp:loa:2"})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, e *callbackEnv, _ oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.NotContains(t, e.logs.String(), "malformed-assurance-claim")
			},
		},
		{
			name: "the asserted amr and acr travel in the result, amr in order without duplicates",
			setup: func(t *testing.T, e *callbackEnv) {
				e.reissue(t, map[string]any{"amr": []any{"pwd", "mfa", "mfa"}, "acr": "urn:corp:loa:2"})
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.expectBroker(1)
				return e.genuine(t)
			},
			assert: func(t *testing.T, _ *callbackEnv, got oidc.CallbackResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, got.AMR)
				assert.Equal(t, "urn:corp:loa:2", got.ACR)
			},
		},
		{
			name: "a broker returning no principal and no error is a failure",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(nil, nil)
				return e.genuine(t)
			},
			assert: func(t *testing.T, _ *callbackEnv, got oidc.CallbackResult, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent)
				assert.Equal(t, oidc.CallbackResult{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, tc.flows)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			got, err := tc.act(t, e)
			tc.assert(t, e, got, err)
			assertNoFlowSecretsLogged(t, e)
		})
	}
}

func TestManagerCallbackAbortFlow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbDown := errors.New("db down")

	type testCase struct {
		name   string
		flows  func(t *testing.T) oidc.FlowStore
		act    func(t *testing.T, e *callbackEnv) (bool, error)
		assert func(t *testing.T, e *callbackEnv, ended bool, err error)
	}

	cases := []testCase{
		{
			name: "a forged error link changes nothing",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "", e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.False(t, ended)
				e.expectBroker(1)
				_, err = e.genuine(t)
				require.NoError(t, err, "the victim's genuine callback must still complete")
			},
		},
		{
			name: "an error link with a wrong state changes nothing",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "attacker", e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.False(t, ended)
				e.expectBroker(1)
				_, err = e.genuine(t)
				require.NoError(t, err)
			},
		},
		{
			name: "a genuine denial ends the flow",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.True(t, ended)
				_, err = e.genuine(t)
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				assert.Equal(t, int64(0), e.p.tokenCalls.Load())
			},
		},
		{
			name: "a store that completes another provider's flow has ended it",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "partner", State: "s"}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, _ *callbackEnv, ended bool, err error) {
				require.NoError(t, err)
				assert.True(t, ended, "the store consumed the flow, so the cookie may go")
			},
		},
		{
			name: "an unknown provider ends nothing",
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "nope", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, e *callbackEnv, ended bool, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				assert.False(t, ended)
				e.expectBroker(1)
				_, err = e.genuine(t)
				require.NoError(t, err)
			},
		},
		{
			name: "a store fault propagates as itself",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, dbDown)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (bool, error) {
				return e.m.AbortFlow(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, _ *callbackEnv, ended bool, err error) {
				require.ErrorIs(t, err, dbDown)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
				assert.False(t, ended)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, tc.flows)
			ended, err := tc.act(t, e)
			tc.assert(t, e, ended, err)
			assertNoFlowSecretsLogged(t, e)
		})
	}
}

// newCallbackEnv builds a manager for providers corp and partner at a fixed
// clock. With the default store it begins one flow at corp, and makes corp's
// token endpoint answer that flow's code with a valid ID token.
func newCallbackEnv(t *testing.T, now time.Time, flows func(t *testing.T) oidc.FlowStore) *callbackEnv {
	t.Helper()

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)

	e := &callbackEnv{p: p, broker: NewMockIdentityBroker(gomock.NewController(t)), logs: &bytes.Buffer{}, now: now}
	opts := []oidc.ManagerOption{
		oidc.WithOutboundClient(p.Outbound(t)),
		oidc.WithClock(clockwork.NewFakeClockAt(now)),
		oidc.WithLogger(testTextLogger(e.logs)),
	}
	if flows != nil {
		opts = append(opts, oidc.WithFlowStore(flows(t)))
	}
	e.m, err = oidc.NewManager(reg, e.broker, opts...)
	require.NoError(t, err)
	if flows != nil {
		return e
	}

	e.auth, err = e.m.Authorize(t.Context(), "corp", "/after")
	require.NoError(t, err)
	e.flow = authorizeFlow(t, e.m, e.auth.Handle)
	e.reissue(t, nil)

	return e
}

// reissue makes corp's token endpoint answer the flow's code with a valid ID
// token carrying extra claims beside the usual ones.
func (e *callbackEnv) reissue(t *testing.T, extra map[string]any) {
	t.Helper()

	claims := map[string]any{
		"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
		"exp": e.now.Add(5 * time.Minute).Unix(), "iat": e.now.Unix(),
		"nonce": e.flow.Nonce, "sid": "provider-session",
		"email": "alice@corp.example", "email_verified": true,
	}
	maps.Copy(claims, extra)
	idTok := e.p.Sign(t, claims)
	e.idTok = idTok
	verifier := e.flow.Verifier
	e.p.SetTokenResponse(func(r *http.Request) (int, string) {
		if r.ParseForm() != nil || r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") != verifier {
			return http.StatusBadRequest, `{"error":"invalid_grant"}`
		}
		return http.StatusOK, `{"access_token":"at","id_token":"` + idTok + `"}`
	})
}

// assertNoFlowSecretsLogged fails when a flow secret or token reached a log.
func assertNoFlowSecretsLogged(t *testing.T, e *callbackEnv) {
	t.Helper()

	out := e.logs.String()
	for _, secret := range []string{e.flow.State, e.flow.Nonce, e.flow.Verifier, e.idTok, e.auth.Handle,
		url.QueryEscape(e.flow.State), "the-code", "secret-corp"} {
		if secret != "" {
			assert.NotContains(t, out, secret)
		}
	}
}
