package oidc_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

const parkedNext = "https://op.example/login?req=h-1"

// nextCarrier is a consumer error type that holds a field named Next. The
// callback must never read the destination from an error chain.
type nextCarrier struct{ Next string }

func (c nextCarrier) Error() string { return "broker failure" }

// parkedFlowStore answers the completion of handle "h" at provider corp with
// a flow parked at parkedNext.
func parkedFlowStore(t *testing.T) oidc.FlowStore {
	t.Helper()
	s := NewMockFlowStore(gomock.NewController(t))
	s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
		Return(oidc.Flow{Provider: "corp", State: "s", Nonce: "n", Verifier: "v", Next: parkedNext}, nil)
	return s
}

// validTokenFor makes the token endpoint answer a valid ID token for the
// parked flow's nonce and verifier.
func validTokenFor(t *testing.T, e *callbackEnv) {
	t.Helper()
	e.flow = oidc.Flow{Nonce: "n", Verifier: "v"}
	e.reissue(t, nil)
}

func TestCallback_FailureAfterSpendCarriesNext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		setup  func(t *testing.T, e *callbackEnv)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:  "discovery fails",
			setup: func(_ *testing.T, e *callbackEnv) { e.p.failDiscovery.Store(true) },
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{
			name: "the exchange fails",
			setup: func(_ *testing.T, e *callbackEnv) {
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusBadRequest, `{"error":"invalid_grant"}`
				})
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
			},
		},
		{
			name: "the ID token is invalid",
			setup: func(t *testing.T, e *callbackEnv) {
				bad := e.p.Sign(t, map[string]any{
					"iss": e.p.Issuer(), "aud": "client-corp", "sub": "subject-1",
					"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nonce": "another-flow",
				})
				e.p.SetTokenResponse(func(*http.Request) (int, string) {
					return http.StatusOK, `{"id_token":"` + bad + `"}`
				})
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
			},
		},
		{
			name: "the broker finds no linked account",
			setup: func(t *testing.T, e *callbackEnv) {
				validTokenFor(t, e)
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(nil, oidc.ErrNoLinkedAccount)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
			},
		},
		{
			name: "the broker's error wraps a struct with a Next field",
			setup: func(t *testing.T, e *callbackEnv) {
				validTokenFor(t, e)
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("broker: %w", nextCarrier{Next: "https://evil"}))
			},
			assert: func(t *testing.T, err error) {
				var c nextCarrier
				require.ErrorAs(t, err, &c, "the broker's error stays reachable")
			},
		},
		{
			name: "the broker returns no principal and no error",
			setup: func(t *testing.T, e *callbackEnv) {
				validTokenFor(t, e)
				e.broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return((*identity.Principal)(nil), nil)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, parkedFlowStore)
			tc.setup(t, e)

			got, err := e.m.Callback(t.Context(), "corp", "the-code", "s", "h")

			require.Error(t, err)
			assert.NotErrorIs(t, err, oidc.ErrFlowUnspent, "the flow is spent")
			tc.assert(t, err)
			assert.Equal(t, oidc.CallbackResult{Next: parkedNext}, got,
				"only the stored flow's Next survives a failure after the spend")
			assert.Nil(t, got.Principal)
			assert.Empty(t, got.IDToken)
		})
	}
}

func TestCallback_UnspentFailureHasNoNext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		flows  func(t *testing.T) oidc.FlowStore
		act    func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error)
		assert func(t *testing.T, err error)
	}

	unspent := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrFlowUnspent)
	}

	cases := []testCase{
		{
			name: "an unknown state",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "attacker", e.auth.Handle)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				unspent(t, err)
			},
		},
		{
			name: "an empty code",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				unspent(t, err)
			},
		},
		{
			name: "an unknown provider",
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "nope", "the-code", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				unspent(t, err)
			},
		},
		{
			name: "a store fault",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, errDBDown)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errDBDown)
				unspent(t, err)
			},
		},
		{
			name: "a flow of another provider has no destination to trust",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "partner", State: "s", Next: parkedNext}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent, "the store consumed the flow")
			},
		},
		{
			name: "a flow whose state differs from the presented one has no destination to trust",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "corp", State: "other", Next: parkedNext}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.CallbackResult, error) {
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				assert.NotErrorIs(t, err, oidc.ErrFlowUnspent, "the store consumed the flow")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, tc.flows)
			got, err := tc.act(t, e)
			require.Error(t, err)
			tc.assert(t, err)
			assert.Equal(t, oidc.CallbackResult{}, got)
		})
	}
}
