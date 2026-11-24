package oidc_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
)

func TestAbortFlowNext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		flows  func(t *testing.T) oidc.FlowStore
		act    func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error)
		assert func(t *testing.T, got oidc.AbortedFlow, err error)
	}

	cases := []testCase{
		{
			name: "the matching state ends the flow and reports its destination",
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "corp", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.AbortedFlow{Ended: true, Next: "/after"}, got)
			},
		},
		{
			name: "a wrong state ends nothing and reports no destination",
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "corp", "attacker", e.auth.Handle)
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.AbortedFlow{}, got)
			},
		},
		{
			name: "an empty state ends nothing and reports no destination",
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "corp", "", e.auth.Handle)
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.AbortedFlow{}, got)
			},
		},
		{
			name: "a flow of another provider is ended with no destination",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "partner", State: "s", Next: "https://other.example/x"}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.AbortedFlow{Ended: true}, got)
			},
		},
		{
			name: "a flow whose state differs from the presented one is ended with no destination",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
					Return(oidc.Flow{Provider: "corp", State: "other", Next: "https://op.example/login?req=h-1"}, nil)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.NoError(t, err)
				assert.Equal(t, oidc.AbortedFlow{Ended: true}, got)
			},
		},
		{
			name: "an unknown provider ends nothing",
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "nope", e.flow.State, e.auth.Handle)
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				assert.Equal(t, oidc.AbortedFlow{}, got)
			},
		},
		{
			name: "a store fault is returned wrapped and ends nothing",
			flows: func(t *testing.T) oidc.FlowStore {
				s := NewMockFlowStore(gomock.NewController(t))
				s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, errDBDown)
				return s
			},
			act: func(t *testing.T, e *callbackEnv) (oidc.AbortedFlow, error) {
				return e.m.AbortFlowNext(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, got oidc.AbortedFlow, err error) {
				require.ErrorIs(t, err, errDBDown)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
				assert.Equal(t, oidc.AbortedFlow{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCallbackEnv(t, now, tc.flows)
			got, err := tc.act(t, e)
			tc.assert(t, got, err)
			assertNoFlowSecretsLogged(t, e)
		})
	}
}
