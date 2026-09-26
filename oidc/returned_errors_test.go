package oidc_test

//go:generate mockgen -destination=passwordencoder_mock_test.go -package=oidc_test -typed github.com/kartaladev/scrty/password Encoder

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// TestOidcReturnedErrors pins task 5.7: an error caused by a consumer-supplied
// dependency at Authorize, Callback, AbortFlow, HandoffManager.Issue or
// NewBroker's password-encoder probe carries fixed library text, with the
// dependency's own error and any sentinel the path already matched (before
// this change, regardless of cause) still reachable by identity.
func TestOidcReturnedErrors(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

	assertNoLeak := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errRedactionFixture, "the dependency's own error is still reachable")
	}

	// failingCompletion is a flow store whose completion of the flow the
	// callback environment presents fails with the fixture.
	failingCompletion := func(t *testing.T) oidc.FlowStore {
		t.Helper()
		s := NewMockFlowStore(gomock.NewController(t))
		s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, errRedactionFixture)
		return s
	}

	type testCase struct {
		name string
		// call builds the entry point under test and calls it; result is
		// whatever that entry point returns besides its error, for rows that
		// assert it.
		call   func(t *testing.T) (result any, err error)
		assert func(t *testing.T, result any, err error)
	}

	cases := []testCase{
		{
			name: "Authorize's flow store begin fails",
			call: func(t *testing.T) (any, error) {
				t.Helper()

				ctrl := gomock.NewController(t)

				p := newTestProvider(t)
				reg, err := oidc.NewRegistry(p.Provider("corp"))
				require.NoError(t, err)

				store := NewMockFlowStore(ctrl)
				store.EXPECT().Begin(gomock.Any(), gomock.Any()).Return("", errRedactionFixture)

				m, err := oidc.NewManager(reg, stubBroker{},
					oidc.WithOutboundClient(p.Outbound(t)), oidc.WithFlowStore(store))
				require.NoError(t, err)

				return m.Authorize(t.Context(), "corp", "/after")
			},
			assert: func(t *testing.T, _ any, err error) {
				assertNoLeak(t, err)
				assert.NotErrorIs(t, err, oidc.ErrFlowStoreFull,
					"a store outage must not read as the default store's own full-capacity refusal")
			},
		},
		{
			name: "Callback's flow-store completion fails",
			call: func(t *testing.T) (any, error) {
				t.Helper()

				e := newCallbackEnv(t, now, failingCompletion)
				return e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
			},
			assert: func(t *testing.T, _ any, err error) {
				assertNoLeak(t, err)
				assert.ErrorIs(t, err, oidc.ErrFlowUnspent,
					"already joined regardless of cause: a failure before completion always leaves the flow cookie live")
			},
		},
		{
			name: "AbortFlow's flow-store completion fails",
			call: func(t *testing.T) (any, error) {
				t.Helper()

				e := newCallbackEnv(t, now, failingCompletion)
				return e.m.AbortFlow(t.Context(), "corp", "s", "h")
			},
			assert: func(t *testing.T, ended any, err error) {
				assertNoLeak(t, err)
				assert.Equal(t, false, ended, "a flow whose completion failed is not reported as ended")
			},
		},
		{
			name: "HandoffManager.Issue's store insert fails",
			call: func(t *testing.T) (any, error) {
				t.Helper()

				ctrl := gomock.NewController(t)

				store := NewMockHandoffStore(ctrl)
				store.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errRedactionFixture)

				h, err := oidc.NewHandoffManager(store, NewMockUserLoader(ctrl))
				require.NoError(t, err)

				return h.Issue(t.Context(), oidc.CallbackResult{
					Principal: &identity.Principal{ID: "u-1"},
				})
			},
			assert: func(t *testing.T, _ any, err error) {
				assertNoLeak(t, err)
			},
		},
		{
			name: "NewBroker's password-encoder probe fails",
			call: func(t *testing.T) (any, error) {
				t.Helper()

				ctrl := gomock.NewController(t)

				enc := NewMockEncoder(ctrl)
				enc.EXPECT().Encode(gomock.Any()).Return(nil, errRedactionFixture)

				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl),
					oidc.WithPasswordEncoder(enc))
			},
			assert: func(t *testing.T, _ any, err error) {
				assertNoLeak(t, err)
				assert.ErrorIs(t, err, oidc.ErrConfig,
					"the outer config sentinel already matched regardless of cause before this change")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := tc.call(t)
			tc.assert(t, result, err)
		})
	}
}
