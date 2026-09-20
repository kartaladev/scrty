package authorize_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
)

// errBackendDown stands in for a failure that is an outage rather than a
// decision about the caller, so the tests can assert it stays matchable.
var errBackendDown = errors.New("backend down")

func TestManagerAuthorize(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		authorizers func(t *testing.T, ctrl *gomock.Controller) []authorize.Authorizer
		ctx         func(ctx context.Context) context.Context
		assert      func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the first authorizer that does not skip decides",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				first := NewMockAuthorizer(ctrl)
				first.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)
				second := NewMockAuthorizer(ctrl) // no EXPECT: asking it is the failure

				return []authorize.Authorizer{first, second}
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a declining authorizer is passed over",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				first := NewMockAuthorizer(ctrl)
				first.EXPECT().Authorize(gomock.Any(), gomock.Any()).
					Return(authorize.ErrUnsupportedAttributes)
				second := NewMockAuthorizer(ctrl)
				second.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)

				return []authorize.Authorizer{first, second}
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a refusal ends the chain, so later authorizers never judge",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				first := NewMockAuthorizer(ctrl)
				first.EXPECT().Authorize(gomock.Any(), gomock.Any()).
					Return(authorize.ErrInvalidAttributes)
				second := NewMockAuthorizer(ctrl) // no EXPECT: asking it is the failure

				return []authorize.Authorizer{first, second}
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrInvalidAttributes)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"malformed attributes were reported as a decision about the caller")
			},
		},
		{
			name: "all skipping denies",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				first := NewMockAuthorizer(ctrl)
				first.EXPECT().Authorize(gomock.Any(), gomock.Any()).
					Return(authorize.ErrUnsupportedAttributes)
				second := NewMockAuthorizer(ctrl)
				second.EXPECT().Authorize(gomock.Any(), gomock.Any()).
					Return(authorize.ErrUnsupportedAttributes)

				return []authorize.Authorizer{first, second}
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
			},
		},
		{
			name: "a consumer authorizer's own error is returned unchanged",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				custom := NewMockAuthorizer(ctrl)
				custom.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(errBackendDown)

				return []authorize.Authorizer{custom}
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"a consumer authorizer's outage was rewritten as a denial")
			},
		},
		{
			name: "the caller's context reaches the authorizer unchanged",
			authorizers: func(t *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				only := NewMockAuthorizer(ctrl)
				only.EXPECT().Authorize(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ authorize.Attributes) error {
						assert.ErrorIs(t, ctx.Err(), context.Canceled,
							"the manager substituted a context of its own")

						return ctx.Err()
					})

				return []authorize.Authorizer{only}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			manager, err := authorize.NewManager(tc.authorizers(t, ctrl)...)
			require.NoError(t, err)

			tc.assert(t, manager.Authorize(ctx, authorize.PrivilegeAttributes{
				Group:    "billing",
				Resource: "invoice",
				Required: []string{"read"},
			}))
		})
	}
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		authorizers func(t *testing.T, ctrl *gomock.Controller) []authorize.Authorizer
		assert      func(t *testing.T, manager *authorize.Manager, err error)
	}

	configError := func(t *testing.T, manager *authorize.Manager, err error) {
		require.ErrorIs(t, err, authorize.ErrConfig)
		assert.Nil(t, manager, "a refused configuration still produced a manager")
	}

	cases := []testCase{
		{
			name: "a manager over one authorizer is built",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				return []authorize.Authorizer{NewMockAuthorizer(ctrl)}
			},
			assert: func(t *testing.T, manager *authorize.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, manager)
			},
		},
		{
			name: "no authorizers at all is a configuration error",
			authorizers: func(_ *testing.T, _ *gomock.Controller) []authorize.Authorizer {
				return nil
			},
			assert: configError,
		},
		{
			name: "an untyped nil authorizer is a configuration error",
			authorizers: func(_ *testing.T, ctrl *gomock.Controller) []authorize.Authorizer {
				return []authorize.Authorizer{NewMockAuthorizer(ctrl), nil}
			},
			assert: configError,
		},
		{
			// What an unchecked constructor error hands over: the interface
			// carries a type, so `a == nil` misses it and the first request
			// panics instead of the wiring failing here.
			name: "a typed nil authorizer is a configuration error",
			authorizers: func(_ *testing.T, _ *gomock.Controller) []authorize.Authorizer {
				var absent *authorize.Manager

				return []authorize.Authorizer{absent}
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			manager, err := authorize.NewManager(tc.authorizers(t, ctrl)...)
			tc.assert(t, manager, err)
		})
	}
}

func TestManagerHoldsItsOwnAuthorizerSlice(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	judging := NewMockAuthorizer(ctrl)
	judging.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil)

	authorizers := []authorize.Authorizer{judging}

	manager, err := authorize.NewManager(authorizers...)
	require.NoError(t, err)

	// A caller reusing its slice must not be able to swap an authorizer out
	// from under a built manager, which would replace a check with one the
	// consumer never configured.
	authorizers[0] = nil

	require.NoError(t, manager.Authorize(t.Context(), authorize.PrivilegeAttributes{
		Group:    "billing",
		Resource: "invoice",
		Required: []string{"read"},
	}))
}
