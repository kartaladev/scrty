package guardauth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/internal/guardauth"
)

// The authorizers here are only ever compared, never called: a mock with no
// expectations fails the test if the rule calls one.
//
//go:generate mockgen -destination=authorizer_mock_test.go -package=guardauth_test -typed github.com/kartaladev/scrty/authorize Authorizer

func TestFallback(t *testing.T) {
	t.Parallel()

	usable := NewMockAuthorizer(gomock.NewController(t))

	var typedNil *MockAuthorizer

	type testCase struct {
		name          string
		az            authorize.Authorizer
		chainDeclared bool
		assert        func(t *testing.T, fallback authorize.Authorizer, ok bool)
	}

	cases := []testCase{
		{
			name: "a usable authorizer is the fallback",
			az:   usable,
			assert: func(t *testing.T, fallback authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.Same(t, usable, fallback)
			},
		},
		{
			name:          "a usable authorizer beside the chain declaration is still the fallback",
			az:            usable,
			chainDeclared: true,
			assert: func(t *testing.T, fallback authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.Same(t, usable, fallback)
			},
		},
		{
			name: "a nil authorizer without the chain declaration is refused",
			az:   nil,
			assert: func(t *testing.T, fallback authorize.Authorizer, ok bool) {
				assert.False(t, ok)
				assert.True(t, fallback == nil, "fallback must be a plain nil, got %#v", fallback)
			},
		},
		{
			name:          "a nil authorizer with the chain declaration means no fallback",
			az:            nil,
			chainDeclared: true,
			assert: func(t *testing.T, fallback authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.True(t, fallback == nil, "fallback must be a plain nil, got %#v", fallback)
			},
		},
		{
			// What an unchecked constructor error hands over: the interface is
			// not nil, but every method call on it would panic.
			name: "a typed nil authorizer without the chain declaration is refused",
			az:   typedNil,
			assert: func(t *testing.T, fallback authorize.Authorizer, ok bool) {
				assert.False(t, ok)
				assert.True(t, fallback == nil, "fallback must be a plain nil, got %#v", fallback)
			},
		},
		{
			name:          "a typed nil authorizer with the chain declaration is stored as no fallback",
			az:            typedNil,
			chainDeclared: true,
			assert: func(t *testing.T, fallback authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.True(t, fallback == nil, "fallback must be a plain nil, got %#v", fallback)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fallback, ok := guardauth.Fallback(tc.az, tc.chainDeclared)
			tc.assert(t, fallback, ok)
		})
	}
}

func TestFor(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	fromChain := NewMockAuthorizer(ctrl)
	fallback := NewMockAuthorizer(ctrl)

	var typedNil *MockAuthorizer

	publish := func(az authorize.Authorizer) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context { return authorize.WithAuthorizer(ctx, az) }
	}

	type testCase struct {
		name     string
		ctx      func(ctx context.Context) context.Context // nil means identity
		fallback authorize.Authorizer
		assert   func(t *testing.T, az authorize.Authorizer, ok bool)
	}

	cases := []testCase{
		{
			name:     "the chain's authorizer is preferred over the fallback",
			ctx:      publish(fromChain),
			fallback: fallback,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.Same(t, fromChain, az)
			},
		},
		{
			name:     "the chain's authorizer judges when there is no fallback",
			ctx:      publish(fromChain),
			fallback: nil,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.Same(t, fromChain, az)
			},
		},
		{
			name:     "the fallback judges a request the chain published nothing on",
			fallback: fallback,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.Same(t, fallback, az)
			},
		},
		{
			name:     "the fallback judges when the chain published a typed nil",
			ctx:      publish(typedNil),
			fallback: fallback,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.True(t, ok)
				assert.Same(t, fallback, az)
			},
		},
		{
			name:     "no authorizer anywhere is no judge",
			fallback: nil,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.False(t, ok)
				assert.True(t, az == nil, "az must be a plain nil, got %#v", az)
			},
		},
		{
			// Construction never stores a typed nil, but the request-time
			// check stays defensive so a later way of setting the fallback
			// cannot turn a refusal into a nil-method panic.
			name:     "a typed nil fallback is no judge",
			fallback: typedNil,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.False(t, ok)
				assert.True(t, az == nil, "az must be a plain nil, got %#v", az)
			},
		},
		{
			name:     "a typed nil on the request and a typed nil fallback are no judge",
			ctx:      publish(typedNil),
			fallback: typedNil,
			assert: func(t *testing.T, az authorize.Authorizer, ok bool) {
				assert.False(t, ok)
				assert.True(t, az == nil, "az must be a plain nil, got %#v", az)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			az, ok := guardauth.For(ctx, tc.fallback)
			tc.assert(t, az, ok)
		})
	}
}
