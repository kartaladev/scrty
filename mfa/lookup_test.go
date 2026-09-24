package mfa_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
)

func TestLookupFor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method mfa.Method
		assert func(t *testing.T, l policy.MFAMethodLookup, err error)
	}

	configError := func(t *testing.T, l policy.MFAMethodLookup, err error) {
		require.Error(t, err)
		assert.Nil(t, l)
	}

	cases := []testCase{
		{
			name:   "a method with a channel",
			method: &stubMethod{channel: factor.AuthenticatorApp},
			assert: func(t *testing.T, l policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, factor.AuthenticatorApp, l.Channel())
			},
		},
		{
			name:   "a consumer's email method",
			method: &stubMethod{name: "email-otp", channel: factor.Email},
			assert: func(t *testing.T, l policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, factor.Email, l.Channel())
			},
		},
		{name: "an empty channel", method: &stubMethod{channel: ""}, assert: configError},
		{name: "a nil method", method: nil, assert: configError},
		{name: "a typed-nil method", method: (*stubMethod)(nil), assert: configError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := mfa.LookupFor(tc.method)
			tc.assert(t, l, err)
		})
	}
}

func TestLookupContract(t *testing.T) {
	t.Parallel()

	outage := errors.New("dial tcp: connection refused")

	type testCase struct {
		name   string
		method mfa.Method
		assert func(t *testing.T, enrolled bool, err error)
	}

	cases := []testCase{
		{
			name:   "a confirmed enrolment is true",
			method: &stubMethod{channel: factor.AuthenticatorApp, enrolled: true},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
		{
			name:   "no enrolment is false",
			method: &stubMethod{channel: factor.AuthenticatorApp, enrolled: false},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.NoError(t, err)
				assert.False(t, enrolled)
			},
		},
		{
			name:   "a store outage is an error, never a false",
			method: &stubMethod{channel: factor.AuthenticatorApp, err: outage},
			assert: func(t *testing.T, enrolled bool, err error) {
				assert.ErrorIs(t, err, outage)
				assert.False(t, enrolled, "and the bool must not be read as an answer")
			},
		},
		{
			name: "an unreadable secret is an error",
			method: &stubMethod{
				channel: factor.AuthenticatorApp,
				err:     errors.New("cipher: message authentication failed"),
			},
			assert: func(t *testing.T, _ bool, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := mfa.LookupFor(tc.method)
			require.NoError(t, err)

			enrolled, lookupErr := l.Enrolled(t.Context(), "u-1")
			tc.assert(t, enrolled, lookupErr)
		})
	}
}
