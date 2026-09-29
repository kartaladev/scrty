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

func TestLookupsFor(t *testing.T) {
	t.Parallel()

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	responding := func(f mfa.ResponseFormat) *mfa.ResponseFormat { return &f }
	named := func(name string) mfa.Method {
		return &stubMethod{name: name, channel: factor.Email}
	}

	type testCase struct {
		name    string
		methods []mfa.Method
		assert  func(t *testing.T, l []policy.MFAMethodLookup, err error)
	}

	configError := func(t *testing.T, l []policy.MFAMethodLookup, err error) {
		require.ErrorIs(t, err, mfa.ErrConfig)
		assert.Nil(t, l)
	}

	cases := []testCase{
		{
			name:    "TOTP and a consumer's method, in order",
			methods: []mfa.Method{totp, named("email-code")},
			assert: func(t *testing.T, l []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				require.Len(t, l, 2)
				assert.Equal(t, "totp", l[0].Name())
				assert.Equal(t, factor.AuthenticatorApp, l[0].Channel())
				assert.Equal(t, "email-code", l[1].Name())
				assert.Equal(t, factor.Email, l[1].Channel())
			},
		},
		{
			name: "a JSON method at the largest limit",
			methods: []mfa.Method{&stubMethod{
				name: "webauthn", channel: factor.Channel("security-key"),
				response: responding(mfa.JSONBody(1 << 20)),
			}},
			assert: func(t *testing.T, l []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Len(t, l, 1)
			},
		},
		{name: "no methods", methods: nil, assert: configError},
		{name: "an empty set", methods: []mfa.Method{}, assert: configError},
		{name: "a nil method", methods: []mfa.Method{totp, nil}, assert: configError},
		{name: "a typed-nil TOTP", methods: []mfa.Method{(*mfa.TOTP)(nil)}, assert: configError},
		{name: "a typed-nil consumer method", methods: []mfa.Method{(*stubMethod)(nil)}, assert: configError},
		{
			name:    "an empty channel",
			methods: []mfa.Method{&stubMethod{name: "email-code", channel: ""}},
			assert:  configError,
		},
		{name: "an empty name", methods: []mfa.Method{&emptyNamedMethod{}}, assert: configError},
		{name: "an upper-case name", methods: []mfa.Method{named("TOTP")}, assert: configError},
		{name: "a name with a slash", methods: []mfa.Method{named("a/b")}, assert: configError},
		{name: "a name starting with a hyphen", methods: []mfa.Method{named("-x")}, assert: configError},
		{name: "a name with a space", methods: []mfa.Method{named("email code")}, assert: configError},
		{name: "two methods named totp", methods: []mfa.Method{totp, named("totp")}, assert: configError},
		{
			name: "a form field limit of zero",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.FormField("code", 0)),
			}},
			assert: configError,
		},
		{
			name: "a form field limit above 1 MiB",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.FormField("code", 1<<20+1)),
			}},
			assert: configError,
		},
		{
			name: "a form field with no name",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.FormField("", 10)),
			}},
			assert: configError,
		},
		{
			name: "a negative JSON limit",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.JSONBody(-1)),
			}},
			assert: configError,
		},
		{
			name: "the zero response format",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.ResponseFormat{}),
			}},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := mfa.LookupsFor(tc.methods...)
			tc.assert(t, l, err)
		})
	}
}

// emptyNamedMethod reports an empty name, which stubMethod cannot: its empty
// name field stands for its default.
type emptyNamedMethod struct{ stubMethod }

func (*emptyNamedMethod) Name() string { return "" }

func (*emptyNamedMethod) Channel() factor.Channel { return factor.Email }

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

			l, err := mfa.LookupsFor(tc.method)
			require.NoError(t, err)
			require.Len(t, l, 1)

			enrolled, lookupErr := l[0].Enrolled(t.Context(), "u-1")
			tc.assert(t, enrolled, lookupErr)
		})
	}
}
