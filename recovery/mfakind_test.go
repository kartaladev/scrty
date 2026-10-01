package recovery_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/recovery"
)

// removableMethod is an MFA method that can remove its enrolments, as TOTP
// can: a Method and an EnrolmentRemover in one value.
type removableMethod struct {
	*MockMethod
	*MockEnrolmentRemover
}

// mfaMethods holds the mocks behind one MFA kind under test, by method name.
type mfaMethods struct {
	methods  map[string]*MockMethod
	removers map[string]*MockEnrolmentRemover
}

// declaredMethod returns a method mock that passes mfa.LookupsFor's checks
// under name.
func declaredMethod(ctrl *gomock.Controller, name string, channel factor.Channel) *MockMethod {
	m := NewMockMethod(ctrl)
	m.EXPECT().Name().Return(name).AnyTimes()
	m.EXPECT().Channel().Return(channel).AnyTimes()
	m.EXPECT().Response().Return(mfa.FormField("mfa_code", 64)).AnyTimes()

	return m
}

// removableMethods builds TOTP and email-code, both able to remove enrolments,
// in that configuration order.
func removableMethods(ctrl *gomock.Controller) (mfaMethods, []mfa.Method) {
	set := mfaMethods{methods: map[string]*MockMethod{}, removers: map[string]*MockEnrolmentRemover{}}
	var methods []mfa.Method

	for _, m := range []struct {
		name    string
		channel factor.Channel
	}{{"totp", factor.AuthenticatorApp}, {"email-code", factor.Email}} {
		set.methods[m.name] = declaredMethod(ctrl, m.name, m.channel)
		set.removers[m.name] = NewMockEnrolmentRemover(ctrl)
		methods = append(methods, removableMethod{set.methods[m.name], set.removers[m.name]})
	}

	return set, methods
}

func TestMFAEnrolments_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		methods func(ctrl *gomock.Controller) []mfa.Method
		assert  func(t *testing.T, kind recovery.AuthenticatorKind, err error)
	}

	cases := []testCase{
		{
			name: "removable methods build the mfa kind",
			methods: func(ctrl *gomock.Controller) []mfa.Method {
				_, methods := removableMethods(ctrl)

				return methods
			},
			assert: func(t *testing.T, kind recovery.AuthenticatorKind, err error) {
				require.NoError(t, err)
				assert.Equal(t, recovery.MFAKind, kind.Kind())
			},
		},
		{
			name: "a method that cannot remove enrolments is a configuration error",
			methods: func(ctrl *gomock.Controller) []mfa.Method {
				_, methods := removableMethods(ctrl)

				return append(methods, declaredMethod(ctrl, "sms", factor.Channel("phone")))
			},
			assert: func(t *testing.T, kind recovery.AuthenticatorKind, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, kind)
			},
		},
		{
			name:    "an empty method set is a configuration error",
			methods: func(*gomock.Controller) []mfa.Method { return nil },
			assert: func(t *testing.T, kind recovery.AuthenticatorKind, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, kind)
			},
		},
		{
			name: "duplicate method names are a configuration error",
			methods: func(ctrl *gomock.Controller) []mfa.Method {
				a := removableMethod{declaredMethod(ctrl, "totp", factor.AuthenticatorApp), NewMockEnrolmentRemover(ctrl)}
				b := removableMethod{declaredMethod(ctrl, "totp", factor.AuthenticatorApp), NewMockEnrolmentRemover(ctrl)}

				return []mfa.Method{a, b}
			},
			assert: func(t *testing.T, kind recovery.AuthenticatorKind, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				require.ErrorIs(t, err, mfa.ErrConfig)
				assert.Nil(t, kind)
			},
		},
		{
			name: "a nil method is a configuration error",
			methods: func(ctrl *gomock.Controller) []mfa.Method {
				_, methods := removableMethods(ctrl)

				return append(methods, nil)
			},
			assert: func(t *testing.T, kind recovery.AuthenticatorKind, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, kind)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kind, err := recovery.MFAEnrolments(tc.methods(gomock.NewController(t))...)
			tc.assert(t, kind, err)
		})
	}
}

func TestMFAEnrolments_Held(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errLookup := errors.New("enrolment store unreachable: row 42")

	type testCase struct {
		name   string
		setup  func(set mfaMethods)
		assert func(t *testing.T, refs []recovery.AuthenticatorRef, err error)
	}

	cases := []testCase{
		{
			name: "lists the enrolled methods only",
			setup: func(set mfaMethods) {
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(false, nil)
			},
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}}, refs)
			},
		},
		{
			name: "lists in configuration order",
			setup: func(set mfaMethods) {
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
			},
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{
					{Kind: recovery.MFAKind, ID: "totp"},
					{Kind: recovery.MFAKind, ID: "email-code"},
				}, refs)
			},
		},
		{
			name: "a lookup failure is an error with no refs, never an empty holding",
			setup: func(set mfaMethods) {
				set.methods["totp"].EXPECT().Enrolled(gomock.Any(), user).Return(true, nil)
				set.methods["email-code"].EXPECT().Enrolled(gomock.Any(), user).Return(false, errLookup)
			},
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.ErrorIs(t, err, errLookup)
				assert.NotContains(t, err.Error(), "row 42")
				assert.Nil(t, refs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, methods := removableMethods(gomock.NewController(t))
			tc.setup(set)

			kind, err := recovery.MFAEnrolments(methods...)
			require.NoError(t, err)

			refs, err := kind.Held(t.Context(), user)
			tc.assert(t, refs, err)
		})
	}
}

func TestMFAEnrolments_Remove(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errRemove := errors.New("delete failed: row 42")

	type testCase struct {
		name   string
		refs   []recovery.AuthenticatorRef
		setup  func(set mfaMethods)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "removes through the named method's remover only",
			refs: []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}},
			setup: func(set mfaMethods) {
				set.removers["totp"].EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "removes in the order of the refs",
			refs: []recovery.AuthenticatorRef{
				{Kind: recovery.MFAKind, ID: "email-code"},
				{Kind: recovery.MFAKind, ID: "totp"},
			},
			setup: func(set mfaMethods) {
				gomock.InOrder(
					set.removers["email-code"].EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil),
					set.removers["totp"].EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil),
				)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "an unknown id is ignored",
			refs:   []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "sms"}},
			setup:  func(mfaMethods) {},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "a ref of another kind is skipped even when its id names a method",
			refs:   []recovery.AuthenticatorRef{{Kind: "passkey", ID: "totp"}},
			setup:  func(mfaMethods) {},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "the first removal error stops and is returned",
			refs: []recovery.AuthenticatorRef{
				{Kind: recovery.MFAKind, ID: "totp"},
				{Kind: recovery.MFAKind, ID: "email-code"},
			},
			setup: func(set mfaMethods) {
				set.removers["totp"].EXPECT().RemoveEnrolment(gomock.Any(), user).Return(errRemove)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errRemove)
				assert.NotContains(t, err.Error(), "row 42")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, methods := removableMethods(gomock.NewController(t))
			tc.setup(set)

			kind, err := recovery.MFAEnrolments(methods...)
			require.NoError(t, err)

			tc.assert(t, kind.Remove(t.Context(), user, tc.refs))
		})
	}
}
