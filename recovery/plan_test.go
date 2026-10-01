package recovery_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

var (
	refTOTP    = recovery.AuthenticatorRef{Kind: recovery.MFAKind, ID: "totp"}
	refEmail   = recovery.AuthenticatorRef{Kind: recovery.MFAKind, ID: "email-code"}
	refSMS     = recovery.AuthenticatorRef{Kind: recovery.MFAKind, ID: "sms"}
	refPasskey = recovery.AuthenticatorRef{Kind: "passkey", ID: "cred-1"}
)

// namedKind returns a kind mock answering name.
func namedKind(ctrl *gomock.Controller, name string) *MockAuthenticatorKind {
	k := NewMockAuthenticatorKind(ctrl)
	k.EXPECT().Kind().Return(name).AnyTimes()

	return k
}

func TestNewPlanner(t *testing.T) {
	t.Parallel()

	keepNothing := func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) { return nil, nil }

	type testCase struct {
		name   string
		kinds  func(ctrl *gomock.Controller) []recovery.AuthenticatorKind
		mode   recovery.ResetMode
		policy recovery.ResetPolicy
		assert func(t *testing.T, err error)
	}

	configError := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, recovery.ErrConfig)
	}

	one := func(name string) func(ctrl *gomock.Controller) []recovery.AuthenticatorKind {
		return func(ctrl *gomock.Controller) []recovery.AuthenticatorKind {
			return []recovery.AuthenticatorKind{namedKind(ctrl, name)}
		}
	}

	cases := []testCase{
		{
			name: "distinct kinds build a planner",
			kinds: func(ctrl *gomock.Controller) []recovery.AuthenticatorKind {
				return []recovery.AuthenticatorKind{namedKind(ctrl, "mfa"), namedKind(ctrl, "passkey")}
			},
			mode:   recovery.ResetAll,
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "a custom policy builds a planner",
			kinds:  one("mfa"),
			mode:   recovery.ResetCustom,
			policy: keepNothing,
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{name: "no kinds", kinds: func(*gomock.Controller) []recovery.AuthenticatorKind { return nil }, assert: configError},
		{
			name:   "a nil kind",
			kinds:  func(*gomock.Controller) []recovery.AuthenticatorKind { return []recovery.AuthenticatorKind{nil} },
			assert: configError,
		},
		{
			name: "a typed nil kind",
			kinds: func(*gomock.Controller) []recovery.AuthenticatorKind {
				return []recovery.AuthenticatorKind{(*MockAuthenticatorKind)(nil)}
			},
			assert: configError,
		},
		{
			name: "a duplicate kind",
			kinds: func(ctrl *gomock.Controller) []recovery.AuthenticatorKind {
				return []recovery.AuthenticatorKind{namedKind(ctrl, "mfa"), namedKind(ctrl, "mfa")}
			},
			assert: configError,
		},
		{name: "an empty kind name", kinds: one(""), assert: configError},
		{name: "a kind name with a colon", kinds: one("m:fa"), assert: configError},
		{name: "a kind name with a newline", kinds: one("mfa\n"), assert: configError},
		{name: "a custom mode with no policy", kinds: one("mfa"), mode: recovery.ResetCustom, assert: configError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := recovery.NewPlanner(tc.kinds(gomock.NewController(t)), tc.mode, tc.policy)
			tc.assert(t, err)
		})
	}
}

// assertBadListing asserts a plan refused because a kind listed a malformed
// reference: an error that is neither the caller's mistake nor quotes the
// reference, and no plan.
func assertBadListing(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
	t.Helper()
	require.Error(t, err)
	assert.NotErrorIs(t, err, recovery.ErrMalformed)
	assert.NotContains(t, err.Error(), "secret-cred-7")
	assert.Nil(t, plan)
}

func TestPlanner_Plan(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errLookup := errors.New("listing failed")
	errPolicy := errors.New("policy failed")

	type testCase struct {
		name     string
		mode     recovery.ResetMode
		policy   func(t *testing.T) recovery.ResetPolicy
		held     []recovery.AuthenticatorRef
		heldErr  error
		reported []recovery.AuthenticatorRef
		proven   []recovery.AuthenticatorRef
		assert   func(t *testing.T, plan []recovery.AuthenticatorRef, err error)
	}

	policyReturning := func(refs ...recovery.AuthenticatorRef) func(t *testing.T) recovery.ResetPolicy {
		return func(*testing.T) recovery.ResetPolicy {
			return func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) { return refs, nil }
		}
	}

	cases := []testCase{
		{
			name: "default removes everything held when nothing is proven",
			mode: recovery.ResetAll,
			held: []recovery.AuthenticatorRef{refTOTP, refEmail},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, plan)
			},
		},
		{
			name:   "default keeps a proven method",
			mode:   recovery.ResetAll,
			held:   []recovery.AuthenticatorRef{refTOTP, refEmail},
			proven: []recovery.AuthenticatorRef{refTOTP},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, plan)
			},
		},
		{
			name:     "reported mode removes only the reported loss",
			mode:     recovery.ResetReported,
			held:     []recovery.AuthenticatorRef{refTOTP, refEmail},
			reported: []recovery.AuthenticatorRef{refEmail},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, plan)
			},
		},
		{
			name:     "reported mode refuses a loss the user does not hold",
			mode:     recovery.ResetReported,
			held:     []recovery.AuthenticatorRef{refTOTP, refEmail},
			reported: []recovery.AuthenticatorRef{refEmail, refSMS},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.ErrorIs(t, err, recovery.ErrMalformed)
				assert.Nil(t, plan)
			},
		},
		{
			name: "reported mode refuses a request that reports nothing",
			mode: recovery.ResetReported,
			held: []recovery.AuthenticatorRef{refTOTP, refEmail},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.ErrorIs(t, err, recovery.ErrMalformed)
				assert.Nil(t, plan)
			},
		},
		{
			name:     "reported mode refuses a loss the user proved in the same recovery",
			mode:     recovery.ResetReported,
			held:     []recovery.AuthenticatorRef{refTOTP, refEmail},
			reported: []recovery.AuthenticatorRef{refEmail, refTOTP},
			proven:   []recovery.AuthenticatorRef{refTOTP},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.ErrorIs(t, err, recovery.ErrMalformed)
				assert.Nil(t, plan)
			},
		},
		{
			name: "a listed ref of another kind is refused like a listing failure",
			mode: recovery.ResetAll,
			held: []recovery.AuthenticatorRef{refTOTP, {Kind: "passkey", ID: "secret-cred-7"}},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				assertBadListing(t, plan, err)
			},
		},
		{
			name: "a listed ref with an empty id is refused like a listing failure",
			mode: recovery.ResetAll,
			held: []recovery.AuthenticatorRef{refTOTP, {Kind: recovery.MFAKind}},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				assertBadListing(t, plan, err)
			},
		},
		{
			name: "a listed ref whose id contains a newline is refused like a listing failure",
			mode: recovery.ResetAll,
			held: []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "secret-cred-7\nmfa:totp"}},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				assertBadListing(t, plan, err)
			},
		},
		{
			name:   "a consumer policy's choice is removed",
			mode:   recovery.ResetCustom,
			policy: policyReturning(refTOTP),
			held:   []recovery.AuthenticatorRef{refTOTP, refEmail},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP}, plan)
			},
		},
		{
			name:   "a policy's unheld ref is ignored",
			mode:   recovery.ResetCustom,
			policy: policyReturning(refSMS, refEmail),
			held:   []recovery.AuthenticatorRef{refTOTP, refEmail},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, plan)
			},
		},
		{
			name: "a policy is given what is held, reported and proven",
			mode: recovery.ResetCustom,
			policy: func(t *testing.T) recovery.ResetPolicy {
				return func(_ context.Context, in recovery.ResetInput) ([]recovery.AuthenticatorRef, error) {
					assert.Equal(t, recovery.ResetInput{
						User:     user,
						Held:     []recovery.AuthenticatorRef{refTOTP, refEmail},
						Reported: []recovery.AuthenticatorRef{refEmail},
						Proven:   []recovery.AuthenticatorRef{refTOTP},
					}, in)

					return in.Reported, nil
				}
			},
			held:     []recovery.AuthenticatorRef{refTOTP, refEmail},
			reported: []recovery.AuthenticatorRef{refEmail},
			proven:   []recovery.AuthenticatorRef{refTOTP},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, plan)
			},
		},
		{
			name: "a policy error is returned",
			mode: recovery.ResetCustom,
			policy: func(*testing.T) recovery.ResetPolicy {
				return func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) {
					return []recovery.AuthenticatorRef{refTOTP}, errPolicy
				}
			},
			held: []recovery.AuthenticatorRef{refTOTP, refEmail},
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.ErrorIs(t, err, errPolicy)
				assert.Nil(t, plan)
			},
		},
		{
			name:    "a listing failure refuses with no plan",
			mode:    recovery.ResetAll,
			heldErr: errLookup,
			assert: func(t *testing.T, plan []recovery.AuthenticatorRef, err error) {
				require.ErrorIs(t, err, errLookup)
				assert.Nil(t, plan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kind := namedKind(gomock.NewController(t), recovery.MFAKind)
			kind.EXPECT().Held(gomock.Any(), user).Return(tc.held, tc.heldErr)

			var policy recovery.ResetPolicy
			if tc.policy != nil {
				policy = tc.policy(t)
			}

			p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{kind}, tc.mode, policy)
			require.NoError(t, err)

			plan, err := p.Plan(t.Context(), user, tc.reported, tc.proven)
			tc.assert(t, plan, err)
		})
	}
}

func TestPlanner_PlanListsEveryKindInOrder(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	ctrl := gomock.NewController(t)

	mfaKind := namedKind(ctrl, recovery.MFAKind)
	passkeys := namedKind(ctrl, "passkey")
	gomock.InOrder(
		mfaKind.EXPECT().Held(gomock.Any(), user).Return([]recovery.AuthenticatorRef{refTOTP}, nil),
		passkeys.EXPECT().Held(gomock.Any(), user).Return([]recovery.AuthenticatorRef{refPasskey}, nil),
	)

	p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{mfaKind, passkeys}, recovery.ResetAll, nil)
	require.NoError(t, err)

	plan, err := p.Plan(t.Context(), user, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refPasskey}, plan)
}

func TestPlanner_Execute(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")
	errRemove := errors.New("removal failed")

	type testCase struct {
		name   string
		plan   []recovery.AuthenticatorRef
		setup  func(mfaKind, passkeys *MockAuthenticatorKind)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "removes per kind in registration order",
			plan: []recovery.AuthenticatorRef{refPasskey, refTOTP, refEmail},
			setup: func(mfaKind, passkeys *MockAuthenticatorKind) {
				gomock.InOrder(
					mfaKind.EXPECT().Remove(gomock.Any(), user, []recovery.AuthenticatorRef{refTOTP, refEmail}).Return(nil),
					passkeys.EXPECT().Remove(gomock.Any(), user, []recovery.AuthenticatorRef{refPasskey}).Return(nil),
				)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "the second kind failing returns its error after the first kind's removal",
			plan: []recovery.AuthenticatorRef{refTOTP, refPasskey},
			setup: func(mfaKind, passkeys *MockAuthenticatorKind) {
				gomock.InOrder(
					mfaKind.EXPECT().Remove(gomock.Any(), user, []recovery.AuthenticatorRef{refTOTP}).Return(nil),
					passkeys.EXPECT().Remove(gomock.Any(), user, []recovery.AuthenticatorRef{refPasskey}).Return(errRemove),
				)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, errRemove) },
		},
		{
			name: "the first kind failing stops before the second",
			plan: []recovery.AuthenticatorRef{refTOTP, refPasskey},
			setup: func(mfaKind, _ *MockAuthenticatorKind) {
				mfaKind.EXPECT().Remove(gomock.Any(), user, []recovery.AuthenticatorRef{refTOTP}).Return(errRemove)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, errRemove) },
		},
		{
			name: "a kind with nothing planned is not called",
			plan: []recovery.AuthenticatorRef{refPasskey},
			setup: func(_, passkeys *MockAuthenticatorKind) {
				passkeys.EXPECT().Remove(gomock.Any(), user, []recovery.AuthenticatorRef{refPasskey}).Return(nil)
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mfaKind := namedKind(ctrl, recovery.MFAKind)
			passkeys := namedKind(ctrl, "passkey")
			tc.setup(mfaKind, passkeys)

			p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{mfaKind, passkeys}, recovery.ResetAll, nil)
			require.NoError(t, err)

			tc.assert(t, p.Execute(t.Context(), user, tc.plan))
		})
	}
}

func TestPlanner_PolicyGetsItsOwnCopies(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")

	kind := namedKind(gomock.NewController(t), recovery.MFAKind)
	kind.EXPECT().Held(gomock.Any(), user).Return([]recovery.AuthenticatorRef{refTOTP, refEmail}, nil)

	// The policy scribbles over every slice it is given, then chooses both
	// held refs by value.
	policy := func(_ context.Context, in recovery.ResetInput) ([]recovery.AuthenticatorRef, error) {
		for _, s := range [][]recovery.AuthenticatorRef{in.Held, in.Reported, in.Proven} {
			for i := range s {
				s[i] = refSMS
			}
		}

		return []recovery.AuthenticatorRef{refTOTP, refEmail}, nil
	}

	p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{kind}, recovery.ResetCustom, policy)
	require.NoError(t, err)

	reported := []recovery.AuthenticatorRef{refEmail}
	proven := []recovery.AuthenticatorRef{refTOTP}

	plan, err := p.Plan(t.Context(), user, reported, proven)
	require.NoError(t, err)
	assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, plan, "the planner's own holding is unchanged")
	assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, reported, "the caller's reported losses are unchanged")
	assert.Equal(t, []recovery.AuthenticatorRef{refTOTP}, proven, "the caller's proofs are unchanged")
}
