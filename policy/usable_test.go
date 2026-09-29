package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// lookupStub is a method lookup whose every answer is fixed at construction. It
// is a value type, so a case can build a set of several in one line.
//
// It answers a request whose context has ended with that context's error, as a
// store would, which is how a case shows the caller's context reaches it.
type lookupStub struct {
	name     string
	channel  factor.Channel
	enrolled bool
	err      error
}

func (s lookupStub) Name() string { return s.name }

func (s lookupStub) Channel() factor.Channel { return s.channel }

func (s lookupStub) Enrolled(ctx context.Context, _ identity.UserID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.enrolled, s.err
}

// lookupNames lists the names of methods, in order, so a case compares a
// result by what a reader recognises.
func lookupNames(methods []policy.MFAMethodLookup) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, m.Name())
	}

	return out
}

func TestUsableMFAMethods(t *testing.T) {
	t.Parallel()

	storeDown := errors.New("store down")
	totp := lookupStub{name: "totp", channel: factor.AuthenticatorApp, enrolled: true}
	email := lookupStub{name: "email-code", channel: factor.Email, enrolled: true}

	type testCase struct {
		name    string
		methods []policy.MFAMethodLookup
		first   factor.Kind
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, got []policy.MFAMethodLookup, err error)
	}

	cases := []testCase{
		{
			name:    "usable methods in configuration order",
			methods: []policy.MFAMethodLookup{totp, email},
			first:   factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"totp", "email-code"}, lookupNames(got))
			},
		},
		{
			name:    "the configuration order is kept when it is reversed",
			methods: []policy.MFAMethodLookup{email, totp},
			first:   factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"email-code", "totp"}, lookupNames(got))
			},
		},
		{
			name:    "a method on the first factor's channel is not usable",
			methods: []policy.MFAMethodLookup{totp, email},
			first:   factor.MagicLink,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"totp"}, lookupNames(got))
			},
		},
		{
			name: "a failed lookup is an error, not a shorter list",
			methods: []policy.MFAMethodLookup{
				totp, lookupStub{name: "email-code", channel: factor.Email, err: storeDown},
			},
			first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, storeDown,
					"a lost enrolment read as a shorter list would downgrade the user")
				assert.Nil(t, got)
			},
		},
		{
			name: "a failed lookup ahead of a usable method is an error too",
			methods: []policy.MFAMethodLookup{
				lookupStub{name: "email-code", channel: factor.Email, err: storeDown}, totp,
			},
			first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, storeDown)
				assert.Nil(t, got)
			},
		},
		{
			name:    "not enrolled anywhere is an empty list, not an error",
			methods: []policy.MFAMethodLookup{lookupStub{name: "totp", channel: factor.AuthenticatorApp}},
			first:   factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name:  "no methods at all is an empty list, not an error",
			first: factor.Password,
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name:    "the caller's context reaches every lookup",
			methods: []policy.MFAMethodLookup{totp, email},
			first:   factor.Password,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, got []policy.MFAMethodLookup, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)
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

			got, err := policy.UsableMFAMethods(ctx, tc.methods, mfaUser, tc.first)
			tc.assert(t, got, err)
		})
	}
}
