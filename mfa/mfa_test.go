package mfa_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
)

// stubMethod is a consumer's own method: it proves the port admits one that is
// not TOTP, and lets a test choose what the store underneath it answers.
type stubMethod struct {
	name     string
	channel  factor.Channel
	enrolled bool
	err      error
}

func (s *stubMethod) Name() string {
	if s.name == "" {
		return "stub"
	}

	return s.name
}

func (s *stubMethod) Channel() factor.Channel { return s.channel }

func (s *stubMethod) Enrolled(context.Context, identity.UserID) (bool, error) {
	return s.enrolled, s.err
}

func (s *stubMethod) Verify(context.Context, identity.UserID, string) error { return s.err }

func TestMethodSatisfiesLookup(t *testing.T) {
	t.Parallel()

	// The assertion is on the interface type, not on one implementation of it:
	// a concrete type may satisfy both ports by coincidence, while what this
	// pins is that every Method is a policy lookup, with no adapter at all.
	assert.True(t,
		reflect.TypeFor[mfa.Method]().Implements(reflect.TypeFor[policy.MFAMethodLookup]()),
		"a Method is usable as a policy lookup without an adapter")

	var m mfa.Method = &stubMethod{channel: factor.AuthenticatorApp}

	_, ok := any(m).(policy.MFAMethodLookup)
	assert.True(t, ok)
}

func TestMFASentinels(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		mfa.ErrInvalidCode,
		mfa.ErrAlreadyEnrolled,
		mfa.ErrSameChannel,
		mfa.ErrVerifyThrottled,
		mfa.ErrEmailCodeInvalid,
		mfa.ErrEnrolmentThrottled,
		mfa.ErrConfig,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			// An emailed-code refusal is the invalid second-factor code
			// refusal; TestEmailCodeInvalidIsInvalidCode pins that pair.
			// Identity, not errors.Is: the pair is excluded by name.
			if i != j && (a != mfa.ErrEmailCodeInvalid || b != mfa.ErrInvalidCode) { //nolint:errorlint // sentinel identity
				assert.NotErrorIs(t, a, b)
			}
		}

		assert.Contains(t, a.Error(), "mfa: ")
	}
}

// TestEmailCodeInvalidIsInvalidCode pins that an emailed-code refusal is
// identifiable as the invalid second-factor code refusal, so a caller mapping
// ErrInvalidCode answers it the same way, while its own message still tells an
// operator which code was refused.
func TestEmailCodeInvalidIsInvalidCode(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, mfa.ErrEmailCodeInvalid, mfa.ErrInvalidCode)
	assert.NotErrorIs(t, mfa.ErrInvalidCode, mfa.ErrEmailCodeInvalid,
		"a device-code refusal is not an emailed-code one")
	assert.Contains(t, mfa.ErrEmailCodeInvalid.Error(), "emailed code")
}
