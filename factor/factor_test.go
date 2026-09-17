package factor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/factor"
)

func TestKind(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   factor.Kind
		assert func(t *testing.T, channel factor.Channel, exempt bool)
	}

	cases := []testCase{
		{
			name: "password is knowledge and not exempt",
			kind: factor.Password,
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Equal(t, factor.Knowledge, channel)
				assert.False(t, exempt)
			},
		},
		{
			name: "basic is knowledge and not exempt",
			kind: factor.Basic,
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Equal(t, factor.Knowledge, channel)
				assert.False(t, exempt)
			},
		},
		{
			name: "magic link is email and not exempt",
			kind: factor.MagicLink,
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Equal(t, factor.Email, channel)
				assert.False(t, exempt)
			},
		},
		{
			name: "oidc is federated and exempt",
			kind: factor.OIDC,
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Equal(t, factor.Federated, channel)
				assert.True(t, exempt)
			},
		},
		{
			name: "api key is machine and exempt",
			kind: factor.APIKey,
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Equal(t, factor.Machine, channel)
				assert.True(t, exempt)
			},
		},
		{
			name: "the empty kind fails closed",
			kind: factor.Kind(""),
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Empty(t, channel, "a caller that forgot to set the kind reports no channel")
				assert.False(t, exempt, "and is never exempt from a second factor")
			},
		},
		{
			name: "a consumer's own kind fails closed",
			kind: factor.Kind("smart-card"),
			assert: func(t *testing.T, channel factor.Channel, exempt bool) {
				assert.Empty(t, channel)
				assert.False(t, exempt)
			},
		},
	}

	covered := make(map[factor.Kind]bool, len(cases))
	for _, tc := range cases {
		covered[tc.kind] = true
	}

	for _, k := range factor.AllKinds {
		assert.True(t, covered[k],
			"kind %q has no row in this table, so its channel and exemption are untested", k)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.kind.Channel(), tc.kind.MFAExempt())
		})
	}
}

// TestSecondFactorChannels is a standalone test rather than rows in TestKind's
// table: it asserts a property of the vocabulary as a whole, not one kind's
// mapping, so it has no per-kind input to vary.
func TestSecondFactorChannels(t *testing.T) {
	t.Parallel()

	assert.Equal(t, factor.Channel("authenticator-app"), factor.AuthenticatorApp,
		"TOTP and other authenticator-app second factors travel on this channel")
	assert.Equal(t, factor.Channel("email"), factor.Email,
		"email-delivered second factors share the channel a magic-link login arrives on")

	for _, k := range factor.AllKinds {
		assert.NotEqual(t, factor.AuthenticatorApp, k.Channel(),
			"no first-factor kind may report the authenticator-app channel, but %q does", k)
	}
}
