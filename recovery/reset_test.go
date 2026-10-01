package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/recovery"
)

func TestParseAuthenticatorRef(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		input  string
		assert func(t *testing.T, ref recovery.AuthenticatorRef, err error)
	}

	malformed := func(t *testing.T, ref recovery.AuthenticatorRef, err error) {
		t.Helper()
		require.ErrorIs(t, err, recovery.ErrMalformed)
		assert.Zero(t, ref)
	}

	cases := []testCase{
		{
			name:  "kind and id",
			input: "mfa:totp",
			assert: func(t *testing.T, ref recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, recovery.AuthenticatorRef{Kind: "mfa", ID: "totp"}, ref)
				assert.Equal(t, "mfa:totp", ref.String())
			},
		},
		{
			name:  "the id may contain a colon",
			input: "passkey:urn:cred:1",
			assert: func(t *testing.T, ref recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, recovery.AuthenticatorRef{Kind: "passkey", ID: "urn:cred:1"}, ref)
			},
		},
		{name: "no colon", input: "mfatotp", assert: malformed},
		{name: "empty kind", input: ":totp", assert: malformed},
		{name: "empty id", input: "mfa:", assert: malformed},
		{name: "empty text", input: "", assert: malformed},
		{name: "newline in the id", input: "mfa:totp\nmfa:email-code", assert: malformed},
		{name: "newline in the kind", input: "m\nfa:totp", assert: malformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ref, err := recovery.ParseAuthenticatorRef(tc.input)
			tc.assert(t, ref, err)
		})
	}
}
