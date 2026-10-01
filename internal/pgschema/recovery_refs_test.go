package pgschema_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/recovery"
)

func TestRecoveryRefsText(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		refs   []recovery.AuthenticatorRef
		assert func(t *testing.T, text string, err error)
	}

	cases := []testCase{
		{
			name: "references are kind:id lines, in order",
			refs: []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}, {Kind: "passkey", ID: "cred:1"}},
			assert: func(t *testing.T, text string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "saved:code\npasskey:cred:1", text)
			},
		},
		{
			name: "no references is the empty text",
			assert: func(t *testing.T, text string, err error) {
				require.NoError(t, err)
				assert.Empty(t, text)
			},
		},
		{
			name: "an identifier holding a newline is refused without the value",
			refs: []recovery.AuthenticatorRef{{Kind: "mfa", ID: "totp\nmfa:email"}},
			assert: func(t *testing.T, _ string, err error) {
				require.ErrorIs(t, err, pgschema.ErrRecoveryRefUnstorable)
				assert.NotContains(t, err.Error(), "totp")
			},
		},
		{
			name: "a kind holding a colon is refused, since it would read back as another reference",
			refs: []recovery.AuthenticatorRef{{Kind: "sa:ved", ID: "code"}},
			assert: func(t *testing.T, _ string, err error) {
				require.ErrorIs(t, err, pgschema.ErrRecoveryRefUnstorable)
				assert.NotContains(t, err.Error(), "sa:ved")
			},
		},
		{
			name: "an empty kind or identifier is refused",
			refs: []recovery.AuthenticatorRef{{Kind: "saved", ID: ""}},
			assert: func(t *testing.T, _ string, err error) {
				require.ErrorIs(t, err, pgschema.ErrRecoveryRefUnstorable)
			},
		},
		{
			name: "a NUL byte is refused, since PostgreSQL text cannot hold it",
			refs: []recovery.AuthenticatorRef{{Kind: "saved", ID: "co\x00de"}},
			assert: func(t *testing.T, _ string, err error) {
				require.ErrorIs(t, err, pgschema.ErrRecoveryRefUnstorable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			text, err := pgschema.RecoveryRefsText(tc.refs)
			tc.assert(t, text, err)
		})
	}
}

func TestParseRecoveryRefs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		text   string
		assert func(t *testing.T, refs []recovery.AuthenticatorRef, err error)
	}

	cases := []testCase{
		{
			name: "lines read back as the references written, an identifier's colon kept",
			text: "saved:code\npasskey:cred:1",
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}, {Kind: "passkey", ID: "cred:1"}}, refs)
			},
		},
		{
			name: "the empty text is no references",
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.NoError(t, err)
				assert.Nil(t, refs)
			},
		},
		{
			name: "a line that is not kind:id is an error, never skipped",
			text: "saved:code\nno-colon",
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.Error(t, err)
				assert.Nil(t, refs)
			},
		},
		{
			name: "an empty line is an error",
			text: "saved:code\n",
			assert: func(t *testing.T, refs []recovery.AuthenticatorRef, err error) {
				require.Error(t, err)
				assert.Nil(t, refs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			refs, err := pgschema.ParseRecoveryRefs(tc.text)
			tc.assert(t, refs, err)
		})
	}
}
