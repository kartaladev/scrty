package mfa_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

func TestUsernameAsAddress(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		details *identity.Details
		assert  func(t *testing.T, got string, err error)
	}

	cases := []testCase{
		{
			name:    "the username is returned unchanged",
			details: &identity.Details{ID: "u-1", Username: " Ada+MFA@Example.com", Name: "Ada"},
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, " Ada+MFA@Example.com", got, "never trimmed, case-folded or parsed")
			},
		},
		{
			name:    "a username with a colon is returned as it is, for the method to refuse",
			details: &identity.Details{ID: "u-1", Username: "ada:example"},
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "ada:example", got)
			},
		},
		{
			name:    "an empty username is an error, not an empty address",
			details: &identity.Details{ID: "u-1"},
			assert: func(t *testing.T, got string, err error) {
				require.Error(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name:    "no details is an error",
			details: nil,
			assert: func(t *testing.T, got string, err error) {
				require.Error(t, err)
				assert.Empty(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := mfa.UsernameAsAddress(t.Context(), tc.details)
			tc.assert(t, got, err)
		})
	}
}
