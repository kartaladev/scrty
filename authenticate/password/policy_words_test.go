package password_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

func TestPolicy_ContextWords(t *testing.T) {
	t.Parallel()

	errWords := errors.New("the profile store is down")

	type testCase struct {
		name      string
		words     []string
		fail      error
		candidate string
		assert    func(t *testing.T, err error, calls int)
	}

	refused := func(t *testing.T, err error, _ int) {
		t.Helper()
		rejectedBy(password.RuleContextWord)(t, err)
	}

	passes := func(t *testing.T, err error, _ int) {
		t.Helper()
		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name:      "the username as the password, in another case",
			words:     []string{"alice.smith2026"},
			candidate: "Alice.Smith2026",
			assert:    refused,
		},
		{
			name:      "the username inside the password",
			words:     []string{"alice.smith2026"},
			candidate: "my-alice.smith2026-pass",
			assert:    refused,
		},
		{
			name:      "a word of exactly four characters inside the password, in another case",
			words:     []string{"ACME"},
			candidate: "welcome-to-acme-portal",
			assert:    refused,
		},
		{
			name:      "a word shorter than four characters only refuses on equality",
			words:     []string{"abc"},
			candidate: "abcdefghijklmnopq",
			assert:    passes,
		},
		{
			name:      "an empty word refuses nothing",
			words:     []string{""},
			candidate: "correcthorsebatterystaple",
			assert:    passes,
		},
		{
			name:      "no words accepts",
			candidate: "correcthorsebatterystaple",
			assert:    passes,
		},
		{
			name:      "an unrelated candidate is accepted",
			words:     []string{"alice.smith2026", "Example Corp"},
			candidate: "correcthorsebatterystaple",
			assert: func(t *testing.T, err error, calls int) {
				require.NoError(t, err)
				assert.Equal(t, 1, calls)
			},
		},
		{
			name:      "a failing word function fails the check with its error, not a refusal",
			fail:      errWords,
			candidate: "correcthorsebatterystaple",
			assert: func(t *testing.T, err error, _ int) {
				require.ErrorIs(t, err, errWords)
				assert.NotErrorIs(t, err, password.ErrPasswordRejected)
			},
		},
		{
			name:      "a candidate refused as too short asks for no words",
			words:     []string{"alice"},
			candidate: "alice",
			assert: func(t *testing.T, err error, calls int) {
				rejectedBy(password.RuleTooShort)(t, err)
				assert.Zero(t, calls)
			},
		},
		{
			name:      "a candidate refused as common asks for no words",
			words:     []string{longCommon},
			candidate: longCommon,
			assert: func(t *testing.T, err error, calls int) {
				rejectedBy(password.RuleCommon)(t, err)
				assert.Zero(t, calls)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := checkUser()
			calls := 0
			words := func(ctx context.Context, got *identity.Details) ([]string, error) {
				calls++
				assert.Same(t, user, got, "the word function gets the record being checked")
				assert.NotNil(t, ctx)

				return tc.words, tc.fail
			}

			p, err := password.NewPolicy(password.ContextWords(words))
			require.NoError(t, err)

			err = p.Check(t.Context(), user, tc.candidate)
			tc.assert(t, err, calls)
		})
	}
}
