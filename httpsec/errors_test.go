package httpsec_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

func TestChallengeError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    *httpsec.ChallengeError
		assert func(t *testing.T, text string)
	}

	cases := []testCase{
		{
			name: "names the kind and hides the token and the session handle",
			err: &httpsec.ChallengeError{ //nolint:gosec // a fake token is the point of the case
				Kind:    policy.ChallengeMFA,
				Session: &session.Session{ID: "sess-handle-0123456789"},
				Token:   "eyJhbGciOiJFUzI1NiJ9.secret.sig",
			},
			assert: func(t *testing.T, text string) {
				assert.Contains(t, text, policy.ChallengeMFA.String())
				assert.NotContains(t, text, "eyJhbGciOiJFUzI1NiJ9.secret.sig")
				assert.NotContains(t, text, "sess-handle-0123456789")
			},
		},
		{
			name: "a gate challenge carries the session and no token",
			err: &httpsec.ChallengeError{
				Kind:    policy.ChallengePasswordChange,
				Session: &session.Session{ID: "sess-handle-0123456789"},
			},
			assert: func(t *testing.T, text string) {
				assert.Contains(t, text, policy.ChallengePasswordChange.String())
				assert.NotContains(t, text, "sess-handle-0123456789")
			},
		},
		{
			name: "a stateless challenge carries neither",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			assert: func(t *testing.T, text string) {
				assert.Contains(t, text, policy.ChallengeMFA.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.err.Error())
		})
	}
}

func TestChallengeErrorIsReachableThroughAWrap(t *testing.T) {
	t.Parallel()

	pending := &session.Session{ID: "sess-handle-0123456789"}
	wrapped := fmt.Errorf("completing the login: %w",
		&httpsec.ChallengeError{Kind: policy.ChallengeMFA, Session: pending, Token: "t"})

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, wrapped, &ch)
	assert.Equal(t, policy.ChallengeMFA, ch.Kind)
	assert.Same(t, pending, ch.Session)
	assert.Equal(t, "t", ch.Token)
}

func TestRefusalSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"ErrAuthenticationRequired": httpsec.ErrAuthenticationRequired,
		"ErrCredentialsMissing":     httpsec.ErrCredentialsMissing,
		"ErrRequestTooLarge":        httpsec.ErrRequestTooLarge,
	}

	for name, err := range sentinels {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "httpsec: ")

			for other, o := range sentinels {
				if other == name {
					continue
				}
				assert.False(t, errors.Is(err, o), "%s must not match %s", name, other)
			}
		})
	}
}
