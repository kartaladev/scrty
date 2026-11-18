package httpsec_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// asChallenge presents ch as a *httpsec.ChallengeError only through its own
// As method. It has no Unwrap, so only errors.As semantics can see ch.
type asChallenge struct{ ch *httpsec.ChallengeError }

func (asChallenge) Error() string { return "presents a challenge through As" }

func (a asChallenge) As(target any) bool {
	p, ok := target.(**httpsec.ChallengeError)
	if !ok {
		return false
	}
	*p = a.ch

	return true
}

// wrapLayers wraps err in n fmt.Errorf %w layers. The returned error sits at
// depth 0 of the walk, so err sits at depth n.
func wrapLayers(err error, n int) error {
	for range n {
		err = fmt.Errorf("w: %w", err)
	}

	return err
}

func TestStatusForError_ChallengeWalk(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error, status int, ok bool)
	}

	answers := func(want int) func(t *testing.T, err error, status int, ok bool) {
		return func(t *testing.T, err error, status int, ok bool) {
			t.Helper()
			assert.True(t, ok, "recognised")
			assert.Equal(t, want, status)
			assert.Equal(t, want, httpsec.StatusForError(err))
		}
	}
	noChallenge := func(t *testing.T, err error, status int, ok bool) {
		t.Helper()
		assert.False(t, ok, "not recognised")
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
	}

	mfa := func() *httpsec.ChallengeError { return &httpsec.ChallengeError{Kind: policy.ChallengeMFA} }
	pwChange := func() *httpsec.ChallengeError {
		return &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange}
	}
	typedNil := (*httpsec.ChallengeError)(nil)

	cases := []testCase{
		{
			name:   "As method presents a challenge",
			err:    asChallenge{ch: mfa()},
			assert: answers(http.StatusUnauthorized),
		},
		{
			name:   "As method presents a challenge under a wrap",
			err:    fmt.Errorf("w: %w", asChallenge{ch: pwChange()}),
			assert: answers(http.StatusForbidden),
		},
		{
			// errors.As reports true with a nil result; that is no challenge.
			name:   "As method presents a typed nil",
			err:    asChallenge{ch: nil},
			assert: noChallenge,
		},
		{
			name:   "As method presents a typed nil ahead of a real challenge",
			err:    errors.Join(asChallenge{ch: nil}, pwChange()),
			assert: answers(http.StatusForbidden),
		},
		{
			name:   "typed-nil challenge joined ahead of a real one",
			err:    errors.Join(typedNil, pwChange()),
			assert: answers(http.StatusForbidden),
		},
		{
			// Two real challenges: the first in errors.As order decides.
			name:   "challenge through As joined ahead of a direct one",
			err:    errors.Join(asChallenge{ch: mfa()}, pwChange()),
			assert: answers(http.StatusUnauthorized),
		},
		{
			name:   "direct challenge joined ahead of one through As",
			err:    errors.Join(pwChange(), asChallenge{ch: mfa()}),
			assert: answers(http.StatusForbidden),
		},
		{
			// The fallback walk follows Unwrap only, so a challenge
			// presented through As behind a typed nil is not seen.
			name:   "challenge through As behind a typed nil",
			err:    errors.Join(typedNil, asChallenge{ch: mfa()}),
			assert: noChallenge,
		},
		{
			// errors.As has no depth limit.
			name:   "challenge 101 wraps deep",
			err:    wrapLayers(mfa(), 101),
			assert: answers(http.StatusUnauthorized),
		},
		{
			// Behind a typed nil only the bounded walk can find it: the
			// join is depth 0 and the challenge depth 100, the limit.
			name:   "challenge 99 wraps deep behind a typed nil",
			err:    errors.Join(typedNil, wrapLayers(mfa(), 99)),
			assert: answers(http.StatusUnauthorized),
		},
		{
			// Depth 101, past the limit: the rest of the chain decides.
			name:   "challenge 100 wraps deep behind a typed nil",
			err:    errors.Join(typedNil, wrapLayers(mfa(), 100)),
			assert: noChallenge,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.NotPanics(t, func() {
				status, ok := httpsec.LookupStatus(tc.err)
				tc.assert(t, tc.err, status, ok)
			})
		})
	}
}
