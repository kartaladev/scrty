package prblmsec_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
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

func TestMapper_ChallengeWalk(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error, prob *prblm.Problem)
	}

	// ofType asserts prob has the type sub and the status the core answers,
	// and returns its extension members.
	ofType := func(t *testing.T, err error, prob *prblm.Problem, sub string) map[string]any {
		t.Helper()
		require.NotNil(t, prob)
		assert.Equal(t, "security/"+sub, prob.Type)
		assert.Equal(t, httpsec.StatusForError(err), prob.Status)
		_, doc := document(t, prob)
		return extensions(doc)
	}
	typed := func(sub string) func(t *testing.T, err error, prob *prblm.Problem) {
		return func(t *testing.T, err error, prob *prblm.Problem) {
			t.Helper()
			ofType(t, err, prob, sub)
		}
	}
	noChallenge := func(t *testing.T, err error, prob *prblm.Problem) {
		t.Helper()
		_, recognised := httpsec.LookupStatus(err)
		require.False(t, recognised)
		assert.Nil(t, prob)
	}

	mfa := func() *httpsec.ChallengeError {
		return &httpsec.ChallengeError{
			Kind: policy.ChallengeMFA, Methods: twoMethods,
			Token: "tok-as", TokenType: httpsec.TokenTypeBearer,
		}
	}
	pwChange := func() *httpsec.ChallengeError {
		return &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange}
	}
	typedNil := (*httpsec.ChallengeError)(nil)

	cases := []testCase{
		{
			name: "As method presents a challenge",
			err:  asChallenge{ch: mfa()},
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ext := ofType(t, err, prob, "mfa-required")
				assert.Equal(t, "mfa", ext["challenge"])
				assert.Equal(t, "tok-as", ext["access_token"])
				assert.Equal(t, "Bearer", ext["token_type"])
				raw, _ := document(t, prob)
				assert.Contains(t, raw, `"methods":`+twoMethodsJSON)
				assert.Equal(t, "no-store", prob.Header.Get("Cache-Control"))
			},
		},
		{
			name: "As method presents a challenge under a wrap",
			err:  fmt.Errorf("w: %w", asChallenge{ch: pwChange()}),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ext := ofType(t, err, prob, "password-change-required")
				assert.Equal(t, map[string]any{"challenge": "password-change"}, ext)
			},
		},
		{
			name:   "As method presents a typed nil",
			err:    asChallenge{ch: nil},
			assert: noChallenge,
		},
		{
			name:   "As method presents a typed nil ahead of a real challenge",
			err:    errors.Join(asChallenge{ch: nil}, pwChange()),
			assert: typed("password-change-required"),
		},
		{
			name:   "typed-nil challenge joined ahead of a real one",
			err:    errors.Join(typedNil, pwChange()),
			assert: typed("password-change-required"),
		},
		{
			name: "challenge through As joined ahead of a direct one",
			err:  errors.Join(asChallenge{ch: mfa()}, pwChange()),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ext := ofType(t, err, prob, "mfa-required")
				assert.Equal(t, "tok-as", ext["access_token"])
			},
		},
		{
			name:   "direct challenge joined ahead of one through As",
			err:    errors.Join(pwChange(), asChallenge{ch: mfa()}),
			assert: typed("password-change-required"),
		},
		{
			// The walk skips the typed nil and keeps going, so a challenge
			// presented through As behind it is found, as the core finds it.
			name:   "challenge through As behind a typed nil",
			err:    errors.Join(typedNil, asChallenge{ch: mfa()}),
			assert: typed("mfa-required"),
		},
		{
			name:   "challenge 101 wraps deep",
			err:    wrapLayers(mfa(), 101),
			assert: typed("mfa-required"),
		},
		{
			// The join, the typed nil, Budget-3 wraps and the challenge: the
			// challenge is the budget's last entry.
			name:   "challenge behind a typed nil at the budget's last entry",
			err:    errors.Join(typedNil, wrapLayers(mfa(), errwalk.Budget-3)),
			assert: typed("mfa-required"),
		},
		{
			// One wrap more puts it past the budget: the walk gives up and
			// the mapper answers nothing, as the lookup does.
			name:   "challenge behind a typed nil one entry past the budget",
			err:    errors.Join(typedNil, wrapLayers(mfa(), errwalk.Budget-2)),
			assert: noChallenge,
		},
	}

	p := newProblems(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var prob *prblm.Problem
			require.NotPanics(t, func() { prob = p.Mapper().MapError(t.Context(), tc.err) })
			tc.assert(t, tc.err, prob)
		})
	}
}
