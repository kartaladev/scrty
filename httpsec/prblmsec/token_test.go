package prblmsec_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/policy"
)

func TestMapper_ChallengeToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []prblmsec.Option
		err    error
		assert func(t *testing.T, prob *prblm.Problem, ext map[string]any)
	}

	mfaChallenge := func(token string, tt httpsec.TokenType) error {
		return &httpsec.ChallengeError{Kind: policy.ChallengeMFA, Methods: twoMethods, Token: token, TokenType: tt}
	}
	noToken := func(t *testing.T, prob *prblm.Problem, ext map[string]any) {
		t.Helper()
		assert.NotContains(t, ext, "access_token")
		assert.NotContains(t, ext, "token_type")
		assert.Empty(t, prob.Header.Get("Cache-Control"))
		assert.Equal(t, "mfa", ext["challenge"], "the rest is unchanged")
		assert.Contains(t, ext, "methods", "the rest is unchanged")
	}

	cases := []testCase{
		{
			name: "bearer",
			err:  mfaChallenge("tok-bearer", httpsec.TokenTypeBearer),
			assert: func(t *testing.T, prob *prblm.Problem, ext map[string]any) {
				t.Helper()
				assert.Equal(t, "tok-bearer", ext["access_token"])
				assert.Equal(t, "Bearer", ext["token_type"])
				assert.Equal(t, "no-store", prob.Header.Get("Cache-Control"))
				assert.Empty(t, prob.Header.Get("WWW-Authenticate"))
			},
		},
		{
			name: "dpop",
			err:  mfaChallenge("tok-dpop", httpsec.TokenTypeDPoP),
			assert: func(t *testing.T, prob *prblm.Problem, ext map[string]any) {
				t.Helper()
				assert.Equal(t, "tok-dpop", ext["access_token"])
				assert.Equal(t, "DPoP", ext["token_type"])
				assert.Equal(t, "no-store", prob.Header.Get("Cache-Control"))
			},
		},
		{name: "no token", err: mfaChallenge("", ""), assert: noToken},
		{
			// A consumer-built challenge: the type is never guessed.
			name: "token without type",
			err:  mfaChallenge("tok-untyped", ""),
			assert: func(t *testing.T, prob *prblm.Problem, ext map[string]any) {
				t.Helper()
				assert.Equal(t, "tok-untyped", ext["access_token"])
				assert.NotContains(t, ext, "token_type")
				assert.Equal(t, "no-store", prob.Header.Get("Cache-Control"))
			},
		},
		{
			name:   "withheld",
			opts:   []prblmsec.Option{prblmsec.WithoutChallengeToken()},
			err:    mfaChallenge("tok-withheld", httpsec.TokenTypeBearer),
			assert: noToken,
		},
		{
			// A dependency failure beside a token-bearing challenge: the core
			// answers 500, so the mapper must not leak the token.
			name: "challenge joined with a challenge verifier outage",
			err: errors.Join(
				mfaChallenge("tok-outage", httpsec.TokenTypeBearer),
				httpsec.ErrChallengeUnavailable,
			),
			assert: func(t *testing.T, prob *prblm.Problem, ext map[string]any) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, prob.Status)
				assert.Equal(t, "about:blank", prob.EffectiveType())
				assert.NotContains(t, ext, "access_token")
				assert.NotContains(t, ext, "token_type")
				assert.NotContains(t, ext, "challenge")
				assert.Empty(t, prob.Header.Get("Cache-Control"))
			},
		},
		{
			name: "withheld on a rotated password-change challenge",
			opts: []prblmsec.Option{prblmsec.WithoutChallengeToken()},
			err:  &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange, Token: "tok-rotated", TokenType: httpsec.TokenTypeBearer},
			assert: func(t *testing.T, prob *prblm.Problem, ext map[string]any) {
				t.Helper()
				assert.Equal(t, map[string]any{"challenge": "password-change"}, ext)
				assert.Empty(t, prob.Header.Get("Cache-Control"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newProblems(t, tc.opts...)
			prob := p.Mapper().MapError(t.Context(), tc.err)
			require.NotNil(t, prob)
			assert.Equal(t, httpsec.StatusForError(tc.err), prob.Status)
			_, doc := document(t, prob)
			tc.assert(t, prob, extensions(doc))
		})
	}
}
