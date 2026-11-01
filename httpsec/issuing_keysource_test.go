package httpsec_test

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// signerDown is a consumer key source that cannot hand out a signing key: it
// fails Signer with err, as a key service that is unreachable does.
type signerDown struct {
	signingkey.KeySource

	err error
}

func (s signerDown) Signer(context.Context, signingkey.Alg) (string, crypto.Signer, error) {
	return "", nil, s.err
}

// TestFormLogin_KeySourceFailureAnswerCarriesNoKeySourceText pins that a login whose
// token cannot be issued because the key source behind the real generator
// fails, writes no log record carrying the key source's text, and is answered
// as a dependency failure with the key source's error still reachable. The
// generator is real, because the text the key source's error reaches the chain
// with is the generator's to wrap. What it pins is the text of the answer:
// form login writes no record at all for this failure.
func TestFormLogin_KeySourceFailureAnswerCarriesNoKeySourceText(t *testing.T) {
	t.Parallel()

	errKMS := errors.New("kms: arn:aws:kms:eu-west-1:111122223333:key/abcd is unavailable")

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	gen, err := token.NewGenerator(signerDown{KeySource: keys, err: errKMS},
		token.WithIssuer("https://issuer.example"), token.WithAudience("orders-api"))
	require.NoError(t, err)

	h := newAuthHarness(t)

	sessions, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
	require.NoError(t, err)

	h.sessions = sessions

	deps := h.formLoginDeps()
	deps.Tokens = gen

	h.expectAuthenticated(testPrincipal())
	h.attempts.EXPECT().Reset(t.Context(), "ada").Return(nil).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableFormLogin(deps),
	)
	require.NoError(t, err)

	out := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret"))

	require.ErrorIs(t, out.err, errKMS, "the key source's error stays reachable")
	assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
	assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.NotContains(t, out.err.Error(), "kms", "the answer's text is the library's")
	assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan)

	for i, rec := range h.logs.records() {
		assert.NotContains(t, recordText(rec), "kms", "record %d carries the key source's text", i)
		assert.NotContains(t, recordText(rec), "abcd", "record %d carries the key source's text", i)
	}
}

// failingGenerator is a consumer token generator that fails every issue with
// cause.
func failingGenerator(t *testing.T, cause error) *MockGenerator {
	t.Helper()

	g := NewMockGenerator(gomock.NewController(t))
	g.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("", cause).AnyTimes()

	return g
}

// TestIssuingFailureIsNeverARefusal pins that a credential the chain's issuer
// cannot issue is a dependency failure on every path that issues through it,
// whatever the generator's error wraps: the default status mapping answers it
// 500, even when the cause wraps a sentinel the mapping answers 401, the cause
// stays reachable, and nothing is charged against a source or a user. The
// limiters each row installs expect no failure recorded, so a charge fails the
// row when the test ends.
func TestIssuingFailureIsNeverARefusal(t *testing.T) {
	t.Parallel()

	unavailable := fmt.Errorf("kms adapter: %w", authenticate.ErrUnavailable)
	refused := fmt.Errorf("kms adapter: %w", authenticate.ErrAuthenticationFailed)

	// renewal posts a renewal of a live session held by a signed bearer token.
	// The renewal limiter counts every attempt by design, so the charge it
	// pins is the supersession: the presented session still loads.
	renewal := func(cause error) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			ctrl := gomock.NewController(t)

			sessions, err := session.New(session.WithStore(must.Must(session.NewMemoryStore())))
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			verifier := NewMockVerifier(ctrl)
			verifier.EXPECT().Verify(gomock.Any(), "signed-old").
				Return(token.NewClaims(testSubject, s.ID), nil).AnyTimes()

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil).AnyTimes()
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

			chain, err := httpsec.New(
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: users}),
				httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
					Sessions: sessions, Users: users, Tokens: failingGenerator(t, cause),
				}))
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
			req.Header.Set("Authorization", "Bearer signed-old")
			out := serve(t, chain, req)

			_, err = sessions.Load(t.Context(), s.ID)
			require.NoError(t, err, "nothing was superseded")

			return out.err
		}
	}

	// formLogin posts a login that authenticates; the attempt store expects
	// no failure recorded against the user.
	formLogin := func(cause error) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			h := newAuthHarness(t)
			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).AnyTimes()

			deps := h.formLoginDeps()
			deps.Tokens = failingGenerator(t, cause)

			chain, err := httpsec.New(httpsec.EnableFormLogin(deps,
				httpsec.WithLoginLimiter(countingLimiter(t, 0))))
			require.NoError(t, err)

			return serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret")).err
		}
	}

	// magicLink redeems a valid link.
	magicLink := func(cause error) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			h := newMagicLinkHarness(t)
			tok, nonce := h.link(t, h.chain(t))

			h.tokens = failingGenerator(t, cause)
			h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkLimiter(countingLimiter(t, 0)))

			out := h.redeem(t, h.chain(t), tok, nonce)
			assert.Zero(t, h.activeSessions(t), "no session was stored")

			return out.err
		}
	}

	// mfaVerification submits a code the method accepts for a session owing
	// a second factor.
	mfaVerification := func(cause error) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			sessions, err := session.New()
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			s.MFA = session.MFAPending
			require.NoError(t, sessions.Save(t.Context(), s))

			method := mfaMethod(t, factor.AuthenticatorApp)
			method.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
			method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)

			return refusedBy(t, postCode(t.Context(), testMFAVerifyPath),
				carrying(s),
				httpsec.EnableMFA([]mfa.Method{method},
					httpsec.WithMFAVerifyLimiter(countingLimiter(t, 0)),
					httpsec.WithMFATokens(failingGenerator(t, cause))),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions})).err
		}
	}

	// recoveryCompletion completes a recovery with a saved code and the
	// password, both valid.
	recoveryCompletion := func(cause error) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			h := newRecoveryHarness(t)
			h.recOpts = []httpsec.RecoveryOption{
				httpsec.WithRecoveryTokens(failingGenerator(t, cause)),
				httpsec.WithRecoveryLimiter(countingLimiter(t, 0)),
				httpsec.WithRecoveryUserLimiter(countingLimiter(t, 0)),
			}
			h.build(t)

			saved := h.saved(t)
			out := h.complete(t, recoveryForm(
				httpsec.RecoverySavedCodeParam, saved,
				httpsec.RecoveryPasswordParam, e2ePassword))

			require.NoError(t, h.codes.Confirm(t.Context(), e2eUser, saved), "the saved code was not spent")

			return out.err
		}
	}

	// dependencyFailure asserts err is an issuing failure caused by cause.
	dependencyFailure := func(cause error) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.Error(t, err)
			require.ErrorIs(t, err, cause, "the generator's error stays reachable")
			assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err),
				"an issuing failure is a dependency failure, never a refusal")
			assert.NotContains(t, err.Error(), "kms", "the answer's text is the library's")
		}
	}

	type testCase struct {
		name   string
		act    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{name: "renewal", act: renewal(unavailable), assert: dependencyFailure(unavailable)},
		{name: "renewal, the cause wrapping a refused authentication", act: renewal(refused), assert: dependencyFailure(refused)},
		{name: "form login", act: formLogin(unavailable), assert: dependencyFailure(unavailable)},
		{name: "magic-link redemption", act: magicLink(unavailable), assert: dependencyFailure(unavailable)},
		{name: "MFA verification", act: mfaVerification(unavailable), assert: dependencyFailure(unavailable)},
		{name: "recovery completion", act: recoveryCompletion(unavailable), assert: dependencyFailure(unavailable)},
		{
			name:   "recovery completion, the cause wrapping a refused authentication",
			act:    recoveryCompletion(refused),
			assert: dependencyFailure(refused),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t))
		})
	}
}
