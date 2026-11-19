package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// generatorPortPath is one endpoint that issues through the chain's token
// generator and answers its failure. serve builds a world of its own around
// gen, with the chain logging to log, sends the request that reaches the
// generator on ctx, and returns the response. Every limiter it installs
// expects no failure recorded, so a charge fails the row.
type generatorPortPath struct {
	name  string
	serve func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder
}

// generatorPortPaths are the endpoints that issue through the chain's
// generator. The rows that fail without signedTokens' own sanitize are form
// login and recovery completion. The rest (MFA verification, session renewal,
// passkey login, re-authentication) are parity rows: the error signedTokens
// returns there reaches only the chain's status classifier, which walks it
// with a bound and writes the same one abort record, so the response is the
// same with or without signedTokens' sanitize. TestSignedTokens_Sanitizes
// TheGeneratorsError, an internal test, pins signedTokens itself.
func generatorPortPaths() []generatorPortPath {
	return []generatorPortPath{
		{
			// The login tail (completeLogin), which passwordless login
			// shares.
			name: "form login",
			serve: func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).AnyTimes()

				deps := h.formLoginDeps()
				deps.Tokens = gen

				chain, err := httpsec.New(httpsec.WithLogger(log),
					httpsec.EnableFormLogin(deps, httpsec.WithLoginLimiter(countingLimiter(t, 0))))
				require.NoError(t, err)

				return loginServeWithin(t, chain,
					formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=s3cret"))
			},
		},
		{
			// A rotation that issues the successor's credential
			// (Sessions.RotateIssuing), which re-authentication shares.
			name: "MFA verification",
			serve: func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				sessions, err := session.New()
				require.NoError(t, err)

				s, err := sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				s.MFA = session.MFAPending
				require.NoError(t, sessions.Save(t.Context(), s))

				method := mfaMethod(t, factor.AuthenticatorApp)
				method.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
				method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil).AnyTimes()

				chain, err := httpsec.New(httpsec.WithLogger(log),
					carrying(s),
					httpsec.EnableMFA([]mfa.Method{method},
						httpsec.WithMFAVerifyLimiter(countingLimiter(t, 0)),
						httpsec.WithMFATokens(gen)),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
				require.NoError(t, err)

				return loginServeWithin(t, chain, postCode(ctx, testMFAVerifyPath))
			},
		},
		{
			// A renewal's rotation, answered through rotationFailure.
			name: "session renewal",
			serve: func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder {
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
				users.EXPECT().LoadByUserID(gomock.Any(), testUserID).Return(storedUser(), nil).AnyTimes()
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

				chain, err := httpsec.New(httpsec.WithLogger(log),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: users}),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
						Sessions: sessions, Users: users, Tokens: gen,
					}))
				require.NoError(t, err)

				req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
				req.Header.Set("Authorization", "Bearer signed-old")

				return loginServeWithin(t, chain, req)
			},
		},
		{
			// Passwordless passkey login, issuing through its own
			// PasswordlessTokens setting.
			name: "passkey login",
			serve: func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				d := newPwlDeployment(t)
				d.settings = append(d.settings, httpsec.PasswordlessTokens(gen))
				d.extra = append(d.extra, httpsec.WithLogger(log))
				d.build(t)

				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)

				req := jsonPost(ctx, passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

				return loginServeWithin(t, d.chain, req)
			},
		},
		{
			// A re-proof's rotation (reauthInterceptor.resolve) issues the
			// successor's credential through the re-authentication tokens.
			name: "re-authentication",
			serve: func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				f := newPwFixture(t)
				f.attempts.EXPECT().Reset(gomock.Any(), mfaUsername).Return(nil).AnyTimes()
				f.reauthOpts = append(f.reauthOpts, httpsec.WithReauthenticationTokens(gen))
				// The fixture's constructor appended its own WithLogger as the
				// last chain option, and a chain takes one: swap it for the
				// row's.
				f.chainOpts = append(f.chainOpts[:len(f.chainOpts)-1], httpsec.WithLogger(log))

				s := f.newSession(t, factor.Password, session.MFANone)
				f.clock.Advance(10 * time.Minute)

				c, err := f.build(nil)
				require.NoError(t, err)

				return loginServeWithin(t, c,
					passwordPost(ctx, mfaTokenFor(s.ID), url.Values{httpsec.DefaultLoginPasswordParam: {reauthAdaPassword}}))
			},
		},
		{
			// The recovery core's issuer (issueRecovered), which marks the
			// failure a second time.
			name: "recovery completion",
			serve: func(t *testing.T, ctx context.Context, gen token.Generator, log *slog.Logger) *httptest.ResponseRecorder {
				t.Helper()

				h := newRecoveryHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.WithLogger(log))
				h.recOpts = []httpsec.RecoveryOption{
					httpsec.WithRecoveryTokens(gen),
					httpsec.WithRecoveryLimiter(countingLimiter(t, 0)),
					httpsec.WithRecoveryUserLimiter(countingLimiter(t, 0)),
				}
				h.build(t)

				return loginServeWithin(t, h.chain, postValues(ctx, httpsec.DefaultRecoveryCompletePath, e2eSource,
					recoveryForm(httpsec.RecoverySavedCodeParam, h.saved(t), httpsec.RecoveryPasswordParam, e2ePassword)))
			},
		},
	}
}

// countedFailingGenerator is failingGenerator, counting the issues it was
// asked for.
func countedFailingGenerator(t *testing.T, cause error) (*MockGenerator, *atomic.Int32) {
	t.Helper()

	var calls atomic.Int32

	g := newMockGenerator(gomock.NewController(t))
	g.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string, *identity.Principal) (string, error) {
			calls.Add(1)

			return "", cause
		})

	return g, &calls
}

// TestPortErrors_TokenGenerator pins that a token generator error whose chain
// cannot be walked is answered, on every path that issues through the chain's
// generator, exactly as a plain generator failure: the same response, byte for
// byte, nothing charged against a source or a user, one abort record on the
// chain's logger and none on slog.Default(). The magic-link and OIDC
// redemptions are pinned by TestPortErrors_Redemption and
// TestPortErrors_OIDCRedemption.
func TestPortErrors_TokenGenerator(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(redemptionPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live"},
		{name: "cancelled", ctx: func(ctx context.Context) context.Context {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			return cctx
		}},
	}

	plainOutage := errors.New("generator_porterr_test: key source unavailable")

	for _, path := range generatorPortPaths() {
		for _, c := range contexts {
			for _, kind := range redemptionPortErrKinds() {
				row := path.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						redemptionPortErrInChild(t, row)

						return
					}

					defaults := swapDefaultLogger(t)

					ctx := t.Context()
					if c.ctx != nil {
						ctx = c.ctx(ctx)
					}

					plainLogs, gotLogs := &capturingHandler{}, &capturingHandler{}

					plainGen, plainCalls := countedFailingGenerator(t, plainOutage)
					plain := path.serve(t, ctx, plainGen, slog.New(plainLogs))
					require.Empty(t, abortRecords(plainLogs.records()), "the plain error writes no abort record")

					if c.ctx == nil {
						require.Positive(t, plainCalls.Load(), "the request reaches the generator")
						require.Equal(t, http.StatusInternalServerError, plain.Code,
							"a generator failure is a dependency failure")
					}

					gotGen, gotCalls := countedFailingGenerator(t, kind.err)
					got := path.serve(t, ctx, gotGen, slog.New(gotLogs))

					assert.Equal(t, plain.Code, got.Code, "status")
					assert.Equal(t, plain.Header(), got.Header(), "headers")
					assert.Equal(t, plain.Body.String(), got.Body.String(), "body")
					assert.NotContains(t, got.Body.String(), hostileSecret, "the response quotes the error")
					require.Equal(t, plainCalls.Load(), gotCalls.Load(), "the generator is reached as often")

					aborts := abortRecords(gotLogs.records())
					if kind.reason == "" || gotCalls.Load() == 0 {
						// A path that refuses a cancelled request before it
						// issues never meets the generator's error.
						assert.Empty(t, aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, aborts, 1, "one abort record, on the chain's logger")
						assertAbortRecord(t, aborts[0], kind.reason)
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						fmt.Fprintln(os.Stdout, redemptionPortErrRan+row)
					}
				})
			}
		}
	}
}
