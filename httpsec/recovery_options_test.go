package httpsec_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/recovery"
)

// TestEnableAccountRecovery_Config pins spec account-recovery "Recovery is off
// by default, and its wiring mistakes fail at construction" and "A recovery
// produces a confined session, never a full one" (scenario "Nothing to
// bind"): every wiring mistake is refused by New with ErrConfig, and a chain
// that never enabled recovery attempts none.
func TestEnableAccountRecovery_Config(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options builds the chain's options from a fresh harness.
		options func(t *testing.T, h *recoveryHarness) []httpsec.Option

		assert func(t *testing.T, h *recoveryHarness, chain *httpsec.Chain, err error)
	}

	// refused asserts New failed with the chain's configuration error.
	refused := func(t *testing.T, _ *recoveryHarness, chain *httpsec.Chain, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, chain)
	}

	// with applies change to the harness and returns its options.
	with := func(change func(h *recoveryHarness)) func(t *testing.T, h *recoveryHarness) []httpsec.Option {
		return func(t *testing.T, h *recoveryHarness) []httpsec.Option {
			t.Helper()

			change(h)

			return h.options(t)
		}
	}

	pathCase := func(name string, opts ...httpsec.RecoveryOption) testCase {
		return testCase{
			name:    name,
			options: with(func(h *recoveryHarness) { h.recOpts = opts }),
			assert:  refused,
		}
	}

	cases := []testCase{
		{
			name:    "the harness's wiring builds",
			options: with(func(*recoveryHarness) {}),
			assert: func(t *testing.T, _ *recoveryHarness, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "saved codes only is the core's configuration error",
			options: with(func(h *recoveryHarness) {
				h.proofs = []recovery.ProofKind{recovery.ProofSaved}
			}),
			assert: func(t *testing.T, h *recoveryHarness, chain *httpsec.Chain, err error) {
				refused(t, h, chain, err)
				require.ErrorIs(t, err, recovery.ErrConfig)
			},
		},
		{
			name:    "no binding route",
			options: with(func(h *recoveryHarness) { h.noBinding = true }),
			assert:  refused,
		},
		{
			name: "the password proof without form login",
			options: with(func(h *recoveryHarness) {
				h.noFormLogin = true
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryTokens(h.tokens)}
			}),
			assert: func(t *testing.T, h *recoveryHarness, chain *httpsec.Chain, err error) {
				refused(t, h, chain, err)
				require.ErrorIs(t, err, recovery.ErrConfig)
			},
		},
		{
			name: "no form login and no token generator",
			options: with(func(h *recoveryHarness) {
				h.noFormLogin = true
				h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
			}),
			assert: refused,
		},
		{
			name: "no form login, with a token generator and no password proof, builds",
			options: with(func(h *recoveryHarness) {
				h.noFormLogin = true
				h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryTokens(h.tokens)}
			}),
			assert: func(t *testing.T, _ *recoveryHarness, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		pathCase("the start path is the logout path", httpsec.WithRecoveryStartPath(httpsec.DefaultLogoutPath)),
		pathCase("the complete path is the login path", httpsec.WithRecoveryCompletePath(httpsec.DefaultLoginPath)),
		pathCase("an empty finish path", httpsec.WithRecoveryFinishPath("")),
		pathCase("a cancel path with no leading slash", httpsec.WithRecoveryCancelPath("recovery/cancel")),
		pathCase("the codes path is the complete path",
			httpsec.WithRecoveryCodesPath(httpsec.DefaultRecoveryCompletePath)),
		pathCase("the start path is the finish path",
			httpsec.WithRecoveryStartPath(httpsec.DefaultRecoveryFinishPath)),
		pathCase("a nil complete limiter", httpsec.WithRecoveryLimiter(nil)),
		pathCase("a nil start limiter", httpsec.WithRecoveryStartLimiter(nil)),
		pathCase("a nil user limiter", httpsec.WithRecoveryUserLimiter(nil)),
		pathCase("a nil token generator", httpsec.WithRecoveryTokens(nil)),
		pathCase("a nil responder", httpsec.WithRecoveryResponder(nil)),
		pathCase("a nil hold responder", httpsec.WithRecoveryHoldResponder(nil)),
		{
			name: "without issued codes, a POST to the start path reaches the application",
			options: with(func(h *recoveryHarness) {
				h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofPassword}
			}),
			assert: func(t *testing.T, _ *recoveryHarness, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				started := serve(t, chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
				require.NoError(t, started.err)
				assert.True(t, started.handlerRan, "the start endpoint exists with issued codes off")
			},
		},
		{
			name: "with issued codes, the start path is answered",
			options: with(func(h *recoveryHarness) {
				h.proofs = []recovery.ProofKind{recovery.ProofIssued, recovery.ProofPassword}
			}),
			assert: func(t *testing.T, _ *recoveryHarness, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				started := serve(t, chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
				require.NoError(t, started.err)
				assert.False(t, started.handlerRan)
				assert.Equal(t, http.StatusAccepted, started.rec.Code)
			},
		},
		{
			name: "an issued-code lifetime of 25 hours passed through the core",
			options: with(func(h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts, recovery.WithIssuedCodeTTL(25*time.Hour))
			}),
			assert: func(t *testing.T, h *recoveryHarness, chain *httpsec.Chain, err error) {
				refused(t, h, chain, err)
				require.ErrorIs(t, err, recovery.ErrConfig)
			},
		},
		{
			name: "a sender that waits for delivery, without synchronous delivery accepted",
			options: func(t *testing.T, h *recoveryHarness) []httpsec.Option {
				t.Helper()

				// A strict double that is not a notify.NonBlocking: nothing is
				// ever sent through it.
				h.send = NewMockSender(gomock.NewController(t))

				return h.options(t)
			},
			assert: func(t *testing.T, h *recoveryHarness, chain *httpsec.Chain, err error) {
				refused(t, h, chain, err)
				require.ErrorIs(t, err, recovery.ErrConfig)
			},
		},
		{
			name: "enabled twice",
			options: func(t *testing.T, h *recoveryHarness) []httpsec.Option {
				t.Helper()

				opts := h.options(t)

				return append(opts, opts[len(opts)-1])
			},
			assert: func(t *testing.T, h *recoveryHarness, chain *httpsec.Chain, err error) {
				refused(t, h, chain, err)
				assert.Contains(t, err.Error(), "EnableAccountRecovery", "the error names the option given twice")
				assert.Contains(t, err.Error(), "given twice")
			},
		},
		{
			name: "off by default: a POST to the complete path reaches the application",
			options: func(t *testing.T, h *recoveryHarness) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions})}
			},
			assert: func(t *testing.T, _ *recoveryHarness, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				out := serve(t, chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "a chain without recovery answered the complete path")

				started := serve(t, chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
				require.NoError(t, started.err)
				assert.True(t, started.handlerRan, "a chain without recovery answered the start path")
				assert.NotEqual(t, http.StatusAccepted, started.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			chain, err := httpsec.New(tc.options(t, h)...)
			tc.assert(t, h, chain, err)
		})
	}
}
