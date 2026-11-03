package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// challengeFor is the seam enabled for flow. Basic authentication is outside
// the default selection, so it is named; every other flow is in it.
func challengeFor(flow httpsec.ChallengeFlow, v httpsec.ChallengeVerifier, opts ...httpsec.ChallengeOption) httpsec.Option {
	if flow == httpsec.ChallengeFlowBasicAuth {
		opts = append([]httpsec.ChallengeOption{httpsec.WithChallengeFlows(flow)}, opts...)
	}

	return httpsec.EnableAutomationChallenge(v, opts...)
}

// challengeFlow is one of the five flows the verifier can stand in front of,
// built over a chain carrying extra, with doubles strict enough that a step the
// case did not expect fails the test.
type challengeFlow struct {
	name string
	flow httpsec.ChallengeFlow

	// other is a second flow the chain also enables, so a selection can name
	// one flow and leave this one out; also is the options that enable it, nil
	// when the flow's own chain already does.
	other httpsec.ChallengeFlow
	also  func(t *testing.T) []httpsec.Option

	// build wires the flow's chain. work says whether the case expects the
	// flow's guarded work, its account lookup among it, to run: the doubles
	// that do that work are told to expect exactly one call, or none.
	build func(t *testing.T, work bool, extra ...httpsec.Option) challengeRun
}

// challengeRun is a built flow: sendWith posts one request of it under ctx,
// and worked reports, from what was served, whether its guarded work ran.
type challengeRun struct {
	sendWith func(t *testing.T, ctx context.Context) served
	worked   func(t *testing.T, out served) bool
}

// send posts one request of the flow under the test's own context.
func (r challengeRun) send(t *testing.T) served { return r.sendWith(t, t.Context()) }

// challengeFlows is every flow the seam covers.
func challengeFlows() []challengeFlow {
	return []challengeFlow{
		{
			name: "form login", flow: httpsec.ChallengeFlowFormLogin, build: formLoginChallengeRun,
			other: httpsec.ChallengeFlowBasicAuth, also: alsoBasic,
		},
		{
			name: "basic", flow: httpsec.ChallengeFlowBasicAuth, build: basicChallengeRun,
			other: httpsec.ChallengeFlowFormLogin, also: alsoFormLogin,
		},
		{
			name: "magic-link request", flow: httpsec.ChallengeFlowMagicLinkRequest, build: magicLinkChallengeRun,
			other: httpsec.ChallengeFlowFormLogin, also: alsoFormLogin,
		},
		{
			name: "passwordless begin", flow: httpsec.ChallengeFlowPasswordlessBegin, build: passwordlessChallengeRun,
			other: httpsec.ChallengeFlowFormLogin,
		},
		{
			name: "recovery start", flow: httpsec.ChallengeFlowRecoveryStart, build: recoveryStartChallengeRun,
			other: httpsec.ChallengeFlowFormLogin,
		},
	}
}

// alsoFormLogin enables form login over doubles nothing calls, so a chain
// whose flow is another one has a second flow to select.
func alsoFormLogin(t *testing.T) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{httpsec.EnableFormLogin(newAuthHarness(t).formLoginDeps())}
}

// alsoBasic is alsoFormLogin for Basic authentication.
func alsoBasic(t *testing.T) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{httpsec.EnableBasicAuth(newAuthHarness(t).basicAuthDeps())}
}

// passwordWork expects, when work is set, one refused password check: the
// authenticator reached, and the failure recorded against the account. With
// work unset neither is expected, so a lookup or a lockout failure fails the
// test. The failure count the signals read is answered either way.
func passwordWork(h *authHarness, work bool) {
	h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

	if work {
		h.expectAuthenticationFailed()
		h.attempts.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	}
}

func formLoginChallengeRun(t *testing.T, work bool, extra ...httpsec.Option) challengeRun {
	t.Helper()

	h := newAuthHarness(t)
	passwordWork(h, work)

	chain, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(h.logger()),
		httpsec.EnableFormLogin(h.formLoginDeps()),
	}, extra...)...)
	require.NoError(t, err)

	return challengeRun{
		sendWith: func(_ *testing.T, ctx context.Context) served {
			return serveWithContext(ctx, chain, formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=wrong"))
		},
		worked: func(_ *testing.T, out served) bool {
			return errors.Is(out.err, authenticate.ErrAuthenticationFailed)
		},
	}
}

func basicChallengeRun(t *testing.T, work bool, extra ...httpsec.Option) challengeRun {
	t.Helper()

	h := newAuthHarness(t)
	passwordWork(h, work)

	chain, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBasicAuth(h.basicAuthDeps()),
	}, extra...)...)
	require.NoError(t, err)

	return challengeRun{
		sendWith: func(_ *testing.T, ctx context.Context) served {
			return serveWithContext(ctx, chain, basicRequest(ctx, "ada", "wrong"))
		},
		worked: func(_ *testing.T, out served) bool {
			return errors.Is(out.err, authenticate.ErrAuthenticationFailed)
		},
	}
}

func magicLinkChallengeRun(t *testing.T, work bool, extra ...httpsec.Option) challengeRun {
	t.Helper()

	h := newMagicLinkHarness(t)

	// A loader of its own, strict, so the request's account lookup is seen.
	users := NewMockUserLoader(gomock.NewController(t))
	if work {
		users.EXPECT().LoadByUsername(gomock.Any(), magicLinkKnown).Return(nil, identity.ErrUserNotFound)
	}

	onetimes, err := onetime.New("magic-link", onetime.WithTokenTTL(magicLinkTTL))
	require.NoError(t, err)

	h.manager, err = magiclink.New(onetimes, users, h.sender, "https://app.example.com")
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts, extra...)
	chain := h.chain(t)

	return challengeRun{
		sendWith: func(_ *testing.T, ctx context.Context) served {
			body := url.Values{httpsec.DefaultMagicLinkAddressParam: {magicLinkKnown}}.Encode()

			return serveWithContext(ctx, chain, formRequest(ctx, httpsec.DefaultMagicLinkRequestPath, body))
		},
		worked: func(_ *testing.T, out served) bool {
			return out.err == nil && out.rec.Code == http.StatusAccepted
		},
	}
}

func passwordlessChallengeRun(t *testing.T, _ bool, extra ...httpsec.Option) challengeRun {
	t.Helper()

	d := newPwlDeployment(t)
	d.extra = append(d.extra, extra...)
	d.build(t)

	return challengeRun{
		sendWith: func(_ *testing.T, ctx context.Context) served {
			return serveWithContext(ctx, d.chain, post(ctx, passwordlessBeginPath, ""))
		},
		worked: func(t *testing.T, out served) bool {
			assert.Zero(t, d.lookups.Load(), "a passwordless begin looks up no account")

			return cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName) != nil
		},
	}
}

func recoveryStartChallengeRun(t *testing.T, work bool, extra ...httpsec.Option) challengeRun {
	t.Helper()

	h := newRecoveryHarness(t)

	// The recovery's own loader, strict, so the start's account lookup is
	// seen; form login keeps the harness's.
	h.users = NewMockUserLoader(gomock.NewController(t))
	if work {
		h.users.EXPECT().LoadByUsername(gomock.Any(), "nobody").Return(nil, identity.ErrUserNotFound)
	}

	h.chainOpts = append(h.chainOpts, extra...)
	h.build(t)

	return challengeRun{
		sendWith: func(_ *testing.T, ctx context.Context) served {
			body := url.Values{httpsec.RecoveryUsernameParam: {"nobody"}}.Encode()

			return serveWithContext(ctx, h.chain, formRequest(ctx, httpsec.DefaultRecoveryStartPath, body))
		},
		worked: func(_ *testing.T, out served) bool {
			return out.err == nil && out.rec.Code == http.StatusAccepted
		},
	}
}

func TestChallenge_Flows(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		flow challengeFlow

		// options are the challenge options the chain is built with, nil for a
		// chain without the seam; decision is what the verifier answers, and
		// zero when it must not be asked at all.
		options  func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option
		decision httpsec.ChallengeDecision
		work     bool

		assert func(t *testing.T, run challengeRun, out served)
	}

	// enabled turns the seam on for f's flow. Basic is not in the default
	// selection, so its cases name it.
	enabled := func(f challengeFlow, opts ...httpsec.ChallengeOption) func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
		return func(_ *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
			return []httpsec.Option{challengeFor(f.flow, v, opts...)}
		}
	}

	// selecting enables the flow's second flow as well, then selects flows.
	selecting := func(f challengeFlow, flows ...httpsec.ChallengeFlow) func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
		return func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
			t.Helper()

			var opts []httpsec.Option
			if f.also != nil {
				opts = f.also(t)
			}

			return append(opts, httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(flows...)))
		}
	}

	proceeded := func(t *testing.T, run challengeRun, out served) {
		t.Helper()

		assert.NotErrorIs(t, out.err, httpsec.ErrChallengeRequired)
		assert.True(t, run.worked(t, out), "the flow's work runs")
	}

	var cases []testCase

	for _, f := range challengeFlows() {
		cases = append(cases,
			testCase{
				name: f.name + ": not configured, no verifier is asked and the flow runs",
				flow: f, work: true, assert: proceeded,
			},
			testCase{
				name: f.name + ": a refusal is the challenge-required error, before any account lookup",
				flow: f, options: enabled(f), decision: httpsec.ChallengeRefuse,
				assert: func(t *testing.T, run challengeRun, out served) {
					require.ErrorIs(t, out.err, httpsec.ErrChallengeRequired)
					assert.False(t, run.worked(t, out), "no guarded work runs")
				},
			},
			testCase{
				name: f.name + ": a pass lets the flow run",
				flow: f, options: enabled(f), decision: httpsec.ChallengePass, work: true, assert: proceeded,
			},
			testCase{
				name: f.name + ": not needed lets the flow run",
				flow: f, options: enabled(f), decision: httpsec.ChallengeNotNeeded, work: true, assert: proceeded,
			},
			testCase{
				name:    f.name + ": selected explicitly, the verifier is asked",
				flow:    f,
				options: selecting(f, f.other, f.flow), decision: httpsec.ChallengeRefuse,
				assert: func(t *testing.T, _ challengeRun, out served) {
					require.ErrorIs(t, out.err, httpsec.ErrChallengeRequired)
				},
			},
			testCase{
				name: f.name + ": not selected, the verifier is not asked",
				flow: f, options: selecting(f, f.other), work: true, assert: proceeded,
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := NewMockChallengeVerifier(gomock.NewController(t))
			if tc.decision != 0 {
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.decision, nil)
			}

			var extra []httpsec.Option
			if tc.options != nil {
				extra = tc.options(t, v)
			}

			run := tc.flow.build(t, tc.work, extra...)
			tc.assert(t, run, run.send(t))
		})
	}
}

func TestChallenge_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option
		assert  func(t *testing.T, err error)
	}

	refused := func(names ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)

			for _, n := range names {
				assert.Contains(t, err.Error(), n)
			}
		}
	}

	built := func(t *testing.T, err error) { require.NoError(t, err) }

	formLogin := func(t *testing.T) httpsec.Option { return alsoFormLogin(t)[0] }
	basic := func(t *testing.T) httpsec.Option { return alsoBasic(t)[0] }

	cases := []testCase{
		{
			name: "a verifier and the default flows build over a chain that enables one of them",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{formLogin(t), httpsec.EnableAutomationChallenge(v)}
			},
			assert: built,
		},
		{
			name: "the verifier may be given before the flow it stands in front of",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v), formLogin(t)}
			},
			assert: built,
		},
		{
			name: "a selection naming only enabled flows builds",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{
					formLogin(t), basic(t),
					httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(httpsec.ChallengeFlowBasicAuth)),
				}
			},
			assert: built,
		},
		{
			name: "a nil verifier is refused, naming the verifier",
			options: func(*testing.T, httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(nil)}
			},
			assert: refused("EnableAutomationChallenge", "verifier"),
		},
		{
			name: "a typed-nil verifier is refused, naming the verifier",
			options: func(*testing.T, httpsec.ChallengeVerifier) []httpsec.Option {
				var v *MockChallengeVerifier

				return []httpsec.Option{httpsec.EnableAutomationChallenge(v)}
			},
			assert: refused("EnableAutomationChallenge", "verifier"),
		},
		{
			name: "selecting no flow is refused",
			options: func(_ *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows())}
			},
			assert: refused("WithChallengeFlows"),
		},
		{
			name: "a flow the seam does not know is refused",
			options: func(_ *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows("signup"))}
			},
			assert: refused("WithChallengeFlows", "signup"),
		},
		{
			name: "a flow the chain does not enable is refused, naming the flow",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{
					formLogin(t),
					httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(httpsec.ChallengeFlowPasswordlessBegin)),
				}
			},
			assert: refused("WithChallengeFlows", string(httpsec.ChallengeFlowPasswordlessBegin)),
		},
		{
			name: "one enabled flow does not excuse another that is not, which is named",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{
					formLogin(t),
					httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(
						httpsec.ChallengeFlowFormLogin, httpsec.ChallengeFlowBasicAuth)),
				}
			},
			assert: refused("WithChallengeFlows", string(httpsec.ChallengeFlowBasicAuth)),
		},
		{
			name: "the default selection over a chain that enables none of the flows is refused",
			options: func(_ *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v)}
			},
			assert: refused("EnableAutomationChallenge", "no flow"),
		},
		{
			name: "the default selection over a chain that enables only Basic is refused, naming WithChallengeFlows",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{basic(t), httpsec.EnableAutomationChallenge(v)}
			},
			assert: refused("WithChallengeFlows", "ChallengeFlowBasicAuth"),
		},
		{
			name: "Basic named in the selection builds over a Basic-only chain",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{
					basic(t),
					httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(httpsec.ChallengeFlowBasicAuth)),
				}
			},
			assert: built,
		},
		{
			name: "enabling the seam twice is refused",
			options: func(t *testing.T, v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{formLogin(t), httpsec.EnableAutomationChallenge(v), httpsec.EnableAutomationChallenge(v)}
			},
			assert: refused("EnableAutomationChallenge", "twice"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.options(t, NewMockChallengeVerifier(gomock.NewController(t)))...)
			tc.assert(t, err)
		})
	}
}

// errVerifierDown is a verifier's own failure, worded with something no
// response or record may repeat.
var errVerifierDown = errors.New("dial tcp 203.0.113.9:443: connection refused (site-key=sk-live-123)")

func TestChallenge_Outage(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// verify is what the verifier does; cancel ends the request's context,
		// as a client hanging up does.
		verify func(cancel context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error)

		// failures is what the attempt store answers when the identifier
		// signal is read, and nil counts none.
		failures func(cancel context.CancelFunc) (int, error)
		assert   func(t *testing.T, err error, logs []slog.Record)
	}

	outage := func(t *testing.T, err error, logs []slog.Record) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrChallengeUnavailable)
		require.NotErrorIs(t, err, httpsec.ErrChallengeRequired, "an outage is not a refusal")
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
		assert.NotContains(t, err.Error(), "sk-live-123", "the verifier's own text never reaches the error")

		var errorRecords int

		for _, r := range logs {
			assert.NotContains(t, recordText(r), "sk-live-123", "nor a record")

			if r.Level == slog.LevelError {
				errorRecords++
			}
		}

		assert.Equal(t, 1, errorRecords, "the outage is recorded at ERROR")
	}

	// storeText is what an attempt store's own error says: a username and a
	// credential no record may repeat.
	const storeText = "pq: password authentication failed for user ada (password=pg-pass-123)"

	down := func(context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
		return func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
			return 0, errVerifierDown
		}
	}

	cases := []testCase{
		{
			name:     "an attempt store that cannot count is logged by type, with neither the username nor its text",
			verify:   down,
			failures: func(context.CancelFunc) (int, error) { return 0, errors.New(storeText) },
			assert: func(t *testing.T, _ error, logs []slog.Record) {
				var stored []slog.Record

				for _, r := range logs {
					r.Attrs(func(a slog.Attr) bool {
						if a.Key == "reason" && a.Value.String() == "attempt-store" {
							stored = append(stored, r)
						}

						return true
					})
				}

				require.Len(t, stored, 1, "the failed read is recorded once")
				assert.Equal(t, slog.LevelError, stored[0].Level)
				assert.NotContains(t, recordText(stored[0]), "pg-pass-123")
				assert.NotContains(t, recordText(stored[0]), "user ada")
				assert.Contains(t, recordText(stored[0]), "error_type=*errors.errorString")
			},
		},
		{
			name: "an attempt store that fails because the client left is a hang-up, nothing at ERROR",
			verify: func(context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
				return func(ctx context.Context, _ httpsec.Request, _ httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					return 0, fmt.Errorf("verify: %w", ctx.Err())
				}
			},
			failures: func(cancel context.CancelFunc) (int, error) {
				cancel()

				return 0, fmt.Errorf("count: %w", context.Canceled)
			},
			assert: func(t *testing.T, err error, logs []slog.Record) {
				require.ErrorIs(t, err, context.Canceled)

				for _, r := range logs {
					assert.Less(t, r.Level, slog.LevelError, "nothing is recorded at ERROR: %s", r.Message)
				}
			},
		},
		{
			name: "a verifier error is a dependency failure with fixed text",
			verify: func(context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
				return func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					return 0, errVerifierDown
				}
			},
			assert: func(t *testing.T, err error, logs []slog.Record) {
				outage(t, err, logs)
				require.ErrorIs(t, err, errVerifierDown, "the verifier's error stays reachable")
			},
		},
		{
			name: "a deadline of the verifier's own, with the request still live, is an outage",
			verify: func(context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
				return func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					return 0, fmt.Errorf("verify: %w", context.DeadlineExceeded)
				}
			},
			assert: outage,
		},
		{
			name: "an answer that is none of the three is an outage",
			verify: func(context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
				return func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					return httpsec.ChallengeDecision(42), nil
				}
			},
			assert: outage,
		},
		{
			name: "a client that leaves while the verifier runs fails with its context's error, nothing at ERROR",
			verify: func(cancel context.CancelFunc) func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
				return func(ctx context.Context, _ httpsec.Request, _ httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					cancel()

					return 0, fmt.Errorf("verify: %w", ctx.Err())
				}
			},
			assert: func(t *testing.T, err error, logs []slog.Record) {
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, httpsec.ErrChallengeUnavailable, "a hang-up is not an outage")
				require.NotErrorIs(t, err, httpsec.ErrChallengeRequired, "nor a refusal")

				for _, r := range logs {
					assert.Less(t, r.Level, slog.LevelError, "nothing is recorded at ERROR: %s", r.Message)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			h := newAuthHarness(t)
			h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, string, time.Time) (int, error) {
					if tc.failures == nil {
						return 0, nil
					}

					return tc.failures(cancel)
				}).AnyTimes()

			// Strict: no account is looked up (the authenticator has no
			// expectations), and nothing is charged to the source, which a
			// RecordFailure on this limiter would be.
			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(tc.verify(cancel))

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginLimiter(limiter)),
				httpsec.EnableAutomationChallenge(v),
			)
			require.NoError(t, err)

			run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
			ex := httpsec.NewExchange(ctx,
				httpsec.NewHTTPRequest(formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=wrong")),
				httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))

			tc.assert(t, run(ex), h.logs.records())
		})
	}
}

// TestChallenge_OutageAcrossFlows pins, at every flow the verifier stands in
// front of, that a verifier that fails is a dependency failure answered 500
// with the guarded work not run, and that a client who hangs up while it runs
// fails with its context's error: neither is a refusal. TestChallenge_Outage
// goes deeper at form login alone.
func TestChallenge_OutageAcrossFlows(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		flow challengeFlow

		// verify is what the verifier does, given the request's cancel
		// function and context.
		verify func(cancel context.CancelFunc, ctx context.Context) (httpsec.ChallengeDecision, error)
		assert func(t *testing.T, run challengeRun, out served)
	}

	var cases []testCase

	for _, f := range challengeFlows() {
		cases = append(cases,
			testCase{
				name: f.name + ": a verifier error is a dependency failure, and no guarded work runs",
				flow: f,
				verify: func(context.CancelFunc, context.Context) (httpsec.ChallengeDecision, error) {
					return 0, errVerifierDown
				},
				assert: func(t *testing.T, run challengeRun, out served) {
					require.ErrorIs(t, out.err, httpsec.ErrChallengeUnavailable)
					require.NotErrorIs(t, out.err, httpsec.ErrChallengeRequired, "an outage is not a refusal")
					assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
					assert.NotContains(t, out.err.Error(), "sk-live-123", "the verifier's own text never reaches the error")
					assert.False(t, run.worked(t, out), "no guarded work runs")
				},
			},
			testCase{
				name: f.name + ": a client that hangs up while the verifier runs fails with its context's error",
				flow: f,
				verify: func(cancel context.CancelFunc, ctx context.Context) (httpsec.ChallengeDecision, error) {
					cancel()

					return 0, fmt.Errorf("verify: %w", ctx.Err())
				},
				assert: func(t *testing.T, run challengeRun, out served) {
					require.ErrorIs(t, out.err, context.Canceled)
					require.NotErrorIs(t, out.err, httpsec.ErrChallengeUnavailable, "a hang-up is not an outage")
					require.NotErrorIs(t, out.err, httpsec.ErrChallengeRequired, "nor a refusal")
					assert.False(t, run.worked(t, out), "no guarded work runs")
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(vctx context.Context, _ httpsec.Request, _ httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					return tc.verify(cancel, vctx)
				})

			run := tc.flow.build(t, false, challengeFor(tc.flow.flow, v))
			tc.assert(t, run, run.sendWith(t, ctx))
		})
	}
}

// TestChallenge_MagicLinkRefusalCountsNowhere pins that a refused challenge at
// a magic-link request counts against no source limit, because the endpoint
// has none: its limiter counts failed redemptions alone. The limiter is
// strict, so a charge to it fails the test, and the refusals stay refusals
// however many arrive.
func TestChallenge_MagicLinkRefusalCountsNowhere(t *testing.T) {
	t.Parallel()

	const requests = 5

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

	v := NewMockChallengeVerifier(gomock.NewController(t))
	v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(httpsec.ChallengeRefuse, nil).Times(requests)

	h := newMagicLinkHarness(t)
	h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkLimiter(limiter))
	h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
	chain := h.chain(t)

	body := url.Values{httpsec.DefaultMagicLinkAddressParam: {magicLinkKnown}}.Encode()

	for range requests {
		out := serve(t, chain, formRequest(t.Context(), httpsec.DefaultMagicLinkRequestPath, body))
		require.ErrorIs(t, out.err, httpsec.ErrChallengeRequired)
		require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "nothing was counted, so nothing is throttled")
	}
}

// reportingLimiter is a consumer's limiter that also says whether a source has
// recent failures (ratelimit.RecentFailureReporter).
type reportingLimiter struct {
	*MockLimiter

	has func(ctx context.Context, key string) (bool, error)
}

func (l reportingLimiter) HasRecentFailures(ctx context.Context, key string) (bool, error) {
	return l.has(ctx, key)
}

// aggregateFailures are three sources, each its own /64 inside
// 2001:db8:1::/56, the default IPv6 aggregate's prefix length.
var aggregateFailures = []string{"2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1"}

func TestChallenge_Signals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// limiter replaces form login's source limiter when set; engine is
		// the chain's policy engine, nil for none; failures is what the
		// attempt store counts for the username, given the instant it counts
		// strictly after.
		limiter  func(t *testing.T) ratelimit.Limiter
		engine   func(t *testing.T) *policy.Engine
		failures func(since time.Time) (int, error)

		// before are logins sent first, each answered not needed and refused
		// as a wrong password; beforeFrom are more of them, one from each
		// address. from is the address the login under test comes from, the
		// request's default when empty, and chainOpts are added to the chain.
		before     int
		beforeFrom []string
		from       string
		chainOpts  []httpsec.Option

		assert func(t *testing.T, seen httpsec.ChallengeSignals, out served)
	}

	allowing := func(t *testing.T) *MockLimiter {
		t.Helper()

		m := NewMockLimiter(gomock.NewController(t))
		m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		m.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		return m
	}

	none := func(time.Time) (int, error) { return 0, nil }

	// failedAgo is an attempt store holding one failure, age old: counted when
	// it is strictly after the instant the caller asks from.
	failedAgo := func(age time.Duration) func(time.Time) (int, error) {
		return func(since time.Time) (int, error) {
			if time.Now().Add(-age).After(since) {
				return 1, nil
			}

			return 0, nil
		}
	}

	// lockoutWindows is an engine holding one lockout policy per window.
	lockoutWindows := func(windows ...time.Duration) func(t *testing.T) *policy.Engine {
		return func(t *testing.T) *policy.Engine {
			t.Helper()

			var policies []policy.Policy

			for _, w := range windows {
				policies = append(policies, must.Must(lockout.New(lockout.WithFailureWindow(w))))
			}

			return engineOf(t, policies...)
		}
	}

	// lockoutDefault is the window a lockout policy counts in when it is
	// given none.
	lockoutDefault := must.Must(lockout.New()).FailureWindow()

	cases := []testCase{
		{
			name:     "a clean source and identifier: nothing suspicious, and not needed lets the login through",
			failures: none,
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, out served) {
				assert.Equal(t, httpsec.ChallengeSignals{}, seen)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "the password was checked")
			},
		},
		{
			name:     "a source with a recent failure is reported, however far below its limit",
			failures: none, before: 1,
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.Equal(t, httpsec.ChallengeSignals{SourceHasFailures: true}, seen)
			},
		},
		{
			name:     "a clean source posting for a username with recent failures: the identifier is reported",
			failures: func(time.Time) (int, error) { return 3, nil },
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.Equal(t, httpsec.ChallengeSignals{IdentifierHasFailures: true}, seen)
			},
		},
		{
			name:     "an attempt store that cannot count is reported as failures",
			failures: func(time.Time) (int, error) { return 0, errors.New("db down") },
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.IdentifierHasFailures)
			},
		},
		{
			name:     "a failure older than the lockout policy's window is not reported",
			engine:   lockoutWindows(time.Hour),
			failures: failedAgo(2 * time.Hour),
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.False(t, seen.IdentifierHasFailures)
			},
		},
		{
			name:     "a failure inside the lockout policy's window is reported",
			engine:   lockoutWindows(time.Hour),
			failures: failedAgo(30 * time.Minute),
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.IdentifierHasFailures)
			},
		},
		{
			name:     "under several lockout policies the widest window is the one used",
			engine:   lockoutWindows(time.Hour, 3*time.Hour),
			failures: failedAgo(2 * time.Hour),
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.IdentifierHasFailures)
			},
		},
		{
			name:     "with no lockout policy the lockout's default window is used: a failure inside it is reported",
			failures: failedAgo(lockoutDefault - time.Minute),
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.IdentifierHasFailures)
			},
		},
		{
			name:     "with no lockout policy the lockout's default window is used: a failure outside it is not",
			failures: failedAgo(lockoutDefault + time.Minute),
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.False(t, seen.IdentifierHasFailures)
			},
		},
		{
			name: "a limiter that cannot answer is reported as failures",
			limiter: func(t *testing.T) ratelimit.Limiter {
				return reportingLimiter{MockLimiter: allowing(t), has: func(context.Context, string) (bool, error) {
					return true, errors.New("redis down")
				}}
			},
			failures: none,
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.SourceHasFailures)
			},
		},
		{
			name:     "a limiter that does not report is reported as failures",
			limiter:  func(t *testing.T) ratelimit.Limiter { return allowing(t) },
			failures: none,
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.SourceHasFailures)
			},
		},
		{
			name: "a reporting limiter's clean answer is passed on",
			limiter: func(t *testing.T) ratelimit.Limiter {
				return reportingLimiter{MockLimiter: allowing(t), has: func(context.Context, string) (bool, error) {
					return false, nil
				}}
			},
			failures: none,
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.False(t, seen.SourceHasFailures)
			},
		},
		{
			name:       "a fresh /64 in a /56 others failed from: the source is clean, its aggregate is not",
			failures:   none,
			beforeFrom: aggregateFailures,
			from:       "2001:db8:1:ff::1",
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.Equal(t, httpsec.ChallengeSignals{SourceAggregateHasFailures: true}, seen)
			},
		},
		{
			name:       "with no aggregate configured, a fresh /64 in a /56 others failed from reports none",
			failures:   none,
			beforeFrom: aggregateFailures,
			from:       "2001:db8:1:ff::1",
			chainOpts:  []httpsec.Option{httpsec.WithoutIPv6Aggregate()},
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.Equal(t, httpsec.ChallengeSignals{}, seen)
			},
		},
		{
			name:       "an IPv4-mapped source reports no aggregate, whatever the IPv6 aggregates hold",
			failures:   none,
			beforeFrom: aggregateFailures,
			from:       "::ffff:203.0.113.7",
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.Equal(t, httpsec.ChallengeSignals{}, seen)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logins := tc.before + len(tc.beforeFrom) + 1

			h := newAuthHarness(t)
			h.attempts.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, since time.Time) (int, error) {
					return tc.failures(since)
				}).AnyTimes()
			h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(nil).Times(logins)
			h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
				Return(nil, authenticate.ErrAuthenticationFailed).Times(logins)

			var seen httpsec.ChallengeSignals

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(logins).
				DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					seen = s

					return httpsec.ChallengeNotNeeded, nil
				})

			var loginOpts []httpsec.LoginOption
			if tc.limiter != nil {
				loginOpts = append(loginOpts, httpsec.WithLoginLimiter(tc.limiter(t)))
			}

			opts := []httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), loginOpts...),
				httpsec.EnableAutomationChallenge(v),
			}
			if tc.engine != nil {
				opts = append(opts, httpsec.WithPolicyEngine(tc.engine(t)))
			}

			chain, err := httpsec.New(append(opts, tc.chainOpts...)...)
			require.NoError(t, err)

			login := func() served {
				return serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=wrong"))
			}

			for range tc.before {
				login()
			}

			for _, addr := range tc.beforeFrom {
				out := formLoginFrom(t, chain, addr, "ada", "wrong")
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "no failure before is refused")
			}

			if tc.from != "" {
				tc.assert(t, seen, formLoginFrom(t, chain, tc.from, "ada", "wrong"))

				return
			}

			tc.assert(t, seen, login())
		})
	}
}

// TestChallenge_SignalsPerFlow pins what each of the other flows reports: the
// source's recorded failures from the flow's own guard, and an identifier only
// where the flow reads one before its lookup.
func TestChallenge_SignalsPerFlow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, v httpsec.ChallengeVerifier) served
		assert func(t *testing.T, seen []httpsec.ChallengeSignals)
	}

	cases := []testCase{
		{
			name: "recovery start reports no identifier, whatever login failures the username has",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				h := newRecoveryHarness(t)
				require.NoError(t, h.attempts.RecordFailure(t.Context(), e2eAddress, time.Now()))
				h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
				h.build(t)

				body := url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}.Encode()

				return serve(t, h.chain, formRequest(t.Context(), httpsec.DefaultRecoveryStartPath, body))
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				assert.Equal(t, []httpsec.ChallengeSignals{{}}, seen)
			},
		},
		{
			name: "recovery start reads its source from the completion guard: earlier starts are no failures",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				h := newRecoveryHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
				h.build(t)

				start := func() served {
					return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
						url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
				}
				start()

				return start()
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				assert.Equal(t, []httpsec.ChallengeSignals{{}, {}}, seen)
			},
		},
		{
			name: "recovery start reports a source with a refused recovery, from the completion guard",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				h := newRecoveryHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
				h.build(t)

				refused := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, "not-a-saved-code", httpsec.RecoveryPasswordParam, "wrong"))
				require.Error(t, refused.err, "the recovery was refused")

				return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				assert.Equal(t, []httpsec.ChallengeSignals{{SourceHasFailures: true}}, seen)
			},
		},
		{
			name: "Basic reports a username with recent failures, over a clean source",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				h := newAuthHarness(t)
				h.attempts.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(3, nil)
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()),
					httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(httpsec.ChallengeFlowBasicAuth)),
				)
				require.NoError(t, err)

				return serve(t, chain, basicRequest(t.Context(), "ada", "s3cret"))
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				assert.Equal(t, []httpsec.ChallengeSignals{{IdentifierHasFailures: true}}, seen)
			},
		},
		{
			name: "a passwordless begin reads no identifier, and its source's earlier begins count",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				d := newPwlDeployment(t)
				d.extra = append(d.extra, httpsec.EnableAutomationChallenge(v))
				d.build(t)
				d.begin(t)

				return d.begin(t)
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				assert.Equal(t, []httpsec.ChallengeSignals{{}, {SourceHasFailures: true}}, seen)
			},
		},
		{
			name: "a magic-link request reads no identifier, and a clean source is clean",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				h := newMagicLinkHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
				body := url.Values{httpsec.DefaultMagicLinkAddressParam: {magicLinkKnown}}.Encode()

				return serve(t, h.chain(t), formRequest(t.Context(), httpsec.DefaultMagicLinkRequestPath, body))
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				assert.Equal(t, []httpsec.ChallengeSignals{{}}, seen)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen []httpsec.ChallengeSignals

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					seen = append(seen, s)

					return httpsec.ChallengeNotNeeded, nil
				})

			out := tc.run(t, v)
			require.NoError(t, out.err)
			tc.assert(t, seen)
		})
	}
}

// TestChallenge_AsksBeforeThePreAuthenticationPhase pins that the verifier is
// asked before anything about the account is read: a locked account the
// verifier refuses spends no decoy verification, since the encoder is strict
// and the lock never reached, and no source charge beyond the refusal's own,
// which the opt-out removes, so a charge here would be the lock's.
func TestChallenge_AsksBeforeThePreAuthenticationPhase(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		send func(t *testing.T, c *httpsec.Chain) served
	}

	cases := []testCase{
		{
			name: "form login",
			send: func(t *testing.T, c *httpsec.Chain) served {
				return formLoginFrom(t, c, loginGuardSource, "ada", lockedGuess)
			},
		},
		{
			name: "Basic",
			send: func(t *testing.T, c *httpsec.Chain) served {
				return basicFrom(t, c, loginGuardSource, "ada", lockedGuess)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A decoy verification is a Match on this strict encoder, which
			// has no expectation.
			h := newLockResponseHarness(t, true)
			ctrl := gomock.NewController(t)

			sessions, err := session.New(session.WithStore(NewMockStore(ctrl)))
			require.NoError(t, err)

			attempts := must.Must(lockout.NewMemoryAttemptStore())

			// Strict: a source charge, a RecordFailure, fails the case.
			limiter := NewMockLimiter(ctrl)
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

			v := NewMockChallengeVerifier(ctrl)
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(httpsec.ChallengeRefuse, nil).Times(1)

			chain, err := httpsec.New(
				httpsec.WithLogger(slog.New(h.logs)),
				httpsec.WithPolicyEngine(lockingAda(t)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: sessions, Tokens: newMockGenerator(ctrl), Attempts: attempts,
				}, httpsec.WithLoginLimiter(limiter)),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: attempts},
					httpsec.WithBasicAuthLimiter(limiter)),
				httpsec.EnableAutomationChallenge(v, httpsec.WithoutChallengeRefusalCounting(),
					httpsec.WithChallengeFlows(httpsec.ChallengeFlowFormLogin, httpsec.ChallengeFlowBasicAuth)),
			)
			require.NoError(t, err)

			out := tc.send(t, chain)

			require.ErrorIs(t, out.err, httpsec.ErrChallengeRequired)
			assert.NotErrorIs(t, out.err, lockout.ErrAccountLocked, "the lock was never reached")
		})
	}
}

// TestChallenge_NoEnumeration pins that the identifier signal cannot tell a
// known username from an unknown one on a flow that answers alike for both.
// An owner's sign-in clears a known account's failures and no sign-in clears
// an unknown name's, so a verifier that challenged on the signal at recovery
// start would answer whether an account exists. Form login keeps the signal,
// and the row for it pins the residual: the same reset already lifts a known
// account's lockout and not an unknown one's.
func TestChallenge_NoEnumeration(t *testing.T) {
	t.Parallel()

	const unknown = "nobody"

	type testCase struct {
		name string

		// probe sends one request of the flow under test for username. Both
		// probes come from the same source, so the source signal is equal by
		// construction and only the identifier signal can differ.
		probe func(t *testing.T, h *recoveryHarness, username string)

		assert func(t *testing.T, known, unknown httpsec.ChallengeSignals)
	}

	cases := []testCase{
		{
			name: "recovery start gives the verifier identical signals for a known and an unknown username",
			probe: func(t *testing.T, h *recoveryHarness, username string) {
				serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {username}}))
			},
			assert: func(t *testing.T, known, unknown httpsec.ChallengeSignals) {
				assert.Equal(t, known, unknown)
				assert.False(t, known.IdentifierHasFailures)
			},
		},
		{
			name: "form login keeps the signal: a known account's failures were cleared by its owner, an unknown name's were not",
			probe: func(t *testing.T, h *recoveryHarness, username string) {
				serve(t, h.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
					httpsec.DefaultLoginUsernameParam: {username},
					httpsec.DefaultLoginPasswordParam: {"wrong"},
				}))
			},
			assert: func(t *testing.T, known, unknown httpsec.ChallengeSignals) {
				assert.False(t, known.IdentifierHasFailures)
				assert.True(t, unknown.IdentifierHasFailures)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				asking bool
				seen   httpsec.ChallengeSignals
			)

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					if asking {
						seen = s
					}

					return httpsec.ChallengeNotNeeded, nil
				})

			h := newRecoveryHarness(t)
			h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
			h.build(t)

			wrong := func(username string) {
				serve(t, h.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
					httpsec.DefaultLoginUsernameParam: {username},
					httpsec.DefaultLoginPasswordParam: {"wrong"},
				}))
			}

			// One failed login each for a known and an unknown username, then
			// the known account's owner signs in.
			wrong(e2eAddress)
			wrong(unknown)
			require.NoError(t, h.passwordLogin(t).err, "the owner signs in")

			asking = true

			tc.probe(t, h, e2eAddress)

			known := seen

			tc.probe(t, h, unknown)

			tc.assert(t, known, seen)
		})
	}
}

func TestChallenge_CountsAgainstSource(t *testing.T) {
	t.Parallel()

	const limit = 2

	type testCase struct {
		name string

		// build wires the flow over limiter, its source limit, with the
		// challenge options, and returns one request of it.
		build func(t *testing.T, limiter ratelimit.Limiter, v httpsec.ChallengeVerifier,
			opts ...httpsec.ChallengeOption) func() served
		opts  []httpsec.ChallengeOption
		asked int

		assert func(t *testing.T, last served)
	}

	// login's attempt store is strict: a refusal is never charged to the
	// username's lockout, and the authenticator is never reached.
	login := func(t *testing.T, limiter ratelimit.Limiter, v httpsec.ChallengeVerifier,
		opts ...httpsec.ChallengeOption,
	) func() served {
		t.Helper()

		h := newAuthHarness(t)
		h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

		chain, err := httpsec.New(
			httpsec.WithLogger(h.logger()),
			httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginLimiter(limiter)),
			httpsec.EnableAutomationChallenge(v, opts...),
		)
		require.NoError(t, err)

		return func() served {
			return serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=wrong"))
		}
	}

	// basic's attempt store is as strict as login's.
	basic := func(t *testing.T, limiter ratelimit.Limiter, v httpsec.ChallengeVerifier,
		opts ...httpsec.ChallengeOption,
	) func() served {
		t.Helper()

		h := newAuthHarness(t)
		h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

		chain, err := httpsec.New(
			httpsec.WithLogger(h.logger()),
			httpsec.EnableBasicAuth(h.basicAuthDeps(), httpsec.WithBasicAuthLimiter(limiter)),
			httpsec.EnableAutomationChallenge(v,
				append([]httpsec.ChallengeOption{httpsec.WithChallengeFlows(httpsec.ChallengeFlowBasicAuth)}, opts...)...),
		)
		require.NoError(t, err)

		return func() served { return serve(t, chain, basicRequest(t.Context(), "ada", "wrong")) }
	}

	passwordless := func(t *testing.T, limiter ratelimit.Limiter, v httpsec.ChallengeVerifier,
		opts ...httpsec.ChallengeOption,
	) func() served {
		t.Helper()

		d := newPwlDeployment(t)
		d.settings = append(d.settings, httpsec.PasswordlessLimiter(limiter))
		d.extra = append(d.extra, httpsec.EnableAutomationChallenge(v, opts...))
		d.build(t)

		return func() served { return d.begin(t) }
	}

	start := func(t *testing.T, limiter ratelimit.Limiter, v httpsec.ChallengeVerifier,
		opts ...httpsec.ChallengeOption,
	) func() served {
		t.Helper()

		h := newRecoveryHarness(t)
		h.recOpts = append(h.recOpts, httpsec.WithRecoveryStartLimiter(limiter))
		h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v, opts...))
		h.build(t)

		return func() served {
			body := url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}.Encode()

			return serve(t, h.chain, formRequest(t.Context(), httpsec.DefaultRecoveryStartPath, body))
		}
	}

	cases := []testCase{
		{
			name:  "form login: refusals spend the source limit, and the next login is throttled before the verifier",
			build: login, asked: limit,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, ratelimit.ErrThrottled)
				require.NotErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
		{
			name:  "form login: opted out, refusals spend nothing and the next login still reaches the verifier",
			build: login, opts: []httpsec.ChallengeOption{httpsec.WithoutChallengeRefusalCounting()}, asked: limit + 1,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
		{
			name:  "basic: refusals spend the source limit, and the next request is throttled before the verifier",
			build: basic, asked: limit,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, ratelimit.ErrThrottled)
				require.NotErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
		{
			name:  "basic: opted out, refusals spend nothing and the next request still reaches the verifier",
			build: basic, opts: []httpsec.ChallengeOption{httpsec.WithoutChallengeRefusalCounting()}, asked: limit + 1,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
		{
			name:  "passwordless begin: refusals spend the source limit, and the next begin is throttled before the verifier",
			build: passwordless, asked: limit,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, ratelimit.ErrThrottled)
				require.NotErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
		{
			name:  "passwordless begin: opted out, refusals spend nothing and the next begin still reaches the verifier",
			build: passwordless, opts: []httpsec.ChallengeOption{httpsec.WithoutChallengeRefusalCounting()}, asked: limit + 1,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
		{
			name:  "recovery start: refusals spend the start limit, and the next start is throttled before the verifier",
			build: start, asked: limit,
			assert: func(t *testing.T, last served) {
				require.NoError(t, last.err, "a throttled start answers the uniform 202")
				assert.Equal(t, http.StatusAccepted, last.rec.Code)
			},
		},
		{
			name:  "recovery start: opted out, the next start still reaches the verifier",
			build: start, opts: []httpsec.ChallengeOption{httpsec.WithoutChallengeRefusalCounting()}, asked: limit + 1,
			assert: func(t *testing.T, last served) {
				require.ErrorIs(t, last.err, httpsec.ErrChallengeRequired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limiter, err := ratelimit.NewMemoryLimiter(limit, time.Hour,
				ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(httpsec.ChallengeRefuse, nil).Times(tc.asked)

			send := tc.build(t, limiter, v, tc.opts...)

			for range limit {
				require.ErrorIs(t, send().err, httpsec.ErrChallengeRequired)
			}

			tc.assert(t, send())
		})
	}
}

// TestEnableAutomationChallenge_BasicRequestFromCleanSourceConsultsNothing
// pins that, under the default selection, a run of successful Basic requests
// from a clean source does not consult the verifier, so it reads neither the
// attempt store's failure count nor the limiter's recent failures on the way
// to the password check. Form login is enabled beside Basic so the default
// selection builds.
func TestEnableAutomationChallenge_BasicRequestFromCleanSourceConsultsNothing(t *testing.T) {
	t.Parallel()

	const requests = 5

	var verifierCalls, failureCountCalls, recentFailuresCalls atomic.Int32

	h := newAuthHarness(t)
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		Return(&authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}, nil).AnyTimes()
	h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).AnyTimes()
	h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string, time.Time) (int, error) {
			failureCountCalls.Add(1)

			return 0, nil
		}).AnyTimes()

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	reporting := reportingLimiter{
		MockLimiter: limiter,
		has: func(context.Context, string) (bool, error) {
			recentFailuresCalls.Add(1)

			return false, nil
		},
	}

	v := NewMockChallengeVerifier(gomock.NewController(t))
	v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
			verifierCalls.Add(1)

			return httpsec.ChallengeNotNeeded, nil
		}).AnyTimes()

	chain, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBasicAuth(h.basicAuthDeps(), httpsec.WithBasicAuthLimiter(reporting)),
		httpsec.EnableAutomationChallenge(v),
	}, alsoFormLogin(t)...)...)
	require.NoError(t, err)

	for i := range requests {
		out := serve(t, chain, basicRequest(t.Context(), "ada", "s3cret"))
		require.NoError(t, out.err, "request %d", i)
		require.True(t, out.handlerRan, "request %d was not let through", i)
	}

	assert.Zero(t, verifierCalls.Load(), "the verifier was consulted on clean Basic requests")
	assert.Zero(t, failureCountCalls.Load(), "the attempt store's FailureCount was read on clean Basic requests")
	assert.Zero(t, recentFailuresCalls.Load(), "the limiter's HasRecentFailures was read on clean Basic requests")
}

// TestEnableAutomationChallenge_BasicNamedAsksOncePerRequest pins that Basic is
// challenged when WithChallengeFlows names it: the verifier is asked once per
// request, before the password check.
func TestEnableAutomationChallenge_BasicNamedAsksOncePerRequest(t *testing.T) {
	t.Parallel()

	const requests = 3

	h := newAuthHarness(t)
	h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
	h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).AnyTimes()

	var asked, authenticated atomic.Int32

	v := NewMockChallengeVerifier(gomock.NewController(t))
	v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
			asked.Add(1)

			return httpsec.ChallengeNotNeeded, nil
		}).Times(requests)
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			n := authenticated.Add(1)
			assert.Equal(t, n, asked.Load(), "the verifier was not asked before the password check")

			return &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}, nil
		}).Times(requests)

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBasicAuth(h.basicAuthDeps()),
		httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows(httpsec.ChallengeFlowBasicAuth)),
	)
	require.NoError(t, err)

	for i := range requests {
		out := serve(t, chain, basicRequest(t.Context(), "ada", "s3cret"))
		require.NoError(t, out.err, "request %d", i)
		require.True(t, out.handlerRan, "request %d was not let through", i)
	}
}
