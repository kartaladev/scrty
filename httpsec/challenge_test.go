package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/token/onetime"
)

// challengeFlow is one of the five flows the verifier can stand in front of,
// built over a chain carrying extra, with doubles strict enough that a step the
// case did not expect fails the test.
type challengeFlow struct {
	name string
	flow httpsec.ChallengeFlow

	// build wires the flow's chain. work says whether the case expects the
	// flow's guarded work, its account lookup among it, to run: the doubles
	// that do that work are told to expect exactly one call, or none.
	build func(t *testing.T, work bool, extra ...httpsec.Option) challengeRun
}

// challengeRun is a built flow: send posts one request of it, and worked
// reports, from what was served, whether its guarded work ran.
type challengeRun struct {
	send   func(t *testing.T) served
	worked func(t *testing.T, out served) bool
}

// challengeFlows is every flow the seam covers.
func challengeFlows() []challengeFlow {
	return []challengeFlow{
		{name: "form login", flow: httpsec.ChallengeFlowFormLogin, build: formLoginChallengeRun},
		{name: "basic", flow: httpsec.ChallengeFlowBasicAuth, build: basicChallengeRun},
		{name: "magic-link request", flow: httpsec.ChallengeFlowMagicLinkRequest, build: magicLinkChallengeRun},
		{name: "passwordless begin", flow: httpsec.ChallengeFlowPasswordlessBegin, build: passwordlessChallengeRun},
		{name: "recovery start", flow: httpsec.ChallengeFlowRecoveryStart, build: recoveryStartChallengeRun},
	}
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
		send: func(t *testing.T) served {
			return serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=wrong"))
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
		send: func(t *testing.T) served {
			return serve(t, chain, basicRequest(t.Context(), "ada", "wrong"))
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
		send: func(t *testing.T) served {
			body := url.Values{httpsec.DefaultMagicLinkAddressParam: {magicLinkKnown}}.Encode()

			return serve(t, chain, formRequest(t.Context(), httpsec.DefaultMagicLinkRequestPath, body))
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
		send: func(t *testing.T) served { return d.begin(t) },
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
		send: func(t *testing.T) served {
			body := url.Values{httpsec.RecoveryUsernameParam: {"nobody"}}.Encode()

			return serve(t, h.chain, formRequest(t.Context(), httpsec.DefaultRecoveryStartPath, body))
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
		options  func(v httpsec.ChallengeVerifier) []httpsec.Option
		decision httpsec.ChallengeDecision
		work     bool

		assert func(t *testing.T, run challengeRun, out served)
	}

	enabled := func(opts ...httpsec.ChallengeOption) func(v httpsec.ChallengeVerifier) []httpsec.Option {
		return func(v httpsec.ChallengeVerifier) []httpsec.Option {
			return []httpsec.Option{httpsec.EnableAutomationChallenge(v, opts...)}
		}
	}

	proceeded := func(t *testing.T, run challengeRun, out served) {
		t.Helper()

		assert.NotErrorIs(t, out.err, httpsec.ErrChallengeRequired)
		assert.True(t, run.worked(t, out), "the flow's work runs")
	}

	var cases []testCase

	for _, f := range challengeFlows() {
		other := httpsec.ChallengeFlowMagicLinkRequest
		if f.flow == other {
			other = httpsec.ChallengeFlowFormLogin
		}

		cases = append(cases,
			testCase{
				name: f.name + ": not configured, no verifier is asked and the flow runs",
				flow: f, work: true, assert: proceeded,
			},
			testCase{
				name: f.name + ": a refusal is the challenge-required error, before any account lookup",
				flow: f, options: enabled(), decision: httpsec.ChallengeRefuse,
				assert: func(t *testing.T, run challengeRun, out served) {
					require.ErrorIs(t, out.err, httpsec.ErrChallengeRequired)
					assert.False(t, run.worked(t, out), "no guarded work runs")
				},
			},
			testCase{
				name: f.name + ": a pass lets the flow run",
				flow: f, options: enabled(), decision: httpsec.ChallengePass, work: true, assert: proceeded,
			},
			testCase{
				name: f.name + ": not needed lets the flow run",
				flow: f, options: enabled(), decision: httpsec.ChallengeNotNeeded, work: true, assert: proceeded,
			},
			testCase{
				name:    f.name + ": selected explicitly, the verifier is asked",
				flow:    f,
				options: enabled(httpsec.WithChallengeFlows(other, f.flow)), decision: httpsec.ChallengeRefuse,
				assert: func(t *testing.T, _ challengeRun, out served) {
					require.ErrorIs(t, out.err, httpsec.ErrChallengeRequired)
				},
			},
			testCase{
				name: f.name + ": not selected, the verifier is not asked",
				flow: f, options: enabled(httpsec.WithChallengeFlows(other)), work: true, assert: proceeded,
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
				extra = tc.options(v)
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
		options func(v httpsec.ChallengeVerifier) []httpsec.Option
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

	cases := []testCase{
		{
			name: "a verifier and the default flows build",
			options: func(v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v)}
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a nil verifier is refused, naming the verifier",
			options: func(httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(nil)}
			},
			assert: refused("EnableAutomationChallenge", "verifier"),
		},
		{
			name: "a typed-nil verifier is refused, naming the verifier",
			options: func(httpsec.ChallengeVerifier) []httpsec.Option {
				var v *MockChallengeVerifier

				return []httpsec.Option{httpsec.EnableAutomationChallenge(v)}
			},
			assert: refused("EnableAutomationChallenge", "verifier"),
		},
		{
			name: "selecting no flow is refused",
			options: func(v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows())}
			},
			assert: refused("WithChallengeFlows"),
		},
		{
			name: "a flow the seam does not know is refused",
			options: func(v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v, httpsec.WithChallengeFlows("signup"))}
			},
			assert: refused("WithChallengeFlows", "signup"),
		},
		{
			name: "enabling the seam twice is refused",
			options: func(v httpsec.ChallengeVerifier) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableAutomationChallenge(v), httpsec.EnableAutomationChallenge(v)}
			},
			assert: refused("EnableAutomationChallenge", "twice"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.options(NewMockChallengeVerifier(gomock.NewController(t)))...)
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
		assert func(t *testing.T, err error, logs []slog.Record)
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

	cases := []testCase{
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

			h := newAuthHarness(t)
			h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

			// Strict: no account is looked up (the authenticator has no
			// expectations), and nothing is charged to the source, which a
			// RecordFailure on this limiter would be.
			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

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

// reportingLimiter is a consumer's limiter that also says whether a source has
// recent failures (ratelimit.RecentFailureReporter).
type reportingLimiter struct {
	*MockLimiter

	has func(ctx context.Context, key string) (bool, error)
}

func (l reportingLimiter) HasRecentFailures(ctx context.Context, key string) (bool, error) {
	return l.has(ctx, key)
}

func TestChallenge_Signals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// limiter replaces form login's source limiter when set; failures is
		// what the attempt store counts for the username.
		limiter  func(t *testing.T) ratelimit.Limiter
		failures func() (int, error)

		// before are logins sent first, each answered not needed and refused
		// as a wrong password.
		before int

		assert func(t *testing.T, seen httpsec.ChallengeSignals, out served)
	}

	allowing := func(t *testing.T) *MockLimiter {
		t.Helper()

		m := NewMockLimiter(gomock.NewController(t))
		m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
		m.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		return m
	}

	none := func() (int, error) { return 0, nil }

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
			failures: func() (int, error) { return 3, nil },
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.Equal(t, httpsec.ChallengeSignals{IdentifierHasFailures: true}, seen)
			},
		},
		{
			name:     "an attempt store that cannot count is reported as failures",
			failures: func() (int, error) { return 0, errors.New("db down") },
			assert: func(t *testing.T, seen httpsec.ChallengeSignals, _ served) {
				assert.True(t, seen.IdentifierHasFailures)
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			h.attempts.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).
				DoAndReturn(func(context.Context, string, time.Time) (int, error) { return tc.failures() }).AnyTimes()
			h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(nil).Times(tc.before + 1)
			h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
				Return(nil, authenticate.ErrAuthenticationFailed).Times(tc.before + 1)

			var seen httpsec.ChallengeSignals

			v := NewMockChallengeVerifier(gomock.NewController(t))
			v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(tc.before + 1).
				DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					seen = s

					return httpsec.ChallengeNotNeeded, nil
				})

			var loginOpts []httpsec.LoginOption
			if tc.limiter != nil {
				loginOpts = append(loginOpts, httpsec.WithLoginLimiter(tc.limiter(t)))
			}

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), loginOpts...),
				httpsec.EnableAutomationChallenge(v),
			)
			require.NoError(t, err)

			login := func() served {
				return serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=wrong"))
			}

			for range tc.before {
				login()
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
			name: "recovery start reports a username with recent login failures",
			run: func(t *testing.T, v httpsec.ChallengeVerifier) served {
				h := newRecoveryHarness(t)
				require.NoError(t, h.attempts.RecordFailure(t.Context(), e2eAddress, time.Now()))
				h.chainOpts = append(h.chainOpts, httpsec.EnableAutomationChallenge(v))
				h.build(t)

				body := url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}.Encode()

				return serve(t, h.chain, formRequest(t.Context(), httpsec.DefaultRecoveryStartPath, body))
			},
			assert: func(t *testing.T, seen []httpsec.ChallengeSignals) {
				require.Len(t, seen, 1)
				assert.Equal(t, httpsec.ChallengeSignals{IdentifierHasFailures: true}, seen[0])
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
