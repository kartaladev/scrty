package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// throttledRecord is what the record of a throttled sign-in says.
const throttledRecord = "a sign-in is throttled"

// deniedPerRequest is a chain whose per-request phase denies with reason, so the refusal comes once
// the bearer has published its sign-in.
func deniedPerRequest(t *testing.T, reason error) func(*streamRig) []httpsec.Option {
	t.Helper()

	engine := engineOf(t, phasePolicy(t, policy.Decision{Outcome: policy.Deny, Reason: reason}, policy.PerRequest))

	return func(*streamRig) []httpsec.Option { return []httpsec.Option{httpsec.WithPolicyEngine(engine)} }
}

// policyDeciding is a policy of one phase that answers with decide.
func policyDeciding(t *testing.T, phase policy.Phase, decide func(*policy.Input) policy.Decision) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: decides by its input").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{phase}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, in *policy.Input) policy.Decision { return decide(in) }).AnyTimes()

	return p
}

// refusedOnThePath is a consumer's interceptor at the given slot, refusing the stream's path with err.
func refusedOnThePath(err error, at httpsec.Order) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Request.Path() != httpsec.DefaultSessionSignalsPath {
			return next(ex)
		}

		return err
	}), at)
}

// TestSessionSignals_Caps_Throttled is a throttle reaching a sign-in that has been published: a retry
// would succeed, and any other answer stops a browser for good. Nothing failed, so it counts as its own
// thing.
func TestSessionSignals_Caps_Throttled(t *testing.T) {
	t.Parallel()

	throttled := deniedPerRequest(t, ratelimit.ErrThrottled)

	withRetryable := func(fn func(error) bool) streamSetup {
		return streamSetup{opts: throttled, signals: httpsec.SessionSignals{RetryableError: fn}}
	}

	// aThrottleAnswered asserts the stream was told to come back, and how that was counted.
	aThrottleAnswered := func(t *testing.T, r *streamRig, stream *riggedStream, count uint64) {
		t.Helper()

		requireOnlyRetry(t, stream, busyLeast, busyMost)
		assert.Empty(t, stream.w.header.Get("Connection"), "no replica is going away")
		assert.Empty(t, stream.w.header.Get("WWW-Authenticate"), "a retry asks for no credential")

		stats := r.chain.SessionSignalStats()
		assert.Equal(t, count, r.chain.SessionSignalStats().Throttled)
		assert.Zero(t, stats.ReloadFailures, "no dependency failed")
		assert.Zero(t, stats.RefusedByCap, "no cap was reached")
		assert.Zero(t, stats.Open, "a throttled request holds no place")
	}

	var (
		hungUp        atomic.Pointer[context.CancelFunc]
		matched       atomic.Bool
		consumerAsked atomic.Int64
	)

	cases := []streamCase{
		{
			name:  "a policy's throttle is told to retry, on its own record and count",
			setup: streamSetup{opts: throttled},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				aThrottleAnswered(t, r, r.open(t, s.ID), 1)

				record := streamLogRecord(t, r.logs.String(), throttledRecord)
				assert.Equal(t, "WARN", record["level"])
				assert.NotEmpty(t, record["flow"])
				assert.NotContains(t, r.logs.String(), s.ID, "a log holds a session identifier")
				assert.NotContains(t, r.logs.String(), "a dependency failed")
				assert.NotContains(t, r.logs.String(), "a cap is reached")
			},
		},
		{
			name:  "the record is sampled, and every refusal is counted",
			setup: streamSetup{opts: throttled},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				for range 8 {
					requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
				}

				assert.Equal(t, 1, strings.Count(r.logs.String(), throttledRecord), "the record is not sampled")
				assert.EqualValues(t, 8, r.chain.SessionSignalStats().Throttled)
			},
		},
		{
			name:  "a throttle a policy wrapped is the same throttle",
			setup: streamSetup{opts: deniedPerRequest(t, fmt.Errorf("consumer: %w", ratelimit.ErrThrottled))},
			assert: func(t *testing.T, r *streamRig) {
				aThrottleAnswered(t, r, r.open(t, r.signIn(t).ID), 1)
			},
		},
		{
			name: "a consumer wrapping the throttle on its way out keeps it a throttle, and can still match it",
			setup: streamSetup{opts: func(r *streamRig) []httpsec.Option {
				return append(throttled(r), httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						err := next(ex)
						matched.Store(errors.Is(err, ratelimit.ErrThrottled))

						return fmt.Errorf("consumer: %w", err)
					}), httpsec.After(httpsec.OrderCSRF)))
			}},
			assert: func(t *testing.T, r *streamRig) {
				aThrottleAnswered(t, r, r.open(t, r.signIn(t).ID), 1)
				assert.True(t, matched.Load(), "a consumer's errors.Is no longer finds the throttle")
			},
		},
		{
			name: "a consumer's own interceptor throttling beside a published sign-in answers what the chain's mapping answers",
			setup: streamSetup{
				signals: httpsec.SessionSignals{RetryableError: func(error) bool {
					consumerAsked.Add(1)

					return true
				}},
				opts: func(*streamRig) []httpsec.Option {
					return []httpsec.Option{refusedOnThePath(ratelimit.ErrThrottled, httpsec.After(httpsec.OrderBearerToken))}
				},
			},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				assert.Equal(t, http.StatusUnauthorized, stream.status())
				assert.Empty(t, stream.frames())
				assert.Zero(t, consumerAsked.Load(), "RetryableError was asked about the consumer's own answer")
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
				assert.NotContains(t, r.logs.String(), throttledRecord)
			},
		},
		{
			name: "before a sign-in is published a throttle stays 401",
			setup: streamSetup{opts: func(*streamRig) []httpsec.Option {
				return []httpsec.Option{refusedOnThePath(ratelimit.ErrThrottled, httpsec.Before(httpsec.OrderBearerToken))}
			}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				assert.Equal(t, http.StatusUnauthorized, stream.status())
				assert.Empty(t, stream.frames())
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
			},
		},
		{
			name:  "RetryableError returning true is told it, and the throttle is retried",
			setup: withRetryable(func(err error) bool { return errors.Is(err, ratelimit.ErrThrottled) }),
			assert: func(t *testing.T, r *streamRig) {
				aThrottleAnswered(t, r, r.open(t, r.signIn(t).ID), 1)
			},
		},
		{
			name:  "RetryableError returning false sends it through the chain's mapping, and counts nothing",
			setup: withRetryable(func(error) bool { return false }),
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				assert.Equal(t, http.StatusUnauthorized, stream.status())
				assert.Empty(t, stream.frames())
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
				assert.NotContains(t, r.logs.String(), throttledRecord)
			},
		},
		{
			name:  "a RetryableError that panics is logged without its value, and the throttle retried",
			setup: withRetryable(func(error) bool { panic(errors.New(streamSecret)) }),
			assert: func(t *testing.T, r *streamRig) {
				aThrottleAnswered(t, r, r.open(t, r.signIn(t).ID), 1)
				assert.NotContains(t, r.logs.String(), streamSecret)
			},
		},
		{
			name: "a client that has left is not told to retry, and is not counted",
			setup: streamSetup{
				requestCtx: func(ctx context.Context) context.Context {
					ctx, cancel := context.WithCancel(ctx)
					hungUp.Store(&cancel)

					return ctx
				},
				opts: func(*streamRig) []httpsec.Option {
					return []httpsec.Option{httpsec.WithPolicyEngine(engineOf(t, policyDeciding(t, policy.PerRequest,
						func(*policy.Input) policy.Decision {
							(*hungUp.Load())()

							return policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}
						})))}
				},
			},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				assert.Equal(t, http.StatusUnauthorized, stream.status())
				assert.Empty(t, stream.frames())
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
				assert.NotContains(t, r.logs.String(), throttledRecord)
			},
		},
		{
			name:  "a closing replica answers as it does anything, and counts no throttle",
			setup: streamSetup{opts: throttled},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				require.NoError(t, r.chain.CloseSessionSignals(t.Context()))

				stream := r.open(t, s.ID)

				requireOnlyRetry(t, stream, time.Second, 15*time.Second)
				assert.Equal(t, "close", stream.w.header.Get("Connection"))
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
				assert.NotContains(t, r.logs.String(), "refused", "a closing replica is not a problem to report")
			},
		},
		{
			name: "a consumer turning the throttle into an error of its own has a dependency failure's answer",
			setup: streamSetup{opts: func(r *streamRig) []httpsec.Option {
				return append(throttled(r), httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						err := next(ex)
						if errors.Is(err, ratelimit.ErrThrottled) {
							return errors.New("consumer: throttled, come back later")
						}

						return err
					}), httpsec.After(httpsec.OrderCSRF)))
			}},
			assert: func(t *testing.T, r *streamRig) {
				requireOnlyRetry(t, r.open(t, r.signIn(t).ID), busyLeast, busyMost)

				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
			},
		},
		{
			name: "an outage that also wraps a throttle is the outage",
			setup: streamSetup{opts: deniedPerRequest(t,
				fmt.Errorf("%w: %w", httpsec.ErrChallengeUnavailable, ratelimit.ErrThrottled))},
			assert: func(t *testing.T, r *streamRig) {
				requireOnlyRetry(t, r.open(t, r.signIn(t).ID), busyLeast, busyMost)

				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
				assert.Zero(t, r.chain.SessionSignalStats().Throttled)
				assert.Equal(t, "*fmt.wrapErrors", streamLogRecord(t, r.logs.String(), "a dependency failed")["error_type"],
					"the record names the policy's error, not anything the chain put around it")
			},
		},
	}

	runStreamCases(t, cases)
}

// TestSessionSignals_Caps_PolicyDenials is what a per-request denial answers on the stream's path, each
// a reason a policy may give: only the throttle changes, so a consumer's 429 stays the 429 it chose, and
// RetryableError is not asked about it.
func TestSessionSignals_Caps_PolicyDenials(t *testing.T) {
	t.Parallel()

	final := func(status int) func(*testing.T, *streamRig, *riggedStream, *atomic.Int64) {
		return func(t *testing.T, r *streamRig, stream *riggedStream, asked *atomic.Int64) {
			t.Helper()

			assert.Equal(t, status, stream.status())
			assert.Empty(t, stream.frames())
			assert.Zero(t, asked.Load(), "RetryableError was asked about an answer")
			assert.Zero(t, r.chain.SessionSignalStats().Throttled)
			assert.Zero(t, r.chain.SessionSignalStats().ReloadFailures)
		}
	}

	retried := func(reloadFailures, throttled uint64) func(*testing.T, *streamRig, *riggedStream, *atomic.Int64) {
		return func(t *testing.T, r *streamRig, stream *riggedStream, asked *atomic.Int64) {
			t.Helper()

			requireOnlyRetry(t, stream, busyLeast, busyMost)
			assert.EqualValues(t, 1, asked.Load())
			assert.Equal(t, reloadFailures, r.chain.SessionSignalStats().ReloadFailures)
			assert.Equal(t, throttled, r.chain.SessionSignalStats().Throttled)
		}
	}

	type testCase struct {
		name   string
		reason error
		assert func(t *testing.T, r *streamRig, stream *riggedStream, asked *atomic.Int64)
	}

	cases := []testCase{
		{"a throttle", ratelimit.ErrThrottled, retried(0, 1)},
		{"too many sessions keeps its 429", policy.ErrTooManySessions, final(http.StatusTooManyRequests)},
		{"too many renewals keeps its 429", httpsec.ErrRenewalThrottled, final(http.StatusTooManyRequests)},
		{"a locked account keeps its 429", lockout.ErrAccountLocked, final(http.StatusTooManyRequests)},
		{"a held account keeps its 429", lockout.ErrAccountHeld, final(http.StatusTooManyRequests)},
		{"an idle session keeps its 401", policy.ErrSessionIdle, final(http.StatusUnauthorized)},
		{"a denial keeps its 403", policy.ErrDenied, final(http.StatusForbidden)},
		{"a denial with no reason keeps its 403", nil, final(http.StatusForbidden)},
		{"an outage of the user store keeps its 401", authenticate.ErrUnavailable, final(http.StatusUnauthorized)},
		{"a policy's failed read is a dependency failure", diag.Wrap(errors.New("down"), "policy: could not be read"), retried(1, 0)},
		{"a consumer's unknown error is a dependency failure", errors.New("consumer: no"), retried(1, 0)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var asked atomic.Int64

				r := newStreamRig(t, streamSetup{
					opts: deniedPerRequest(t, tc.reason),
					signals: httpsec.SessionSignals{RetryableError: func(error) bool {
						asked.Add(1)

						return true
					}},
				})

				tc.assert(t, r, r.open(t, r.signIn(t).ID), &asked)
			})
		})
	}
}

// cookieJudgedPerRequest is a consumer's cookie authenticator that is judged by the chain's per-request
// phase, as PublishSession's and EvaluatePerRequest's godoc tell it to be.
type cookieJudgedPerRequest struct{ consumerSessionCookie }

func (a cookieJudgedPerRequest) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	return a.consumerSessionCookie.Intercept(ex, func(ex *httpsec.Exchange) error {
		if ex.Session != nil {
			if err := ex.EvaluatePerRequest(ex.Session, ex.Authentication.Principal); err != nil {
				return err
			}
		}

		return next(ex)
	})
}

// TestSessionSignals_Caps_ThrottledCookie is a browser's own path: EventSource can send nothing but a
// cookie, and it is a consumer's authenticator that reads it.
func TestSessionSignals_Caps_ThrottledCookie(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		signals httpsec.SessionSignals
		// cors is the chain's CORS policy. Default: none, which trusts no origin.
		cors *httpsec.CORSPolicy
		// csrf turns the chain's CSRF protection on. Default: off.
		csrf bool
		// bearer presents the sign-in as a bearer credential and not as the consumer's cookie.
		bearer bool
		// observed takes the chain's log and security events. Default: neither is kept.
		observed *crossSiteObserved
		// change adjusts the request first.
		change []func(*http.Request)
		assert func(t *testing.T, f *signalsFixture, resp *http.Response)
	}

	fromAnotherSite := func(origin string) []func(*http.Request) {
		return []func(*http.Request){func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Origin", origin)
		}}
	}

	refused := func(t *testing.T, f *signalsFixture, resp *http.Response) {
		t.Helper()

		requireNoStream(t, resp, http.StatusForbidden)
		assert.Zero(t, f.chain.SessionSignalStats().Throttled, "a refused request is no throttle to report")
	}

	// send builds the row's chain, with or without the throttle, and sends the row's request to it.
	send := func(t *testing.T, tc testCase, throttled bool) (*signalsFixture, *http.Response) {
		t.Helper()

		f := newSignalsFixture(t, signalsSetup{
			withoutBearer: !tc.bearer,
			signals:       tc.signals,
			opts: func(f *signalsFixture) []httpsec.Option {
				opts := []httpsec.Option{httpsec.WithSessions(f.sessions), httpsec.WithoutCSRFProtection()}

				if tc.csrf {
					opts[1] = httpsec.EnableCSRFProtection()
				}

				if throttled {
					opts = append(opts, httpsec.WithPolicyEngine(
						engineOf(t, phasePolicy(t, policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}, policy.PerRequest))))
				}

				if tc.cors != nil {
					opts = append(opts, httpsec.EnableCORS(*tc.cors))
				}

				if tc.observed != nil {
					opts = append(opts, httpsec.WithLogger(slog.New(&tc.observed.logs)), httpsec.EnableSecurityEvents(tc.observed.events.sink))
				}

				if !tc.bearer {
					opts = append(opts, httpsec.RegisterInterceptor(cookieJudgedPerRequest{consumerSessionCookie{sessions: f.sessions}}, httpsec.OrderBearerToken))
				}

				return opts
			},
		})

		own := f.signIn(t, "u-1").ID
		credential, change := "", append([]func(*http.Request){withSignalsCookie(own)}, tc.change...)

		if tc.bearer {
			credential, change = own, tc.change
		}

		resp, _ := f.openStream(t, credential, change...)

		return f, resp
	}

	// refusedAsUnthrottled makes tc assert that the refusal is the one the same request gets with no
	// throttle, to the last header and byte, so that a page cannot tell one from the other.
	refusedAsUnthrottled := func(tc testCase) testCase {
		tc.assert = func(t *testing.T, f *signalsFixture, resp *http.Response) {
			t.Helper()

			refused(t, f, resp)

			_, plain := send(t, tc, false) //nolint:bodyclose // the fixture closes it when the test ends
			requireNoStream(t, plain, http.StatusForbidden)

			throttledBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			plainBody, err := io.ReadAll(plain.Body)
			require.NoError(t, err)

			resp.Header.Del("Date")
			plain.Header.Del("Date")

			assert.Equal(t, plain.Header, resp.Header)
			assert.Equal(t, plainBody, throttledBody)
		}

		return tc
	}

	flood := &crossSiteObserved{}
	bearerFromWildcard := testCase{
		bearer: true,
		cors:   &httpsec.CORSPolicy{AllowedOrigins: []string{"*"}},
		change: fromAnotherSite("https://evil.example"),
	}

	cases := []testCase{
		{
			// The policy runs before the cross-site rule, so its denial's event is out by the time the rule
			// refuses. What the rule can stop, the log and the count, it stops.
			name:     "a flood of throttled streams from another site logs once and counts nothing, and each emits its denial's event",
			observed: flood,
			change:   fromAnotherSite("https://evil.example"),
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				refused(t, f, resp)

				for range 4 {
					again, _ := f.openStream(t, "", append([]func(*http.Request){withSignalsCookie(f.signIn(t, "u-1").ID)}, fromAnotherSite("https://evil.example")...)...)
					refused(t, f, again)
				}

				assert.Len(t, flood.refusalRecords(), 1)
				assert.Len(t, flood.logs.records(), 1)
				assert.Equal(t, []string{"authz_fail", "authz_fail", "authz_fail", "authz_fail", "authz_fail"}, flood.events.names())
			},
		},
		refusedAsUnthrottled(testCase{
			name:   "a throttled cookie stream from another site is refused as any other is",
			change: fromAnotherSite("https://evil.example"),
		}),
		refusedAsUnthrottled(testCase{
			name:   "a throttled cookie stream from another site, with CSRF protection on, is refused as any other is",
			csrf:   true,
			change: fromAnotherSite("https://evil.example"),
		}),
		refusedAsUnthrottled(testCase{
			name:   "a throttled cookie stream from an origin the CORS policy does not name is refused as any other is",
			cors:   &httpsec.CORSPolicy{AllowedOrigins: []string{"https://app.example"}, AllowCredentials: true},
			change: fromAnotherSite("https://evil.example"),
		}),
		refusedAsUnthrottled(testCase{
			name:   "a throttled cookie stream from another site, with a CORS wildcard, is refused: a cookie needs a named origin",
			cors:   &httpsec.CORSPolicy{AllowedOrigins: []string{"*"}},
			change: fromAnotherSite("https://evil.example"),
		}),
		{
			name:   "a throttled cookie stream from an allowed origin is told to retry",
			cors:   &httpsec.CORSPolicy{AllowedOrigins: []string{"https://app.example"}, AllowCredentials: true},
			change: fromAnotherSite("https://app.example"),
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				assert.EqualValues(t, 1, f.chain.SessionSignalStats().Throttled)
			},
		},
		{
			name: "a throttled cookie stream from its own site is told to retry",
			change: []func(*http.Request){func(r *http.Request) {
				r.Header.Set("Sec-Fetch-Site", "same-origin")
			}},
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				assert.EqualValues(t, 1, f.chain.SessionSignalStats().Throttled)
			},
		},
		{
			// The throttle runs before the session bearer records its credential, so the stream is judged
			// by the stricter cookie rule, where an unthrottled one would be allowed. Recording it there, a
			// small change in session_bearer.go, would let this stream retry. The stricter answer is the
			// safe default, so this pins it, and that change is left for the maintainer to decide.
			name:   "a throttled bearer stream is judged by the cookie rule, as its credential is not yet recorded",
			bearer: bearerFromWildcard.bearer,
			cors:   bearerFromWildcard.cors,
			change: bearerFromWildcard.change,
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				refused(t, f, resp)

				_, plain := send(t, bearerFromWildcard, false) //nolint:bodyclose // the fixture closes it when the test ends
				require.Equal(t, http.StatusOK, plain.StatusCode, "with no throttle the bearer rule allows it")
				assert.Equal(t, "text/event-stream", plain.Header.Get("Content-Type"))
			},
		},
		refusedAsUnthrottled(testCase{
			name:   "a throttled bearer stream from an origin nothing trusts is refused as any other is",
			bearer: true,
			change: fromAnotherSite("https://evil.example"),
		}),
		{
			name: "the default is told to retry",
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				assert.Empty(t, resp.Header.Get("WWW-Authenticate"), "a retry asks for no credential")
				assert.EqualValues(t, 1, f.chain.SessionSignalStats().Throttled)
				assert.Zero(t, f.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name: "RetryableError is handed the policy's own reason, which a consumer may compare",
			signals: httpsec.SessionSignals{RetryableError: func(err error) bool {
				return err == ratelimit.ErrThrottled //nolint:errorlint // the point: the reason arrives as the policy gave it
			}},
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				assert.EqualValues(t, 1, f.chain.SessionSignalStats().Throttled)
			},
		},
		{
			name:    "RetryableError returning false keeps the chain's mapping",
			signals: httpsec.SessionSignals{RetryableError: func(error) bool { return false }},
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				requireNoStream(t, resp, http.StatusUnauthorized)
				assert.Zero(t, f.chain.SessionSignalStats().Throttled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, resp := send(t, tc, true) //nolint:bodyclose // the fixture closes it when the test ends

			tc.assert(t, f, resp)
		})
	}
}

// rightPasswordBasic is Basic auth whose authenticator accepts only the password "right".
func rightPasswordBasic(t *testing.T) httpsec.Option {
	t.Helper()

	authn := NewMockAuthenticator(gomock.NewController(t))
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
			if up, ok := c.(*identity.UsernamePassword); ok && string(up.Password) == "right" {
				return &authenticate.Authentication{Principal: identity.PrincipalFromDetails(storedUser())}, nil
			}

			return nil, authenticate.ErrAuthenticationFailed
		})

	attempts := NewMockAttemptStore(gomock.NewController(t))
	attempts.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts})
}

// statusOnTheStream asks for the stream with the given changes and returns its status and whether the
// body is only a retry. The stream is cut after a short wait, since a stream that is admitted does not end.
func statusOnTheStream(t *testing.T, f *signalsFixture, change ...func(*http.Request)) (status int, retried bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
	defer cancel()

	resp := f.send(ctx, t, http.MethodGet, httpsec.DefaultSessionSignalsPath, "", change...)
	body, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, strings.Contains(string(body), "retry:") && !strings.Contains(string(body), "event:")
}

// TestSessionSignals_Caps_BasicBesideAThrottledCookie is Basic outside the caller's own throttled
// cookie: the throttle is the cookie's, so Basic's right password hears a retry and a wrong one a 401,
// which is what each hears anyway as a stream and a 401 beside an unthrottled cookie. It tells nothing a
// caller could not learn without the throttle.
func TestSessionSignals_Caps_BasicBesideAThrottledCookie(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		throttled bool
		assert    func(t *testing.T, right, wrong int, rightRetried bool)
	}

	cases := []testCase{
		{
			name:      "throttled: a right password hears a retry, a wrong one a 401",
			throttled: true,
			assert: func(t *testing.T, right, wrong int, rightRetried bool) {
				assert.Equal(t, http.StatusOK, right)
				assert.True(t, rightRetried, "a retry, not a stream")
				assert.Equal(t, http.StatusUnauthorized, wrong)
			},
		},
		{
			name: "unthrottled twin: a right password hears the stream, a wrong one a 401",
			assert: func(t *testing.T, right, wrong int, rightRetried bool) {
				assert.Equal(t, http.StatusOK, right)
				assert.False(t, rightRetried)
				assert.Equal(t, http.StatusUnauthorized, wrong)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
				opts := []httpsec.Option{
					httpsec.WithoutCSRFProtection(), httpsec.WithSessions(f.sessions), rightPasswordBasic(t),
					httpsec.RegisterInterceptor(cookieJudgedPerRequest{consumerSessionCookie{sessions: f.sessions}}, httpsec.OrderBearerToken),
				}
				if tc.throttled {
					opts = append(opts, httpsec.WithPolicyEngine(engineOf(t, phasePolicy(t,
						policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}, policy.PerRequest))))
				}

				return opts
			}})

			own := withSignalsCookie(f.signIn(t, "u-1").ID)
			right, rightRetried := statusOnTheStream(t, f, own, func(r *http.Request) { r.SetBasicAuth("victim", "right") })
			wrong, _ := statusOnTheStream(t, f, own, func(r *http.Request) { r.SetBasicAuth("victim", "wrong") })

			tc.assert(t, right, wrong, rightRetried)
		})
	}
}

// TestSessionSignals_Caps_ThrottleOfAProvenCredential is a consumer that verifies a password on every
// request, publishes the session and uses a per-request policy as a guess throttle. That throttle fires
// only after the credential succeeded, so by default a right password hears a retry on the stream and a
// wrong one a 401; RetryableError returning false sends it through the chain's mapping, and both answer 401.
func TestSessionSignals_Caps_ThrottleOfAProvenCredential(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		signals httpsec.SessionSignals
		assert  func(t *testing.T, right, wrong int)
	}

	cases := []testCase{
		{
			name: "the default tells a right password from a wrong one",
			assert: func(t *testing.T, right, wrong int) {
				assert.Equal(t, http.StatusOK, right)
				assert.Equal(t, http.StatusUnauthorized, wrong)
			},
		},
		{
			name:    "RetryableError returning false answers both alike",
			signals: httpsec.SessionSignals{RetryableError: func(error) bool { return false }},
			assert: func(t *testing.T, right, wrong int) {
				assert.Equal(t, http.StatusUnauthorized, right)
				assert.Equal(t, http.StatusUnauthorized, wrong)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, signalsSetup{withoutBearer: true, signals: tc.signals, opts: func(f *signalsFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithoutCSRFProtection(), httpsec.WithSessions(f.sessions),
					httpsec.WithPolicyEngine(engineOf(t, phasePolicy(t,
						policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}, policy.PerRequest))),
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						if ex.Request.Header("X-Pass") != "right" {
							return authenticate.ErrAuthenticationFailed
						}

						s, err := f.sessions.Create(ex.Context(), "u-1", session.WithFirstFactor(factor.Password))
						if err != nil {
							return err
						}

						a := &authenticate.Authentication{Principal: identity.PrincipalFromDetails(storedUser())}
						if err := ex.PublishSession(a, s); err != nil {
							return err
						}

						if err := ex.EvaluatePerRequest(s, a.Principal); err != nil {
							return err
						}

						return next(ex)
					}), httpsec.OrderBearerToken),
				}
			}})

			header := func(v string) func(*http.Request) { return func(r *http.Request) { r.Header.Set("X-Pass", v) } }
			right, _ := statusOnTheStream(t, f, header("right"))
			wrong, _ := statusOnTheStream(t, f, header("wrong"))

			tc.assert(t, right, wrong)
		})
	}
}

// basicAnswer is what a Basic client hears on the stream's path.
type basicAnswer struct {
	status    int
	challenge string
	body      string
}

// TestSessionSignals_Caps_BasicStays is Basic on the stream's path, where a retry would be a lock oracle,
// with or without a sign-in of the caller's own beside it: over its limit or on a concealed lock, a client
// hears what any wrong password hears.
func TestSessionSignals_Caps_BasicStays(t *testing.T) {
	t.Parallel()

	lockedAtPreAuthentication := func(t *testing.T) *policy.Engine {
		t.Helper()

		return engineOf(t, phasePolicy(t,
			policy.Decision{Outcome: policy.Deny, Reason: lockout.ErrAccountLocked}, policy.PreAuthentication))
	}

	type wiring struct {
		basic  []httpsec.BasicAuthOption
		chain  []httpsec.Option
		cookie bool
	}

	answer := func(t *testing.T, w wiring) (basicAnswer, *signalsFixture) {
		t.Helper()

		authn := NewMockAuthenticator(gomock.NewController(t))
		authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, authenticate.ErrAuthenticationFailed).AnyTimes()

		attempts := NewMockAttemptStore(gomock.NewController(t))
		attempts.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		f := newSignalsFixture(t, signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
			opts := append([]httpsec.Option{
				httpsec.WithSessions(f.sessions),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}, w.basic...),
			}, w.chain...)

			if w.cookie {
				opts = append(opts, httpsec.WithoutCSRFProtection(), httpsec.RegisterInterceptor(
					consumerSessionCookie{sessions: f.sessions}, httpsec.Before(httpsec.OrderBasicAuth)))
			}

			return opts
		}})

		change := []func(*http.Request){func(r *http.Request) { r.SetBasicAuth("ada", "pw") }}
		if w.cookie {
			change = append(change, withSignalsCookie(f.signIn(t, "u-1").ID))
		}

		resp := f.send(t.Context(), t, http.MethodGet, httpsec.DefaultSessionSignalsPath, "", change...)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		return basicAnswer{resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(body)}, f
	}

	type testCase struct {
		name   string
		wiring func(t *testing.T) wiring
		assert func(t *testing.T, got, wrongPassword basicAnswer)
	}

	likeAWrongPassword := func(t *testing.T, got, wrongPassword basicAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, wrongPassword.status)
		assert.NotEmpty(t, wrongPassword.challenge)
		assert.Equal(t, wrongPassword, got)
	}

	cases := []testCase{
		{
			name: "a source over its limit",
			wiring: func(t *testing.T) wiring {
				t.Helper()

				return wiring{basic: []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(limiterThrottling(t))}}
			},
			assert: likeAWrongPassword,
		},
		{
			name: "a source over its limit beside a published sign-in",
			wiring: func(t *testing.T) wiring {
				t.Helper()

				return wiring{cookie: true, basic: []httpsec.BasicAuthOption{httpsec.WithBasicAuthLimiter(limiterThrottling(t))}}
			},
			assert: likeAWrongPassword,
		},
		{
			name: "a concealed lock",
			wiring: func(t *testing.T) wiring {
				t.Helper()

				return wiring{chain: []httpsec.Option{httpsec.WithPolicyEngine(lockedAtPreAuthentication(t))}}
			},
			assert: likeAWrongPassword,
		},
		{
			name: "a concealed lock beside a published sign-in",
			wiring: func(t *testing.T) wiring {
				t.Helper()

				return wiring{cookie: true, chain: []httpsec.Option{httpsec.WithPolicyEngine(lockedAtPreAuthentication(t))}}
			},
			assert: likeAWrongPassword,
		},
		{
			name: "a disclosed lock keeps its 429, unchallenged",
			wiring: func(t *testing.T) wiring {
				t.Helper()

				return wiring{chain: []httpsec.Option{httpsec.WithLockDisclosure(), httpsec.WithPolicyEngine(lockedAtPreAuthentication(t))}}
			},
			assert: func(t *testing.T, got, _ basicAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusTooManyRequests, got.status)
				assert.Empty(t, got.challenge)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wrongPassword, _ := answer(t, wiring{})
			got, f := answer(t, tc.wiring(t))

			tc.assert(t, got, wrongPassword)
			assert.Zero(t, f.chain.SessionSignalStats().Throttled)
		})
	}
}

// headerPassword is a consumer's authenticator that reads a username from a header of its own and
// judges it with the library's password provider. Nothing on the request says it is a credential.
type headerPassword struct{ authn authenticate.Authenticator }

func (a headerPassword) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	user := ex.Request.Header("X-Username")
	if user == "" {
		return next(ex)
	}

	_, err := a.authn.Authenticate(ex.Context(), identity.NewUsernamePassword(user, []byte("pw")))

	return err
}

// TestSessionSignals_Caps_CredentialsAnswerAlike is a user store that fails for one row, against a
// username it does not hold. An outage is 401 so that the answer tells no one which accounts exist.
func TestSessionSignals_Caps_CredentialsAnswerAlike(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    func(f *signalsFixture, authn authenticate.Authenticator, attempts *MockAttemptStore) []httpsec.Option
		present func(user string) func(*http.Request)
	}

	cases := []testCase{
		{
			name: "over Basic",
			opts: func(f *signalsFixture, authn authenticate.Authenticator, attempts *MockAttemptStore) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}),
				}
			},
			present: func(user string) func(*http.Request) {
				return func(r *http.Request) { r.SetBasicAuth(user, "pw") }
			},
		},
		{
			name: "on a consumer's own header",
			opts: func(f *signalsFixture, authn authenticate.Authenticator, _ *MockAttemptStore) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.RegisterInterceptor(headerPassword{authn: authn}, httpsec.OrderBearerToken),
				}
			},
			present: func(user string) func(*http.Request) {
				return func(r *http.Request) { r.Header.Set("X-Username", user) }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(_ context.Context, username string) (*identity.Details, error) {
					if username == "known" {
						return nil, errors.New("row cannot be decoded")
					}

					return nil, identity.ErrUserNotFound
				})
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(storedUser(), nil)

			authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(e2eEncoder(t)),
				authenticate.WithPasswordLogger(discardLogger()))
			require.NoError(t, err)

			attempts := NewMockAttemptStore(gomock.NewController(t))
			attempts.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			f := newSignalsFixture(t, signalsSetup{
				withoutBearer: true,
				opts:          func(f *signalsFixture) []httpsec.Option { return tc.opts(f, authn, attempts) },
			})

			answer := func(user string) basicAnswer {
				resp := f.send(t.Context(), t, http.MethodGet, httpsec.DefaultSessionSignalsPath, "", tc.present(user))

				return basicAnswer{status: resp.StatusCode, challenge: resp.Header.Get("WWW-Authenticate")}
			}

			known, unknown := answer("known"), answer("unknown")

			assert.Equal(t, http.StatusUnauthorized, unknown.status)
			assert.Equal(t, unknown, known, "the answer tells a known account from an unknown one")
		})
	}
}

// cookieThrottlePassedOver is a consumer's cookie authenticator that asks the chain's per-request phase
// about its sign-in, is told it is throttled, and lets the request go on to the next credential.
type cookieThrottlePassedOver struct{ consumerSessionCookie }

func (a cookieThrottlePassedOver) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	return a.consumerSessionCookie.Intercept(ex, func(ex *httpsec.Exchange) error {
		if ex.Session == nil {
			return next(ex)
		}

		if err := ex.EvaluatePerRequest(ex.Session, ex.Authentication.Principal); !errors.Is(err, ratelimit.ErrThrottled) {
			return fmt.Errorf("this row needs the per-request phase to throttle, and it answered %w", err)
		}

		return next(ex)
	})
}

// TestSessionSignals_Caps_ThrottleBesideASignIn is a caller signed in as themselves who presents another
// credential on the stream's path. Being signed in says who the caller is and nothing of the credential
// refused, so two presentations a refusal should not tell apart stay alike: any other answer is an oracle
// for an account, a password or a key, open to anyone with a sign-in of their own.
func TestSessionSignals_Caps_ThrottleBesideASignIn(t *testing.T) {
	t.Parallel()

	basic := func(user, password string) func(*http.Request) {
		return func(r *http.Request) { r.SetBasicAuth(user, password) }
	}

	header := func(name, value string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set(name, value) }
	}

	throttlingUsername := func(t *testing.T, name string) *policy.Engine {
		t.Helper()

		return engineOf(t, policyDeciding(t, policy.PreAuthentication, func(in *policy.Input) policy.Decision {
			if in.Username == name {
				return policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}
			}

			return policy.Decision{Outcome: policy.Allow}
		}))
	}

	throttlingAt := func(t *testing.T, phases ...policy.Phase) *policy.Engine {
		t.Helper()

		return engineOf(t, phasePolicy(t, policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}, phases...))
	}

	basicAuth := func(t *testing.T) httpsec.Option {
		t.Helper()

		authn := NewMockAuthenticator(gomock.NewController(t))
		authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
				if up, ok := c.(*identity.UsernamePassword); ok && string(up.Password) == "right" {
					return &authenticate.Authentication{Principal: identity.PrincipalFromDetails(storedUser())}, nil
				}

				return nil, authenticate.ErrAuthenticationFailed
			})

		attempts := NewMockAttemptStore(gomock.NewController(t))
		attempts.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		return httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts})
	}

	cookieAt := func(f *signalsFixture, at httpsec.Order) []httpsec.Option {
		return []httpsec.Option{
			httpsec.WithoutCSRFProtection(),
			httpsec.WithSessions(f.sessions),
			httpsec.RegisterInterceptor(consumerSessionCookie{sessions: f.sessions}, at),
		}
	}

	// namingAnAccount is a consumer's credential naming an account in a header of its own, throttling one
	// of them. The library cannot see that it names anything.
	namingAnAccount := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		switch ex.Request.Header("X-Username") {
		case "":
			return next(ex)
		case "throttled":
			return ratelimit.ErrThrottled
		default:
			return authenticate.ErrAuthenticationFailed
		}
	})

	apiKeys := newAPIKeyHarness(t)

	alikeAnd401 := func(t *testing.T, first, second basicAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, second.status)
		assert.Equal(t, second, first, "the two presentations can be told apart")
	}

	type testCase struct {
		name string
		// bearer signs the caller in with the session bearer, and otherwise with the consumer's cookie.
		bearer bool
		// signedOut presents no sign-in of the caller's own.
		signedOut     bool
		opts          func(t *testing.T, f *signalsFixture) []httpsec.Option
		first, second func(*http.Request)
		assert        func(t *testing.T, first, second basicAnswer)
	}

	cases := []testCase{
		{
			name: "Basic naming a throttled username, a cookie before Basic",
			opts: func(t *testing.T, f *signalsFixture) []httpsec.Option {
				t.Helper()

				return append(cookieAt(f, httpsec.Before(httpsec.OrderBasicAuth)),
					basicAuth(t), httpsec.WithPolicyEngine(throttlingUsername(t, "victim")))
			},
			first: basic("victim", "x"), second: basic("nobody", "x"),
			assert: alikeAnd401,
		},
		{
			name: "Basic with the right password under a stateless throttle, a cookie before Basic",
			opts: func(t *testing.T, f *signalsFixture) []httpsec.Option {
				t.Helper()

				return append(cookieAt(f, httpsec.Before(httpsec.OrderBasicAuth)),
					basicAuth(t), httpsec.WithPolicyEngine(throttlingAt(t, policy.StatelessAuthentication)))
			},
			first: basic("victim", "right"), second: basic("victim", "wrong"),
			assert: alikeAnd401,
		},
		{
			name: "a valid API key under a stateless throttle, a cookie before the key",
			opts: func(t *testing.T, f *signalsFixture) []httpsec.Option {
				t.Helper()

				return append(cookieAt(f, httpsec.Before(httpsec.OrderBasicAuth)),
					httpsec.EnableAPIKey(apiKeys.keys), httpsec.WithPolicyEngine(throttlingAt(t, policy.StatelessAuthentication)))
			},
			first: header("Authorization", "ApiKey "+apiKeys.valid), second: header("Authorization", "ApiKey "+unknownAPIKey),
			assert: alikeAnd401,
		},
		{
			name:   "a consumer's account-naming credential after the session bearer",
			bearer: true,
			opts: func(*testing.T, *signalsFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(namingAnAccount, httpsec.After(httpsec.OrderBearerToken))}
			},
			first: header("X-Username", "throttled"), second: header("X-Username", "other"),
			assert: alikeAnd401,
		},
		{
			name: "a per-request throttle evaluated and passed over is not what a later credential's refusal reads",
			opts: func(t *testing.T, f *signalsFixture) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithoutCSRFProtection(),
					httpsec.WithSessions(f.sessions),
					httpsec.RegisterInterceptor(cookieThrottlePassedOver{consumerSessionCookie{sessions: f.sessions}},
						httpsec.Before(httpsec.OrderBasicAuth)),
					basicAuth(t),
					httpsec.WithPolicyEngine(throttlingAt(t, policy.PerRequest, policy.StatelessAuthentication)),
				}
			},
			first: basic("victim", "right"), second: basic("victim", "wrong"),
			assert: alikeAnd401,
		},
		{
			name:      "with no sign-in at all",
			signedOut: true,
			opts: func(t *testing.T, f *signalsFixture) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithSessions(f.sessions), basicAuth(t), httpsec.WithPolicyEngine(throttlingUsername(t, "victim")),
				}
			},
			first: basic("victim", "x"), second: basic("nobody", "x"),
			assert: alikeAnd401,
		},
		{
			name: "with the cookie at its usual slot, inside Basic",
			opts: func(t *testing.T, f *signalsFixture) []httpsec.Option {
				t.Helper()

				return append(cookieAt(f, httpsec.OrderBearerToken),
					basicAuth(t), httpsec.WithPolicyEngine(throttlingUsername(t, "victim")))
			},
			first: basic("victim", "x"), second: basic("nobody", "x"),
			assert: alikeAnd401,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, signalsSetup{withoutBearer: !tc.bearer, opts: func(f *signalsFixture) []httpsec.Option {
				return tc.opts(t, f)
			}})

			own := f.signIn(t, "u-1").ID

			answer := func(presenting func(*http.Request)) basicAnswer {
				changes, credential := []func(*http.Request){presenting}, ""

				switch {
				case tc.signedOut:
				case tc.bearer:
					credential = own
				default:
					changes = append(changes, withSignalsCookie(own))
				}

				resp := f.send(t.Context(), t, http.MethodGet, httpsec.DefaultSessionSignalsPath, credential, changes...)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				return basicAnswer{resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(body)}
			}

			first, second := answer(tc.first), answer(tc.second)

			tc.assert(t, first, second)
			assert.Zero(t, f.chain.SessionSignalStats().Throttled)
		})
	}
}

// TestSessionSignals_Caps_ThrottleWhatTheChainSees is what the per-request phase's throttle is to whatever
// reads it. Away from the stream it is the policy's reason itself, the very value, so nothing else a chain
// answers changes; on the stream's path it reads as that reason, to errors.Is and in its text.
func TestSessionSignals_Caps_ThrottleWhatTheChainSees(t *testing.T) {
	t.Parallel()

	theReasonItself := func(t *testing.T, got error) {
		t.Helper()

		assert.Same(t, ratelimit.ErrThrottled, got)
	}

	type testCase struct {
		name           string
		method, target string
		setup          signalsSetup
		assert         func(t *testing.T, got error)
	}

	cases := []testCase{
		{name: "a GET of another path", method: http.MethodGet, target: "/elsewhere", assert: theReasonItself},
		{name: "another method on the stream's path", method: http.MethodPost, target: httpsec.DefaultSessionSignalsPath, assert: theReasonItself},
		{
			name: "a chain with no stream", method: http.MethodGet, target: httpsec.DefaultSessionSignalsPath,
			setup: signalsSetup{withoutSignals: true}, assert: theReasonItself,
		},
		{
			name: "the stream's own path, refused by the consumer's choice", method: http.MethodGet, target: httpsec.DefaultSessionSignalsPath,
			setup: signalsSetup{signals: httpsec.SessionSignals{RetryableError: func(error) bool { return false }}},
			assert: func(t *testing.T, got error) {
				t.Helper()

				require.ErrorIs(t, got, ratelimit.ErrThrottled)
				assert.EqualError(t, got, ratelimit.ErrThrottled.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen atomic.Pointer[error]

			setup := tc.setup
			setup.opts = func(*signalsFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithPolicyEngine(engineOf(t, phasePolicy(t,
						policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}, policy.PerRequest))),
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						err := next(ex)
						seen.Store(&err)

						return err
					}), httpsec.After(httpsec.OrderCSRF)),
				}
			}

			f := newSignalsFixture(t, setup)

			resp := f.send(t.Context(), t, tc.method, tc.target, f.signIn(t, "u-1").ID)

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

			got := seen.Load()
			require.NotNil(t, got, "the request reached no interceptor")

			tc.assert(t, *got)
		})
	}
}
