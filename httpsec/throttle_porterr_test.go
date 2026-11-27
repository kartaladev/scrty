package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
)

// throttlePortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const throttlePortErrRowEnv = "SCRTY_HTTPSEC_THROTTLE_PORTERR_ROW"

// throttlePortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const throttlePortErrRan = "throttle-porterr-row-ran:"

// throttleClientAddr is an IPv6 client, so the chain's default IPv6 aggregate
// counts it.
const throttleClientAddr = "[2001:db8:1:2::1]:4711"

// throttleCouldNotAnswer is the record sourceThrottled writes for a check the
// limiter could not answer.
const throttleCouldNotAnswer = "httpsec: the rate limiter could not answer"

// throttleCycleWrapping wraps a sentinel and itself through Unwrap() []error:
// stdlib errors.Is finds the sentinel before it loops, and overflows the
// stack when asked for anything else.
type throttleCycleWrapping struct{ sentinel error }

func (*throttleCycleWrapping) Error() string { return hostileSecret }
func (c *throttleCycleWrapping) Unwrap() []error {
	return []error{c.sentinel, c}
}

// throttleLimiters are what the Basic flow's source and aggregate limiters
// answer to a check, and what the attempt is authenticated as.
type throttleLimiters struct {
	sourceErr, aggregateErr error
	authErr                 error
}

// throttleSite is one guard check whose limiter error reaches sourceThrottled.
type throttleSite struct {
	name     string
	limiters func(portErr error) throttleLimiters
}

func throttleSites() []throttleSite {
	return []throttleSite{
		{
			name:     "basic, the source limiter's check",
			limiters: func(portErr error) throttleLimiters { return throttleLimiters{sourceErr: portErr} },
		},
		{
			name:     "basic, the IPv6 aggregate limiter's check",
			limiters: func(portErr error) throttleLimiters { return throttleLimiters{aggregateErr: portErr} },
		},
	}
}

// basicThrottledThrough serves one Basic request on ctx from an IPv6 client,
// through the chain's net/http middleware, with the flow's source and
// aggregate limiters built by the chain's factory and answering as l says.
// Every record goes to logger.
func basicThrottledThrough(ctx context.Context, t *testing.T, l throttleLimiters, logger *slog.Logger) loginPortOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)

	var (
		mu  sync.Mutex
		out loginPortOutcome
	)

	authn := NewMockAuthenticator(ctrl)
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, l.authErr).AnyTimes()

	attempts := NewMockAttemptStore(ctrl)
	attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
	attempts.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string, time.Time) error {
			mu.Lock()
			defer mu.Unlock()

			out.recorded++

			return nil
		}).AnyTimes()
	attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	limiter := func(exceededErr error) ratelimit.Limiter {
		lim := NewMockLimiter(ctrl)
		lim.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, exceededErr).AnyTimes()
		lim.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, string) error {
				mu.Lock()
				defer mu.Unlock()

				out.charged++

				return nil
			}).AnyTimes()

		return lim
	}

	factory := NewMockLimiterFactory(ctrl)
	factory.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(namespace string, _ int, _ time.Duration) (ratelimit.Limiter, error) {
			if strings.HasSuffix(namespace, "-ipv6-aggregate") {
				return limiter(l.aggregateErr), nil
			}

			return limiter(l.sourceErr), nil
		}).AnyTimes()

	events := &eventRecorder{}

	chain, err := httpsec.New(
		httpsec.WithLogger(logger),
		httpsec.WithRateLimiterFactory(factory),
		httpsec.EnableSecurityEvents(events.sink),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}))
	require.NoError(t, err)

	req := basicRequest(ctx, "ada", "guess")
	req.RemoteAddr = throttleClientAddr

	rec := loginServeWithin(t, chain, req)

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.events = steadyEvents(events.all())

	return out
}

func throttlePortErrKinds() []loginPortErrKind {
	return []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{
			name: "cycle wrapping ErrThrottled", err: &throttleCycleWrapping{sentinel: ratelimit.ErrThrottled},
			reason: "budget", child: true,
		},
		{
			name: "cycle wrapping ErrLimiterFull", err: &throttleCycleWrapping{sentinel: ratelimit.ErrLimiterFull},
			reason: "budget", child: true,
		},
		{
			name: "cycle wrapping context.Canceled", err: &throttleCycleWrapping{sentinel: context.Canceled},
			reason: "budget", child: true, ctx: "cancelled",
		},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain limiter error.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}
}

// nonAbortMessages is the message of every record in recs other than an
// aborted classification, in order.
func nonAbortMessages(recs []slog.Record) []string {
	var out []string

	for _, r := range recs {
		if r.Message != msgClassificationAborted {
			out = append(out, r.Level.String()+" "+r.Message)
		}
	}

	return out
}

// TestPortErrors_SourceThrottle pins that a hostile error from a flow's source
// or IPv6 aggregate limiter, met by the guard's check on the request path, is
// answered exactly as a plain limiter outage: the same response, byte for
// byte, which is the response to an ordinary failed attempt; the same writes,
// charges, events and records. It is never a throttled source. It is reported
// once, to the chain's logger, which is the guard's, and not to
// slog.Default().
func TestPortErrors_SourceThrottle(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(throttlePortErrRowEnv)
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

	plainOutage := errors.New("limiter: connection refused")

	for _, site := range throttleSites() {
		for _, c := range contexts {
			for _, kind := range throttlePortErrKinds() {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						throttlePortErrInChild(t, row)

						return
					}

					defaults := swapDefaultLogger(t)

					ctx := t.Context()
					if c.ctx != nil {
						ctx = c.ctx(ctx)
					}

					serve := func(l throttleLimiters) loginPortOutcome {
						logs := &capturingHandler{}
						out := basicThrottledThrough(ctx, t, l, slog.New(logs))
						out.logs = logs.records()

						return out
					}

					withAuth := func(l throttleLimiters) throttleLimiters {
						l.authErr = authenticate.ErrAuthenticationFailed

						return l
					}

					plain := serve(withAuth(site.limiters(plainOutage)))
					require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
					require.Equal(t, 1, plain.count(throttleCouldNotAnswer), "the plain outage is reported")

					got := serve(withAuth(site.limiters(kind.err)))
					assertSameOutcome(t, plain, got, throttleCouldNotAnswer)
					assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")
					assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")

					// A limiter outage reads to the client exactly as a wrong
					// credential through a healthy limiter.
					wrong := serve(withAuth(throttleLimiters{}))
					assert.Equal(t, wrong.status, got.status, "status against a failed attempt")
					assert.Equal(t, wrong.header, got.header, "headers against a failed attempt")
					assert.Equal(t, wrong.body, got.body, "body against a failed attempt")

					aborts := abortRecords(got.logs)
					if kind.reason == "" {
						assert.Empty(t, aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, aborts, 1, "one abort record, on the chain's logger")
						assertAbortRecord(t, aborts[0], kind.reason)
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						_, _ = fmt.Fprintln(os.Stdout, throttlePortErrRan+row)
					}
				})
			}
		}
	}
}

// throttlePortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having printed
// the row's marker as a whole line: a stack overflow is fatal and only a child
// can watch for one, and a row name that matched nothing would otherwise pass
// without running.
func throttlePortErrInChild(t *testing.T, row string) {
	limiterPortErrInChild(t, throttlePortErrRowEnv, throttlePortErrRan, row)
}
