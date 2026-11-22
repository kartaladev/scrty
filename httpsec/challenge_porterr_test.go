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
	"os"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/porterr"
)

// stepUpPortErrRowEnv names the row a child process of
// TestPortErrors_StepUpChallenge runs. It is empty in the parent.
const stepUpPortErrRowEnv = "SCRTY_HTTPSEC_STEPUP_PORTERR_ROW"

// stepUpPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const stepUpPortErrRan = "stepup-porterr-row-ran:"

// stepUpIsPanicsFor is an error whose Is panics only when asked about target:
// the walk never calls Is, so it passes the sanitizer unchanged and panics at
// the stdlib check that asks about target. That is the accepted case (design
// decision 11, failure row "an error whose Is panics only for one particular
// sentinel").
type stepUpIsPanicsFor struct{ target error }

func (stepUpIsPanicsFor) Error() string { return hostileSecret }

func (e stepUpIsPanicsFor) Is(target error) bool {
	if target == e.target { //nolint:errorlint // identity of a sentinel
		panic(isPanicMessage)
	}

	return false
}

// stepUpPortErrKind is one error a step-up port answers with.
type stepUpPortErrKind struct {
	name string
	err  error

	// reason is the abort record's reason, and "" when the walk completes.
	reason string

	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool

	// ctx, when set, restricts the row to the named context.
	ctx string

	// panics is the accepted row: the request panics past the chain, as it
	// does before and after the sanitizer, for net/http to recover.
	panics bool
}

// stepUpPortErrKinds are the hostile errors a step-up site's port may answer
// with. sentinel, when set, is a library sentinel the site reads the port's
// error for with the stdlib, which a cycle wraps and a selective Is panics on.
func stepUpPortErrKinds(sentinel error) []stepUpPortErrKind {
	kinds := []stepUpPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{
			name:   "cycle wrapping context.Canceled",
			err:    &throttleCycleWrapping{sentinel: context.Canceled},
			reason: "budget", child: true, ctx: "cancelled",
		},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain port error.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}

	if sentinel != nil {
		kinds = append(kinds,
			stepUpPortErrKind{
				name: "cycle wrapping the site's sentinel",
				err:  &throttleCycleWrapping{sentinel: sentinel}, reason: "budget", child: true,
			},
			stepUpPortErrKind{
				name: "Is panicking only for the site's sentinel (accepted)",
				err:  stepUpIsPanicsFor{target: sentinel}, panics: true,
			},
		)
	}

	return kinds
}

// stepUpOutcome is everything one request through a failing step-up port
// produced that a client or the account can observe, and the records the
// chain's logger received.
type stepUpOutcome struct {
	status  int
	header  http.Header
	body    string
	charged int
	state   string
	logs    []slog.Record

	// panicked reports that the request panicked past the chain.
	panicked bool

	// unwalkable reports that the error the flow returned to the chain's
	// caller matches porterr.ErrUnwalkable, and escaped that its chain could
	// not be walked: a hostile error travelling on past the site.
	unwalkable, escaped bool
}

// stepUpReturned is what the outermost interceptor saw the flow return.
type stepUpReturned struct {
	mu                  sync.Mutex
	unwalkable, escaped bool
}

// stepUpObserver registers an interceptor outside every other one that
// records, through the library's bounded walk, what the flow returned: an
// unbounded check of a hostile error would hang or crash the test itself.
//
// A swallowing observer returns nil after recording, so the chain's own
// dispatch never classifies the error and never writes a record of its own:
// the records of such a run are the site's alone.
func stepUpObserver(r *stepUpReturned, swallow bool) httpsec.Option {
	observe := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		err := next(ex)

		chain, abort := errwalk.Flatten(err)

		r.mu.Lock()
		r.escaped = abort != nil

		if abort == nil {
			found, _ := errwalk.Is(chain, porterr.ErrUnwalkable)
			r.unwalkable = found
		}
		r.mu.Unlock()

		if swallow {
			return nil
		}

		return err
	})

	return httpsec.RegisterInterceptor(observe, httpsec.Before(httpsec.OrderSecurityHeaders))
}

// stepUpRun is how one request through a failing port is served.
type stepUpRun struct {
	// cancelDuring cancels the request inside the port call.
	cancelDuring bool

	// swallow makes the outermost interceptor return nil, so the chain's
	// dispatch writes no abort record and the records are the site's own.
	swallow bool
}

// stepUpPortSite is one port call of a step-up flow. through serves the site's
// request with its port failing with portErr, as run says.
type stepUpPortSite struct {
	name     string
	sentinel error
	through  func(t *testing.T, portErr error, run stepUpRun) stepUpOutcome

	// charged is the failures a plain outage of the port charges to the user:
	// a hostile error is charged the same, so a throttle bypass shows here.
	charged int

	// logOnly marks a site that only logs its port's error and returns none:
	// the flow's result is then never the sanitizer's fault.
	logOnly bool
}

// stepUpServeWithin serves req through chain's net/http middleware, as a
// server does, and fails the test if it does not return within five seconds.
// A panic past the chain is reported, not recovered into a failure: the
// accepted row expects one.
func stepUpServeWithin(t *testing.T, chain *httpsec.Chain, req *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	type result struct {
		rec      *httptest.ResponseRecorder
		panicked bool
	}

	done := make(chan result, 1)

	go func() {
		r := result{rec: httptest.NewRecorder()}
		returned := false

		defer func() {
			if !returned {
				// A panic(nil) recovers as a *runtime.PanicNilError, so
				// returned is what tells a panic apart, not recover's value.
				_ = recover()
				r.panicked = true
			}

			done <- r
		}()

		chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(r.rec, req)

		returned = true
	}()

	select {
	case r := <-done:
		return r.rec, r.panicked
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the request")

		return nil, false
	}
}

// stepUpCharges counts the failures charged to a limiter.
type stepUpCharges struct {
	mu sync.Mutex
	n  int
}

func (c *stepUpCharges) add() {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func (c *stepUpCharges) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.n
}

// stepUpOutcomeOf collects what rec, the charges and the chain's logs show.
func stepUpOutcomeOf(rec *httptest.ResponseRecorder, panicked bool, charges *stepUpCharges, state string,
	logs *capturingHandler, returned *stepUpReturned,
) stepUpOutcome {
	out := stepUpOutcome{panicked: panicked, state: state, logs: logs.records()}

	returned.mu.Lock()
	out.unwalkable, out.escaped = returned.unwalkable, returned.escaped
	returned.mu.Unlock()

	if charges != nil {
		out.charged = charges.count()
	}

	if rec != nil && !panicked {
		out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	}

	return out
}

// runStepUpPortErrors runs every hostile kind at every site, live and with the
// request cancelled inside the port call, against the site's plain outage.
// Rows that would overflow the stack unsanitized run in a child process,
// selected by envName and confirmed by a marker line.
func runStepUpPortErrors(t *testing.T, envName, marker string, sites []stepUpPortSite, plainOutage error) {
	t.Helper()

	childRow := os.Getenv(envName)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name         string
		cancelDuring bool
	}{
		{name: "live"},
		{name: "cancelled", cancelDuring: true},
	}

	for _, site := range sites {
		for _, c := range contexts {
			for _, kind := range stepUpPortErrKinds(site.sentinel) {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						limiterPortErrInChild(t, envName, marker, row)

						return
					}

					defaults := swapDefaultLogger(t)

					plain := site.through(t, plainOutage, stepUpRun{cancelDuring: c.cancelDuring})
					require.False(t, plain.panicked, "the plain outage does not panic")
					require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
					require.GreaterOrEqual(t, plain.status, http.StatusBadRequest, "a plain outage refuses")
					require.False(t, plain.unwalkable, "the plain outage is no fault")
					require.Equal(t, site.charged, plain.charged, "failures a plain outage charges")

					got := site.through(t, kind.err, stepUpRun{cancelDuring: c.cancelDuring})

					if kind.panics {
						// Accepted: the selective Is passes the walk and panics
						// at the stdlib check behind it, for net/http's
						// per-request recovery.
						assert.True(t, got.panicked, "the accepted case panics past the chain")
					} else {
						assert.False(t, got.panicked, "a hostile port error escaped as a panic")
						assert.Equal(t, plain.status, got.status, "status")
						assert.Equal(t, plain.header, got.header, "headers")
						assert.Equal(t, plain.body, got.body, "body")
						assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
						assert.Equal(t, plain.charged, got.charged, "failures charged to the user")
						assert.Equal(t, plain.state, got.state, "the session")
						assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")
						assert.False(t, got.escaped, "an unwalkable error travelled on past the site")
						assert.Equal(t, kind.reason != "" && !site.logOnly, got.unwalkable,
							"the flow returned the sanitizer's fault, matching porterr.ErrUnwalkable")

						aborts := abortRecords(got.logs)
						if kind.reason == "" {
							assert.Empty(t, aborts, "a walk that completes writes no abort record")
						} else {
							require.Len(t, aborts, 1, "one abort record, on the chain's logger")
							assertAbortRecord(t, aborts[0], kind.reason)
						}

						// The chain's own dispatch classifies the error a flow
						// returns and writes the same record, so the count above
						// cannot tell the site's sanitizer from it. With the
						// dispatch out of the way, the site's record is the only one.
						alone := site.through(t, kind.err, stepUpRun{cancelDuring: c.cancelDuring, swallow: true})
						assert.False(t, alone.panicked, "a hostile port error escaped as a panic")

						soleAborts := abortRecords(alone.logs)
						if kind.reason == "" {
							assert.Empty(t, soleAborts, "a walk that completes writes no abort record")
						} else {
							require.Len(t, soleAborts, 1, "the site's own sanitizer writes the one abort record")
							assertAbortRecord(t, soleAborts[0], kind.reason)
						}
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						_, _ = fmt.Fprintln(os.Stdout, marker+row)
					}
				})
			}
		}
	}
}

// requestContext is the context a site's request is served under, and the
// cancel the port calls when the row cancels the request inside it.
func requestContext(t *testing.T, cancelDuring bool) (context.Context, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	if !cancelDuring {
		return ctx, func() {}
	}

	return ctx, cancel
}

// challengeVerifierThrough serves a form login whose automation challenge
// verifier fails with portErr. No password is checked: the authenticator is
// strict, so a hostile error that let the login through fails the test.
func challengeVerifierThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	h := newAuthHarness(t)
	passwordWork(h, false)

	v := NewMockChallengeVerifier(gomock.NewController(t))
	v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
			onCall()

			return 0, portErr
		})

	logs := &capturingHandler{}
	returned := &stepUpReturned{}

	chain, err := httpsec.New(
		stepUpObserver(returned, run.swallow),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableFormLogin(h.formLoginDeps()),
		challengeFor(httpsec.ChallengeFlowFormLogin, v),
	)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain,
		formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=wrong"))

	return stepUpOutcomeOf(rec, panicked, nil, "", logs, returned)
}

// failingVerify wires m's Verify to fail with portErr, calling onCall first,
// and the limiter to admit the user and count each failure charged.
func failingVerify(m *MockMethod, l *MockLimiter, portErr error, onCall func()) *stepUpCharges {
	charges := &stepUpCharges{}

	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) error {
			charges.add()

			return nil
		})

	m.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).
		DoAndReturn(func(context.Context, identity.UserID, []byte) error {
			onCall()

			return portErr
		})

	return charges
}

// mfaVerifyThrough serves a second-factor verification whose method's Verify
// fails with portErr.
func mfaVerifyThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp)
	s := h.pendingSession(t, factor.Password)
	charges := failingVerify(h.method, h.limiter, portErr, onCall)

	logs := &capturingHandler{}
	returned := &stepUpReturned{}
	chain := h.chain(t, s, httpsec.WithLogger(slog.New(logs)), stepUpObserver(returned, run.swallow))

	rec, panicked := stepUpServeWithin(t, chain, post(ctx, testMFAVerifyPath, "code="+testMFACode))

	stored := h.stored(t, s.ID)

	return stepUpOutcomeOf(rec, panicked, charges, fmt.Sprintf("%v issued=%v", stored.MFA, h.issuedFor.Load()), logs, returned)
}

// reauthVerifyThrough serves a second-factor re-proof whose method's Verify
// fails with portErr.
func reauthVerifyThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	h := newReauthHarness(t)
	s := h.fullSession(t, factor.Password)
	charges := failingVerify(h.method, h.limiter, portErr, onCall)

	logs := &capturingHandler{}
	returned := &stepUpReturned{}
	h.chainOpts = append(h.chainOpts, httpsec.WithLogger(slog.New(logs)), stepUpObserver(returned, run.swallow))

	chain, err := h.build(s)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain, post(ctx, reauthVerifyTOTP, "code="+testMFACode))

	return stepUpOutcomeOf(rec, panicked, charges, reauthState(t, h, s.ID), logs, returned)
}

// reauthState is what a re-proof could change: the session's authentication
// time and second-factor state, and whether a credential was issued.
func reauthState(t *testing.T, h *reauthHarness, id string) string {
	t.Helper()

	stored := h.stored(t, id)

	return fmt.Sprintf("authenticated=%s mfa=%v issued=%v",
		stored.AuthenticatedAt.Format(time.RFC3339Nano), stored.MFA, h.issuedFor.Load())
}

// TestPortErrors_StepUpChallenge pins that a hostile error from the automation
// challenge verifier, or from a second-factor method's Verify at the
// second-factor and the re-proof endpoints, is answered exactly as a plain
// outage of that port is: the same refusal, byte for byte, the same failures
// charged to the user, and the session untouched. It is never a pass, and at
// Verify never a refusal of the authenticator that charges nothing. It is
// reported once, to the chain's logger, and not to slog.Default().
//
// One row is accepted, not sanitized: an error whose Is panics only for
// mfa.ErrAuthenticatorRefused passes the walk and panics at Verify's stdlib
// check, for net/http's per-request recovery.
func TestPortErrors_StepUpChallenge(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, stepUpPortErrRowEnv, stepUpPortErrRan, []stepUpPortSite{
		{name: "the automation challenge verifier", through: challengeVerifierThrough},
		{name: "second-factor verify, the method's Verify", sentinel: mfa.ErrAuthenticatorRefused, through: mfaVerifyThrough, charged: 1},
		{name: "re-proof verify, the method's Verify", sentinel: mfa.ErrAuthenticatorRefused, through: reauthVerifyThrough, charged: 1},
	}, errors.New("dependency: connection refused"))
}
