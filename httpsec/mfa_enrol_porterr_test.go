package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
)

// enrolPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const enrolPortErrRowEnv = "SCRTY_HTTPSEC_ENROL_PORTERR_ROW"

// enrolPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const enrolPortErrRan = "enrol-porterr-row-ran:"

// limiterPortErrKinds are the hostile errors a rate limiter's Exceeded may
// return at a site whose own throttle sentinel is sentinel. Rows that overflow
// the stack on an unsanitized error run in a child process.
func limiterPortErrKinds(sentinel error) []loginPortErrKind {
	return []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{
			name: "cycle wrapping the site's throttle sentinel",
			err:  &throttleCycleWrapping{sentinel: sentinel}, reason: "budget", child: true,
		},
		{
			name:   "cycle wrapping context.Canceled",
			err:    &throttleCycleWrapping{sentinel: context.Canceled},
			reason: "budget", child: true, ctx: "cancelled",
		},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain limiter error.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}
}

// limiterPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having printed
// marker+row as a whole line: a stack overflow is fatal and only a child can
// watch for one, and a row name that matched nothing would otherwise pass
// without running.
func limiterPortErrInChild(t *testing.T, envName, marker, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), envName+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == marker+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", marker+row)
}

// limiterAsk counts the checks and charges a hostile limiter saw.
type limiterAsk struct {
	mu            sync.Mutex
	asked, charge int
}

func (a *limiterAsk) counts() (asked, charged int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.asked, a.charge
}

// hostileLimiter is a mock limiter that fails every check with err, cancelling
// cancel first when it is set, and counts its checks and charges in a.
func hostileLimiter(t *testing.T, a *limiterAsk, err error, cancel context.CancelFunc) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (bool, error) {
			a.mu.Lock()
			a.asked++
			a.mu.Unlock()

			if cancel != nil {
				cancel()
			}

			return false, err
		})
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) error {
			a.mu.Lock()
			a.charge++
			a.mu.Unlock()

			return nil
		})

	return l
}

// enrolLimiterOutcome is everything one enrolment request through a failing
// limiter produced that a client or the account can observe, and the records
// the chain's logger received.
type enrolLimiterOutcome struct {
	status          int
	header          http.Header
	body            string
	asked, charged  int
	enrolmentStored bool
	logs            []slog.Record
}

// enrolLimiterSite is one enrolment limiter whose check reaches throttled.
type enrolLimiterSite struct {
	name string

	// limit wires the failing limiter l into the enrolment options.
	limit func(l *MockLimiter) httpsec.EnrolmentOption

	// confirm serves a begin first and then a confirm with a valid code,
	// rather than a begin alone.
	confirm bool
}

func enrolLimiterSites() []enrolLimiterSite {
	return []enrolLimiterSite{
		{
			name:  "the begin limiter's check",
			limit: func(l *MockLimiter) httpsec.EnrolmentOption { return httpsec.WithEnrolmentBeginLimiter(l) },
		},
		{
			name:    "the confirmation limiter's check",
			limit:   func(l *MockLimiter) httpsec.EnrolmentOption { return httpsec.WithEnrolmentConfirmLimiter(l) },
			confirm: true,
		},
	}
}

// enrolThrough serves the site's request through the chain's net/http
// middleware, as a server does, with its limiter failing with portErr. When
// cancelDuring is set the request is cancelled inside the limiter's check.
func enrolThrough(t *testing.T, site enrolLimiterSite, portErr error, cancelDuring bool) enrolLimiterOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var onAsk context.CancelFunc
	if cancelDuring {
		onAsk = cancel
	}

	h := newEnrolHarness(t)
	logs := &capturingHandler{}
	ask := &limiterAsk{}

	h.enrolOpts = append(h.enrolOpts, site.limit(hostileLimiter(t, ask, portErr, onAsk)))
	h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))

	c := h.chain(t, h.enrolmentOnly(t, factor.Password))

	rec := loginServeWithin

	if site.confirm {
		// The begin is the harness's own, healthy one, under a context that
		// outlives the confirm's.
		begin := rec(t, c, post(t.Context(), enrolBeginPath, ""))
		require.Equal(t, http.StatusOK, begin.Code, "the begin before the confirm")

		var doc beginBody
		require.NoError(t, json.Unmarshal(begin.Body.Bytes(), &doc))

		out := rec(t, c, post(ctx, enrolConfirmPath, "code="+h.codeFor(t, doc.Secret)))

		return enrolOutcomeOf(t, h, out.Code, out.Header(), out.Body.String(), ask, logs)
	}

	out := rec(t, c, post(ctx, enrolBeginPath, ""))

	return enrolOutcomeOf(t, h, out.Code, out.Header(), out.Body.String(), ask, logs)
}

func enrolOutcomeOf(
	t *testing.T, h *enrolHarness, status int, header http.Header, body string, ask *limiterAsk, logs *capturingHandler,
) enrolLimiterOutcome {
	t.Helper()

	asked, charged := ask.counts()
	_, stored := h.enrolment(t)

	return enrolLimiterOutcome{
		status: status, header: header, body: body,
		asked: asked, charged: charged, enrolmentStored: stored,
		logs: logs.records(),
	}
}

// TestPortErrors_EnrolmentLimiter pins that a hostile error from an enrolment
// limiter's check is answered exactly as a plain limiter outage is: the same
// refusal, byte for byte, the same writes and charges, and the same records.
// It is never "under the limit", which would lift the limit exactly when
// something is wrong. It is reported once, to the chain's logger, and not to
// slog.Default().
func TestPortErrors_EnrolmentLimiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(enrolPortErrRowEnv)
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

	plainOutage := errors.New("limiter: connection refused")

	for _, site := range enrolLimiterSites() {
		for _, c := range contexts {
			for _, kind := range limiterPortErrKinds(mfa.ErrEnrolmentThrottled) {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						limiterPortErrInChild(t, enrolPortErrRowEnv, enrolPortErrRan, row)

						return
					}

					defaults := swapDefaultLogger(t)

					plain := enrolThrough(t, site, plainOutage, c.cancelDuring)
					require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
					require.Equal(t, http.StatusUnauthorized, plain.status, "a plain outage refuses")
					require.Equal(t, 1, plain.asked, "the limiter was asked")

					got := enrolThrough(t, site, kind.err, c.cancelDuring)

					assert.Equal(t, plain.status, got.status, "status")
					assert.Equal(t, plain.header, got.header, "headers")
					assert.Equal(t, plain.body, got.body, "body")
					assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
					assert.Equal(t, plain.asked, got.asked, "checks of the limiter")
					assert.Equal(t, plain.charged, got.charged, "charges to the limiter")
					assert.Equal(t, plain.enrolmentStored, got.enrolmentStored, "the stored enrolment")
					assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")

					aborts := abortRecords(got.logs)
					if kind.reason == "" {
						assert.Empty(t, aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, aborts, 1, "one abort record, on the chain's logger")
						assertAbortRecord(t, aborts[0], kind.reason)
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						fmt.Fprintln(os.Stdout, enrolPortErrRan+row)
					}
				})
			}
		}
	}
}
