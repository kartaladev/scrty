package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// basicPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const basicPortErrRowEnv = "SCRTY_HTTPSEC_BASIC_PORTERR_ROW"

// basicPortErrRan is what a child prints once it has run its row to the end,
// followed by the row's name. A child whose row matched nothing prints
// nothing, and its parent fails rather than passing on an empty run.
const basicPortErrRan = "basic-porterr-row-ran:"

// The records the Basic sites write for a failing attempt store, whatever its
// error.
const (
	basicPortErrNotRecorded = "httpsec: a failed login attempt could not be recorded"
	basicPortErrNotReset    = "httpsec: failed login attempts could not be cleared"
)

const basicAuthenticatorSite = "basic, the authenticator"

// basicPorts are what the Basic ports answer on one request.
type basicPorts struct {
	auth      *authenticate.Authentication
	authErr   error
	recordErr error
	resetErr  error
}

// basicPortSite is one Basic site whose port error the sanitizer stands in
// front of.
type basicPortSite struct {
	name string

	// plain is the port's plain outage: the parity row.
	plain error

	// wrong, when set, is the wrong-password reference the site is also
	// compared against.
	wrong error

	// failureMsg is the record the site writes for a failing port, if any.
	failureMsg string

	// ports maps the port's error to what every port answers.
	ports func(portErr error) basicPorts
}

// basicAuthThrough serves one Basic request on ctx whose ports answer as ports
// says, through the chain's net/http middleware, counting what the attempt
// store and the source limiter were asked. Every record goes to logger.
func basicAuthThrough(t *testing.T, ctx context.Context, ports basicPorts, logger *slog.Logger) loginPortOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)

	var (
		mu  sync.Mutex
		out loginPortOutcome
	)

	authn := NewMockAuthenticator(ctrl)
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(ports.auth, ports.authErr).AnyTimes()

	attempts := NewMockAttemptStore(ctrl)
	attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
	attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(context.Context, string, time.Time) error {
			mu.Lock()
			defer mu.Unlock()

			out.recorded++

			return ports.recordErr
		}).AnyTimes()
	attempts.EXPECT().Reset(gomock.Any(), "ada").
		DoAndReturn(func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()

			out.resets++

			return ports.resetErr
		}).AnyTimes()

	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()

			out.charged++

			return nil
		}).AnyTimes()

	events := &eventRecorder{}

	chain, err := httpsec.New(
		httpsec.WithLogger(logger),
		httpsec.EnableSecurityEvents(events.sink),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts},
			httpsec.WithBasicAuthLimiter(limiter)))
	require.NoError(t, err)

	rec := loginServeWithin(t, chain, basicRequest(ctx, "ada", "guess"))

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.events = steadyEvents(events.all())

	return out
}

func basicPortSites() []basicPortSite {
	success := &authenticate.Authentication{
		Principal: &identity.Principal{ID: "u-1", Username: "ada"},
		Time:      time.Now(),
	}

	return []basicPortSite{
		{
			name:  basicAuthenticatorSite,
			plain: authenticate.ErrUnavailable,
			wrong: authenticate.ErrAuthenticationFailed,
			ports: func(portErr error) basicPorts { return basicPorts{authErr: portErr} },
		},
		{
			name:       "basic, recording a failed attempt",
			plain:      errors.New("attempt store: connection refused"),
			failureMsg: basicPortErrNotRecorded,
			ports: func(portErr error) basicPorts {
				return basicPorts{authErr: authenticate.ErrAuthenticationFailed, recordErr: portErr}
			},
		},
		{
			name:       "basic, clearing failures after a success",
			plain:      errors.New("attempt store: connection refused"),
			failureMsg: basicPortErrNotReset,
			ports:      func(portErr error) basicPorts { return basicPorts{auth: success, resetErr: portErr} },
		},
	}
}

// basicPortErrKinds are the hostile errors each Basic site is fed. The two
// cycles that wrap a sentinel are run against the authenticator only, the
// site whose branches test for one.
func basicPortErrKinds() []loginPortErrKind {
	return []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{
			name: "cycle wrapping ErrUserNotFound", err: &loginNotFoundCycle{}, reason: "budget",
			child: true, site: basicAuthenticatorSite, ctx: "live",
		},
		{
			name: "cycle wrapping context.Canceled", err: &loginCanceledCycle{}, reason: "budget",
			child: true, site: basicAuthenticatorSite, ctx: "cancelled",
		},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain error no branch recognises.
		{name: "typed-nil root", err: (*loginTypedNil)(nil), ref: errLoginUnrecognised},
	}
}

// TestPortErrors_BasicAuth pins that a hostile error from the Basic
// authenticator or from the attempt store is answered exactly as a plain
// outage of that port is, through the real request path: the same response,
// byte for byte (a challenged 401 for an authenticator outage), the same
// writes for the username, the same charge to the source and the same
// security events. It is reported once, to the chain's own logger and not to
// slog.Default(). A hostile authenticator error is an outage: never an
// unknown user, a wrong password or the caller's hang-up.
func TestPortErrors_BasicAuth(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(basicPortErrRowEnv)
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

	for _, site := range basicPortSites() {
		for _, c := range contexts {
			for _, kind := range basicPortErrKinds() {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if (kind.site != "" && kind.site != site.name) || (kind.ctx != "" && kind.ctx != c.name) {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						basicPortErrInChild(t, row)

						return
					}

					defaults := swapDefaultLogger(t)

					ctx := t.Context()
					if c.ctx != nil {
						ctx = c.ctx(ctx)
					}

					serve := func(portErr error) loginPortOutcome {
						logs := &capturingHandler{}
						out := basicAuthThrough(t, ctx, site.ports(portErr), slog.New(logs))
						out.logs = logs.records()

						return out
					}

					refErr := site.plain
					if kind.ref != nil {
						refErr = kind.ref
					}

					plain := serve(refErr)
					require.Empty(t, abortRecords(plain.logs), "the reference writes no abort record")

					got := serve(kind.err)
					assertSameOutcome(t, plain, got, site.failureMsg)
					assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")

					aborts := abortRecords(got.logs)
					if kind.reason == "" {
						assert.Empty(t, aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, aborts, 1, "one abort record, on the chain's logger")
						assertAbortRecord(t, aborts[0], kind.reason)
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if site.wrong != nil && kind.ref == nil {
						assertOutageAgainstWrongPassword(t, plain, serve(site.wrong), got)
					}

					if childRow != "" && !t.Failed() {
						fmt.Fprintln(os.Stdout, basicPortErrRan+row)
					}
				})
			}
		}
	}
}

// basicPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having run the
// row: a stack overflow is fatal and only a child can watch for one, and a row
// name that matched nothing would otherwise pass without running.
func basicPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), basicPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	assert.Contains(t, string(out), basicPortErrRan+row+"\n", "the child ran its row")
}
