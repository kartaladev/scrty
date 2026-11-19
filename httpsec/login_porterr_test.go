package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// loginPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const loginPortErrRowEnv = "SCRTY_HTTPSEC_LOGIN_PORTERR_ROW"

// The records the login and password-change sites write for a failing
// attempt store, whatever its error.
const (
	loginPortErrNotRecorded  = "httpsec: a failed login attempt could not be recorded"
	loginPortErrNotReset     = "httpsec: failed login attempts could not be cleared"
	loginPortErrNotClearedPC = "httpsec: lockout failures could not be cleared after a password change"
)

// loginUnwrapPanics is an error whose Unwrap panics.
type loginUnwrapPanics struct{}

func (loginUnwrapPanics) Error() string { return hostileSecret }
func (loginUnwrapPanics) Unwrap() error { panic(isPanicMessage) }

// loginUnwrapPanicsNil is an error whose Unwrap panics with nil.
type loginUnwrapPanicsNil struct{}

func (loginUnwrapPanicsNil) Error() string { return hostileSecret }
func (loginUnwrapPanicsNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// loginTypedNil is returned as a nil pointer inside a non-nil error.
type loginTypedNil struct{}

func (*loginTypedNil) Error() string { return hostileSecret }

// loginFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func loginFanOut(depth int) error {
	err := errors.New(hostileSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// loginPortOutcome is everything one request through a failing port produced
// that a client or the account can observe, and the records the chain's
// logger received.
type loginPortOutcome struct {
	status int
	header http.Header
	body   string

	// recorded and resets are the attempt store's RecordFailure and Reset
	// calls: what was recorded, or cleared, for the username.
	recorded, resets int

	// charged is the source limiter's RecordFailure calls.
	charged int

	// events are the security events emitted, with At and Session cleared,
	// since a clock and a random session identifier differ between runs.
	events []event.Event

	logs []slog.Record
}

// count is how many records of logs carry msg.
func (o loginPortOutcome) count(msg string) int {
	n := 0

	for _, r := range o.logs {
		if r.Message == msg {
			n++
		}
	}

	return n
}

// loginPorts are what the form-login ports answer on one request.
type loginPorts struct {
	auth      *authenticate.Authentication
	authErr   error
	recordErr error
	resetErr  error
}

// loginPortSite is one site whose port error the sanitizer stands in front of.
// serve runs one request on ctx through a chain whose port fails with portErr,
// logging to a capturing logger of its own.
type loginPortSite struct {
	name string

	// plain is the port's plain outage: the parity row.
	plain error

	// wrong, when set, is the wrong-password reference the site is also
	// compared against.
	wrong error

	// failureMsg is the record the site writes for a failing port, if any.
	failureMsg string

	serve func(t *testing.T, ctx context.Context, portErr error) loginPortOutcome
}

// loginPortErrKind is one hostile error a port may return.
type loginPortErrKind struct {
	name string
	err  error

	// reason is the abort record's reason, and "" when the walk completes.
	reason string

	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool

	// ref, when set, replaces the site's plain outage as the reference the
	// row is compared with.
	ref error

	// site and ctx, when set, restrict the row to the named site and context.
	site, ctx string
}

// loginNotFoundCycle wraps identity.ErrUserNotFound and itself through
// Unwrap() []error: the one hostile shape the stdlib reads as "not found",
// since errors.Is finds the sentinel before it loops.
type loginNotFoundCycle struct{}

func (*loginNotFoundCycle) Error() string { return hostileSecret }
func (c *loginNotFoundCycle) Unwrap() []error {
	return []error{identity.ErrUserNotFound, c}
}

// loginCanceledCycle wraps context.Canceled and itself, so the stdlib reads it
// as the caller's hang-up when the walk is not sanitized.
type loginCanceledCycle struct{}

func (*loginCanceledCycle) Error() string { return hostileSecret }
func (c *loginCanceledCycle) Unwrap() []error {
	return []error{context.Canceled, c}
}

const loginAuthenticatorSite = "form login, the authenticator"

// errLoginUnrecognised is a plain error no branch recognises.
var errLoginUnrecognised = errors.New("store: something else went wrong")

func loginPortErrKinds() []loginPortErrKind {
	return []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		// The one shape the stdlib reads as an unknown user. It is compared with
		// the plain outage and with the real not-found row, so a regression to
		// the not-found branch changes the side effects and fails.
		{
			name: "cycle wrapping ErrUserNotFound", err: &loginNotFoundCycle{}, reason: "budget",
			child: true, site: loginAuthenticatorSite, ctx: "live",
		},
		// Hostile, and carrying the caller's cancellation: still an outage, not a
		// hang-up, so it is charged and answered as the plain outage is.
		{
			name: "cycle wrapping context.Canceled", err: &loginCanceledCycle{}, reason: "budget",
			child: true, site: loginAuthenticatorSite, ctx: "cancelled",
		},
		// A typed-nil root is walked to the end, so it passes unchanged and is
		// answered as any plain error no branch recognises.
		{name: "typed-nil root", err: (*loginTypedNil)(nil), ref: errLoginUnrecognised},
	}
}

// formLoginThrough serves one form login on ctx whose ports answer as ports
// says, counting what the attempt store and the source limiter were asked.
func formLoginThrough(t *testing.T, ctx context.Context, ports loginPorts, logger *slog.Logger) loginPortOutcome {
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

	tokens := newMockGenerator(ctrl)
	tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("tok", nil).AnyTimes()

	events := &eventRecorder{}

	chain, err := httpsec.New(
		httpsec.WithLogger(logger),
		httpsec.EnableSecurityEvents(events.sink),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore())))),
			Tokens:        tokens,
			Attempts:      attempts,
		}, httpsec.WithLoginLimiter(limiter)))
	require.NoError(t, err)

	rec := loginServeWithin(t, chain, formRequest(ctx, httpsec.DefaultLoginPath,
		url.Values{"username": {"ada"}, "password": {"guess"}}.Encode()))

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header = rec.Code, rec.Header()
	out.body = loginValidUntil.ReplaceAllString(rec.Body.String(), `"valid_until":"T"`)
	out.events = steadyEvents(events.all())

	return out
}

// loginValidUntil is a login success document's expiry, which the chain's
// clock sets and so differs between runs. It is masked; nothing else is.
var loginValidUntil = regexp.MustCompile(`"valid_until":"[^"]*"`)

// passwordChangeThrough serves one successful password change on ctx, whose
// form-login attempt store fails to clear with resetErr.
func passwordChangeThrough(t *testing.T, ctx context.Context, resetErr error, logger *slog.Logger) loginPortOutcome {
	t.Helper()

	var (
		mu  sync.Mutex
		out loginPortOutcome
	)

	h := newAuthHarness(t)
	h.expectVerified()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
	h.users.EXPECT().LoadByUserID(gomock.Any(), testUserID).Return(storedUser(), nil).AnyTimes()
	h.expectSaved(&savedSessions{}, nil)
	h.acceptsActivityWriteBack()
	h.attempts.EXPECT().Reset(gomock.Any(), testUsername).
		DoAndReturn(func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()

			out.resets++

			return resetErr
		}).AnyTimes()

	events := &eventRecorder{}

	chain, err := httpsec.New(
		httpsec.WithLogger(logger),
		httpsec.EnableSecurityEvents(events.sink),
		httpsec.EnableBearerToken(h.bearerTokenDeps()),
		httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithPasswordChangeEndpoint(testChangePasswordPath, func(ex *httpsec.Exchange) error {
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			})),
		httpsec.EnableFormLogin(h.formLoginDeps()))
	require.NoError(t, err)

	rec := loginServeWithin(t, chain, changePasswordRequest(ctx, http.MethodPost, true))

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.events = steadyEvents(events.all())

	return out
}

// steadyEvents is events with what differs between runs cleared.
func steadyEvents(events []event.Event) []event.Event {
	out := make([]event.Event, 0, len(events))

	for _, e := range events {
		e.At, e.Session = time.Time{}, ""
		out = append(out, e)
	}

	return out
}

// loginServeWithin serves req through the chain's net/http middleware, as a server
// does, and fails the test when the request does not finish in time or lets a
// panic escape.
func loginServeWithin(t *testing.T, chain *httpsec.Chain, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	type result struct {
		rec      *httptest.ResponseRecorder
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		r := result{rec: httptest.NewRecorder()}
		returned := false

		defer func() {
			if !returned {
				r.panicked, r.value = true, recover()
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
		require.False(t, r.panicked, "a hostile port error escaped as a panic: %v", r.value)

		return r.rec
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the request")

		return nil
	}
}

func loginPortSites() []loginPortSite {
	login := func(ports func(portErr error) loginPorts) func(*testing.T, context.Context, error) loginPortOutcome {
		return func(t *testing.T, ctx context.Context, portErr error) loginPortOutcome {
			t.Helper()

			logs := &capturingHandler{}
			out := formLoginThrough(t, ctx, ports(portErr), slog.New(logs))
			out.logs = logs.records()

			return out
		}
	}

	success := &authenticate.Authentication{
		Principal: &identity.Principal{ID: "u-1", Username: "ada"},
		Time:      time.Now(),
	}

	return []loginPortSite{
		{
			name:  "form login, the authenticator",
			plain: authenticate.ErrUnavailable,
			wrong: authenticate.ErrAuthenticationFailed,
			serve: login(func(portErr error) loginPorts { return loginPorts{authErr: portErr} }),
		},
		{
			name:       "form login, recording a failed attempt",
			plain:      errors.New("attempt store: connection refused"),
			failureMsg: loginPortErrNotRecorded,
			serve: login(func(portErr error) loginPorts {
				return loginPorts{authErr: authenticate.ErrAuthenticationFailed, recordErr: portErr}
			}),
		},
		{
			name:       "form login, clearing failures after a success",
			plain:      errors.New("attempt store: connection refused"),
			failureMsg: loginPortErrNotReset,
			serve:      login(func(portErr error) loginPorts { return loginPorts{auth: success, resetErr: portErr} }),
		},
		{
			name:       "password change, clearing failures",
			plain:      errors.New("attempt store: connection refused"),
			failureMsg: loginPortErrNotClearedPC,
			serve: func(t *testing.T, ctx context.Context, portErr error) loginPortOutcome {
				t.Helper()

				logs := &capturingHandler{}
				out := passwordChangeThrough(t, ctx, portErr, slog.New(logs))
				out.logs = logs.records()

				return out
			},
		},
	}
}

// assertSameOutcome asserts got is want as a client and the account see it:
// byte-identical status, headers and body, the same attempt-store writes, the
// same source charges and the same security events.
func assertSameOutcome(t *testing.T, want, got loginPortOutcome, failureMsg string) {
	t.Helper()

	assert.Equal(t, want.status, got.status, "status")
	assert.Equal(t, want.header, got.header, "headers")
	assert.Equal(t, want.body, got.body, "body")
	assert.Equal(t, want.recorded, got.recorded, "failures recorded for the username")
	assert.Equal(t, want.resets, got.resets, "clearings of the username")
	assert.Equal(t, want.charged, got.charged, "charges to the source")
	assert.Equal(t, want.events, got.events, "security events")

	if failureMsg != "" {
		assert.Equal(t, want.count(failureMsg), got.count(failureMsg), "the site's failure record")
	}
}

// TestPortErrors_LoginAndPasswordChange pins that a hostile error from the
// login authenticator or from the attempt store is answered exactly as a plain
// outage of that port is, through the real request path: the same response,
// byte for byte, the same writes for the username, the same charge to the
// source and the same security events. It is reported once, to the chain's
// own logger and not to slog.Default(). A user-store outage, and so a hostile
// one, conceals: it is never an unknown user, a throttle or an outage claim.
func TestPortErrors_LoginAndPasswordChange(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(loginPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live"},
		{name: "cancelled", ctx: cancelled},
	}

	for _, site := range loginPortSites() {
		for _, c := range contexts {
			prefix := site.name + "/" + c.name

			if childRow != "" && !strings.HasPrefix(childRow, prefix+"/") {
				continue
			}

			ctxOf := func(t *testing.T) context.Context {
				t.Helper()

				if c.ctx == nil {
					return t.Context()
				}

				return c.ctx(t.Context())
			}

			for _, kind := range loginPortErrKinds() {
				row := prefix + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if (kind.site != "" && kind.site != site.name) || (kind.ctx != "" && kind.ctx != c.name) {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						loginPortErrInChild(t, row)

						return
					}

					defaults := swapDefaultLogger(t)
					ctx := ctxOf(t)

					refErr := site.plain
					if kind.ref != nil {
						refErr = kind.ref
					}

					plain := site.serve(t, ctx, refErr)
					require.Empty(t, abortRecords(plain.logs), "the reference writes no abort record")

					got := site.serve(t, ctx, kind.err)
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
						wrong := site.serve(t, ctx, site.wrong)
						assertOutageAgainstWrongPassword(t, plain, wrong, got)
					}
				})
			}
		}
	}
}

// assertOutageAgainstWrongPassword pins how a user-store outage, and so a
// hostile authenticator error, compares with a wrong password: the response
// is the same, byte for byte, and only the side effects differ. A wrong
// password is recorded for the username and reported as a failed login; an
// outage judged no credential, so it is neither. Both are charged to the
// source.
func assertOutageAgainstWrongPassword(t *testing.T, plain, wrong, got loginPortOutcome) {
	t.Helper()

	assert.Equal(t, wrong.status, plain.status, "an outage answers with the wrong password's status")
	assert.Equal(t, wrong.header, plain.header, "and its headers")
	assert.Equal(t, wrong.body, plain.body, "and its body")
	assert.Equal(t, wrong.status, got.status, "a hostile error answers with the wrong password's status")
	assert.Equal(t, wrong.header, got.header, "and its headers")
	assert.Equal(t, wrong.body, got.body, "and its body")

	assert.Equal(t, 1, wrong.recorded, "a wrong password is recorded for the username")
	assert.Equal(t, 0, got.recorded, "a hostile error is recorded for no one")
	assert.Equal(t, wrong.charged, got.charged, "both are charged to the source")
	assert.NotEmpty(t, wrong.events, "a wrong password is reported")
	assert.Empty(t, got.events, "a hostile error reports no failed login")
}

// loginPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute: a stack
// overflow is fatal and only a child can watch for one.
func loginPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), loginPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
}
