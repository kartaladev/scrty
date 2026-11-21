package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
)

// pwlPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const pwlPortErrRowEnv = "SCRTY_HTTPSEC_PASSKEY_LOGIN_PORTERR_ROW"

// pwlPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once that row has run and passed.
const pwlPortErrRan = "passkey-login-porterr-row-ran:"

// pwlIsNotFoundCycle claims identity.ErrUserNotFound through its own Is and
// contains itself through Unwrap() error: the stdlib reads it as an unknown
// user, since errors.Is asks Is before it unwraps.
type pwlIsNotFoundCycle struct{}

func (*pwlIsNotFoundCycle) Error() string   { return hostileSecret }
func (c *pwlIsNotFoundCycle) Unwrap() error { return c }
func (*pwlIsNotFoundCycle) Is(target error) bool {
	return target == identity.ErrUserNotFound //nolint:errorlint // the hostile claim under test
}

// pwlLoaderOutcome is everything one passwordless finish through a failing
// user loader produced that a client, the account or an operator can observe.
type pwlLoaderOutcome struct {
	status int
	header http.Header
	body   string

	// loads is the user loader's LoadByUserID calls, charged the source
	// limiter's recorded failures and charges, sessions the sessions saved.
	loads, charged, sessions int

	events []event.Event
	logs   []slog.Record
}

// others is the level and message of every record of logs that is not an
// abort record: what an operator reads besides the sanitizer's own record.
func (o pwlLoaderOutcome) others() []string {
	var out []string

	for _, r := range o.logs {
		if r.Message != msgClassificationAborted {
			out = append(out, r.Level.String()+" "+r.Message)
		}
	}

	return out
}

// passwordlessLoaderThrough serves one passwordless finish for a valid
// assertion whose user loader answers loaderErr, through the chain's net/http
// middleware. When cancel is set, the loader cancels the request's context
// before it answers, so the site reads the error on a cancelled context.
func passwordlessLoaderThrough(t *testing.T, loaderErr error, cancel bool) pwlLoaderOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)

	var (
		mu  sync.Mutex
		out pwlLoaderOutcome
	)

	reqCtx, cancelReq := context.WithCancel(t.Context())
	defer cancelReq()

	d := newPwlDeployment(t)

	d.users = NewMockUserLoader(ctrl)
	d.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(nil, identity.ErrUserNotFound).AnyTimes()
	d.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			mu.Lock()
			out.loads++
			mu.Unlock()

			if cancel {
				cancelReq()
			}

			return nil, loaderErr
		})

	mem, err := ratelimit.NewMemoryLimiter(100, time.Minute)
	require.NoError(t, err)

	charge := func() {
		mu.Lock()
		defer mu.Unlock()

		out.charged++
	}

	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).DoAndReturn(mem.Exceeded).AnyTimes()
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, key string) error {
			charge()

			return mem.RecordFailure(ctx, key)
		}).AnyTimes()
	limiter.EXPECT().Charge(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
			charge()

			return mem.Charge(ctx, key)
		}).AnyTimes()
	limiter.EXPECT().Refund(gomock.Any(), gomock.Any()).DoAndReturn(mem.Refund).AnyTimes()

	logs := &capturingHandler{}
	events := &eventRecorder{}

	d.settings = append(d.settings, httpsec.PasswordlessLimiter(limiter))
	d.extra = append(d.extra, httpsec.WithLogger(slog.New(logs)), httpsec.EnableSecurityEvents(events.sink))
	d.build(t)

	handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
	cookie, challenge := d.begun(t)

	req := jsonPost(reqCtx, passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
	req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

	rec := loginServeWithin(t, d.chain, req)

	sessions := d.sessionCount(t, served{})

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.sessions = sessions
	out.events = steadyEvents(events.all())
	out.logs = logs.records()

	return out
}

// TestPortErrors_PasswordlessUserLoader pins that a hostile error from the
// user loader a passwordless login's finish reads is answered exactly as a
// plain loader outage is, through the real request path: the same response,
// byte for byte, the same charges to the source, no session and no security
// event, and the same records besides one abort record on the chain's logger
// and none on slog.Default(). It is never the unknown-user answer, so a
// loader's error cannot be shaped into an enumeration oracle.
func TestPortErrors_PasswordlessUserLoader(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(pwlPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainOutage := fmt.Errorf("user store: %s", pwlLoaderCause) //nolint:err113 // a consumer's outage

	type testCase struct {
		name string
		err  error

		// reason is the abort record's reason, and "" when the walk completes.
		reason string

		// child runs the row in a child process: unsanitized, it may overflow
		// the stack fatally.
		child bool
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		// 2^30 paths: the stdlib's unbounded errors.Is walks them for far
		// longer than the request's bound.
		{name: "join fanning out", err: loginFanOut(30), reason: "budget"},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "cycle claiming ErrUserNotFound through Is", err: &pwlIsNotFoundCycle{}, reason: "budget"},
		{name: "cycle wrapping ErrUserNotFound", err: &loginNotFoundCycle{}, reason: "budget", child: true},
		// A typed-nil root is walked to the end, so it passes unchanged and is
		// answered as any plain outage.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}

	contexts := []struct {
		name   string
		cancel bool
	}{
		{name: "live"},
		{name: "cancelled", cancel: true},
	}

	for _, c := range contexts {
		for _, tc := range cases {
			row := c.name + "/" + tc.name
			if childRow != "" && childRow != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if tc.child && childRow == "" {
					limiterPortErrInChild(t, pwlPortErrRowEnv, pwlPortErrRan, row)

					return
				}

				defaults := swapDefaultLogger(t)

				plain := passwordlessLoaderThrough(t, plainOutage, c.cancel)
				require.Empty(t, abortRecords(plain.logs), "the reference writes no abort record")

				unknown := passwordlessLoaderThrough(t, identity.ErrUserNotFound, c.cancel)
				require.NotEqual(t, unknown.others(), plain.others(),
					"the unknown-user answer must be told apart from an outage for this test to bite")

				got := passwordlessLoaderThrough(t, tc.err, c.cancel)

				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, plain.header, got.header, "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.Equal(t, plain.loads, got.loads, "user loads")
				assert.Positive(t, got.loads, "the loader was asked")
				assert.Equal(t, plain.charged, got.charged, "charges to the source")
				assert.Equal(t, plain.sessions, got.sessions, "sessions saved")
				assert.Zero(t, got.sessions, "no session")
				assert.Equal(t, plain.events, got.events, "security events")
				assert.Equal(t, plain.others(), got.others(), "records besides the abort")
				assert.NotEqual(t, unknown.others(), got.others(), "never the unknown-user answer")
				assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")

				aborts := abortRecords(got.logs)
				if tc.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], tc.reason)
				}

				for _, r := range got.logs {
					assert.NotContains(t, r.Message, hostileSecret)
					r.Attrs(func(a slog.Attr) bool {
						assert.NotContains(t, a.Value.String(), hostileSecret, "attribute %q quotes the error", a.Key)

						return true
					})
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					fmt.Fprintln(os.Stdout, pwlPortErrRan+row)
				}
			})
		}
	}

}
