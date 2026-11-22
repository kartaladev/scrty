package httpsec_test

// The test in this file replaces slog.Default() for its duration, so it does
// not run in parallel, and restores the logger it found.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// lockoutPortOutcome is what one form login through a lockout policy produced
// that a client or the account can observe, and the abort records each
// logger received.
type lockoutPortOutcome struct {
	status int
	header http.Header
	body   string

	// recorded and resets are the attempt store's RecordFailure and Reset
	// calls for the username.
	recorded, resets int

	// authenticated is the authenticator's Authenticate calls: a password
	// check, or a lock's decoy.
	authenticated int

	lockoutAborts, chainAborts, defaultAborts []slog.Record
}

// lockoutPortLogin is how the attempt store answers the lockout policy's
// count on one login, and whether the chain discloses locks.
type lockoutPortLogin struct {
	count    int
	countErr error
	disclose bool
}

// lockoutPortLoginThrough serves one form login for "ada" through a chain
// whose pre-authentication phase is a sliding lockout policy (one failure in
// an hour locks) over an attempt store that answers its count as in says, and
// whose authenticator refuses the password.
func lockoutPortLoginThrough(t *testing.T, in lockoutPortLogin) lockoutPortOutcome {
	t.Helper()

	defaults := swapDefaultLogger(t)
	ctrl := gomock.NewController(t)

	var (
		mu  sync.Mutex
		out lockoutPortOutcome
	)

	authn := NewMockAuthenticator(ctrl)
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			mu.Lock()
			defer mu.Unlock()

			out.authenticated++

			return nil, authenticate.ErrAuthenticationFailed
		}).AnyTimes()

	attempts := NewMockAttemptStore(ctrl)
	attempts.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(in.count, in.countErr).AnyTimes()
	attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(context.Context, string, time.Time) error {
			mu.Lock()
			defer mu.Unlock()

			out.recorded++

			return nil
		}).AnyTimes()
	attempts.EXPECT().Reset(gomock.Any(), "ada").
		DoAndReturn(func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()

			out.resets++

			return nil
		}).AnyTimes()

	lockoutLogs, chainLogs := &capturingHandler{}, &capturingHandler{}

	lp, err := lockout.New(
		lockout.WithAttemptStore(attempts),
		lockout.WithSliding(1, time.Hour),
		lockout.WithLogger(slog.New(lockoutLogs)))
	require.NoError(t, err)

	opts := []httpsec.Option{
		httpsec.WithLogger(slog.New(chainLogs)),
		httpsec.WithPolicyEngine(engineOf(t, lp)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore())))),
			Tokens:        newMockGenerator(ctrl),
			Attempts:      attempts,
		}),
	}
	if in.disclose {
		opts = append(opts, httpsec.WithLockDisclosure())
	}

	chain, err := httpsec.New(opts...)
	require.NoError(t, err)

	rec := lockoutPortServeWithin(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath,
		url.Values{"username": {"ada"}, "password": {"guess"}}.Encode()))

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.lockoutAborts = abortRecords(lockoutLogs.records())
	out.chainAborts = abortRecords(chainLogs.records())
	out.defaultAborts = abortRecords(defaults.records())

	return out
}

// lockoutPortServeWithin serves req through the chain's net/http middleware
// and fails the test when the request does not finish in five seconds or lets
// a panic escape.
func lockoutPortServeWithin(t *testing.T, chain *httpsec.Chain, req *http.Request) *httptest.ResponseRecorder {
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
		require.False(t, r.panicked, "a hostile store error escaped as a panic: %v", r.value)

		return r.rec
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile store error hung the login")

		return nil
	}
}

// TestLockoutPortErrors_FormLogin pins, through the real request path, that a
// lockout policy whose attempt store returns a hostile error (a cycle, a
// fan-out, an Unwrap that panics) answers the login byte for byte as a plain
// store outage does, writes the same records for the username, and reports
// the abort once, to the lockout policy's own logger only. A cycle through
// Unwrap() []error is fatal unsanitized and is pinned in a child process by
// the lockout package's own TestLockoutPortErrors.
//
// It also pins how a plain lockout-store outage compares with a wrong
// password and with a lock, concealed or disclosed, as a client sees each.
func TestLockoutPortErrors_FormLogin(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	plain := lockoutPortLoginThrough(t, lockoutPortLogin{countErr: errAttemptStoreUnreachable})
	require.Empty(t, plain.lockoutAborts, "the reference writes no abort record")

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, got lockoutPortOutcome)
	}

	abortOnce := func(reason string) func(t *testing.T, got lockoutPortOutcome) {
		return func(t *testing.T, got lockoutPortOutcome) {
			require.Len(t, got.lockoutAborts, 1, "one abort record, on the lockout policy's logger")
			assertAbortRecord(t, got.lockoutAborts[0], reason)
			assert.Empty(t, got.chainAborts, "none on the chain's logger")
			assert.Empty(t, got.defaultAborts, "none on slog.Default()")
		}
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, assert: abortOnce("budget")},
		{name: "join fanning out", err: fanOut(25), assert: abortOnce("budget")},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, assert: abortOnce("panic")},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, assert: abortOnce("panic")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lockoutPortLoginThrough(t, lockoutPortLogin{countErr: tc.err})

			assert.Equal(t, plain.status, got.status, "status")
			assert.Equal(t, plain.header, got.header, "headers")
			assert.Equal(t, plain.body, got.body, "body")
			assert.Equal(t, plain.recorded, got.recorded, "failures recorded for the username")
			assert.Equal(t, plain.resets, got.resets, "clearings of the username")
			assert.Equal(t, plain.authenticated, got.authenticated, "password checks and decoys")
			assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
			tc.assert(t, got)
		})
	}

	// How a plain outage reads beside the answers it could be confused with.
	wrong := lockoutPortLoginThrough(t, lockoutPortLogin{})
	concealed := lockoutPortLoginThrough(t, lockoutPortLogin{count: 1})
	disclosed := lockoutPortLoginThrough(t, lockoutPortLogin{count: 1, disclose: true})

	// Today a lockout-store outage is the policy's deny, policy.ErrDenied,
	// answered 403. That is neither the wrong password's 401, which a
	// concealed lock shares, nor the disclosed lock's 429: a client can tell
	// an outage from both. This pins the existing answer; the hostile error
	// above takes exactly it.
	assert.Equal(t, http.StatusForbidden, plain.status, "a lockout-store outage")
	assert.Equal(t, http.StatusUnauthorized, wrong.status, "a wrong password")
	assert.Equal(t, http.StatusUnauthorized, concealed.status, "a concealed lock")
	assert.Equal(t, wrong.header, concealed.header, "a concealed lock's headers are a wrong password's")
	assert.Equal(t, wrong.body, concealed.body, "a concealed lock's body is a wrong password's")
	assert.Equal(t, http.StatusTooManyRequests, disclosed.status, "a disclosed lock")

	assert.Zero(t, plain.authenticated, "an outage checks no password and spends no decoy")
	assert.Zero(t, plain.recorded, "an outage records no failure for the username")
}

// errAttemptStoreUnreachable is a lockout store's plain outage.
var errAttemptStoreUnreachable = lockoutPortErr("attempt store: connection refused")

// lockoutPortErr is a plain error with fixed text.
type lockoutPortErr string

func (e lockoutPortErr) Error() string { return string(e) }
