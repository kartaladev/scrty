package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// errUserStoreRefused is the connection error the user store answers with
// while it is down. Its text names a host on purpose: it must reach no caller.
var errUserStoreRefused = errors.New("user store: connection refused to db-primary:5432")

// outageRun is what one row's sequence produced: a wrong password while the
// store is up, the row's requests with the right password while it is down,
// then the right password once it has recovered.
type outageRun struct {
	// outages are the requests served while the store was down.
	outages   []served
	recovered served

	// recordedFailures is the username's failure count in the lockout policy's
	// store after the outage, and sourceFailures the failures the source
	// guard's limiter was charged. The wrong password before the outage
	// accounts for one of each.
	recordedFailures int
	sourceFailures   int
}

// TestPasswordLoginStoreOutageIsNotACredentialFailure pins that a user store
// that cannot answer is not a failed login, at form login and at Basic: the
// request is refused as unavailable, nothing is recorded, counted or cleared,
// and a lockout policy with a failure-streak limit does not hold an account
// for failures its owner never made. Its hung-up rows pin the other side of
// that line: a client that hangs up mid-login did not find the store down, so
// the request is the uniform failure, answered 401, recorded for the username
// and charged to the source like any guess.
func TestPasswordLoginStoreOutageIsNotACredentialFailure(t *testing.T) {
	t.Parallel()

	const (
		username      = "ada"
		rightPassword = "right horse battery" //nolint:gosec // G101: a fixture password, not a credential
		// outageRequests reaches the failure-streak limit, so an outage counted
		// as failures would hold the account.
		outageRequests = 3
	)

	type testCase struct {
		name string

		// enable wires the endpoint under test, recording into attempts and
		// counting source failures against limiter.
		enable func(
			t *testing.T,
			authn authenticate.Authenticator,
			attempts policy.AttemptStore,
			limiter ratelimit.Limiter,
		) httpsec.Option

		// request builds the endpoint's request for the password.
		request func(ctx context.Context, password string) *http.Request

		// ctx modifies the context the outage requests are served on. nil
		// means the test's own.
		ctx func(ctx context.Context) context.Context

		// downErr is what the user store fails with while it is down, given
		// the context the load ran on. nil means errUserStoreRefused.
		downErr func(ctx context.Context) error

		// requests is how many requests are served while the store is down.
		// Zero means outageRequests.
		requests int

		assert func(t *testing.T, run outageRun)
	}

	basic := func(
		_ *testing.T,
		authn authenticate.Authenticator,
		attempts policy.AttemptStore,
		limiter ratelimit.Limiter,
	) httpsec.Option {
		return httpsec.EnableBasicAuth(
			httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts},
			httpsec.WithBasicAuthLimiter(limiter))
	}

	basicReq := func(ctx context.Context, password string) *http.Request {
		return basicRequest(ctx, username, password)
	}

	formLogin := func(
		t *testing.T,
		authn authenticate.Authenticator,
		attempts policy.AttemptStore,
		limiter ratelimit.Limiter,
	) httpsec.Option {
		t.Helper()

		sessions, err := session.New(session.WithStore(session.NewMemoryStore()))
		require.NoError(t, err)

		tokens := NewMockGenerator(gomock.NewController(t))
		tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("tok", nil).AnyTimes()

		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      sessions,
			Tokens:        tokens,
			Attempts:      attempts,
		}, httpsec.WithLoginLimiter(limiter))
	}

	formReq := func(ctx context.Context, password string) *http.Request {
		return formRequest(ctx, httpsec.DefaultLoginPath,
			url.Values{"username": {username}, "password": {password}}.Encode())
	}

	// cancelled is a client that hung up after sending its request: the
	// endpoints charge a hung-up guess, so it must not turn an outage into one.
	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	// notCounted is what every row asserts: each outage request refused as
	// unavailable, answered 503 and never as a refused credential; nothing
	// recorded, counted or cleared beyond the one wrong password before it;
	// and the right password accepted once the store is back.
	notCounted := func(t *testing.T, run outageRun) {
		t.Helper()

		require.Len(t, run.outages, outageRequests)
		for i, out := range run.outages {
			require.ErrorIs(t, out.err, authenticate.ErrUnavailable, "outage request %d", i+1)
			assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed,
				"outage request %d was refused as a failed credential", i+1)
			assert.Equal(t, http.StatusServiceUnavailable, httpsec.StatusForError(out.err),
				"outage request %d", i+1)
			assert.NotContains(t, out.err.Error(), "db-primary",
				"outage request %d carried the store's error text", i+1)
			assert.False(t, out.handlerRan, "outage request %d reached the application", i+1)
		}

		assert.Equal(t, 1, run.recordedFailures,
			"the outage changed the username's failures: more than one is an outage recorded "+
				"as a failed login, none is a clear no login earned")
		assert.Equal(t, 1, run.sourceFailures,
			"the outage was counted against the source as failed logins")
		assert.NoError(t, run.recovered.err,
			"the right password was refused once the store recovered")
		assert.NotErrorIs(t, run.recovered.err, lockout.ErrAccountHeld,
			"the account was held for failures its owner never made")
	}

	// endedByTheCaller is a store failing with the error of the context it was
	// given, as a SQL driver does once the caller's context has ended.
	endedByTheCaller := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("user store: load user: %w", err)
		}

		return errUserStoreRefused
	}

	// chargedAsAGuess is what a row whose client hung up during the load
	// asserts: the store did not fail, the caller left, so it is the uniform
	// failure, answered 401, recorded for the username and charged to the
	// source like any guess. Otherwise a client timing its hang-ups would
	// spend password work that no throttle pays for.
	chargedAsAGuess := func(t *testing.T, run outageRun) {
		t.Helper()

		require.Len(t, run.outages, 1)
		out := run.outages[0]
		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.NotErrorIs(t, out.err, authenticate.ErrUnavailable,
			"a load the caller ended was answered as an outage, which nothing charges")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan, "the hung-up request reached the application")

		assert.Equal(t, 2, run.recordedFailures,
			"the hung-up request was not recorded for the username")
		assert.Equal(t, 2, run.sourceFailures,
			"the hung-up request was not charged to the source")
		assert.NoError(t, run.recovered.err,
			"the right password was refused once the store recovered")
	}

	// noChallenge is what a Basic row asserts besides: no credential was
	// refused, so no outage response asks for one.
	noChallenge := func(t *testing.T, run outageRun) {
		t.Helper()

		for i, out := range run.outages {
			assert.Empty(t, out.rec.Header().Get("WWW-Authenticate"),
				"outage request %d was challenged as though its credential had been refused", i+1)
		}
		assert.True(t, run.recovered.handlerRan, "the recovered request did not reach the application")
	}

	// loggedIn is what a form login row asserts besides: the recovered login
	// was answered by the endpoint itself.
	loggedIn := func(t *testing.T, run outageRun) {
		t.Helper()

		assert.Equal(t, http.StatusOK, run.recovered.rec.Code)
	}

	cases := []testCase{
		{
			name:    "basic",
			enable:  basic,
			request: basicReq,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				notCounted(t, run)
				noChallenge(t, run)
			},
		},
		{
			name:    "basic, from a client that hung up",
			enable:  basic,
			request: basicReq,
			ctx:     cancelled,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				notCounted(t, run)
				noChallenge(t, run)
			},
		},
		{
			name:     "basic, from a client that hung up during the load",
			enable:   basic,
			request:  basicReq,
			ctx:      cancelled,
			downErr:  endedByTheCaller,
			requests: 1,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				chargedAsAGuess(t, run)
				assert.True(t, run.recovered.handlerRan, "the recovered request did not reach the application")
			},
		},
		{
			name:    "form login",
			enable:  formLogin,
			request: formReq,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				notCounted(t, run)
				loggedIn(t, run)
			},
		},
		{
			name:    "form login, from a client that hung up",
			enable:  formLogin,
			request: formReq,
			ctx:     cancelled,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				notCounted(t, run)
				loggedIn(t, run)
			},
		},
		{
			name:     "form login, from a client that hung up during the load",
			enable:   formLogin,
			request:  formReq,
			ctx:      cancelled,
			downErr:  endedByTheCaller,
			requests: 1,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				chargedAsAGuess(t, run)
				loggedIn(t, run)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			hash, err := e2eEncoder(t).Encode(rightPassword)
			require.NoError(t, err)

			var down atomic.Bool

			downErr := func(context.Context) error { return errUserStoreRefused }
			if tc.downErr != nil {
				downErr = tc.downErr
			}

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), username).
				DoAndReturn(func(ctx context.Context, _ string) (*identity.Details, error) {
					if down.Load() {
						return nil, downErr(ctx)
					}

					return &identity.Details{ID: "u-1", Username: username, Password: hash, Active: true}, nil
				}).AnyTimes()

			authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(e2eEncoder(t)),
				authenticate.WithPasswordLogger(discardLogger()))
			require.NoError(t, err)

			holds, err := lockout.New(
				lockout.WithWaitThreshold(2),
				lockout.WithWait(time.Nanosecond, time.Nanosecond),
				lockout.WithFailureStreakLimit(outageRequests),
				lockout.WithLogger(discardLogger()))
			require.NoError(t, err)

			var charged atomic.Int32

			limiter := NewMockLimiter(ctrl)
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, string) error {
					charged.Add(1)

					return nil
				}).AnyTimes()

			chain, err := httpsec.New(
				httpsec.WithLogger(discardLogger()),
				httpsec.WithPolicyEngine(engineOf(t, holds)),
				tc.enable(t, authn, holds.Attempts(), limiter))
			require.NoError(t, err)

			// One real failure first, so the run shows both that a failure is
			// counted here and that the outage neither adds to nor clears it.
			wrong := serve(t, chain, tc.request(t.Context(), "wrong"))
			require.ErrorIs(t, wrong.err, authenticate.ErrAuthenticationFailed)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			requests := outageRequests
			if tc.requests != 0 {
				requests = tc.requests
			}

			var run outageRun

			down.Store(true)
			for range requests {
				run.outages = append(run.outages, serveIn(ctx, t, chain, tc.request(ctx, rightPassword)))
			}

			run.recordedFailures, err = holds.Attempts().FailureCount(t.Context(), username,
				time.Now().Add(-time.Hour))
			require.NoError(t, err)
			run.sourceFailures = int(charged.Load())

			down.Store(false)
			run.recovered = serve(t, chain, tc.request(t.Context(), rightPassword))

			tc.assert(t, run)
		})
	}
}
