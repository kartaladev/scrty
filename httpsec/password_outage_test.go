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
	// wrong is the wrong password served before the outage.
	wrong served

	// outages are the requests served while the store was down.
	outages   []served
	recovered served

	// recordedFailures is the username's failure count in the lockout policy's
	// store after the outage, and sourceFailures the failures the source
	// guard's limiter was charged on a context that had not ended, as a
	// limiter that honours cancellation records them. The wrong password
	// before the outage accounts for one of each.
	recordedFailures int
	sourceFailures   int
}

// TestPasswordLoginStoreOutageIsNotACredentialFailure pins that a user store
// that cannot answer is not a failed login, at form login and at Basic: the
// request is refused as unavailable and answered as a wrong password is,
// Basic's challenge included; it is charged once to the source, on a context
// with the client's cancellation stripped; nothing is recorded or cleared for
// the username, and a lockout policy with a failure-streak limit does not hold
// an account for failures its owner never made. Its hung-up rows pin the other
// side of that line: a client that hangs up mid-login did not find the store
// down, so the request is the uniform failure, answered 401 and charged to the
// source, but no password was compared, so nothing is recorded for the
// username. Its slow-store rows pin what follows from that: client timeouts in
// front of a slow store never hold an account.
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

		// ctx modifies the context each outage request is served on. nil
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
	// outage is still charged to its source, and still not to the username.
	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	// chargedAsAGuess is what every outage row asserts: each outage request
	// refused as unavailable, never as a refused credential, and answered 401
	// as a wrong password is; each charged once to the source; nothing
	// recorded or cleared for the username beyond the one wrong password
	// before it; and the right password accepted once the store is back.
	chargedAsAGuess := func(t *testing.T, run outageRun) {
		t.Helper()

		require.Len(t, run.outages, outageRequests)
		for i, out := range run.outages {
			require.ErrorIs(t, out.err, authenticate.ErrUnavailable, "outage request %d", i+1)
			assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed,
				"outage request %d was refused as a failed credential", i+1)
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err),
				"outage request %d was not answered as a wrong password", i+1)
			assert.NotContains(t, out.err.Error(), "db-primary",
				"outage request %d carried the store's error text", i+1)
			assert.False(t, out.handlerRan, "outage request %d reached the application", i+1)
		}

		assert.Equal(t, 1, run.recordedFailures,
			"the outage changed the username's failures: more than one is an outage recorded "+
				"as a failed login, none is a clear no login earned")
		assert.Equal(t, 1+outageRequests, run.sourceFailures,
			"each outage request was not charged once to the source")
		assert.NoError(t, run.recovered.err,
			"the right password was refused once the store recovered")
		assert.NotErrorIs(t, run.recovered.err, lockout.ErrAccountHeld,
			"the account was held for failures its owner never made")
	}

	// timingOut is a client that gives up on its request shortly after
	// sending it, as a client or proxy timeout does. The timer's resources are
	// released once the context ends.
	timingOut := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		context.AfterFunc(cctx, cancel)

		return cctx
	}

	// slowStore is a store that cannot answer before the caller's context
	// ends, and then fails with that context's error, as a SQL driver does.
	slowStore := func(ctx context.Context) error {
		<-ctx.Done()

		return fmt.Errorf("user store: load user: %w", ctx.Err())
	}

	// endedByTheCaller is a store failing with the error of the context it was
	// given, as a SQL driver does once the caller's context has ended.
	endedByTheCaller := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("user store: load user: %w", err)
		}

		return errUserStoreRefused
	}

	// chargedToTheSource is what a row whose clients left during the load
	// asserts, given how many did and the context error each left with: the
	// store did not fail, the caller left, so each is the uniform failure,
	// joined with that error and answered 401. It is charged to the source,
	// so a client timing its hang-ups cannot spend password work that no
	// throttle pays for, and recorded nothing for the username, because no
	// password was compared.
	chargedToTheSource := func(t *testing.T, run outageRun, requests int, ctxErr error) {
		t.Helper()

		require.Len(t, run.outages, requests)
		for i, out := range run.outages {
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "request %d", i+1)
			assert.ErrorIs(t, out.err, ctxErr,
				"request %d does not say the caller's context ended its load", i+1)
			assert.NotErrorIs(t, out.err, authenticate.ErrUnavailable,
				"request %d: a load the caller ended was answered as an outage, which nothing charges", i+1)
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err), "request %d", i+1)
			assert.False(t, out.handlerRan, "request %d reached the application", i+1)
		}

		assert.Equal(t, 1, run.recordedFailures,
			"a load the caller ended was recorded for the username, though no password was compared")
		assert.Equal(t, 1+requests, run.sourceFailures,
			"a load the caller ended was not charged to the source")
		assert.NoError(t, run.recovered.err,
			"the right password was refused once the store recovered")
		assert.NotErrorIs(t, run.recovered.err, lockout.ErrAccountHeld,
			"the account was held for loads its callers ended")
	}

	// challenged is what a Basic row whose client left asserts besides: each
	// refusal is a 401, so it carries the realm's challenge.
	challenged := func(t *testing.T, run outageRun) {
		t.Helper()

		for i, out := range run.outages {
			assert.NotEmpty(t, out.rec.Header().Get("WWW-Authenticate"),
				"request %d was answered 401 without a challenge", i+1)
		}
		assert.True(t, run.recovered.handlerRan, "the recovered request did not reach the application")
	}

	// challengedAsWrong is what a Basic outage row asserts besides: each
	// outage response carries the challenge the wrong password got.
	challengedAsWrong := func(t *testing.T, run outageRun) {
		t.Helper()

		want := run.wrong.rec.Header().Get("WWW-Authenticate")
		require.NotEmpty(t, want, "precondition: the wrong password was challenged")

		for i, out := range run.outages {
			assert.Equal(t, want, out.rec.Header().Get("WWW-Authenticate"),
				"outage request %d was not challenged as a wrong password is", i+1)
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

				chargedAsAGuess(t, run)
				challengedAsWrong(t, run)
			},
		},
		{
			name:    "basic, from a client that hung up",
			enable:  basic,
			request: basicReq,
			ctx:     cancelled,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				chargedAsAGuess(t, run)
				challengedAsWrong(t, run)
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

				chargedToTheSource(t, run, 1, context.Canceled)
				challenged(t, run)
			},
		},
		{
			name:    "basic, a slow store behind client timeouts never holds an account",
			enable:  basic,
			request: basicReq,
			ctx:     timingOut,
			downErr: slowStore,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				chargedToTheSource(t, run, outageRequests, context.DeadlineExceeded)
				challenged(t, run)
			},
		},
		{
			name:    "form login",
			enable:  formLogin,
			request: formReq,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				chargedAsAGuess(t, run)
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

				chargedAsAGuess(t, run)
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

				chargedToTheSource(t, run, 1, context.Canceled)
				loggedIn(t, run)
			},
		},
		{
			name:    "form login, a slow store behind client timeouts never holds an account",
			enable:  formLogin,
			request: formReq,
			ctx:     timingOut,
			downErr: slowStore,
			assert: func(t *testing.T, run outageRun) {
				t.Helper()

				chargedToTheSource(t, run, outageRequests, context.DeadlineExceeded)
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
			// A charge on a context that has ended is dropped, as a limiter
			// that honours cancellation drops it, so a charge the client's
			// hang-up could cancel is not counted.
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ string) error {
					if err := ctx.Err(); err != nil {
						return err
					}

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
			var run outageRun

			run.wrong = serve(t, chain, tc.request(t.Context(), "wrong"))
			require.ErrorIs(t, run.wrong.err, authenticate.ErrAuthenticationFailed)

			requests := outageRequests
			if tc.requests != 0 {
				requests = tc.requests
			}

			down.Store(true)
			for range requests {
				ctx := t.Context()
				if tc.ctx != nil {
					ctx = tc.ctx(ctx)
				}

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
