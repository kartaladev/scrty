package httpsec_test

// These tables probe a user-store outage from outside, as a client sees it:
// through the net/http middleware and its default error response. The
// lifecycle of the request's context during an outage, a client that hangs up
// included, is pinned by
// TestPasswordLoginStoreOutageIsNotACredentialFailure, so these tables carry
// no ctx modifier.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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

// outageGuess is the password every probe presents. No probe's password is
// ever compared with a stored hash, so its value does not matter.
const outageGuess = "guess" //nolint:gosec // G101: a fixture password, not a credential

// passwordEndpoint is form login or Basic authentication, wired with the
// collaborators an outage probe controls.
type passwordEndpoint struct {
	enable func(
		t *testing.T,
		authn authenticate.Authenticator,
		attempts policy.AttemptStore,
		limiter ratelimit.Limiter,
	) httpsec.Option

	// request builds the endpoint's request for username and outageGuess.
	request func(ctx context.Context, username string) *http.Request
}

func formLoginEndpoint() passwordEndpoint {
	return passwordEndpoint{
		enable: func(
			t *testing.T,
			authn authenticate.Authenticator,
			attempts policy.AttemptStore,
			limiter ratelimit.Limiter,
		) httpsec.Option {
			t.Helper()

			sessions, err := session.New(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: authn,
				Sessions:      sessions,
				Tokens:        NewMockGenerator(gomock.NewController(t)),
				Attempts:      attempts,
			}, httpsec.WithLoginLimiter(limiter))
		},
		request: func(ctx context.Context, username string) *http.Request {
			return formRequest(ctx, httpsec.DefaultLoginPath,
				url.Values{"username": {username}, "password": {outageGuess}}.Encode())
		},
	}
}

func basicEndpoint() passwordEndpoint {
	return passwordEndpoint{
		enable: func(
			_ *testing.T,
			authn authenticate.Authenticator,
			attempts policy.AttemptStore,
			limiter ratelimit.Limiter,
		) httpsec.Option {
			return httpsec.EnableBasicAuth(
				httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts},
				httpsec.WithBasicAuthLimiter(limiter))
		},
		request: func(ctx context.Context, username string) *http.Request {
			return basicRequest(ctx, username, outageGuess)
		},
	}
}

// probeAnswer is what a client received for one probe, and how many failures
// the probe charged to its source.
type probeAnswer struct {
	rec     *httptest.ResponseRecorder
	charged int32
}

// TestPasswordLoginOutageAnswersEveryUsernameAlike pins that a user store
// that cannot answer tells a client nothing about the username it probed: a
// held or locked account answers as a free one does while locks are
// concealed, the default, and a known user whose load fails answers as an
// unknown user whose load misses. Both probes answer as a wrong password does,
// with the same status, headers and body, and each is charged once to the
// source.
func TestPasswordLoginOutageAnswersEveryUsernameAlike(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint passwordEndpoint

		// lockout configures the lockout policy beyond its defaults.
		lockout []lockout.Option

		// users answers the user loader for the probed usernames.
		users func(m *MockUserLoader)

		// seed prepares the lockout policy before the probes.
		seed func(t *testing.T, p *lockout.Policy, engine *policy.Engine)

		// probes are the two usernames whose answers must not differ.
		probes [2]string

		assert func(t *testing.T, a, b probeAnswer)
	}

	// storeDown is a user store failing every load.
	storeDown := func(m *MockUserLoader) {
		m.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
			Return(nil, errUserStoreRefused).AnyTimes()
	}

	// partlyDown is a partial outage: the known user's load fails, on a table
	// only a found user's load reads, while the unknown user's load misses.
	partlyDown := func(m *MockUserLoader) {
		m.EXPECT().LoadByUsername(gomock.Any(), "known").
			Return(nil, errUserStoreRefused).AnyTimes()
		m.EXPECT().LoadByUsername(gomock.Any(), "nobody").
			Return(nil, identity.ErrUserNotFound).AnyTimes()
	}

	// bobFailed records failures for bob before the outage, enough for the
	// policy to refuse him, and checks that it does.
	bobFailed := func(t *testing.T, p *lockout.Policy, engine *policy.Engine) {
		t.Helper()

		for range 20 {
			require.NoError(t, p.Attempts().RecordFailure(t.Context(), "bob", time.Now()))
		}

		pre := engine.EvaluatePhase(t.Context(), policy.PreAuthentication,
			&policy.Input{Username: "bob", Now: time.Now()})
		require.ErrorIs(t, pre.Reason, lockout.ErrAccountLocked, "precondition: bob is refused")
	}

	held := []lockout.Option{lockout.WithFailureStreakLimit(10)}

	// alike is what every row asserts: both probes answered as a wrong
	// password is, identically, and each charged once to the source.
	alike := func(t *testing.T, a, b probeAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, a.rec.Code, "the first probe")
		assert.Equal(t, a.rec.Code, b.rec.Code, "the outage told the two usernames apart by status")
		assert.Equal(t, a.rec.Header(), b.rec.Header(),
			"the outage told the two usernames apart by headers")
		assert.Equal(t, a.rec.Body.String(), b.rec.Body.String(),
			"the outage told the two usernames apart by body")
		assert.Equal(t, int32(1), a.charged, "the first probe was not charged once to the source")
		assert.Equal(t, int32(1), b.charged, "the second probe was not charged once to the source")
	}

	// challenged is what a Basic row asserts besides: the answer is the
	// wrong-password answer, so it carries the realm's challenge.
	challenged := func(t *testing.T, a, b probeAnswer) {
		t.Helper()

		alike(t, a, b)
		assert.Equal(t, `Basic realm="Restricted"`, a.rec.Header().Get("WWW-Authenticate"))
	}

	cases := []testCase{
		{
			name:     "a held account answers an outage as a free one does, at form login",
			endpoint: formLoginEndpoint(),
			lockout:  held,
			users:    storeDown,
			seed:     bobFailed,
			probes:   [2]string{"bob", "ada"},
			assert:   alike,
		},
		{
			name:     "a held account answers an outage as a free one does, at Basic",
			endpoint: basicEndpoint(),
			lockout:  held,
			users:    storeDown,
			seed:     bobFailed,
			probes:   [2]string{"bob", "ada"},
			assert:   challenged,
		},
		{
			name:     "a locked account answers an outage as a free one does, at form login",
			endpoint: formLoginEndpoint(),
			users:    storeDown,
			seed:     bobFailed,
			probes:   [2]string{"bob", "ada"},
			assert:   alike,
		},
		{
			name:     "a locked account answers an outage as a free one does, at Basic",
			endpoint: basicEndpoint(),
			users:    storeDown,
			seed:     bobFailed,
			probes:   [2]string{"bob", "ada"},
			assert:   challenged,
		},
		{
			name:     "known and unknown users answer a partial outage alike, at form login",
			endpoint: formLoginEndpoint(),
			users:    partlyDown,
			probes:   [2]string{"known", "nobody"},
			assert:   alike,
		},
		{
			name:     "known and unknown users answer a partial outage alike, at Basic",
			endpoint: basicEndpoint(),
			users:    partlyDown,
			probes:   [2]string{"known", "nobody"},
			assert:   challenged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			users := NewMockUserLoader(ctrl)
			tc.users(users)

			authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(e2eEncoder(t)),
				authenticate.WithPasswordLogger(discardLogger()))
			require.NoError(t, err)

			p, err := lockout.New(append([]lockout.Option{lockout.WithLogger(discardLogger())},
				tc.lockout...)...)
			require.NoError(t, err)

			engine := engineOf(t, p)

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
				httpsec.WithPolicyEngine(engine),
				tc.endpoint.enable(t, authn, p.Attempts(), limiter))
			require.NoError(t, err)

			if tc.seed != nil {
				tc.seed(t, p, engine)
			}

			var answers [2]probeAnswer

			for i, username := range tc.probes {
				before := charged.Load()

				rec := httptest.NewRecorder()
				chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusTeapot)
				})).ServeHTTP(rec, tc.endpoint.request(t.Context(), username))

				answers[i] = probeAnswer{rec: rec, charged: charged.Load() - before}
			}

			tc.assert(t, answers[0], answers[1])
		})
	}
}

// TestRecoveryCompleteOutageAnswersEveryUsernameAlike pins that a recovery
// whose own user lookup meets a user store that cannot answer tells a client
// nothing about the username it probed: a known user whose load fails answers
// as an unknown user whose load misses does. Both answer as a refused proof
// does, with the same status and headers, and each is charged once to the
// source.
func TestRecoveryCompleteOutageAnswersEveryUsernameAlike(t *testing.T) {
	t.Parallel()

	const unknownAddress = "nobody@example.com"

	type testCase struct {
		name string

		// users answers the user loader for the probed usernames.
		users func(m *MockUserLoader)

		assert func(t *testing.T, known, unknown probeAnswer)
	}

	// alike is what every row asserts: both probes answered as a refused
	// proof is, identically, and each charged once to the source.
	alike := func(t *testing.T, known, unknown probeAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, unknown.rec.Code, "the unknown user")
		assert.Equal(t, unknown.rec.Code, known.rec.Code,
			"the outage told the two usernames apart by status")
		assert.Equal(t, unknown.rec.Header(), known.rec.Header(),
			"the outage told the two usernames apart by headers")
		assert.Equal(t, int32(1), known.charged, "the known user was not charged once to the source")
		assert.Equal(t, int32(1), unknown.charged, "the unknown user was not charged once to the source")
	}

	cases := []testCase{
		{
			name: "known and unknown users answer a partial outage alike",
			users: func(m *MockUserLoader) {
				m.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).
					Return(nil, errUserStoreRefused).AnyTimes()
				m.EXPECT().LoadByUsername(gomock.Any(), unknownAddress).
					Return(nil, identity.ErrUserNotFound).AnyTimes()
			},
			assert: alike,
		},
		{
			name: "every user answers a total outage as an unknown user does",
			users: func(m *MockUserLoader) {
				m.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
					Return(nil, errUserStoreRefused).AnyTimes()
			},
			assert: func(t *testing.T, known, unknown probeAnswer) {
				t.Helper()

				alike(t, known, unknown)
				assert.NotContains(t, known.rec.Body.String(), "connection refused",
					"the outage's driver text reached the client")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)

			ctrl := gomock.NewController(t)

			users := NewMockUserLoader(ctrl)
			tc.users(users)

			h.users = users

			var err error

			h.authn, err = authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(e2eEncoder(t)),
				authenticate.WithPasswordLogger(discardLogger()))
			require.NoError(t, err)

			var charged atomic.Int32

			limiter := NewMockLimiter(ctrl)
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, string) error {
					charged.Add(1)

					return nil
				}).AnyTimes()

			h.recOpts = []httpsec.RecoveryOption{
				httpsec.WithRecoveryLimiter(limiter),
				httpsec.WithRecoveryUserLimiter(countingLimiter(t, 0)),
			}

			h.build(t)

			saved := h.saved(t)

			probe := func(username string) probeAnswer {
				before := charged.Load()

				rec := h.through(postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource,
					url.Values{
						httpsec.RecoveryUsernameParam:  {username},
						httpsec.RecoverySavedCodeParam: {saved},
						httpsec.RecoveryPasswordParam:  {e2ePassword},
					}))

				return probeAnswer{rec: rec, charged: charged.Load() - before}
			}

			known := probe(e2eAddress)
			unknown := probe(unknownAddress)

			tc.assert(t, known, unknown)
		})
	}
}

// TestPasswordLoginOutageIsChargedToTheSource pins that an outage costs its
// source: with the store failing every load, the source guard refuses the
// requests beyond its limit, and no password work is spent on them.
func TestPasswordLoginOutageIsChargedToTheSource(t *testing.T) {
	t.Parallel()

	const (
		sourceLimit = 5
		requests    = sourceLimit + 3
	)

	type testCase struct {
		name     string
		endpoint passwordEndpoint
		assert   func(t *testing.T, refusals []error, matches int32)
	}

	guarded := func(t *testing.T, refusals []error, matches int32) {
		t.Helper()

		require.Len(t, refusals, requests)

		var throttled int

		for i, err := range refusals {
			if errors.Is(err, ratelimit.ErrThrottled) {
				throttled++

				continue
			}

			assert.ErrorIs(t, err, authenticate.ErrUnavailable, "request %d", i+1)
		}

		statuses := make([]int, 0, len(refusals))
		for _, err := range refusals {
			statuses = append(statuses, httpsec.StatusForError(err))
		}

		assert.Equal(t, slices.Repeat([]int{http.StatusUnauthorized}, requests), statuses,
			"every request, the guard's refusals and the outages alike, answers as a wrong password")

		assert.Equal(t, requests-sourceLimit, throttled,
			"the source guard did not refuse the outage requests beyond its limit")
		assert.Equal(t, int32(sourceLimit), matches,
			"password work was spent beyond the source's allowance, charged to no one")
	}

	cases := []testCase{
		{name: "form login", endpoint: formLoginEndpoint(), assert: guarded},
		{name: "basic", endpoint: basicEndpoint(), assert: guarded},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
				Return(nil, errUserStoreRefused).AnyTimes()

			// Each Match is one full password derivation, the work an outage
			// still spends so that its timing does not change.
			var matches atomic.Int32

			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return(lockReferenceHash, nil).AnyTimes()
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).
				DoAndReturn(func(string, []byte) bool {
					matches.Add(1)

					return false
				}).AnyTimes()

			authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
				authenticate.WithPasswordEncoder(enc),
				authenticate.WithPasswordLogger(discardLogger()))
			require.NoError(t, err)

			p, err := lockout.New(lockout.WithLogger(discardLogger()))
			require.NoError(t, err)

			limiter, err := ratelimit.NewMemoryLimiter(sourceLimit, 15*time.Minute)
			require.NoError(t, err)

			chain, err := httpsec.New(
				httpsec.WithLogger(discardLogger()),
				httpsec.WithPolicyEngine(engineOf(t, p)),
				tc.endpoint.enable(t, authn, p.Attempts(), limiter))
			require.NoError(t, err)

			refusals := make([]error, 0, requests)

			for range requests {
				out := serve(t, chain, tc.endpoint.request(t.Context(), "ada"))
				require.Error(t, out.err, "an outage request was let through")

				refusals = append(refusals, out.err)
			}

			tc.assert(t, refusals, matches.Load())
		})
	}
}
