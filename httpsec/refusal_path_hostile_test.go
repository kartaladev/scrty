package httpsec_test

// Every row of the test in this file replaces slog.Default() for its duration,
// so none of them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// refusalWatchdog bounds one request on the refusal path. A bounded walk takes
// well under a millisecond; an unbounded one on a cyclic error never returns.
const refusalWatchdog = 2 * time.Second

// streamDependencyFailed is what the signal stream's record of a dependency
// failure says.
const streamDependencyFailed = "a dependency failed"

// selectiveIs matches the sentinel matches through its own Is method, and
// panics when asked about panicsOn and nothing else. With panicsOnThrottleMark
// its As method panics when asked for the per-request throttle's mark, and
// answers false to every other As. So a status lookup that matches matches
// before it would ask about panicsOn answers without meeting the panic, and
// only the refusal-path check that asks about panicsOn does.
type selectiveIs struct {
	matches              error
	panicsOn             error
	panicsOnThrottleMark bool
}

func (selectiveIs) Error() string { return hostileSecret }

func (e selectiveIs) Is(target error) bool {
	if e.panicsOn != nil && target == e.panicsOn { //nolint:errorlint // the identity of the target asked about
		panic(isPanicMessage)
	}

	return e.matches != nil && target == e.matches //nolint:errorlint // the identity of the target asked about
}

func (e selectiveIs) As(target any) bool {
	if e.panicsOnThrottleMark && httpsec.IsPerRequestThrottleTarget(target) {
		panic(isPanicMessage)
	}

	return false
}

// refusalWorld is what one row observes: the chain's records and the events.
type refusalWorld struct {
	chainLogs *capturingHandler

	mu     sync.Mutex
	events []string
}

func (w *refusalWorld) logger() httpsec.Option {
	return httpsec.WithLogger(slog.New(w.chainLogs))
}

func (w *refusalWorld) securityEvents() httpsec.Option {
	return httpsec.EnableSecurityEvents(func(_ context.Context, e event.Event) {
		w.mu.Lock()
		defer w.mu.Unlock()

		w.events = append(w.events, e.Name)
	})
}

func (w *refusalWorld) emitted() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]string(nil), w.events...)
}

// refusalGot is what a row's request produced.
type refusalGot struct {
	status        int
	header        http.Header
	events        []string
	chainRecords  []slog.Record
	chainAborts   []slog.Record
	defaultAborts []slog.Record
}

// refusingWith is a consumer's interceptor that refuses every request with err.
func refusingWith(err error) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
		return err
	}), httpsec.Order(100))
}

// behindChain mounts handler behind a chain built from opts, failing the row
// if the route is reached.
func behindChain(t *testing.T, handler http.Handler, opts ...httpsec.Option) http.Handler {
	t.Helper()

	chain, err := httpsec.New(opts...)
	require.NoError(t, err)

	if handler == nil {
		handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("the route ran behind a refusal")
		})
	}

	return chain.Middleware()(handler)
}

// guardRefusing is a route guard built with opts, whose authorizer refuses
// with err, in front of a route that must not run.
func guardRefusing(t *testing.T, err error, opts ...httpsec.GuardOption) http.Handler {
	t.Helper()

	az := NewMockAuthorizer(gomock.NewController(t))
	az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(err).AnyTimes()

	mw := mustGuards(t, az, opts...).ResourcePrivileges("records", "record").RequireOne("read")

	return mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the route ran behind a guard's refusal")
	}))
}

// principalRequest is a request for a record from a signed-in principal, as a
// guard behind a chain sees one.
func principalRequest(ctx context.Context) *http.Request {
	return httptest.NewRequestWithContext(identity.WithPrincipal(ctx, testPrincipal()), http.MethodGet, "/records/r-1", nil)
}

// streamRequest asks for the signal stream as a same-origin browser does,
// with credential as its bearer when it is not empty.
func streamRequest(ctx context.Context, credential string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)
	req.RemoteAddr = "192.0.2.10:4242"
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}

	return req
}

// signedInBearer is a session bearer over a memory store holding one sign-in
// of u-1, and that sign-in's reference.
func signedInBearer(t *testing.T) (httpsec.Option, string) {
	t.Helper()

	sessions, err := session.New(
		session.WithStore(must.Must(session.NewMemoryStore())),
		session.WithIdleTimeout(30*time.Minute),
		session.WithAbsoluteTimeout(12*time.Hour),
	)
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: usersAnswering(t)}), s.ID
}

// usersAnswering is a user loader that answers storedUser for any user.
func usersAnswering(t *testing.T) *MockUserLoader {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(storedUser(), nil).AnyTimes()

	return users
}

// deniedPerRequestBy is a policy engine whose per-request phase denies with
// reason.
func deniedPerRequestBy(t *testing.T, reason error) httpsec.Option {
	t.Helper()

	return httpsec.WithPolicyEngine(engineOf(t,
		phasePolicy(t, policy.Decision{Outcome: policy.Deny, Reason: reason}, policy.PerRequest)))
}

// serveRefusalWithin serves r on h on its own goroutine, and fails the row when it
// does not return within refusalWatchdog or lets a panic escape, so a hostile
// error on the refusal path is a failure with a name instead of a hung suite.
// A stack overflow still kills the process, which nothing can recover.
func serveRefusalWithin(t *testing.T, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	type outcome struct {
		panicked bool
		value    any
	}

	rec := httptest.NewRecorder()
	done := make(chan outcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- outcome{panicked: true, value: recover()}
			}
		}()

		h.ServeHTTP(rec, r)

		returned = true
		done <- outcome{}
	}()

	select {
	case o := <-done:
		if o.panicked {
			t.Fatalf("a panic escaped the refusal path: %v", o.value)
		}

		return rec
	case <-time.After(refusalWatchdog):
		t.Fatalf("the refusal path did not return within %v", refusalWatchdog)

		return nil
	}
}

// refusalSite is one inspection of the refused error, with the configuration
// that reaches it and its answer to a non-hostile error as the code before the
// bounded walk gave it.
type refusalSite struct {
	name string
	// build returns the handler and the request that carry err to the site.
	build func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request)
	// parity is the non-hostile error, and parityAssert what it is answered.
	parity       error
	parityAssert func(t *testing.T, g refusalGot)
}

// TestRefusalPath_HostileChains pins that every inspection of the refused
// error on the refusal path is bounded and recovering: a cyclic error and an
// error whose Is method panics each get the fail-closed outcome, with no hang,
// no escaped panic, no event and one record of the aborted classification,
// while a non-hostile error is answered exactly as before.
func TestRefusalPath_HostileChains(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		build  func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request)
		assert func(t *testing.T, g refusalGot)
	}

	plainRequest := func(ctx context.Context) *http.Request {
		return httptest.NewRequestWithContext(ctx, http.MethodGet, "/records", nil)
	}

	statusAndEvents := func(status int, events ...string) func(*testing.T, refusalGot) {
		return func(t *testing.T, g refusalGot) {
			t.Helper()
			assert.Equal(t, status, g.status)
			assert.Equal(t, events, g.events)
			assert.Empty(t, g.chainAborts)
			assert.Empty(t, g.defaultAborts)
		}
	}

	dpopChallenged := func(status int) func(*testing.T, refusalGot) {
		return func(t *testing.T, g refusalGot) {
			t.Helper()
			assert.Equal(t, status, g.status)
			assert.Contains(t, strings.Join(g.header.Values("WWW-Authenticate"), ", "), "DPoP")
			assert.Empty(t, g.chainAborts)
			assert.Empty(t, g.defaultAborts)
		}
	}

	authorizationRules := func(events bool) func(*testing.T, *refusalWorld, error) (http.Handler, *http.Request) {
		return func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
			t.Helper()

			opts := []httpsec.Option{
				w.logger(),
				httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authorize.Rule[httpsec.Request]{
					Match:   func(httpsec.Request) bool { return true },
					Require: func(context.Context) error { return err },
				}),
			}
			if events {
				opts = append(opts, w.securityEvents())
			}

			return behindChain(t, nil, opts...), plainRequest(t.Context())
		}
	}

	sites := []refusalSite{
		{
			name:         "the authorization stage's rule, always",
			build:        authorizationRules(false),
			parity:       fmt.Errorf("%w: rule", authorize.ErrAccessDenied),
			parityAssert: statusAndEvents(http.StatusForbidden),
		},
		{
			name:         "the authorization stage's rule, events on",
			build:        authorizationRules(true),
			parity:       fmt.Errorf("%w: rule", authorize.ErrAccessDenied),
			parityAssert: statusAndEvents(http.StatusForbidden, event.AuthzFail),
		},
		{
			name: "the refusal event, events on, the request's context ended",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				return behindChain(t, nil, w.logger(), w.securityEvents(), refusingWith(err)), plainRequest(ctx)
			},
			parity:       httpsec.ErrCrossSiteRequest,
			parityAssert: statusAndEvents(http.StatusForbidden, event.MaliciousCSRF),
		},
		{
			name: "a guard's refusal event, events on",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				return behindChain(t, guardRefusing(t, err), w.logger(), w.securityEvents()), principalRequest(t.Context())
			},
			parity:       authorize.ErrAccessDenied,
			parityAssert: statusAndEvents(http.StatusForbidden, event.AuthzFail),
		},
		{
			name: "the DPoP challenge of a refusal leaving the chain",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)

				return behindChain(t, nil, w.logger(), bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}), refusingWith(err)),
					plainRequest(t.Context())
			},
			parity:       httpsec.ErrAuthenticationRequired,
			parityAssert: dpopChallenged(http.StatusUnauthorized),
		},
		{
			name: "the DPoP challenge of a guard's refusal",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)

				return behindChain(t, guardRefusing(t, err), w.logger(), bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL})),
					principalRequest(t.Context())
			},
			parity:       authorize.ErrAuthenticationRequired,
			parityAssert: dpopChallenged(http.StatusUnauthorized),
		},
		{
			name: "the signal stream's retry, a refusal on its path",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)

				return behindChain(t, nil, w.logger(), bearer,
						httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
						refusedOnThePath(err, httpsec.Before(httpsec.OrderBearerToken))),
					streamRequest(t.Context(), "")
			},
			// A store's failure is told to come back.
			parity: errors.New("the store is down"),
			parityAssert: func(t *testing.T, g refusalGot) {
				t.Helper()
				assert.Equal(t, http.StatusOK, g.status, "told only to retry")
				assert.Empty(t, g.chainAborts)
			},
		},
		{
			name: "the signal stream's throttle, a per-request policy's denial",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				bearer, sid := signedInBearer(t)

				return behindChain(t, nil, w.logger(), bearer, deniedPerRequestBy(t, err),
						httpsec.EnableSessionSignals(httpsec.SessionSignals{})),
					streamRequest(t.Context(), sid)
			},
			parity: ratelimit.ErrThrottled,
			parityAssert: func(t *testing.T, g refusalGot) {
				t.Helper()
				assert.Equal(t, http.StatusOK, g.status, "a throttled sign-in is told only to retry")
				assert.Empty(t, g.chainAborts)
			},
		},
		{
			name: "a per-request policy's denial, events on",
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				bearer, sid := signedInBearer(t)

				req := plainRequest(t.Context())
				req.Header.Set("Authorization", "Bearer "+sid)

				return behindChain(t, nil, w.logger(), w.securityEvents(), bearer, deniedPerRequestBy(t, err)), req
			},
			parity:       policy.ErrSessionIdle,
			parityAssert: statusAndEvents(http.StatusUnauthorized, event.SessionExpired),
		},
	}

	// failClosed is the outcome every hostile row must get: status, no event,
	// nothing of the error in a header, and one record of the abort.
	failClosed := func(status int, reason string) func(*testing.T, refusalGot) {
		return func(t *testing.T, g refusalGot) {
			t.Helper()
			assert.Equal(t, status, g.status)
			assert.Empty(t, g.events, "an aborted classification reports no event")
			assert.Empty(t, g.header.Values("WWW-Authenticate"), "an aborted classification sets no challenge")

			for name, values := range g.header {
				assert.NotContains(t, strings.Join(values, " "), hostileSecret, "header %s quotes the error", name)
			}

			all := append(append([]slog.Record(nil), g.chainAborts...), g.defaultAborts...)
			require.Len(t, all, 1, "one record per aborted request")
			assertAbortRecord(t, all[0], reason)
		}
	}

	var cases []testCase

	for _, s := range sites {
		cases = append(cases,
			testCase{name: s.name + "/cyclic", err: &cycleOne{}, build: s.build,
				assert: failClosed(http.StatusInternalServerError, "budget")},
			testCase{name: s.name + "/cyclic join", err: &cycleMany{}, build: s.build,
				assert: failClosed(http.StatusInternalServerError, "budget")},
			testCase{name: s.name + "/panicking Is", err: isPanics{}, build: s.build,
				assert: failClosed(http.StatusInternalServerError, "panic")},
			testCase{name: s.name + "/as before", err: s.parity, build: s.build, assert: s.parityAssert},
		)
	}

	cases = append(cases,
		testCase{
			// The lookup answers 401 from the first row of its table, so the
			// refusal event's own check, after it, is the first to meet the
			// panic. The answer stands; the event is lost, and the abort is
			// reported, since the dispatch's lookup does not meet it.
			name: "the refusal event's own check, past the lookup, events on",
			err:  selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired},
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				return behindChain(t, nil, w.logger(), w.securityEvents(), refusingWith(err)), plainRequest(t.Context())
			},
			assert: func(t *testing.T, g refusalGot) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, g.status)
				assert.Empty(t, g.events)
				require.Len(t, g.chainAborts, 1)
				assertAbortRecord(t, g.chainAborts[0], "panic")
				assert.Empty(t, g.defaultAborts)
			},
		},
		testCase{
			// The standard library walks this fan-out in a few thousand steps,
			// and the library's walk refuses it past its budget: before the
			// stream's own checks were bounded, it read as a dependency
			// failure and was told to retry.
			name: "the signal stream logs an abort as an abort, not a dependency failure",
			err:  fanOut(11),
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)

				return behindChain(t, nil, w.logger(), bearer,
						httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
						refusedOnThePath(err, httpsec.Before(httpsec.OrderBearerToken))),
					streamRequest(t.Context(), "")
			},
			assert: func(t *testing.T, g refusalGot) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, g.status, "an abort is not told to retry")

				for _, r := range g.chainRecords {
					assert.NotContains(t, r.Message, streamDependencyFailed, "an abort recorded as a dependency failure")
				}

				require.Len(t, g.chainAborts, 1, "one record, through the signals logger")
				assertAbortRecord(t, g.chainAborts[0], "budget")
				assert.Empty(t, g.defaultAborts)
			},
		},
		testCase{
			// The consumer's handler answers instead of the dispatch, which
			// therefore classifies nothing, and events are off, so no event
			// check classifies either: the authorization stage, whose walk
			// aborts with the lookup's, is the only one left to report.
			name: "the authorization stage's rule under a consumer's error handler, events off/cyclic",
			err:  &cycleOne{},
			build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				return behindChain(t, nil, w.logger(),
					httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authorize.Rule[httpsec.Request]{
						Match:   func(httpsec.Request) bool { return true },
						Require: func(context.Context) error { return err },
					}),
					httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
						w.WriteHeader(http.StatusTeapot)
					})), plainRequest(t.Context())
			},
			assert: func(t *testing.T, g refusalGot) {
				t.Helper()
				assert.Equal(t, http.StatusTeapot, g.status)
				require.Len(t, g.chainAborts, 1, "one record, through the chain's logger")
				assertAbortRecord(t, g.chainAborts[0], "budget")
				assert.Empty(t, g.defaultAborts)
			},
		},
		testCase{
			name: "a Chain not built by New dispatches a cyclic error",
			err:  &cycleOne{},
			build: func(t *testing.T, _ *refusalWorld, err error) (http.Handler, *http.Request) {
				t.Helper()

				var zero httpsec.Chain

				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					httpsec.DispatchForTest(&zero, w, r, err)
				}), plainRequest(t.Context())
			},
			assert: func(t *testing.T, g refusalGot) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, g.status)
				assert.Empty(t, g.chainAborts)
				require.Len(t, g.defaultAborts, 1, "one record, to the process default")
				assertAbortRecord(t, g.defaultAborts[0], "budget")
			},
		},
	)

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			w := &refusalWorld{chainLogs: &capturingHandler{}}

			h, r := tc.build(t, w, tc.err)
			rec := serveRefusalWithin(t, h, r)

			tc.assert(t, refusalGot{
				status:        rec.Code,
				header:        rec.Header(),
				events:        w.emitted(),
				chainRecords:  w.chainLogs.records(),
				chainAborts:   abortRecords(w.chainLogs.records()),
				defaultAborts: abortRecords(defaultLogs.records()),
			})
		})
	}
}

// TestRefusalPath_SelectiveAborts pins the quiet sites' reporting rule. Each
// row's error has an Is (or As) method that panics only for the sentinel one
// refusal-path site asks about, and matches a sentinel the status lookup finds
// before it would ask, so the site's own walk aborts and the lookup's does not.
// The dispatch then has nothing to report, so the site reports: every row
// writes exactly one record, with or without a consumer's error handler and
// with sampling on or off, the request is answered with no escaped panic, and
// the status is the one the lookup gives (the consumer's, under its handler).
func TestRefusalPath_SelectiveAborts(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		build  func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request)
		assert func(t *testing.T, g refusalGot)
	}

	plainRequest := func(ctx context.Context) *http.Request {
		return httptest.NewRequestWithContext(ctx, http.MethodGet, "/records", nil)
	}

	// site is one quiet site: the configuration that carries the error to it,
	// the error, and the status the chain's own dispatch answers it with. A
	// guard answers its refusal itself, so a consumer's chain handler never
	// sees it, and its status stands under one too (guardAnswers).
	type site struct {
		name         string
		err          error
		status       int
		guardAnswers bool
		// unreported is the event a site whose walk aborted must not report,
		// where the code before the walk reported it; empty for none.
		unreported string
		build      func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request)
	}

	endedRequest := func(t *testing.T) *http.Request {
		t.Helper()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		return plainRequest(ctx)
	}

	sites := []site{
		{
			name:   "the signal stream's retry",
			err:    selectiveIs{matches: authorize.ErrAccessDenied, panicsOn: httpsec.ErrStreamingStarted},
			status: http.StatusForbidden,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)
				opts := append([]httpsec.Option{
					w.logger(), bearer,
					httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
					refusedOnThePath(err, httpsec.Before(httpsec.OrderBearerToken)),
				}, extra...)

				return behindChain(t, nil, opts...), streamRequest(t.Context(), "")
			},
		},
		{
			name:   "the per-request throttle's mark",
			err:    selectiveIs{matches: policy.ErrSessionIdle, panicsOn: ratelimit.ErrThrottled},
			status: http.StatusUnauthorized,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, sid := signedInBearer(t)
				opts := append([]httpsec.Option{
					w.logger(), bearer, deniedPerRequestBy(t, err),
					httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
				}, extra...)

				return behindChain(t, nil, opts...), streamRequest(t.Context(), sid)
			},
		},
		{
			name:   "the DPoP challenge of a refusal leaving the chain, events off",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired},
			status: http.StatusUnauthorized,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)
				opts := append([]httpsec.Option{
					w.logger(), bearer,
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}), refusingWith(err),
				}, extra...)

				return behindChain(t, nil, opts...), plainRequest(t.Context())
			},
		},
		{
			name:         "the DPoP challenge of a guard's refusal",
			err:          selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired},
			status:       http.StatusUnauthorized,
			guardAnswers: true,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)
				opts := append([]httpsec.Option{
					w.logger(), bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
				}, extra...)

				return behindChain(t, guardRefusing(t, err), opts...), principalRequest(t.Context())
			},
		},
		{
			name:   "the authorization stage's rule",
			err:    selectiveIs{matches: httpsec.ErrChallengeUnavailable, panicsOn: authorize.ErrAuthenticationRequired},
			status: http.StatusInternalServerError,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				opts := append([]httpsec.Option{
					w.logger(),
					httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authorize.Rule[httpsec.Request]{
						Match:   func(httpsec.Request) bool { return true },
						Require: func(context.Context) error { return err },
					}),
				}, extra...)

				return behindChain(t, nil, opts...), plainRequest(t.Context())
			},
		},
		{
			name:   "a per-request policy's denial",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: policy.ErrSessionIdle},
			status: http.StatusUnauthorized,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, sid := signedInBearer(t)
				req := plainRequest(t.Context())
				req.Header.Set("Authorization", "Bearer "+sid)

				opts := append([]httpsec.Option{w.logger(), bearer, deniedPerRequestBy(t, err)}, extra...)

				return behindChain(t, nil, opts...), req
			},
		},
		{
			name:   "a bearer's record of a throttled credential",
			err:    selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOnThrottleMark: true},
			status: http.StatusUnauthorized,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, sid := signedInBearer(t)
				req := plainRequest(t.Context())
				req.Header.Set("Authorization", "Bearer "+sid)

				opts := append([]httpsec.Option{w.logger(), bearer, deniedPerRequestBy(t, err)}, extra...)

				return behindChain(t, nil, opts...), req
			},
		},
		{
			// refused's own check for the user store's outage is the only one
			// on the request that asks about authenticate.ErrUnavailable.
			name:       "refused, a per-request policy's denial, events on",
			err:        selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: authenticate.ErrUnavailable},
			status:     http.StatusUnauthorized,
			unreported: event.AuthzFail,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, sid := signedInBearer(t)
				req := plainRequest(t.Context())
				req.Header.Set("Authorization", "Bearer "+sid)

				opts := append([]httpsec.Option{w.logger(), w.securityEvents(), bearer, deniedPerRequestBy(t, err)}, extra...)

				return behindChain(t, nil, opts...), req
			},
		},
		{
			// The request's context has ended, so the refusal event's hang-up
			// check is the only one that asks about context.Canceled.
			name:       "the refusal event's hang-up check, the request's context ended",
			err:        selectiveIs{matches: httpsec.ErrCrossSiteRequest, panicsOn: context.Canceled},
			status:     http.StatusForbidden,
			unreported: event.MaliciousCSRF,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				opts := append([]httpsec.Option{w.logger(), w.securityEvents(), refusingWith(err)}, extra...)

				return behindChain(t, nil, opts...), endedRequest(t)
			},
		},
		{
			// The guard's lookup answers 401 before it would ask about
			// authorize.ErrAccessDenied; the guard's refusal event asks first.
			name:         "a guard's refusal event, events on",
			err:          selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: authorize.ErrAccessDenied},
			status:       http.StatusUnauthorized,
			guardAnswers: true,
			unreported:   event.AuthzFail,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				opts := append([]httpsec.Option{w.logger(), w.securityEvents()}, extra...)

				return behindChain(t, guardRefusing(t, err), opts...), principalRequest(t.Context())
			},
		},
		{
			// The stream's sign-in throttle check is the only one on the
			// stream path that asks for the per-request throttle's mark.
			name:   "the signal stream's throttled sign-in check",
			err:    selectiveIs{matches: authorize.ErrAccessDenied, panicsOnThrottleMark: true},
			status: http.StatusForbidden,
			build: func(t *testing.T, w *refusalWorld, err error, extra ...httpsec.Option) (http.Handler, *http.Request) {
				t.Helper()

				bearer, _ := signedInBearer(t)
				opts := append([]httpsec.Option{
					w.logger(), bearer,
					httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
					refusedOnThePath(err, httpsec.Before(httpsec.OrderBearerToken)),
				}, extra...)

				return behindChain(t, nil, opts...), streamRequest(t.Context(), "")
			},
		},
	}

	oneRecord := func(status int, unreported string) func(*testing.T, refusalGot) {
		return func(t *testing.T, g refusalGot) {
			t.Helper()
			assert.Equal(t, status, g.status)

			if unreported != "" {
				assert.NotContains(t, g.events, unreported, "an aborted check reported its event")
			}

			all := append(append([]slog.Record(nil), g.chainAborts...), g.defaultAborts...)
			require.Len(t, all, 1, "one record per aborted request")
			assertAbortRecord(t, all[0], "panic")
		}
	}

	consumerHandler := httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.WriteHeader(http.StatusTeapot)
	})
	samplingOff := httpsec.WithRefusalLogInterval(0)

	var cases []testCase

	for _, s := range sites {
		underHandler := http.StatusTeapot
		if s.guardAnswers {
			underHandler = s.status
		}

		variants := []struct {
			name   string
			extra  []httpsec.Option
			status int
		}{
			{"", nil, s.status},
			{"/sampling off", []httpsec.Option{samplingOff}, s.status},
			{"/consumer handler", []httpsec.Option{consumerHandler}, underHandler},
			{"/consumer handler, sampling off", []httpsec.Option{consumerHandler, samplingOff}, underHandler},
		}

		for _, v := range variants {
			build, extra := s.build, v.extra
			cases = append(cases, testCase{
				name: s.name + v.name,
				err:  s.err,
				build: func(t *testing.T, w *refusalWorld, err error) (http.Handler, *http.Request) {
					t.Helper()

					return build(t, w, err, extra...)
				},
				assert: oneRecord(v.status, s.unreported),
			})
		}
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			w := &refusalWorld{chainLogs: &capturingHandler{}}

			h, r := tc.build(t, w, tc.err)
			rec := serveRefusalWithin(t, h, r)

			tc.assert(t, refusalGot{
				status:        rec.Code,
				header:        rec.Header(),
				events:        w.emitted(),
				chainRecords:  w.chainLogs.records(),
				chainAborts:   abortRecords(w.chainLogs.records()),
				defaultAborts: abortRecords(defaultLogs.records()),
			})
		})
	}
}

// TestRefusalPath_NestedAbortSamplingOff pins that a refusal whose check
// aborts past the lookup is reported once per request when one chain runs
// inside another, both with sampling off: the inner run's report marks the
// abort reported on the exchange, so the outer run, meeting the same abort in
// the same check, does not report it again. That holds for the refusal event,
// for DPoP's challenge, and for both on one chain, where the event check meets
// the abort the challenge already reported.
func TestRefusalPath_NestedAbortSamplingOff(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		opts   func(t *testing.T, w *refusalWorld) []httpsec.Option
		assert func(t *testing.T, err error, all []slog.Record, events []string)
	}

	refusal := selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired}

	once := func(t *testing.T, err error, all []slog.Record, events []string) {
		t.Helper()
		assert.Equal(t, error(refusal), err)
		require.Len(t, all, 1, "one record per aborted request")
		assertAbortRecord(t, all[0], "panic")
		assert.Empty(t, events, "an aborted check reports no event")
	}

	dpop := func(t *testing.T) []httpsec.Option {
		t.Helper()

		bearer, _ := signedInBearer(t)

		return []httpsec.Option{bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL})}
	}

	cases := []testCase{
		{
			name: "the refusal event, events on",
			opts: func(_ *testing.T, w *refusalWorld) []httpsec.Option {
				return []httpsec.Option{w.securityEvents()}
			},
			assert: once,
		},
		{
			name: "the DPoP challenge, events off",
			opts: func(t *testing.T, _ *refusalWorld) []httpsec.Option {
				t.Helper()

				return dpop(t)
			},
			assert: once,
		},
		{
			name: "the DPoP challenge and the refusal event, events on",
			opts: func(t *testing.T, w *refusalWorld) []httpsec.Option {
				t.Helper()

				return append(dpop(t), w.securityEvents())
			},
			assert: once,
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			w := &refusalWorld{chainLogs: &capturingHandler{}}

			chain := func() *httpsec.Chain {
				opts := append([]httpsec.Option{w.logger(), httpsec.WithRefusalLogInterval(0)}, tc.opts(t, w)...)

				c, err := httpsec.New(opts...)
				require.NoError(t, err)

				return c
			}

			outer, inner := chain(), chain()
			run := outer.Assemble(inner.Assemble(func(*httpsec.Exchange) error { return refusal }))

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil)
			ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(r), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))

			err := run(ex)

			all := append(abortRecords(w.chainLogs.records()), abortRecords(defaultLogs.records())...)
			tc.assert(t, err, all, w.emitted())
		})
	}
}

// TestDPoP_ConsumerNonceRequiredWithoutNonces pins that a consumer's error
// wrapping ErrDPoPNonceRequired, on a DPoP chain whose server nonces are off,
// is refused as the invalid proof its sentinel matches: 401, the
// invalid_dpop_proof challenge, and no nonce, since there is no nonce source
// to issue one from.
func TestDPoP_ConsumerNonceRequiredWithoutNonces(t *testing.T) {
	t.Parallel()

	bearer, _ := signedInBearer(t)
	h := behindChain(t, nil, bearer, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
		refusingWith(fmt.Errorf("x: %w", httpsec.ErrDPoPNonceRequired)))

	rec := serveRefusalWithin(t, h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil))

	challenges := strings.Join(rec.Header().Values("WWW-Authenticate"), ", ")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, challenges, `DPoP error="invalid_dpop_proof", algs=`)
	assert.NotContains(t, challenges, "use_dpop_nonce")
	assert.Empty(t, rec.Header().Get("DPoP-Nonce"))
}
