package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// TestExchangePublishSession pins that a session a consumer interceptor
// publishes is the one the handler reads, with its caller, and that its
// activity is recorded after the handler as for a built-in authenticator.
func TestExchangePublishSession(t *testing.T) {
	t.Parallel()

	f := newResolveFixture(t)

	chain, err := httpsec.New(
		httpsec.WithSessions(f.sessions),
		httpsec.RegisterInterceptor(consumerAuthenticating(f, false), httpsec.OrderBearerToken),
	)
	require.NoError(t, err)

	var (
		seen     *session.Session
		seenOK   bool
		caller   *identity.Principal
		callerOK bool
	)

	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		seen, seenOK = httpsec.SessionFromContext(ex.Context())
		caller, callerOK = identity.PrincipalFromContext(ex.Context())

		return nil
	})

	ex := httpsec.NewExchange(t.Context(),
		httpsec.NewHTTPRequest(bearerRequest(t.Context(), "")), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	require.NoError(t, run(ex))

	require.True(t, seenOK, "the handler reads the published session")
	assert.Equal(t, f.session.ID, seen.ID)
	assert.Same(t, seen, ex.Session, "the exchange carries the same session")

	require.True(t, callerOK, "the caller is published with it")
	assert.Equal(t, identity.UserID("u-1"), caller.ID)
	require.NotNil(t, ex.Authentication)

	stored, err := f.sessions.Load(t.Context(), f.session.ID)
	require.NoError(t, err)
	assert.True(t, stored.LastAccessedAt.Equal(f.clk.Now()),
		"activity is recorded after the handler, got last access %s, want %s",
		stored.LastAccessedAt, f.clk.Now())
	assert.True(t, stored.IdleExpiresAt.After(f.session.IdleExpiresAt),
		"the idle deadline moves with the recorded activity")
}

// TestExchangeEvaluatePerRequest pins that a consumer interceptor running the
// per-request phase gets the challenge handling the signed bearer applies:
// for an enrolment challenge the session is stored enrolment-pending with its
// deadlines lowered, and the gate enforcing enrolment refuses the request with
// the same challenge error, in both cases.
func TestExchangeEvaluatePerRequest(t *testing.T) {
	t.Parallel()

	// confining stands in for the enrolment gate, as in
	// TestBearerMarksEnrolment: it refuses an enrolment-pending session before
	// anything inside it runs.
	confining := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Session != nil && ex.Session.MFA == session.MFAEnrolmentPending {
			return &httpsec.ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: ex.Session}
		}

		return next(ex)
	})

	type testCase struct {
		name string

		// authenticating is the option that authenticates the request and runs
		// the per-request phase, built over the fixture.
		authenticating func(t *testing.T, f resolveFixture) httpsec.Option

		// header is the request's Authorization header.
		header string

		assert func(t *testing.T, f resolveFixture, out served)
	}

	// refusedAndMarked is what both authenticators must produce.
	refusedAndMarked := func(t *testing.T, f resolveFixture, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
		require.NotNil(t, ch.Session)
		assert.Equal(t, f.session.ID, ch.Session.ID)
		assert.False(t, out.handlerRan)

		stored, err := f.sessions.Load(t.Context(), f.session.ID)
		require.NoError(t, err)
		assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the mark is stored")
		assert.True(t, stored.AbsoluteExpiresAt.Equal(f.clk.Now().Add(15*time.Minute)),
			"the deadline is lowered to the enrolment lifetime from the mark, got %s",
			stored.AbsoluteExpiresAt)
		assert.True(t, stored.EnrolmentOriginDeadline.Equal(f.start.Add(f.sessions.AbsoluteTimeout())),
			"the marker records the full session's deadline")
	}

	cases := []testCase{
		{
			name: "signed bearer",
			authenticating: func(t *testing.T, f resolveFixture) httpsec.Option {
				t.Helper()

				ctrl := gomock.NewController(t)
				verifier := NewMockVerifier(ctrl)
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
					Return(token.NewClaims(testSubject, f.session.ID), nil)

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)

				return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: verifier, Sessions: f.sessions, Users: users,
				})
			},
			header: "Bearer abc.def.ghi",
			assert: refusedAndMarked,
		},
		{
			name: "consumer interceptor",
			authenticating: func(t *testing.T, f resolveFixture) httpsec.Option {
				t.Helper()

				return httpsec.RegisterInterceptor(consumerAuthenticating(f, true), httpsec.OrderBearerToken)
			},
			assert: refusedAndMarked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			chain, err := httpsec.New(
				httpsec.WithSessions(f.sessions),
				tc.authenticating(t, f),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				httpsec.RegisterInterceptor(confining, httpsec.OrderMFAEnrolment),
			)
			require.NoError(t, err)

			tc.assert(t, f, serve(t, chain, bearerRequest(t.Context(), tc.header)))
		})
	}
}

// TestExchangeEvaluatePerRequest_FailsClosed pins that the phase judges only
// what PublishSession published: a call for a session or caller that is not
// the published pair is refused before any policy runs.
func TestExchangeEvaluatePerRequest_FailsClosed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// run is the consumer interceptor's body, given the fixture's session
		// and caller.
		run func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) error
	}

	publish := func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) {
		require.NoError(t, ex.PublishSession(&authenticate.Authentication{Principal: p, Time: f.clk.Now()}, s))
	}

	cases := []testCase{
		{
			name: "nothing published",
			run: func(ex *httpsec.Exchange, _ resolveFixture, s *session.Session, p *identity.Principal) error {
				return ex.EvaluatePerRequest(s, p)
			},
		},
		{
			name: "a different session published",
			run: func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) error {
				other := *s
				publish(ex, f, &other, p)

				return ex.EvaluatePerRequest(s, p)
			},
		},
		{
			name: "a different principal published",
			run: func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) error {
				other := *p
				publish(ex, f, s, &other)

				return ex.EvaluatePerRequest(s, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			consumer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				s, err := f.sessions.Load(ex.Context(), f.session.ID)
				if err != nil {
					return err
				}

				if err := tc.run(ex, f, s, identity.PrincipalFromDetails(storedUser())); err != nil {
					return err
				}

				return next(ex)
			})

			// The engine challenges every per-request phase it runs, so a phase
			// that ran would mark the session or report a configuration error.
			chain, err := httpsec.New(
				httpsec.WithSessions(f.sessions),
				httpsec.RegisterInterceptor(consumer, httpsec.OrderBearerToken),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
			)
			require.NoError(t, err)

			out := serve(t, chain, bearerRequest(t.Context(), ""))
			require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
			assert.False(t, out.handlerRan)

			stored, err := f.sessions.Load(t.Context(), f.session.ID)
			require.NoError(t, err)
			assert.NotEqual(t, session.MFAEnrolmentPending, stored.MFA, "no policy ran, so nothing was marked")
		})
	}
}

// resolvingAuthenticator is one of the built-in authenticators that resolve a
// session through the shared core, wired over an authHarness: what it
// presents, the session the store holds for it, and how it reloads the user.
type resolvingAuthenticator struct {
	name string

	// header is the Authorization header the request carries.
	header string

	// sessionID is the identifier the store is asked to load.
	sessionID string

	// session is the live session the store holds under sessionID.
	session func() *session.Session

	// options enables the authenticator on a chain over h.
	options func(h *authHarness) []httpsec.Option

	// limited is options with l as the authenticator's source limiter, and
	// nil for an authenticator that throttles no source.
	limited func(h *authHarness, l ratelimit.Limiter) []httpsec.Option

	// reload wires the authenticator's user reload to answer with fn, called
	// with the context the reload was made with.
	reload func(h *authHarness, fn func(ctx context.Context) (*identity.Details, error))
}

// resolvingAuthenticators are the signed bearer and the session-reference
// bearer, the two built-ins that share session resolution.
func resolvingAuthenticators() []resolvingAuthenticator {
	return []resolvingAuthenticator{
		{
			name:      "signed bearer",
			header:    "Bearer abc.def.ghi",
			sessionID: testJTI,
			session:   liveSession,
			options: func(h *authHarness) []httpsec.Option {
				h.expectVerified()

				return []httpsec.Option{httpsec.EnableBearerToken(h.bearerTokenDeps())}
			},
			reload: func(h *authHarness, fn func(ctx context.Context) (*identity.Details, error)) {
				h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
					DoAndReturn(func(ctx context.Context, _ string) (*identity.Details, error) { return fn(ctx) })
			},
		},
		{
			name:      "session-reference bearer",
			header:    "Bearer " + testReference,
			sessionID: testReference,
			session:   referencedSession,
			options: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableSessionBearer(h.sessionBearerDeps())}
			},
			limited: func(h *authHarness, l ratelimit.Limiter) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableSessionBearer(h.sessionBearerDeps(), httpsec.WithSessionBearerLimiter(l)),
				}
			},
			reload: func(h *authHarness, fn func(ctx context.Context) (*identity.Details, error)) {
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					DoAndReturn(func(ctx context.Context, _ identity.UserID) (*identity.Details, error) { return fn(ctx) })
			},
		},
	}
}

// noErrorRecord asserts that nothing was logged at ERROR or above: neither an
// undecryptable session nor a dependency failure.
func noErrorRecord(t *testing.T, h *authHarness) {
	t.Helper()

	for _, r := range h.logs.records() {
		assert.Less(t, r.Level, slog.LevelError, "unexpected record at %s: %q", r.Level, r.Message)
	}
}

// The fixed texts a dependency failure at resolution is returned with.
const (
	textSessionNotResolved = "httpsec: session could not be resolved"
	textUserNotReloaded    = "httpsec: user could not be reloaded"
)

// TestResolve_DependencyFailureIsNotARefusal pins that session resolution,
// through either authenticator that shares it, answers a session-store or
// user-store failure as a dependency failure, behind fixed text with the
// cause reachable and a 500 by default, and keeps answering every refusal,
// a wrapped "not found" included, with ErrAuthenticationRequired.
func TestResolve_DependencyFailureIsNotARefusal(t *testing.T) {
	t.Parallel()

	dbDown := errors.New("db down")
	storeDeadline := fmt.Errorf("db: %w", context.DeadlineExceeded)

	type testCase struct {
		name   string
		wire   func(h *authHarness, a resolvingAuthenticator)
		assert func(t *testing.T, h *authHarness, out served)
	}

	// failed is a dependency failure with text, its cause reachable.
	failed := func(text string, cause error) func(t *testing.T, h *authHarness, out served) {
		return func(t *testing.T, h *authHarness, out served) {
			t.Helper()

			require.Error(t, out.err)
			assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
			assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
			require.ErrorIs(t, out.err, cause, "the dependency's error stays reachable")
			assert.Equal(t, text, out.err.Error(), "the text is the library's")
			assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
			assert.False(t, out.handlerRan)

			_, unreadable := recordAt(h.logs.records(), slog.LevelError, "httpsec: a session could not be decrypted")
			assert.False(t, unreadable, "an outage is not an undecryptable session")
		}
	}

	refused := func(t *testing.T, h *authHarness, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		noErrorRecord(t, h)
	}

	liveSessionAnd := func(h *authHarness, a resolvingAuthenticator, details *identity.Details, err error) {
		h.store.EXPECT().Load(gomock.Any(), a.sessionID).Return(a.session(), nil)
		h.acceptsFirstPresentation()
		a.reload(h, func(context.Context) (*identity.Details, error) { return details, err })
	}

	cases := []testCase{
		{
			name: "the session store is down",
			wire: func(h *authHarness, a resolvingAuthenticator) {
				h.store.EXPECT().Load(gomock.Any(), a.sessionID).Return(nil, dbDown)
			},
			assert: failed(textSessionNotResolved, dbDown),
		},
		{
			name: "the session store's own deadline passed while the request was still waiting",
			wire: func(h *authHarness, a resolvingAuthenticator) {
				h.store.EXPECT().Load(gomock.Any(), a.sessionID).Return(nil, storeDeadline)
			},
			assert: failed(textSessionNotResolved, context.DeadlineExceeded),
		},
		{
			name: "the user store is down",
			wire: func(h *authHarness, a resolvingAuthenticator) {
				liveSessionAnd(h, a, nil, dbDown)
			},
			assert: failed(textUserNotReloaded, dbDown),
		},
		{
			name: "a user not found, wrapped by the loader, is a refusal",
			wire: func(h *authHarness, a resolvingAuthenticator) {
				liveSessionAnd(h, a, nil, fmt.Errorf("db: %w", identity.ErrUserNotFound))
			},
			assert: refused,
		},
		{
			name: "a session not found, wrapped by the store, is a refusal",
			wire: func(h *authHarness, a resolvingAuthenticator) {
				h.store.EXPECT().Load(gomock.Any(), a.sessionID).Return(nil, fmt.Errorf("db: %w", session.ErrNotFound))
			},
			assert: refused,
		},
		{
			name: "an unreadable session is a refusal, and is recorded at ERROR",
			wire: func(h *authHarness, a resolvingAuthenticator) {
				h.store.EXPECT().Load(gomock.Any(), a.sessionID).Return(nil, session.ErrUnreadable)
			},
			assert: func(t *testing.T, h *authHarness, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))

				_, ok := recordAt(h.logs.records(), slog.LevelError, "httpsec: a session could not be decrypted")
				assert.True(t, ok, "an undecryptable session is visible to an operator")
			},
		},
	}

	for _, a := range resolvingAuthenticators() {
		for _, tc := range cases {
			t.Run(a.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				h := newAuthHarness(t)
				opts := append([]httpsec.Option{httpsec.WithLogger(h.logger())}, a.options(h)...)
				tc.wire(h, a)

				chain, err := httpsec.New(opts...)
				require.NoError(t, err)

				tc.assert(t, h, serve(t, chain, bearerRequest(t.Context(), a.header)))
			})
		}
	}
}

// chargesNothing is a source limiter that admits every source and fails the
// test if a failure is recorded against any.
func chargesNothing(t *testing.T) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

	return l
}

// TestResolve_HangUpIsNotARefusal pins that a request whose own context ended
// while its session loaded or its user reloaded, at either bearer or at the
// renewal endpoint, fails with the context's error: not refused, not recorded
// at ERROR as an outage or an undecryptable session, and not charged to its
// source.
func TestResolve_HangUpIsNotARefusal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options enables what the request goes through, over h; a source
		// limiter it wires is one that fails the test if charged.
		options func(t *testing.T, h *authHarness) []httpsec.Option

		// request builds the request on ctx.
		request func(ctx context.Context) *http.Request

		// wire wires the store and loader; hangUp ends the request's context.
		wire func(h *authHarness, hangUp context.CancelFunc)

		assert func(t *testing.T, h *authHarness, out served)
	}

	hungUp := func(t *testing.T, h *authHarness, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, context.Canceled)
		assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.NotContains(t, []string{textSessionNotResolved, textUserNotReloaded}, out.err.Error(),
			"a client that left is not reported as an outage")
		assert.NotContains(t, out.err.Error(), "db:", "the text is the library's")
		assert.False(t, out.handlerRan)
		noErrorRecord(t, h)
	}

	// loadHangsUp is a store Load during which the client leaves.
	loadHangsUp := func(h *authHarness, id string, hangUp context.CancelFunc) {
		h.store.EXPECT().Load(gomock.Any(), id).
			DoAndReturn(func(ctx context.Context, _ string) (*session.Session, error) {
				hangUp()

				return nil, fmt.Errorf("db: %w", ctx.Err())
			})
	}

	// reloadHangsUp is a user reload during which the client leaves.
	reloadHangsUp := func(hangUp context.CancelFunc) func(ctx context.Context) (*identity.Details, error) {
		return func(ctx context.Context) (*identity.Details, error) {
			hangUp()

			return nil, fmt.Errorf("db: %w", ctx.Err())
		}
	}

	var cases []testCase

	for _, a := range resolvingAuthenticators() {
		get := func(ctx context.Context) *http.Request { return bearerRequest(ctx, a.header) }

		options := func(t *testing.T, h *authHarness) []httpsec.Option {
			t.Helper()

			if a.limited != nil {
				return a.limited(h, chargesNothing(t))
			}

			return a.options(h)
		}

		cases = append(cases,
			testCase{
				name:    a.name + "/the client leaves while the session loads",
				options: options,
				request: get,
				wire: func(h *authHarness, hangUp context.CancelFunc) {
					loadHangsUp(h, a.sessionID, hangUp)
				},
				assert: hungUp,
			},
			testCase{
				name:    a.name + "/the client leaves while the user reloads",
				options: options,
				request: get,
				wire: func(h *authHarness, hangUp context.CancelFunc) {
					h.store.EXPECT().Load(gomock.Any(), a.sessionID).Return(a.session(), nil)
					h.acceptsFirstPresentation()
					a.reload(h, reloadHangsUp(hangUp))
				},
				assert: hungUp,
			},
		)
	}

	renewal := func(t *testing.T, h *authHarness) []httpsec.Option {
		t.Helper()

		return []httpsec.Option{
			httpsec.EnableSessionBearer(h.sessionBearerDeps(), httpsec.WithSessionBearerLimiter(chargesNothing(t))),
			httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users}),
		}
	}
	renew := func(ctx context.Context) *http.Request {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
		req.Header.Set("Authorization", "Bearer "+testReference)

		return req
	}

	cases = append(cases,
		testCase{
			name:    "renewal request/the client leaves while the bearer loads the session",
			options: renewal,
			request: renew,
			wire: func(h *authHarness, hangUp context.CancelFunc) {
				loadHangsUp(h, testReference, hangUp)
			},
			assert: hungUp,
		},
		testCase{
			name:    "renewal endpoint/the client leaves while the endpoint reloads the user",
			options: renewal,
			request: renew,
			wire: func(h *authHarness, hangUp context.CancelFunc) {
				h.store.EXPECT().Load(gomock.Any(), testReference).Return(referencedSession(), nil)
				h.acceptsFirstPresentation()
				gomock.InOrder(
					h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil),
					h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
						DoAndReturn(func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
							return reloadHangsUp(hangUp)(ctx)
						}),
				)
			},
			assert: func(t *testing.T, h *authHarness, out served) {
				t.Helper()

				hungUp(t, h, out)
				assert.NotErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
			},
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, hangUp := context.WithCancel(t.Context())
			t.Cleanup(hangUp)

			h := newAuthHarness(t)
			opts := append([]httpsec.Option{httpsec.WithLogger(h.logger())}, tc.options(t, h)...)
			tc.wire(h, hangUp)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, h, serveIn(ctx, t, chain, tc.request(ctx)))
		})
	}
}
