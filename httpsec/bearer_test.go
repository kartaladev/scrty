package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// TestBearerToken pins which Authorization headers bearer authentication
// claims, and what a token that does not verify is refused with.
func TestBearerToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.BearerTokenOption
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, h *authHarness, s served)
	}

	passedThrough := func(t *testing.T, _ *authHarness, s served) {
		require.NoError(t, s.err)
		assert.True(t, s.handlerRan, "the request continues untouched")
	}

	authenticated := func(t *testing.T, _ *authHarness, s served) {
		require.NoError(t, s.err)
		require.True(t, s.handlerRan)

		auth, ok := authenticate.AuthenticationFromContext(s.handled.Context())
		require.True(t, ok)
		assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)
	}

	valid := func(_ *testing.T, h *authHarness) {
		h.expectVerified()
		h.expectLiveSessionAndUser(liveSession())
	}

	cases := []testCase{
		{
			name: "a valid token reaches the handler with the principal and the session",
			wire: valid,
			request: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, "Bearer abc.def.ghi")
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan)

				auth, ok := authenticate.AuthenticationFromContext(s.handled.Context())
				require.True(t, ok, "the handler must read who the caller is")
				assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)

				sess, ok := httpsec.SessionFromContext(s.handled.Context())
				require.True(t, ok, "the handler must read the session the token names")
				assert.Equal(t, testJTI, sess.ID)
				assert.Same(t, sess, s.handled.Session)
			},
		},
		{
			name:    "the scheme matches in lower case",
			wire:    valid,
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "bearer abc.def.ghi") },
			assert:  authenticated,
		},
		{
			name:    "the scheme matches in upper case",
			wire:    valid,
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "BEARER abc.def.ghi") },
			assert:  authenticated,
		},
		{
			name:    "another scheme passes through untouched",
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "Basic YWRhOnMzY3JldA==") },
			assert:  passedThrough,
		},
		{
			name:    "no Authorization header passes through untouched",
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "") },
			assert:  passedThrough,
		},
		{
			name:    "a bare token is ignored by default",
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "abc.def.ghi") },
			assert:  passedThrough,
		},
		{
			name:    "a bare token is accepted when the consumer opts in",
			opts:    []httpsec.BearerTokenOption{httpsec.WithBearerAllowEmptyScheme()},
			wire:    valid,
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "abc.def.ghi") },
			assert:  authenticated,
		},
		{
			name:    "a consumer scheme",
			opts:    []httpsec.BearerTokenOption{httpsec.WithBearerScheme("Token")},
			wire:    valid,
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "token abc.def.ghi") },
			assert:  authenticated,
		},
		{
			name:    "the default scheme is not claimed once the consumer renamed it",
			opts:    []httpsec.BearerTokenOption{httpsec.WithBearerScheme("Token")},
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "Bearer abc.def.ghi") },
			assert:  passedThrough,
		},
		{
			name:    "a scheme with no credential after it is not a presentation",
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "Bearer   ") },
			assert:  passedThrough,
		},
		{
			name: "a tampered token is refused uniformly and its cause is logged",
			wire: func(_ *testing.T, h *authHarness) {
				h.verifier.EXPECT().Verify(gomock.Any(), "abc.def.tampered").
					Return(nil, errors.New("token: invalid: signature verification failed"))
				// No expectation on the store or the loader: a token that did
				// not verify names nothing worth looking up.
			},
			request: func(ctx context.Context) *http.Request { return bearerRequest(ctx, "Bearer abc.def.tampered") },
			assert: func(t *testing.T, h *authHarness, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)

				r, ok := recordAt(h.logs.records(), slog.LevelDebug,
					"httpsec: a bearer token did not verify")
				require.True(t, ok, "an operator must be able to see which check the token failed")

				errAttr, ok := attrValue(r, "error")
				require.True(t, ok, "the record must carry the verifier's own error text")
				assert.Contains(t, errAttr.String(), "signature verification failed",
					"an operator chasing a rejected client needs the verification failure's own "+
						"text, which is the library's protocol-failure text and a deliberate exception")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			tc.assert(t, h, serveBearer(t, h, nil, tc.request(t.Context()), tc.opts...))
		})
	}
}

// TestBearerSessionResolution pins that a token is a reference to live state:
// the session must still exist and the user is reloaded, and none of the ways
// that fails is distinguishable from the others.
func TestBearerSessionResolution(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		wire   func(t *testing.T, h *authHarness)
		assert func(t *testing.T, h *authHarness, s served)
	}

	unauthenticated := func(t *testing.T, _ *authHarness, s served) {
		require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
		assert.False(t, s.handlerRan)
	}

	cases := []testCase{
		{
			name: "the session is gone",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, session.ErrNotFound)
			},
			assert: unauthenticated,
		},
		{
			name: "the session expired",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, session.ErrExpired)
			},
			assert: unauthenticated,
		},
		{
			name: "the session cannot be decrypted",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, session.ErrUnreadable)
			},
			assert: func(t *testing.T, h *authHarness, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired,
					"the caller is asked to log in again, which is the remedy; a 500 is not")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))

				_, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: a session could not be decrypted")
				require.True(t, ok,
					"a sealing key retired while sessions sealed under it are live must be "+
						"visible to an operator")
			},
		},
		{
			name: "the user no longer exists",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).Return(liveSession(), nil)
				h.acceptsFirstPresentation()
				h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
					Return(nil, identity.ErrUserNotFound)
			},
			assert: unauthenticated,
		},
		{
			name: "the user store is down",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).Return(liveSession(), nil)
				h.acceptsFirstPresentation()
				h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
					Return(nil, errors.New("users: connection refused"))
			},
			assert: unauthenticated,
		},
		{
			name: "the user is reloaded, so the roles are the store's and not the token's",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectLiveSessionAndUser(liveSession())
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan)

				auth, ok := authenticate.AuthenticationFromContext(s.handled.Context())
				require.True(t, ok)
				require.NotNil(t, auth.Principal)
				require.Len(t, auth.Principal.Roles, 1,
					"the principal must come from the store, and the token carries no role at all")
				assert.Equal(t, "administrator", auth.Principal.Roles[0].Name)
				assert.Equal(t, "Ada Lovelace", auth.Principal.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			tc.assert(t, h, serveBearer(t, h, nil, bearerRequest(t.Context(), "Bearer abc.def.ghi")))
		})
	}
}

// TestBearerPerRequestPhase pins what the per-request phase does to a live
// session: a deny refuses, and a challenge is marked and continued so the gate
// that enforces it — and the endpoint that resolves it — stay reachable.
func TestBearerPerRequestPhase(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		opts   []httpsec.Option
		assert func(t *testing.T, loaded *session.Session, s served)
	}

	cases := []testCase{
		{
			name: "a deny refuses with the policy's reason",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.PerRequest, policy.ErrSessionIdle)
			},
			assert: func(t *testing.T, _ *session.Session, s served) {
				require.ErrorIs(t, s.err, policy.ErrSessionIdle)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a reasonless deny is a refusal, never a success",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				// The engine substitutes ErrDenied for a nil reason.
				return denyingIn(t, policy.PerRequest, nil)
			},
			assert: func(t *testing.T, _ *session.Session, s served) {
				require.Error(t, s.err, "a reasonless deny must never return nil")
				require.ErrorIs(t, s.err, policy.ErrDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(s.err),
					"this is the row that catches a refusal served as a 200")
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a password-change challenge marks the session and continues",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingIn(t, policy.PerRequest, policy.ChallengePasswordChange)
			},
			opts: []httpsec.Option{httpsec.EnableGateForTest(policy.ChallengePasswordChange)},
			assert: func(t *testing.T, loaded *session.Session, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan,
					"the gate at its own slot enforces it, and the endpoint that resolves it "+
						"must stay reachable")
				require.NotNil(t, loaded)
				assert.True(t, loaded.PasswordChangePending)
			},
		},
		{
			name: "a second-factor challenge marks the session and continues",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingIn(t, policy.PerRequest, policy.ChallengeMFA)
			},
			opts: []httpsec.Option{httpsec.EnableGateForTest(policy.ChallengeMFA)},
			assert: func(t *testing.T, loaded *session.Session, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
				require.NotNil(t, loaded)
				assert.Equal(t, session.MFAPending, loaded.MFA)
			},
		},
		{
			name:   "with no engine wired the request rests on the token and the session",
			engine: func(*testing.T) *policy.Engine { return nil },
			assert: func(t *testing.T, loaded *session.Session, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
				require.NotNil(t, loaded)
				assert.False(t, loaded.PasswordChangePending)
				assert.Equal(t, session.MFANone, loaded.MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loaded := liveSession()

			h := newAuthHarness(t)
			h.expectVerified()
			h.store.EXPECT().Load(gomock.Any(), testJTI).Return(loaded, nil)
			h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
				Return(storedUser(), nil).AnyTimes()
			h.acceptsActivityWriteBack()

			tc.assert(t, loaded, serveBearerOn(t, h, tc.engine(t),
				bearerRequest(t.Context(), "Bearer abc.def.ghi"), tc.opts))
		})
	}
}

// TestBearerPerRequestInput pins what the per-request phase is told, because a
// field a deployment's rule reads and this interceptor never fills is a gate
// that silently never fires.
func TestBearerPerRequestInput(t *testing.T) {
	t.Parallel()

	var seen *policy.Input

	recorder := NewMockPolicy(gomock.NewController(t))
	recorder.EXPECT().Name().Return("test: input recorder").AnyTimes()
	recorder.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
	recorder.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
			seen = in

			return policy.Decision{Outcome: policy.Allow}
		})

	stored := storedUser()
	stored.PasswordChangedAt = time.Now().Add(-200 * 24 * time.Hour)

	h := newAuthHarness(t)
	h.expectVerified()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(liveSession(), nil)
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(stored, nil)
	h.acceptsActivityWriteBack()

	s := serveBearer(t, h, engineOf(t, recorder), bearerRequest(t.Context(), "Bearer abc.def.ghi"))
	require.NoError(t, s.err)

	require.NotNil(t, seen)
	assert.Equal(t, identity.UserID("u-1"), seen.User)
	assert.Equal(t, testSubject, seen.Username)
	require.NotNil(t, seen.Principal)
	require.NotNil(t, seen.Session)
	assert.Equal(t, testJTI, seen.Session.ID)
	assert.Equal(t, factor.Password, seen.FirstFactor)
	assert.Equal(t, stored.PasswordChangedAt, seen.PasswordChangedAt,
		"a password-age rule running per request has nothing to judge without this")
	assert.False(t, seen.Now.IsZero())
}

// TestBearerPerRequestSeesSatisfiedSecondFactor pins that the per-request
// phase is told whether the session already satisfied its second factor. A
// per-request rule that requires MFA reads this field to decide whether to
// challenge; a session that already gave its second factor must not be
// challenged again on every subsequent request.
func TestBearerPerRequestSeesSatisfiedSecondFactor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mfa    session.MFAState
		assert func(t *testing.T, seen *policy.Input)
	}

	satisfied := func(t *testing.T, seen *policy.Input) {
		t.Helper()

		require.NotNil(t, seen)
		assert.True(t, seen.MFASatisfied,
			"a session that already gave its second factor must not be re-challenged")
	}

	notSatisfied := func(t *testing.T, seen *policy.Input) {
		t.Helper()

		require.NotNil(t, seen)
		assert.False(t, seen.MFASatisfied)
	}

	cases := []testCase{
		{name: "the second factor was satisfied", mfa: session.MFASatisfied, assert: satisfied},
		{name: "the second factor is pending", mfa: session.MFAPending, assert: notSatisfied},
		{name: "the second factor was never asked for", mfa: session.MFANone, assert: notSatisfied},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen *policy.Input

			recorder := NewMockPolicy(gomock.NewController(t))
			recorder.EXPECT().Name().Return("test: input recorder").AnyTimes()
			recorder.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
			recorder.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
					seen = in

					return policy.Decision{Outcome: policy.Allow}
				})

			loaded := liveSession()
			loaded.MFA = tc.mfa

			h := newAuthHarness(t)
			h.expectVerified()
			h.store.EXPECT().Load(gomock.Any(), testJTI).Return(loaded, nil)
			h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
			h.acceptsActivityWriteBack()

			s := serveBearer(t, h, engineOf(t, recorder), bearerRequest(t.Context(), "Bearer abc.def.ghi"))
			require.NoError(t, s.err)

			tc.assert(t, seen)
		})
	}
}

// TestBearerTokenConstruction pins that a bearer configuration that could not
// work is refused before the chain exists.
func TestBearerTokenConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(h *authHarness) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	cases := []testCase{
		{
			name: "a fully wired bearer builds",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableBearerToken(h.bearerTokenDeps())}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no verifier",
			build: func(h *authHarness) []httpsec.Option {
				d := h.bearerTokenDeps()
				d.Verifier = nil

				return []httpsec.Option{httpsec.EnableBearerToken(d)}
			},
			assert: refused("EnableBearerToken", "token verifier"),
		},
		{
			name: "a verifier holding a typed nil",
			build: func(h *authHarness) []httpsec.Option {
				d := h.bearerTokenDeps()
				d.Verifier = (*MockVerifier)(nil)

				return []httpsec.Option{httpsec.EnableBearerToken(d)}
			},
			assert: refused("EnableBearerToken", "token verifier"),
		},
		{
			name: "no session manager",
			build: func(h *authHarness) []httpsec.Option {
				d := h.bearerTokenDeps()
				d.Sessions = nil

				return []httpsec.Option{httpsec.EnableBearerToken(d)}
			},
			assert: refused("EnableBearerToken", "session manager"),
		},
		{
			name: "no user loader",
			build: func(h *authHarness) []httpsec.Option {
				d := h.bearerTokenDeps()
				d.Users = nil

				return []httpsec.Option{httpsec.EnableBearerToken(d)}
			},
			assert: refused("EnableBearerToken", "user loader"),
		},
		{
			name: "an empty scheme",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableBearerToken(h.bearerTokenDeps(), httpsec.WithBearerScheme(" ")),
				}
			},
			assert: refused("WithBearerScheme"),
		},
		{
			name: "a scheme holding a space",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableBearerToken(h.bearerTokenDeps(),
						httpsec.WithBearerScheme("Bearer Token")),
				}
			},
			assert: refused("WithBearerScheme"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.build(newAuthHarness(t))...)
			tc.assert(t, chain, err)
		})
	}
}

// TestBearerMarksEnrolment pins the mid-session half of the enrolment path: a
// full session whose user has become required, with nothing usable enrolled,
// is marked enrolment-pending by the per-request phase, and the mark — state,
// marker and lowered deadlines — is stored, whatever the gate inside the
// bearer slot then does with the request.
func TestBearerMarksEnrolment(t *testing.T) {
	t.Parallel()

	// confining stands in for the enrolment gate: it refuses an
	// enrolment-pending session before anything inside it runs, the session
	// touch step included.
	confining := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Session != nil && ex.Session.MFA == session.MFAEnrolmentPending {
			return &httpsec.ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: ex.Session}
		}

		return next(ex)
	})

	type testCase struct {
		name string
		opts []httpsec.Option

		// pending marks the session enrolment-pending, and stores it, before
		// the request.
		pending bool

		// saves is how many times the request stored the session, and
		// activity how many times it recorded activity on it.
		assert func(t *testing.T, out served, saves, activity int32)
	}

	cases := []testCase{
		{
			name: "marked in place and continued, persisted by the session touch",
			opts: []httpsec.Option{
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				passThroughAt(httpsec.OrderMFAEnrolment),
			},
			assert: func(t *testing.T, out served, _, _ int32) {
				t.Helper()

				require.NoError(t, out.err)
				require.True(t, out.handlerRan, "what occupies the enrolment slot lets it through")
				assert.Equal(t, session.MFAEnrolmentPending, out.handled.Session.MFA)
			},
		},
		{
			name: "persisted even though the gate refuses before the touch step",
			opts: []httpsec.Option{
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				httpsec.RegisterInterceptor(confining, httpsec.OrderMFAEnrolment),
			},
			assert: func(t *testing.T, out served, _, _ int32) {
				t.Helper()

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "a session already in the state is not stored again by the bearer",
			opts: []httpsec.Option{
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				passThroughAt(httpsec.OrderMFAEnrolment),
			},
			pending: true,
			assert: func(t *testing.T, out served, saves, activity int32) {
				t.Helper()

				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
				assert.Equal(t, int32(0), saves,
					"marking it again changes nothing, so the bearer stores nothing")
				assert.Equal(t, int32(1), activity,
					"only the session touch writes, and it writes the activity alone")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			start := time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)
			clk := clockwork.NewFakeClockAt(start)

			// The store judges expiry by the same clock as the manager, or the
			// lowered deadline would be read against the wall clock.
			store := &countingSaves{Store: session.NewMemoryStore(
				session.WithMemoryStoreClock(clk))}

			sessions, err := session.New(
				session.WithClock(clk), session.WithStore(store))
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			// Ten minutes into a full session the user becomes required.
			clk.Advance(10 * time.Minute)

			if tc.pending {
				sessions.MarkEnrolmentPending(s, 15*time.Minute)
				require.NoError(t, sessions.Save(t.Context(), s))
			}

			store.saves.Store(0)
			store.activity.Store(0)

			ctrl := gomock.NewController(t)
			verifier := NewMockVerifier(ctrl)
			verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
				Return(token.NewClaims(testSubject, s.ID), nil)

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)

			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: verifier, Sessions: sessions, Users: users,
				}),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
			}, tc.opts...)...)
			require.NoError(t, err)

			out := serve(t, chain, bearerRequest(t.Context(), "Bearer abc.def.ghi"))
			tc.assert(t, out, store.saves.Load(), store.activity.Load())

			stored, err := sessions.Load(t.Context(), s.ID)
			require.NoError(t, err)
			assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the mark is stored")
			assert.True(t, stored.AbsoluteExpiresAt.Equal(clk.Now().Add(15*time.Minute)),
				"the deadline is lowered to the enrolment lifetime from the mark, got %s",
				stored.AbsoluteExpiresAt)
			assert.True(t, stored.EnrolmentOriginDeadline.Equal(start.Add(sessions.AbsoluteTimeout())),
				"the marker records the full session's deadline")
		})
	}
}

// countingSaves counts the saves and the activity writes that reach the store
// it wraps, so a test can pin how many times a request stored a session and
// how many times it only recorded activity on one.
type countingSaves struct {
	session.Store

	saves    atomic.Int32
	activity atomic.Int32
}

func (c *countingSaves) RecordActivity(ctx context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error {
	c.activity.Add(1)

	return c.Store.RecordActivity(ctx, id, lastAccessed, idleExpires, olderThan)
}

func (c *countingSaves) Save(ctx context.Context, s *session.Session) error {
	c.saves.Add(1)

	return c.Store.Save(ctx, s)
}

// TestBearerMarksEnrolmentSaveFails pins that a session whose enrolment mark
// could not be stored is refused, not served on a mark that exists only in
// memory and a deadline that was never lowered.
func TestBearerMarksEnrolmentSaveFails(t *testing.T) {
	t.Parallel()

	errStore := errors.New("bearer_test: the session store is down")

	h := newAuthHarness(t)
	h.expectVerified()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(liveSession(), nil)
	h.acceptsFirstPresentation()
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
	h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errStore).AnyTimes()

	out := serveBearerOn(t, h, challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment),
		bearerRequest(t.Context(), "Bearer abc.def.ghi"),
		[]httpsec.Option{httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment)})

	require.ErrorIs(t, out.err, errStore)
	assert.False(t, out.handlerRan)
}

// TestBearerRecordsConsumerChallenge pins how a challenge kind of the
// consumer's own, raised per request, reaches the gate the consumer declared
// with WithChallengeEnforcer: the library cannot mark a kind it does not know,
// so it records it on the exchange and lets the request continue to that gate.
func TestBearerRecordsConsumerChallenge(t *testing.T) {
	t.Parallel()

	const terms policy.ChallengeKind = 100

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine

		// extra is what the chain needs besides the consumer's declared gate,
		// such as a built-in gate recorded as enabled.
		extra []httpsec.Option

		assert func(t *testing.T, out served, seen policy.ChallengeKind, stored *session.Session)
	}

	cases := []testCase{
		{
			// A built-in kind is marked on the session, where its own gate
			// reads it. Recording it on the exchange too would hand a consumer
			// gate a kind it was never declared for.
			name: "a built-in kind raised with its gate enabled is not recorded",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return engineOf(t, raisingDeclared{kind: policy.ChallengeMFA, phase: policy.PerRequest})
			},
			extra: []httpsec.Option{httpsec.EnableGateForTest(policy.ChallengeMFA)},
			assert: func(t *testing.T, out served, seen policy.ChallengeKind, stored *session.Session) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, policy.ChallengeNone, seen,
					"only a consumer kind is recorded on the exchange")
				assert.Equal(t, session.MFAPending, stored.MFA, "the built-in kind is marked on the session")
			},
		},
		{
			name: "a declared consumer kind is recorded and the request continues",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return engineOf(t, raisingDeclared{kind: terms, phase: policy.PerRequest})
			},
			assert: func(t *testing.T, out served, seen policy.ChallengeKind, stored *session.Session) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the consumer's gate let it through")
				assert.Equal(t, terms, seen, "the gate behind the bearer reads the raised kind")
				assert.Equal(t, session.MFANone, stored.MFA, "no built-in mark stands in for it")
				assert.False(t, stored.PasswordChangePending, "no built-in mark stands in for it")
			},
		},
		{
			name:   "nothing raised reads as ChallengeNone",
			engine: func(t *testing.T) *policy.Engine { t.Helper(); return engineOf(t) },
			assert: func(t *testing.T, out served, seen policy.ChallengeKind, _ *session.Session) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Equal(t, policy.ChallengeNone, seen)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			h.expectVerified()

			stored := liveSession()
			h.expectLiveSessionAndUser(stored)

			seen := policy.ChallengeKind(-1)
			gate := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				seen = ex.RaisedChallenge()
				return next(ex)
			})

			out := serveBearerOn(t, h, tc.engine(t), bearerRequest(t.Context(), "Bearer abc.def.ghi"),
				append([]httpsec.Option{
					httpsec.WithChallengeEnforcer(terms),
					httpsec.RegisterInterceptor(gate, httpsec.After(httpsec.OrderBearerToken)),
				}, tc.extra...))

			tc.assert(t, out, seen, stored)
		})
	}
}

// TestBearerRefusesReusedSession pins what a token naming a session superseded
// by a renewal is refused with once that renewal's window has ended: an error
// both the authentication-required and the reused-session refusal, after the
// manager has revoked the session's whole family.
func TestBearerRefusesReusedSession(t *testing.T) {
	t.Parallel()

	f := newResolveFixture(t)
	ctrl := gomock.NewController(t)
	verifier := NewMockVerifier(ctrl)
	users := NewMockUserLoader(ctrl)

	successor, _, err := f.sessions.RotateWithGrace(t.Context(), f.session, 30*time.Second)
	require.NoError(t, err)

	f.clk.Advance(31 * time.Second)

	verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
		Return(token.NewClaims(testSubject, f.session.ID), nil)

	chain, err := httpsec.New(
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.WithClock(f.clk),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: f.sessions, Users: users}),
	)
	require.NoError(t, err)

	s := serve(t, chain, bearerRequest(t.Context(), "Bearer abc.def.ghi"))

	require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
	require.ErrorIs(t, s.err, session.ErrReused)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
	assert.False(t, s.handlerRan)

	_, err = f.sessions.Load(t.Context(), successor.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the family is revoked, its live successor with it")
}

// bearerMode is which of the two bearer modes a chain authenticates with.
type bearerMode int

const (
	// signedBearer is EnableBearerToken: a signed token whose subject is the
	// username, reloaded by username.
	signedBearer bearerMode = iota

	// referenceBearer is EnableSessionBearer: the session's own identifier,
	// whose user is reloaded by the reference the session records.
	referenceBearer
)

func (m bearerMode) String() string {
	if m == signedBearer {
		return "signed bearer"
	}

	return "session reference"
}

// ownUserFixture is a chain in one bearer mode over a memory-store manager,
// with one live session of u-1's in it and a user loader whose answer a case
// switches.
type ownUserFixture struct {
	sessions *session.Sessions
	chain    *httpsec.Chain
	user     *switchableUser

	// sid is the live session's identifier.
	sid string
}

// newOwnUserFixture builds the fixture in mode, with the further chain options
// extra returns for the fixture's manager, when extra is not nil.
func newOwnUserFixture(
	t *testing.T,
	mode bearerMode,
	extra func(sessions *session.Sessions) []httpsec.Option,
) *ownUserFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC))

	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	f := &ownUserFixture{sessions: sessions, user: &switchableUser{}, sid: s.ID}
	f.user.set(userActive(true))
	users := f.user.loader(t)

	var auth httpsec.Option

	switch mode {
	case signedBearer:
		// Every token verifies as testSubject's, on the fixture's session.
		verifier := NewMockVerifier(gomock.NewController(t))
		verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
			Return(token.NewClaims(testSubject, s.ID), nil)

		auth = httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: users})
	case referenceBearer:
		auth = httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users})
	}

	opts := []httpsec.Option{httpsec.WithClock(clk), auth}
	if extra != nil {
		opts = append(opts, extra(sessions)...)
	}

	f.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return f
}

// request runs method path through the chain bearing the session's
// credential: its identifier in the reference mode, and a token the verifier
// maps to it in the signed mode.
func (f *ownUserFixture) request(t *testing.T, method, path string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.Header.Set("Authorization", "Bearer "+f.sid)

	return serve(t, f.chain, req)
}

// get is an ordinary request on an application route.
func (f *ownUserFixture) get(t *testing.T) served {
	t.Helper()

	return f.request(t, http.MethodGet, "/orders")
}

// stillStored asserts the fixture's session was not revoked.
func (f *ownUserFixture) stillStored(t *testing.T) {
	t.Helper()

	stored, err := f.sessions.Load(t.Context(), f.sid)
	require.NoError(t, err, "the refused session is still stored")
	assert.Equal(t, identity.UserID("u-1"), stored.UserID)
}

// authenticatedAsOwner asserts out reached the handler as u-1.
func authenticatedAsOwner(t *testing.T, out served) {
	t.Helper()

	require.NoError(t, out.err)
	require.True(t, out.handlerRan)

	auth, ok := authenticate.AuthenticationFromContext(out.handled.Context())
	require.True(t, ok)
	assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)
}

// refusedBeforeHandler asserts out was refused as unauthenticated and the
// handler never ran, naming who it ran as, and why that is wrong, if it did.
func refusedBeforeHandler(t *testing.T, out served, why string) {
	t.Helper()

	if out.handlerRan {
		ran := "nobody"
		if auth, ok := authenticate.AuthenticationFromContext(out.handled.Context()); ok {
			ran = string(auth.Principal.ID)
		}

		t.Fatalf("handler ran as principal %q: %s", ran, why)
	}

	require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
}

// TestBearer_AuthenticatesOnlyOwnActiveUser pins that a resolved session
// authenticates only the user it records, and only while that user is
// active, in both bearer modes: a reassigned username, a loader answering
// with someone else, and a disabled user are refused, and the refusal revokes
// nothing, so a re-enabled user's session authenticates again.
//
// Not rows of TestBearerSessionResolution: it runs both bearer modes on a real manager.
func TestBearer_AuthenticatesOnlyOwnActiveUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   bearerMode
		extra  func(sessions *session.Sessions) []httpsec.Option
		assert func(t *testing.T, f *ownUserFixture)
	}

	var cases []testCase

	for _, mode := range []bearerMode{signedBearer, referenceBearer} {
		cases = append(cases,
			testCase{
				name: "own, active user authenticates",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					authenticatedAsOwner(t, f.get(t))
				},
			},
			testCase{
				// In the signed mode this is the username reassigned to u-2
				// after u-1's token was issued; in the reference mode, a loader
				// answering for the wrong user.
				name: "the reloaded user is another user: refused, and the handler does not run",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(otherUser())

					refusedBeforeHandler(t, f.get(t), "on u-1's session")
					f.stillStored(t)
				},
			},
			testCase{
				name: "disabled user is refused",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(userActive(false))

					refusedBeforeHandler(t, f.get(t), "a disabled user")
				},
			},
			testCase{
				name: "a loader answering with no user and no error is refused",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(nil)

					refusedBeforeHandler(t, f.get(t), "a loader that found no user")
				},
			},
			testCase{
				name: "re-enabled user authenticates again",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					authenticatedAsOwner(t, f.get(t))

					f.user.set(userActive(false))
					refusedBeforeHandler(t, f.get(t), "a disabled user")
					f.stillStored(t)

					f.user.set(userActive(true))
					authenticatedAsOwner(t, f.get(t))
				},
			},
			testCase{
				name: "disabled user's logout is refused and revokes nothing",
				mode: mode,
				extra: func(sessions *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions})}
				},
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(userActive(false))

					out := f.request(t, http.MethodPost, httpsec.DefaultLogoutPath)
					require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
					assert.False(t, out.handlerRan)
					f.stillStored(t)
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.mode.String()+": "+tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newOwnUserFixture(t, tc.mode, tc.extra))
		})
	}
}
