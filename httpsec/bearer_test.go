package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The identifiers the bearer tests share. The session identifier is the
// token's jti, so one constant names both.
const (
	testJTI     = "sess-0123456789abcdef"
	testSubject = "ada"
)

func bearerRequest(ctx context.Context, header string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}

	return req
}

// liveSession is a session the store hands back for testJTI.
func liveSession() *session.Session {
	now := time.Now()

	return &session.Session{
		ID:                testJTI,
		UserID:            "u-1",
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(12 * time.Hour),
		FirstFactor:       factor.Password,
	}
}

// storedUser is what the user loader returns. Its role is deliberately one no
// claim carries, so a test can tell a reloaded principal from one assembled
// out of the token.
func storedUser() *identity.Details {
	return &identity.Details{
		ID:       "u-1",
		Name:     "Ada Lovelace",
		Username: testSubject,
		Active:   true,
		Roles: []*identity.AssignedRole{
			{ID: "r-admin", Name: "administrator", Primary: true},
		},
	}
}

// expectVerified wires the verifier to accept any token as testSubject's, on
// the session testJTI.
func (h *authHarness) expectVerified() {
	h.verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
		Return(token.NewClaims(testSubject, testJTI), nil).AnyTimes()
}

// expectLiveSessionAndUser wires the whole resolution a valid token drives.
func (h *authHarness) expectLiveSessionAndUser(s *session.Session) {
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(s, nil)
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
	h.acceptsActivityWriteBack()
}

// serveBearer builds a chain with bearer authentication enabled and runs one
// request through it.
func serveBearer(
	t *testing.T,
	h *authHarness,
	e *policy.Engine,
	req *http.Request,
	opts ...httpsec.BearerTokenOption,
) served {
	t.Helper()

	chainOpts := []httpsec.Option{
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBearerToken(h.bearerTokenDeps(), opts...),
	}
	if e != nil {
		chainOpts = append(chainOpts, httpsec.WithPolicyEngine(e))
	}

	chain, err := httpsec.New(chainOpts...)
	require.NoError(t, err)

	return serve(t, chain, req)
}

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
				assert.Positive(t, r.NumAttrs())
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
					Return(nil, session.ErrSessionNotFound)
			},
			assert: unauthenticated,
		},
		{
			name: "the session expired",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, session.ErrSessionExpired)
			},
			assert: unauthenticated,
		},
		{
			name: "the session cannot be decrypted",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, session.ErrSessionUnreadable)
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

				// The engine substitutes ErrPolicyDenied for a nil reason.
				return denyingIn(t, policy.PerRequest, nil)
			},
			assert: func(t *testing.T, _ *session.Session, s served) {
				require.Error(t, s.err, "a reasonless deny must never return nil")
				require.ErrorIs(t, s.err, policy.ErrPolicyDenied)
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

			tc.assert(t, loaded, serveBearer(t, h, tc.engine(t), bearerRequest(t.Context(), "Bearer abc.def.ghi")))
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
