package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// testChangePasswordPath is where these tests put the consumer's resolve
// endpoint. There is no default: without a resolve endpoint only a new login
// clears the challenge, so the path is the consumer's to name.
const testChangePasswordPath = "/account/password"

// errChangeRefused is what a consumer's change-password function refuses with,
// so a test can assert the chain returned that error and not one of its own.
var errChangeRefused = errors.New("passwordchange_test: the new password is too weak")

// owingPasswordChange is a live session that owes a password change.
func owingPasswordChange() *session.Session {
	s := touchableSession()
	s.PasswordChangePending = true

	return s
}

// changePasswordRequest is a request to the consumer's resolve endpoint,
// carrying a bearer token so the session is resolved before the gate.
func changePasswordRequest(ctx context.Context, method string, authorized bool) *http.Request {
	req := httptest.NewRequestWithContext(ctx, method, testChangePasswordPath, nil)
	if authorized {
		req.Header.Set("Authorization", "Bearer a-token")
	}

	return req
}

// TestPasswordChangeGate pins which requests the gate holds: a session that
// owes a password change is refused with the challenge, and everything else
// carries on.
func TestPasswordChangeGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, marked *session.Session, s served)
	}

	authenticated := func(ctx context.Context) *http.Request {
		return bearerRequest(ctx, "Bearer a-token")
	}

	passedThrough := func(t *testing.T, _ *session.Session, s served) {
		require.NoError(t, s.err)
		assert.True(t, s.handlerRan, "the request continues to the application untouched")
	}

	cases := []testCase{
		{
			name: "a session with the pending marker is refused",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(owingPasswordChange())
			},
			request: authenticated,
			assert: func(t *testing.T, _ *session.Session, s served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				require.NotNil(t, ch.Session, "the consumer prompting for the change reads who owes it")
				assert.Equal(t, testJTI, ch.Session.ID)
				assert.Empty(t, ch.Token,
					"a gate raises the challenge on a session that already exists, so it issues nothing")

				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name: "a session without the marker passes",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.acceptsActivityWriteBack()
			},
			request: authenticated,
			assert:  passedThrough,
		},
		{
			name: "a request with no session passes",
			// The gate guards sessions. An anonymous request is the business of
			// the authentication interceptors outside it, and refusing it here
			// would report a password change nobody owes.
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, "")
			},
			assert: passedThrough,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
				httpsec.EnablePasswordChangeGate(h.sessions),
			)
			require.NoError(t, err)

			tc.assert(t, nil, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestChangePasswordEndpoint pins the one way through the gate: the consumer's
// own endpoint, which needs a caller, owns its response, and clears the debt
// only when it actually changed the password.
func TestChangePasswordEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		change  func(t *testing.T, ran *bool) httpsec.ChangePasswordFunc
		wire    func(t *testing.T, h *authHarness, saved *savedSessions)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, h *authHarness, chain *httpsec.Chain, s served, saved *savedSessions)
	}

	// changes the password: the consumer's own handler, which owns the
	// response because only it knows what its clients expect to read.
	changes := func(_ *testing.T, ran *bool) httpsec.ChangePasswordFunc {
		return func(ex *httpsec.Exchange) error {
			*ran = true
			ex.Writer.SetHeader("Content-Type", "text/plain")
			ex.Writer.WriteHeader(http.StatusNoContent)

			return nil
		}
	}

	mustNotRun := func(t *testing.T, _ *bool) httpsec.ChangePasswordFunc {
		return func(*httpsec.Exchange) error {
			t.Error("the consumer's change-password function ran for a request with no caller")

			return nil
		}
	}

	refuses := func(_ *testing.T, ran *bool) httpsec.ChangePasswordFunc {
		return func(*httpsec.Exchange) error {
			*ran = true

			return errChangeRefused
		}
	}

	resolvingSession := func(_ *testing.T, h *authHarness, saved *savedSessions) {
		h.expectVerified()
		h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
		h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
			Return(storedUser(), nil).AnyTimes()
		h.expectSaved(saved, nil)
	}

	cases := []testCase{
		{
			name:   "a POST to the resolve path runs the consumer's function, which owns the response",
			change: changes,
			wire:   resolvingSession,
			request: func(ctx context.Context) *http.Request {
				return changePasswordRequest(ctx, http.MethodPost, true)
			},
			assert: func(t *testing.T, _ *authHarness, _ *httpsec.Chain, s served, saved *savedSessions) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan, "the endpoint is answered, not routed")
				assert.Equal(t, http.StatusNoContent, s.rec.Code)
				assert.Equal(t, "text/plain", s.rec.Header().Get("Content-Type"))

				records := saved.all()
				require.Len(t, records, 1, "the cleared marker is persisted once")
				assert.False(t, records[0].PasswordChangePending, "the debt is paid and recorded as paid")
			},
		},
		{
			name:   "the next request on that session passes the gate",
			change: changes,
			wire: func(t *testing.T, h *authHarness, saved *savedSessions) {
				t.Helper()

				// One session value, handed back by every load, so the second
				// request sees exactly what the first one cleared.
				live := owingPasswordChange()
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).Return(live, nil).AnyTimes()
				h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
					Return(storedUser(), nil).AnyTimes()
				h.expectSaved(saved, nil)
			},
			request: func(ctx context.Context) *http.Request {
				return changePasswordRequest(ctx, http.MethodPost, true)
			},
			assert: func(t *testing.T, _ *authHarness, chain *httpsec.Chain, s served, _ *savedSessions) {
				require.NoError(t, s.err)

				next := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.NoError(t, next.err)
				assert.True(t, next.handlerRan, "the session no longer owes a password change")
			},
		},
		{
			name:   "an unauthenticated POST to the resolve path",
			change: mustNotRun,
			wire:   func(*testing.T, *authHarness, *savedSessions) {},
			request: func(ctx context.Context) *http.Request {
				return changePasswordRequest(ctx, http.MethodPost, false)
			},
			assert: func(t *testing.T, _ *authHarness, _ *httpsec.Chain, s served, saved *savedSessions) {
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired,
					"this endpoint changes its caller's own password, so there must be a caller")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Empty(t, saved.all())
			},
		},
		{
			name:   "the consumer's function fails",
			change: refuses,
			wire:   resolvingSession,
			request: func(ctx context.Context) *http.Request {
				return changePasswordRequest(ctx, http.MethodPost, true)
			},
			assert: func(t *testing.T, _ *authHarness, _ *httpsec.Chain, s served, saved *savedSessions) {
				require.ErrorIs(t, s.err, errChangeRefused,
					"the consumer's error is the refusal, unchanged")
				assert.Empty(t, saved.all(), "a change that did not happen clears no marker")
			},
		},
		{
			name:   "a GET on the resolve path is still gated",
			change: mustNotRun,
			wire: func(_ *testing.T, h *authHarness, _ *savedSessions) {
				h.expectVerified()
				h.expectResolvedSession(owingPasswordChange())
			},
			request: func(ctx context.Context) *http.Request {
				return changePasswordRequest(ctx, http.MethodGet, true)
			},
			assert: func(t *testing.T, _ *authHarness, _ *httpsec.Chain, s served, _ *savedSessions) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				assert.False(t, s.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			saved := &savedSessions{}
			tc.wire(t, h, saved)

			var ran bool
			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
				httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithChangePasswordEndpoint(testChangePasswordPath, tc.change(t, &ran))),
			)
			require.NoError(t, err)

			tc.assert(t, h, chain, serve(t, chain, tc.request(t.Context())), saved)
		})
	}
}

// TestPasswordChangeConstruction pins that a gate nobody could resolve, or one
// wired to nothing, is refused before it serves a request.
func TestPasswordChangeConstruction(t *testing.T) {
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
			name: "a gate with no resolve endpoint builds",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnablePasswordChangeGate(h.sessions)}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err, "without one, only a new login clears the challenge")
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no session manager",
			build: func(*authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnablePasswordChangeGate(nil)}
			},
			assert: refused("EnablePasswordChangeGate", "session manager"),
		},
		{
			name: "a resolve endpoint with no path",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnablePasswordChangeGate(h.sessions,
						httpsec.WithChangePasswordEndpoint("",
							func(*httpsec.Exchange) error { return nil })),
				}
			},
			assert: refused("WithChangePasswordEndpoint"),
		},
		{
			name: "a resolve endpoint with no function",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnablePasswordChangeGate(h.sessions,
						httpsec.WithChangePasswordEndpoint(testChangePasswordPath, nil)),
				}
			},
			assert: refused("WithChangePasswordEndpoint"),
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

// carryingSession publishes s on every exchange, standing in for the first
// factor that resolved it. It is registered immediately outside the
// password-change slot, which is where a first factor would have run.
func carryingSession(s *session.Session) httpsec.Option {
	carrier := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.Authentication = &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}
		ex.Session = s
		ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), s))

		return next(ex)
	})

	return httpsec.RegisterInterceptor(carrier, httpsec.Before(httpsec.OrderPasswordChange))
}

// TestPasswordChangeGateLogout pins that a session owing a password change can
// always end itself, wherever the consumer put logout, and that nothing else
// gets through the gate on the strength of that exemption.
//
// The gate's slot is outside logout's, so without the exemption a caller
// stranded mid-challenge could not log out — on a device that is not theirs,
// the one thing they most need to do.
func TestPasswordChangeGateLogout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		logoutOpts []httpsec.LogoutOption
		request    func(ctx context.Context) *http.Request
		assert     func(t *testing.T, sessions *session.Manager, s *session.Session, out served)
	}

	loggedOut := func(t *testing.T, sessions *session.Manager, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.NotErrorAs(t, out.err, &ch, "a pending session is not refused at logout")
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)

		_, err := sessions.Load(t.Context(), s.ID)
		require.Error(t, err, "the session is ended, pending challenge included")
	}

	refused := func(t *testing.T, sessions *session.Manager, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
		assert.False(t, out.handlerRan)

		_, err := sessions.Load(t.Context(), s.ID)
		require.NoError(t, err, "a refused request ends nothing")
	}

	cases := []testCase{
		{
			name: "the default logout path",
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, httpsec.DefaultLogoutPath, "")
			},
			assert: loggedOut,
		},
		{
			name:       "a consumer logout path",
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/auth/sign-out", "")
			},
			assert: loggedOut,
		},
		{
			name: "a protected route is still refused",
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/invoices", nil)
			},
			assert: refused,
		},
		{
			// The exemption is the POST that logs out, not the path.
			name: "a GET on the logout path is still refused",
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, httpsec.DefaultLogoutPath, nil)
			},
			assert: refused,
		},
		{
			name:       "the old default path once logout has moved is refused",
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, httpsec.DefaultLogoutPath, "")
			},
			assert: refused,
		},
		{
			name: "the resolve endpoint still clears the marker",
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, testChangePasswordPath, "")
			},
			assert: func(t *testing.T, sessions *session.Manager, s *session.Session, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)

				stored, err := sessions.Load(t.Context(), s.ID)
				require.NoError(t, err)
				assert.False(t, stored.PasswordChangePending, "the debt is paid and recorded as paid")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.NewManager()
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), testPrincipal().ID)
			require.NoError(t, err)
			s.PasswordChangePending = true
			require.NoError(t, sessions.Save(t.Context(), s))

			chain, err := httpsec.New(
				carryingSession(s),
				httpsec.EnablePasswordChangeGate(sessions,
					httpsec.WithChangePasswordEndpoint(testChangePasswordPath, func(ex *httpsec.Exchange) error {
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					})),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}, tc.logoutOpts...),
			)
			require.NoError(t, err)

			tc.assert(t, sessions, s, serve(t, chain, tc.request(t.Context())))
		})
	}
}
