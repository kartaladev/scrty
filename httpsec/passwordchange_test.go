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
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// testChangePasswordPath is where these tests put the consumer's resolve
// endpoint. There is no default: without a resolve endpoint only a new login
// clears the challenge, so the path is the consumer's to name.
const testChangePasswordPath = "/account/password"

// reuseCurrentPassword is the resolve endpoint's caller's current password in
// the reuse-guard cases of TestChangePasswordEndpoint: a candidate submitted
// unchanged is what "reused" and "no guard configured" both check against.
const reuseCurrentPassword = "current-Secr3t!"

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
			name: "a reused password is refused through the reuse guard, and the debt survives",
			change: func(t *testing.T, ran *bool) httpsec.ChangePasswordFunc {
				t.Helper()

				enc := fastReuseEncoder(t)
				store := newPasswordReuseStore(&identity.Details{
					ID:       "u-1",
					Username: testSubject,
					Password: mustEncodeReuse(t, enc, reuseCurrentPassword),
				})
				history := newPasswordReuseHistory()

				// The candidate equals the current password, so a depth-1 guard —
				// which compares only against user.Password — refuses it without
				// any history seeded.
				return func(ex *httpsec.Exchange) error {
					*ran = true

					details, err := store.LoadByUsername(ex.Context(), testSubject)
					if err != nil {
						return err
					}

					guard, err := password.NewReuseGuard(history, enc, 1)
					if err != nil {
						return err
					}

					write, err := password.ProvisionerWrite(store)
					if err != nil {
						return err
					}

					return guard.Change(ex.Context(), details, ex.Request.FormValue("password"), write)
				}
			},
			wire: resolvingSession,
			request: func(ctx context.Context) *http.Request {
				return changePasswordFormRequest(ctx, reuseCurrentPassword)
			},
			assert: func(t *testing.T, _ *authHarness, chain *httpsec.Chain, s served, saved *savedSessions) {
				require.ErrorIs(t, s.err, password.ErrPasswordReused)
				assert.Equal(t, http.StatusUnprocessableEntity, httpsec.StatusForError(s.err))
				assert.Empty(t, saved.all(), "a change refused as reused clears no marker")

				next := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, next.err, &ch,
					"the next request on the session is still refused with the password-change challenge")
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				assert.False(t, next.handlerRan)
			},
		},
		{
			name: "an endpoint with no reuse guard accepts the current password and clears the marker",
			change: func(t *testing.T, ran *bool) httpsec.ChangePasswordFunc {
				t.Helper()

				enc := fastReuseEncoder(t)
				store := newPasswordReuseStore(&identity.Details{
					ID:       "u-1",
					Username: testSubject,
					Password: mustEncodeReuse(t, enc, reuseCurrentPassword),
				})

				// No guard is built at all: reuse checking is off unless the
				// consumer enables it.
				return func(ex *httpsec.Exchange) error {
					*ran = true

					details, err := store.LoadByUsername(ex.Context(), testSubject)
					if err != nil {
						return err
					}

					hash, err := enc.Encode(ex.Request.FormValue("password"))
					if err != nil {
						return err
					}

					_, err = store.Update(ex.Context(), details.Username, identity.WithUserPassword(hash))

					return err
				}
			},
			wire: resolvingSession,
			request: func(ctx context.Context) *http.Request {
				return changePasswordFormRequest(ctx, reuseCurrentPassword)
			},
			assert: func(t *testing.T, _ *authHarness, chain *httpsec.Chain, s served, saved *savedSessions) {
				require.NoError(t, s.err, "no guard is called, so the current password is accepted")

				records := saved.all()
				require.Len(t, records, 1, "the cleared marker is persisted once")
				assert.False(t, records[0].PasswordChangePending)

				next := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.NoError(t, next.err)
				assert.True(t, next.handlerRan, "the session no longer owes a password change")
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

// TestChangePasswordEndpointClearsLockoutFailures pins that a password the
// caller has just changed is not held to guesses made at the old one: the
// gate clears the principal's username in every attempt store the chain's
// password logins record into, and clears nothing when the change fails.
func TestChangePasswordEndpointClearsLockoutFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, h *authHarness, other policy.AttemptStore) []httpsec.Option
		expect  func(h *authHarness, other *MockAttemptStore)
		change  httpsec.ChangePasswordFunc
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, h *authHarness, s served)

		// user is what the bearer step loads the caller as, and storedUser()
		// when nil. saveErr is what saving the resolved session fails with.
		user    *identity.Details
		saveErr error
	}

	changes := func(ex *httpsec.Exchange) error {
		ex.Writer.WriteHeader(http.StatusNoContent)

		return nil
	}
	refuses := func(*httpsec.Exchange) error { return errChangeRefused }
	post := func(ctx context.Context) *http.Request { return changePasswordRequest(ctx, http.MethodPost, true) }
	succeeded := func(t *testing.T, _ *authHarness, s served) {
		require.NoError(t, s.err)
		assert.Equal(t, http.StatusNoContent, s.rec.Code)
	}
	login := func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
		return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps())}
	}

	cases := []testCase{
		{
			name:    "a successful change clears the principal's username in the login store",
			options: login,
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			name: "a distinct Basic store is cleared too",
			options: func(_ *testing.T, h *authHarness, other policy.AttemptStore) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: other}),
				}
			},
			expect: func(h *authHarness, other *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
				other.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			name: "a store shared by form login and Basic is cleared once",
			options: func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()),
				}
			},
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			// Pins that a chain with no password login has no password lockout, so
			// there is nothing to clear and nothing to fail on.
			name:    "a chain with no password login clears nothing and does not fail",
			options: func(*testing.T, *authHarness, policy.AttemptStore) []httpsec.Option { return nil },
			expect:  func(*authHarness, *MockAttemptStore) {},
			change:  changes, request: post, assert: succeeded,
		},
		{
			// Pins that a value whose dynamic type holds a slice cannot be
			// compared with ==, so it is treated as distinct, never as a panic.
			name: "an attempt store of an uncomparable type is cleared without panicking",
			options: func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
				s := uncomparableStore{AttemptStore: h.attempts, tags: []string{"x"}}
				d := h.formLoginDeps()
				d.Attempts = s

				return []httpsec.Option{
					httpsec.EnableFormLogin(d),
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: s}),
				}
			},
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(2)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			// A struct whose field is an interface is comparable by type, yet
			// == panics when that interface holds an uncomparable value.
			name: "an attempt store wrapping an uncomparable store is cleared without panicking",
			options: func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
				s := wrappingStore{AttemptStore: uncomparableStore{AttemptStore: h.attempts, tags: []string{"x"}}}
				d := h.formLoginDeps()
				d.Attempts = s

				return []httpsec.Option{
					httpsec.EnableFormLogin(d),
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: s}),
				}
			},
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(2)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			// The identifier is read before the consumer's function runs, so a
			// function that replaces the exchange's context cannot change it.
			name:    "a change function that replaces the context cannot change the username cleared",
			options: login,
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: func(ex *httpsec.Exchange) error {
				ex.SetContext(identity.WithPrincipal(ex.Context(), &identity.Principal{Username: "mallory"}))
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			},
			request: post, assert: succeeded,
		},
		{
			name:    "a change function that drops the principal still has the original username cleared",
			options: login,
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: func(ex *httpsec.Exchange) error {
				ex.SetContext(context.Background())
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			},
			request: post, assert: succeeded,
		},
		{
			name:    "a refused change clears nothing",
			options: login,
			expect:  func(*authHarness, *MockAttemptStore) {},
			change:  refuses, request: post,
			assert: func(t *testing.T, _ *authHarness, s served) { require.ErrorIs(t, s.err, errChangeRefused) },
		},
		{
			name:    "a client that hangs up after changing its password is still cleared",
			options: login,
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).
					DoAndReturn(func(ctx context.Context, _ string) error {
						if ctx.Err() != nil {
							return fmt.Errorf("cleared on a cancelled context: %w", ctx.Err())
						}

						return nil
					}).Times(1)
			},
			change: func(ex *httpsec.Exchange) error {
				cancel, ok := ex.Context().Value(cancelKey{}).(context.CancelFunc)
				if !ok {
					return errors.New("passwordchange_test: no cancel function on the exchange")
				}

				cancel()

				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			},
			request: post,
			assert: func(t *testing.T, h *authHarness, s served) {
				require.NoError(t, s.err)
				for _, r := range h.logs.records() {
					assert.NotEqual(t, msgFailuresNotCleared, r.Message,
						"the clearing ran on the client's cancelled context")
				}
			},
		},
		{
			// The password has changed by the time the session is saved, so a
			// save that then fails does not bring the old guesses back.
			name:    "a session that cannot be saved after the change is still cleared",
			options: login,
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: changes, request: post,
			saveErr: errSaveFailed,
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.ErrorIs(t, s.err, errSaveFailed)
			},
		},
		{
			// Pins that the store matches exactly, so only the principal's
			// own spelling is cleared. The token names the caller "ada" and the
			// loader stores them as "Ada": "Ada" is cleared, and neither the
			// token's spelling nor a case-folded one is.
			name:    "only the principal's exact username is cleared",
			options: login,
			user: func() *identity.Details {
				d := storedUser()
				d.Username = "Ada"

				return d
			}(),
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), "Ada").Return(nil).Times(1)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			// A principal with no username names no identifier, and an empty
			// string is never cleared.
			name:    "a principal with an empty username clears nothing and does not fail",
			options: login,
			user: func() *identity.Details {
				d := storedUser()
				d.Username = ""

				return d
			}(),
			expect: func(*authHarness, *MockAttemptStore) {},
			change: changes, request: post, assert: succeeded,
		},
		{
			// The password has changed; a store that cannot clear is bookkeeping
			// that failed, reported once with its type and never its text or the
			// username, and the consumer's response is what the client reads.
			name:    "a clearing that fails is logged and the consumer's response stands",
			options: login,
			expect: func(h *authHarness, _ *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).
					Return(errors.New("db: column secret_hint=hunter2")).Times(1)
			},
			change: changes, request: post,
			assert: func(t *testing.T, h *authHarness, s served) {
				succeeded(t, h, s)

				var cleared []slog.Record
				for _, r := range h.logs.records() {
					if r.Message == msgFailuresNotCleared {
						cleared = append(cleared, r)
					}
				}
				require.Len(t, cleared, 1, "one error record names the failed clearing")
				assert.Equal(t, slog.LevelError, cleared[0].Level)

				errType, ok := attrValue(cleared[0], "error_type")
				require.True(t, ok, "the record names the store's error type")
				assert.Equal(t, "*errors.errorString", errType.String())

				for _, r := range h.logs.records() {
					r.Attrs(func(a slog.Attr) bool {
						assert.NotContains(t, a.Value.String(), "hunter2", "a store's error text reached the log")

						return true
					})
				}
				cleared[0].Attrs(func(a slog.Attr) bool {
					assert.NotEqual(t, testSubject, a.Value.String(), "the username reached the log")

					return true
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := tc.user
			if user == nil {
				user = storedUser()
			}

			h := newAuthHarness(t)
			h.expectVerified()
			h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
			h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(user, nil).AnyTimes()
			h.expectSaved(&savedSessions{}, tc.saveErr)

			other := NewMockAttemptStore(gomock.NewController(t))
			tc.expect(h, other)

			opts := append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
				httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithChangePasswordEndpoint(testChangePasswordPath, tc.change)),
			}, tc.options(t, h, other)...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, h, serveHangingUp(t, chain, tc.request(t.Context())))
		})
	}
}

// serveHangingUp is serve on an exchange whose context carries its own cancel
// function under cancelKey, so the consumer's function can hang the client up
// mid-request as a real client disconnecting would.
func serveHangingUp(t *testing.T, chain *httpsec.Chain, req *http.Request) served {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(context.WithValue(ctx, cancelKey{}, cancel),
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

// msgFailuresNotCleared is the record the gate writes for a store that could
// not clear the failures a password change superseded.
const msgFailuresNotCleared = "httpsec: lockout failures could not be cleared after a password change"

// errSaveFailed is what the session store fails with when a test needs the
// resolved session's save to fail.
var errSaveFailed = errors.New("passwordchange_test: the session could not be saved")

// cancelKey carries a request's cancel function, so a test's change function
// can hang the client up mid-request.
type cancelKey struct{}

// uncomparableStore is an attempt store whose dynamic type cannot be compared
// with ==, as a consumer's struct value holding a slice cannot.
type uncomparableStore struct {
	policy.AttemptStore

	tags []string
}

// wrappingStore is a comparable struct type whose embedded interface may hold
// a value that cannot be compared.
type wrappingStore struct {
	policy.AttemptStore
}

// TestChangePasswordEndpointLetsTheNewPasswordIn pins, against a real lockout
// over the in-memory store, that the new password is not refused for guesses
// made at the old one: seven failures owe a wait, the caller resolves a
// password change, and a form login posted at once is let in.
func TestChangePasswordEndpointLetsTheNewPasswordIn(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	store := policy.NewMemoryAttemptStore()
	now := time.Now()
	for i := range 7 {
		require.NoError(t, store.RecordFailure(t.Context(), testSubject, now.Add(-time.Duration(i)*time.Second)))
	}

	lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(store))
	require.NoError(t, err)
	engine, err := policy.NewEngine(lockout)
	require.NoError(t, err)

	h.expectVerified()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil).AnyTimes()
	h.expectSaved(&savedSessions{}, nil)
	h.expectAuthenticated(testPrincipal())
	h.expectSessionOpened("a-new-token")

	login := h.formLoginDeps()
	login.Attempts = store

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableBearerToken(h.bearerTokenDeps()),
		httpsec.EnableFormLogin(login),
		httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithChangePasswordEndpoint(testChangePasswordPath, func(ex *httpsec.Exchange) error {
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			})),
	)
	require.NoError(t, err)

	require.NoError(t, serve(t, chain, changePasswordRequest(t.Context(), http.MethodPost, true)).err)

	got := serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath,
		"username="+testSubject+"&password=the-new-one"))

	require.NoError(t, got.err, "the new password was refused for guesses at the old one")
}
