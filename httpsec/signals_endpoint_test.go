package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// requireStreamHead asserts resp is the head of an open stream.
func requireStreamHead(t *testing.T, resp *http.Response) {
	t.Helper()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store, no-transform", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no", resp.Header.Get("X-Accel-Buffering"))
}

// requireNoStream asserts resp is an answer and not the head of a stream.
func requireNoStream(t *testing.T, resp *http.Response, status int) {
	t.Helper()

	require.Equal(t, status, resp.StatusCode)
	assert.NotEqual(t, "text/event-stream", resp.Header.Get("Content-Type"))
}

// unflushableWriter is a consumer's wrapper with no Unwrap and no Flush, so a stream cannot
// reach the connection through it.
type unflushableWriter struct{ http.ResponseWriter }

func TestSessionSignals_Endpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  signalsSetup
		assert func(t *testing.T, f *signalsFixture)
	}

	cases := []testCase{
		{
			name:  "not enabled, the request passes through",
			setup: signalsSetup{withoutSignals: true},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				resp, _ := f.openStream(t, s.ID)
				assert.Equal(t, signalsDownstreamStatus, resp.StatusCode)
			},
		},
		{
			name: "GET opens a stream that stays open until the client leaves",
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				resp, cancel := f.openStream(t, s.ID)
				requireStreamHead(t, resp)
				f.requireOpen(t)

				cancel()
				f.waitDone(t)
			},
		},
		{
			name: "another path passes through",
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				resp := f.send(t.Context(), t, http.MethodGet, "/session/signals/more", s.ID)
				assert.Equal(t, signalsDownstreamStatus, resp.StatusCode)
			},
		},
		{
			name: "another method is 405 naming GET, and opens no stream",
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions} {
					resp := f.send(t.Context(), t, method, httpsec.DefaultSessionSignalsPath, s.ID)
					requireNoStream(t, resp, http.StatusMethodNotAllowed)
					assert.Equal(t, http.MethodGet, resp.Header.Get("Allow"), method)
					assert.Contains(t, resp.Header.Get("Cache-Control"), "no-store", method)
					f.waitDone(t)
				}
			},
		},
		{
			name: "another method is judged before the credential",
			assert: func(t *testing.T, f *signalsFixture) {
				resp := f.send(t.Context(), t, http.MethodPost, httpsec.DefaultSessionSignalsPath, "")
				requireNoStream(t, resp, http.StatusMethodNotAllowed)
			},
		},
		{
			name:  "a consumer's path is served, and the default is not",
			setup: signalsSetup{signals: httpsec.SessionSignals{Path: "/api/me/signals"}},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				requireStreamHead(t, f.send(t.Context(), t, http.MethodGet, "/api/me/signals", s.ID))

				resp, _ := f.openStream(t, s.ID)
				assert.Equal(t, signalsDownstreamStatus, resp.StatusCode)
			},
		},
		{
			name: "a wrapper with no Unwrap and no Flush is 501",
			setup: signalsSetup{wrapHandler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(unflushableWriter{w}, r)
				})
			}},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				resp, _ := f.openStream(t, s.ID)
				assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
				assert.NotContains(t, resp.Header.Get("Content-Type"), "text/event-stream", "a refusal is no event stream")
			},
		},
		{
			name: "http.TimeoutHandler is 501",
			setup: signalsSetup{wrapHandler: func(next http.Handler) http.Handler {
				return http.TimeoutHandler(next, time.Minute, "timed out")
			}},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				resp, _ := f.openStream(t, s.ID)
				assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
				assert.NotContains(t, resp.Header.Get("Content-Type"), "text/event-stream", "a refusal is no event stream")
			},
		},
		{
			name: "a consumer's adapter that cannot stream is 501",
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				run := f.chain.Assemble(func(*httpsec.Exchange) error {
					require.Fail(t, "the application's handler must not run")

					return nil
				})

				w := &stubWriter{}

				err := run(httpsec.NewExchange(t.Context(), stubRequest{
					method:   http.MethodGet,
					path:     httpsec.DefaultSessionSignalsPath,
					clientIP: "198.51.100.7",
					headers:  map[string]string{"Authorization": "Bearer " + s.ID},
				}, w))

				require.ErrorIs(t, err, httpsec.ErrStreamingUnsupported)
				assert.Equal(t, http.StatusNotImplemented, httpsec.StatusForError(err))
				assert.NotContains(t, w.header.Get("Content-Type"), "text/event-stream", "a refusal is no event stream")
				assert.Contains(t, w.header.Get("Cache-Control"), "no-store", "a refusal is never cached")
			},
		},
		{
			name: "an interceptor that already wrote gets the chain's error mapping",
			setup: signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						_, err := ex.Writer.Write([]byte("started"))
						require.NoError(t, err)

						return next(ex)
					}), httpsec.Before(httpsec.OrderSessionSignals))}
			}},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)
				req.Header.Set("Authorization", "Bearer "+s.ID)

				out := serve(t, f.chain, req)
				require.ErrorIs(t, out.err, httpsec.ErrStreamingStarted)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.Equal(t, "started", out.rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newSignalsFixture(t, tc.setup))
		})
	}
}

// signalsCookie names the cookie a consumer's authenticator reads in these tests.
const signalsCookie = "signals_session"

// consumerSessionCookie is a consumer's own interceptor authenticating a request by a
// cookie and publishing its sign-in, written against the exported API alone.
//
// record has it also call RecordPresentedToken with the cookie's value, as PublishSession's
// godoc tells such an interceptor to.
type consumerSessionCookie struct {
	sessions *session.Sessions
	record   bool
}

func (consumerSessionCookie) AuthenticatesByCookie() {}

func (a consumerSessionCookie) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	sid, ok := ex.Request.Cookie(signalsCookie)
	if !ok {
		return next(ex)
	}

	s, err := a.sessions.Load(ex.Context(), sid)
	if err != nil {
		return httpsec.ErrAuthenticationRequired
	}

	if err := httpsec.CheckCSRFToken(ex, s); err != nil {
		return err
	}

	if err := ex.PublishSession(&authenticate.Authentication{
		Principal: identity.PrincipalFromDetails(storedUser()),
	}, s); err != nil {
		return err
	}

	if a.record {
		ex.RecordPresentedToken(sid)
	}

	return next(ex)
}

// withSignalsCookie presents sid as the consumer's cookie.
func withSignalsCookie(sid string) func(*http.Request) {
	return func(req *http.Request) { req.AddCookie(&http.Cookie{Name: signalsCookie, Value: sid}) } //nolint:gosec // a request's cookie in a test: attributes belong to a Set-Cookie, which a client does not send
}

// listSpyStore is a session store whose listing calls see before it answers, and fail
// replaces the answer when it returns an error.
type listSpyStore struct {
	session.Store

	see  func(ctx context.Context)
	fail func() error

	// empty answers every listing with no sessions.
	empty bool
}

func (s *listSpyStore) ListByUser(ctx context.Context, user identity.UserID, at time.Time) ([]*session.Session, error) {
	if s.see != nil {
		s.see(ctx)
	}

	if s.fail != nil {
		if err := s.fail(); err != nil {
			return nil, err
		}
	}

	if s.empty {
		return nil, nil
	}

	return s.Store.ListByUser(ctx, user, at)
}

// signalsTenantKey is a value a consumer's middleware puts on the request's context.
type signalsTenantKey struct{}

// withSignalsTenant is a consumer's middleware putting a tenant on the request's context.
func withSignalsTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), signalsTenantKey{}, "t-1")))
	})
}

// publishCallerOnly stands in for a token bound to no session: a consumer's interceptor
// publishing a caller and no sign-in.
func publishCallerOnly() httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Request.Header("X-Stateless") == "" {
			return next(ex)
		}

		if err := ex.PublishSession(&authenticate.Authentication{
			Principal: identity.PrincipalFromDetails(storedUser()),
		}, nil); err != nil {
			return err
		}

		return next(ex)
	}), httpsec.OrderBearerToken)
}

func TestSessionSignals_Admission(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) signalsSetup
		assert func(t *testing.T, f *signalsFixture)
	}

	cases := []testCase{
		{
			name: "no credential is 401",
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "")
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a session reference only in the query is 401",
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				for _, name := range []string{"session", "access_token", "token", "authorization", "id"} {
					resp := f.send(t.Context(), t, http.MethodGet, httpsec.DefaultSessionSignalsPath+"?"+name+"="+s.ID, "")
					requireNoStream(t, resp, http.StatusUnauthorized)
				}
			},
		},
		{
			name: "a session reference opens a stream",
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireStreamHead(t, resp)
			},
		},
		{
			name: "a signed bearer tied to a stored session opens a stream",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
					verifier := NewMockVerifier(gomock.NewController(t))
					verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
						func(_ context.Context, presented string) (*token.Claims, error) {
							return token.NewClaims("u-1", presented), nil
						})

					return []httpsec.Option{httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: verifier, Sessions: f.sessions, Users: f.users,
					})}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireStreamHead(t, resp)
			},
		},
		{
			name: "HTTP Basic is 403",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				ctrl := gomock.NewController(t)

				authn := NewMockAuthenticator(ctrl)
				authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).AnyTimes().Return(
					&authenticate.Authentication{Principal: identity.PrincipalFromDetails(storedUser()), Time: time.Now()}, nil)

				attempts := NewMockAttemptStore(ctrl)
				attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts})}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "", func(req *http.Request) { req.SetBasicAuth("ada", "secret") })
				requireNoStream(t, resp, http.StatusForbidden)
			},
		},
		{
			name: "an API key is 403",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					h := newAPIKeyHarness(t)

					return []httpsec.Option{
						httpsec.EnableAPIKey(h.keys),
						withIssuedAPIKey(t, h.valid),
					}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "", func(req *http.Request) {
					req.Header.Set("X-Present-Key", "yes")
				})
				requireNoStream(t, resp, http.StatusForbidden)
			},
		},
		{
			name: "a token with no session is 403",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{publishCallerOnly()}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "", func(req *http.Request) { req.Header.Set("X-Stateless", "yes") })
				requireNoStream(t, resp, http.StatusForbidden)
			},
		},
		{
			name: "a caller published with WithCaller and SetContext, and no sign-in, is 403",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(ex *httpsec.Exchange, next httpsec.Next) error {
							ex.SetContext(httpsec.WithCaller(ex.Context(), &authenticate.Authentication{
								Principal: identity.PrincipalFromDetails(storedUser()),
							}))

							return next(ex)
						}), httpsec.OrderBearerToken)}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "")
				requireNoStream(t, resp, http.StatusForbidden)
			},
		},
		{
			name: "a sign-in no result owns, beside a caller on the context, is 401",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.WithSessions(f.sessions), httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(ex *httpsec.Exchange, next httpsec.Next) error {
							s, err := f.sessions.Load(ex.Context(), ex.Request.Header("X-Session"))
							if err != nil {
								return err
							}

							if err := ex.PublishSession(nil, s); err != nil {
								return err
							}

							ex.SetContext(httpsec.WithCaller(ex.Context(), &authenticate.Authentication{
								Principal: identity.PrincipalFromDetails(storedUser()),
							}))

							return next(ex)
						}), httpsec.OrderBearerToken)}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")

				resp, _ := f.openStream(t, "", func(req *http.Request) { req.Header.Set("X-Session", s.ID) })
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a sign-in owing a password change is refused by its gate",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{opts: func(f *signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.EnablePasswordChangeGate(f.sessions)}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")
				s.PasswordChangePending = true
				require.NoError(t, f.sessions.Save(t.Context(), s))

				resp, _ := f.openStream(t, s.ID)
				requireNoStream(t, resp, http.StatusForbidden)
			},
		},
		{
			name: "a sign-in still owing something on a chain with no gate holds the line itself",
			assert: func(t *testing.T, f *signalsFixture) {
				s := f.signIn(t, "u-1")
				s.MFA = session.MFAPending
				require.NoError(t, f.sessions.Save(t.Context(), s))

				resp, _ := f.openStream(t, s.ID)
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a consumer's raised challenge is refused",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				const terms policy.ChallengeKind = 100

				engine, err := policy.NewEngine(raisingDeclared{phase: policy.PerRequest, kind: terms})
				require.NoError(t, err)

				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.WithPolicyEngine(engine), httpsec.WithChallengeEnforcer(terms)}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a consumer's CookieAuthenticator opens a stream, with no CSRF token",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
					return []httpsec.Option{
						httpsec.WithSessions(f.sessions),
						httpsec.EnableCSRFProtection(),
						httpsec.RegisterInterceptor(consumerSessionCookie{sessions: f.sessions}, httpsec.OrderBearerToken),
					}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-1").ID))
				requireStreamHead(t, resp)
			},
		},
		{
			name: "a caller who is not the session's user is 401",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
					return []httpsec.Option{
						httpsec.WithSessions(f.sessions),
						httpsec.WithoutCSRFProtection(),
						httpsec.RegisterInterceptor(consumerSessionCookie{sessions: f.sessions}, httpsec.OrderBearerToken),
					}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-2").ID))
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a sign-in the first read cannot find is 401",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{wrap: func(s session.Store) session.Store {
					return &listSpyStore{Store: s, empty: true}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a store failure at the first read opens no stream, and is a dependency failure",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{wrap: func(s session.Store) session.Store {
					return &listSpyStore{Store: s, fail: func() error { return errors.New("db-primary:5432 refused") }}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var setup signalsSetup
			if tc.setup != nil {
				setup = tc.setup(t)
			}

			tc.assert(t, newSignalsFixture(t, setup))
		})
	}
}

// withIssuedAPIKey presents key on a request that asks for it, so a row need not build its
// fixture around the harness that issued it.
func withIssuedAPIKey(t *testing.T, key string) httpsec.Option {
	t.Helper()

	presented := httpsec.DefaultAPIKeyScheme + key

	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Request.Header("X-Present-Key") == "" {
			return next(ex)
		}

		ex.Request = presentedKeyRequest{Request: ex.Request, key: presented}

		return next(ex)
	}), httpsec.Before(httpsec.OrderAPIKey))
}

// presentedKeyRequest is a request carrying an API key as its Authorization header.
type presentedKeyRequest struct {
	httpsec.Request

	key string
}

func (r presentedKeyRequest) Header(name string) string {
	if name == "Authorization" {
		return r.key
	}

	return r.Request.Header(name)
}

// TestSessionSignals_Admission_GateRefusesFirst pins that a pending sign-in is refused by
// its gate and never reaches the stream's slot. It has its own table because it runs on
// the harness those gates are built on, which stands in for the bearer.
func TestSessionSignals_Admission_GateRefusesFirst(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		session func(t *testing.T, h *enrolHarness) *session.Session
		extra   []httpsec.Option
		assert  func(t *testing.T, err error)
	}

	owes := func(kind policy.ChallengeKind) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, err, &ch)
			assert.Equal(t, kind, ch.Kind)
		}
	}

	cases := []testCase{
		{
			name: "a second factor",
			session: func(t *testing.T, h *enrolHarness) *session.Session {
				t.Helper()

				return h.sessionIn(t, factor.Password, session.MFAPending)
			},
			assert: owes(policy.ChallengeMFA),
		},
		{
			name: "an enrolment",
			session: func(t *testing.T, h *enrolHarness) *session.Session {
				t.Helper()

				return h.sessionIn(t, factor.Password, session.MFAEnrolmentPending)
			},
			assert: owes(policy.ChallengeMFAEnrolment),
		},
		{
			name: "a recovery",
			session: func(t *testing.T, h *enrolHarness) *session.Session {
				t.Helper()

				return h.recoveryPending(t)
			},
			extra:  []httpsec.Option{httpsec.EnableRecoveryGateForTest()},
			assert: owes(policy.ChallengeAccountRecovery),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			s := tc.session(t, h)

			var reached atomic.Bool

			h.extra = append([]httpsec.Option{
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					reached.Store(true)

					return next(ex)
				}), httpsec.OrderSessionSignals),
				httpsec.EnableSessionSignals(httpsec.SessionSignals{Users: h.users}),
			}, tc.extra...)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)

			chain := h.chain(t, s)

			// The endpoint refuses a pending sign-in by itself as well, so a refusal alone
			// cannot show which of the two answered: where it sits has to be asserted.
			slot := httpsec.SignalsSlotOf(chain)
			assert.Equal(t, httpsec.OrderSessionSignals, slot, "the endpoint is registered at its own slot")

			for name, gate := range map[string]httpsec.Order{
				"the recovery gate":        httpsec.OrderAccountRecovery,
				"the enrolment gate":       httpsec.OrderMFAEnrolment,
				"the second-factor gate":   httpsec.OrderMFAChallenge,
				"the password-change gate": httpsec.OrderPasswordChange,
				"the re-authentication":    httpsec.OrderReauthentication,
			} {
				assert.Greater(t, slot, gate, "the endpoint sits outside %s", name)
			}

			assert.Less(t, slot, httpsec.OrderSessionTouch)
			assert.Less(t, slot, httpsec.OrderAuthorizer)

			out := serve(t, chain, req)
			tc.assert(t, out.err)
			assert.False(t, reached.Load(), "the request reached the stream's slot")
			assert.False(t, out.handlerRan)
		})
	}
}

// TestSessionSignals_Admission_ReloadContext pins what the first read runs on. It has its
// own table because each row reads the context the store saw.
func TestSessionSignals_Admission_ReloadContext(t *testing.T) {
	t.Parallel()

	tenantOf := func(ctx context.Context) any { return ctx.Value(signalsTenantKey{}) }

	type testCase struct {
		name    string
		signals httpsec.SessionSignals
		assert  func(t *testing.T, seen context.Context, f *signalsFixture, resp *http.Response)
	}

	var hookCalls atomic.Int64

	cases := []testCase{
		{
			name: "by default it carries none of the request's values",
			assert: func(t *testing.T, seen context.Context, _ *signalsFixture, resp *http.Response) {
				requireStreamHead(t, resp)
				require.NotNil(t, seen, "the first read ran")
				assert.Nil(t, tenantOf(seen))
			},
		},
		{
			name: "it is bounded by half the heartbeat by default",
			assert: func(t *testing.T, seen context.Context, _ *signalsFixture, _ *http.Response) {
				require.NotNil(t, seen, "the first read ran")

				deadline, ok := seen.Deadline()
				require.True(t, ok)
				assert.LessOrEqual(t, time.Until(deadline), 7500*time.Millisecond)
			},
		},
		{
			name:    "a consumer's ReloadTimeout bounds it",
			signals: httpsec.SessionSignals{ReloadTimeout: 2 * time.Second},
			assert: func(t *testing.T, seen context.Context, _ *signalsFixture, _ *http.Response) {
				require.NotNil(t, seen, "the first read ran")

				deadline, ok := seen.Deadline()
				require.True(t, ok)
				assert.LessOrEqual(t, time.Until(deadline), 2*time.Second)
			},
		},
		{
			name: "a consumer's ReloadContext carries its tenant, called once",
			signals: httpsec.SessionSignals{ReloadContext: func(ctx context.Context) context.Context {
				hookCalls.Add(1)

				return context.WithValue(context.Background(), signalsTenantKey{}, tenantOf(ctx))
			}},
			assert: func(t *testing.T, seen context.Context, _ *signalsFixture, resp *http.Response) {
				requireStreamHead(t, resp)
				require.NotNil(t, seen, "the first read ran")
				assert.Equal(t, "t-1", tenantOf(seen))
				assert.EqualValues(t, 1, hookCalls.Load())
			},
		},
		{
			name: "a ReloadContext that returns nothing opens no stream",
			signals: httpsec.SessionSignals{ReloadContext: func(context.Context) context.Context {
				return nil
			}},
			assert: func(t *testing.T, seen context.Context, _ *signalsFixture, resp *http.Response) {
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				assert.Nil(t, seen, "no read ran with no context")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// hookCalls is one row's, so this table does not run in parallel with itself.
			var seen atomic.Pointer[context.Context]

			f := newSignalsFixture(t, signalsSetup{
				signals: tc.signals,
				wrap: func(s session.Store) session.Store {
					return &listSpyStore{Store: s, see: func(ctx context.Context) { seen.Store(&ctx) }}
				},
				wrapHandler: withSignalsTenant,
			})

			resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

			var ctx context.Context
			if p := seen.Load(); p != nil {
				ctx = *p
			}

			tc.assert(t, ctx, f, resp)
		})
	}
}

// TestSessionSignals_Admission_ReloadContextLosesCancellation pins that a ReloadContext
// returning the request's own context does not tie the reads to the request.
func TestSessionSignals_Admission_ReloadContextLosesCancellation(t *testing.T) {
	t.Parallel()

	var seenErr atomic.Pointer[error]

	f := newSignalsFixture(t, signalsSetup{
		withoutSignals: true,
		wrap: func(s session.Store) session.Store {
			return &listSpyStore{Store: s, see: func(ctx context.Context) {
				err := ctx.Err()
				seenErr.Store(&err)
			}}
		},
	})

	s := f.signIn(t, "u-1")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	chain, err := httpsec.New(
		httpsec.WithClock(f.clk),
		httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			if err := ex.PublishSession(&authenticate.Authentication{
				Principal: identity.PrincipalFromDetails(storedUser()),
			}, s); err != nil {
				return err
			}

			// The request ends here, after it was authenticated.
			cancel()

			return next(ex)
		}), httpsec.OrderBearerToken),
		httpsec.WithSessions(f.sessions),
		httpsec.EnableSessionSignals(httpsec.SessionSignals{
			Users:         f.users,
			ReloadContext: func(ctx context.Context) context.Context { return ctx },
		}),
	)
	require.NoError(t, err)

	var out served

	requireReturns(t, func() { out = serveContext(ctx, t, chain, req) })
	require.NoError(t, out.err)

	got := seenErr.Load()
	require.NotNil(t, got, "the first read ran")
	assert.NoError(t, *got, "the request's cancellation reached the read")
}

func TestSessionSignals_NoActivity(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(answers *atomic.Pointer[bool], touched *atomic.Bool) signalsSetup
		assert func(t *testing.T, f *signalsFixture, answers *atomic.Pointer[bool], touched *atomic.Bool)
	}

	const touchInterval = time.Minute

	cases := []testCase{
		{
			name: "holding a stream past the touch interval moves nothing and records nothing",
			setup: func(*atomic.Pointer[bool], *atomic.Bool) signalsSetup {
				return signalsSetup{sessionOpts: []session.Option{session.WithTouchInterval(touchInterval)}}
			},
			assert: func(t *testing.T, f *signalsFixture, _ *atomic.Pointer[bool], _ *atomic.Bool) {
				s := f.signIn(t, "u-1")
				before := f.storedSession(t, s.ID)

				_, cancel := f.openStream(t, s.ID)
				opened := f.storedSession(t, s.ID)

				assert.True(t, before.LastAccessedAt.Equal(opened.LastAccessedAt), "opening moved the last-activity time")
				assert.True(t, before.IdleExpiresAt.Equal(opened.IdleExpiresAt), "opening moved the idle deadline")

				f.clk.Advance(2 * touchInterval)
				f.requireOpen(t)

				// Compared once the stream has ended too, since what records activity
				// runs after the handler.
				cancel()
				f.waitDone(t)

				after := f.storedSession(t, s.ID)
				assert.True(t, before.LastAccessedAt.Equal(after.LastAccessedAt), "the stream moved the last-activity time")
				assert.True(t, before.IdleExpiresAt.Equal(after.IdleExpiresAt), "the stream moved the idle deadline")
				assert.True(t, opened.FirstPresentedAt.Equal(after.FirstPresentedAt), "holding a stream recorded a presentation")

				_, err := f.sessions.SignInState(t.Context(), s.UserID, s.FamilyID)
				assert.NoError(t, err, "holding a stream ended the sign-in")
			},
		},
		{
			name: "an ordinary request on the same chain does move them",
			setup: func(*atomic.Pointer[bool], *atomic.Bool) signalsSetup {
				return signalsSetup{sessionOpts: []session.Option{session.WithTouchInterval(touchInterval)}}
			},
			assert: func(t *testing.T, f *signalsFixture, _ *atomic.Pointer[bool], _ *atomic.Bool) {
				s := f.signIn(t, "u-1")
				before := f.storedSession(t, s.ID)

				f.clk.Advance(2 * touchInterval)

				resp := f.send(t.Context(), t, http.MethodGet, "/orders", s.ID)
				require.Equal(t, signalsDownstreamStatus, resp.StatusCode)
				f.waitDone(t)

				after := f.storedSession(t, s.ID)
				assert.True(t, after.LastAccessedAt.After(before.LastAccessedAt), "the control did not record activity")
			},
		},
		{
			name: "a consumer's interceptor is told the stream records no activity, and other requests do",
			setup: func(answers *atomic.Pointer[bool], _ *atomic.Bool) signalsSetup {
				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(ex *httpsec.Exchange, next httpsec.Next) error {
							answer := httpsec.RecordsSessionActivity(ex)
							answers.Store(&answer)

							return next(ex)
						}), httpsec.Before(httpsec.OrderSessionSignals))}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture, answers *atomic.Pointer[bool], _ *atomic.Bool) {
				s := f.signIn(t, "u-1")

				resp, _ := f.openStream(t, s.ID)
				requireStreamHead(t, resp)
				require.NotNil(t, answers.Load())
				assert.False(t, *answers.Load(), "the stream's path records no activity")

				resp = f.send(t.Context(), t, http.MethodGet, "/orders", s.ID)
				require.Equal(t, signalsDownstreamStatus, resp.StatusCode)
				assert.True(t, *answers.Load(), "another path records activity")
			},
		},
		{
			name: "nothing at the session-touch slot or beyond runs for the stream",
			setup: func(_ *atomic.Pointer[bool], touched *atomic.Bool) signalsSetup {
				return signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(ex *httpsec.Exchange, next httpsec.Next) error {
							touched.Store(true)

							return next(ex)
						}), httpsec.OrderSessionTouch)}
				}}
			},
			assert: func(t *testing.T, f *signalsFixture, _ *atomic.Pointer[bool], touched *atomic.Bool) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireStreamHead(t, resp)
				assert.False(t, touched.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				answers atomic.Pointer[bool]
				touched atomic.Bool
			)

			tc.assert(t, newSignalsFixture(t, tc.setup(&answers, &touched)), &answers, &touched)
		})
	}
}

// RecordsSessionActivity on no chain is true, and with no stream on the chain too.
func TestSessionSignals_NoActivity_WithNoStream(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)

	ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	assert.True(t, httpsec.RecordsSessionActivity(ex), "an exchange through no chain")

	chain, err := httpsec.New()
	require.NoError(t, err)

	var answer bool

	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		answer = httpsec.RecordsSessionActivity(ex)

		return nil
	})
	require.NoError(t, run(ex))
	assert.True(t, answer, "a chain with no stream")
}

// TestSessionSignals_Admission_ByCookie pins how a stream's credential is judged, which the
// cross-site rule decides by. A spy just outside the endpoint reads the same exchange.
func TestSessionSignals_Admission_ByCookie(t *testing.T) {
	t.Parallel()

	cookieChain := func(record bool) signalsSetup {
		return signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
			return []httpsec.Option{
				httpsec.WithSessions(f.sessions),
				httpsec.WithoutCSRFProtection(),
				httpsec.RegisterInterceptor(consumerSessionCookie{sessions: f.sessions, record: record}, httpsec.OrderBearerToken),
			}
		}}
	}

	unclaimedAuthorization := func(req *http.Request) { req.Header.Set("Authorization", "Bearer not-claimed") }

	type testCase struct {
		name   string
		setup  func() signalsSetup
		open   func(t *testing.T, f *signalsFixture)
		assert func(t *testing.T, byCookie bool)
	}

	isCookie := func(t *testing.T, byCookie bool) {
		t.Helper()

		assert.True(t, byCookie)
	}

	cases := []testCase{
		{
			name:  "a session reference in Authorization is a bearer",
			setup: func() signalsSetup { return signalsSetup{} },
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				requireStreamHead(t, firstOf(f.openStream(t, f.signIn(t, "u-1").ID)))
			},
			assert: func(t *testing.T, byCookie bool) {
				assert.False(t, byCookie)
			},
		},
		{
			name:  "a cookie that records nothing is a cookie",
			setup: func() signalsSetup { return cookieChain(false) },
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				requireStreamHead(t, firstOf(f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-1").ID))))
			},
			assert: isCookie,
		},
		{
			name:  "a cookie that records its credential is still a cookie",
			setup: func() signalsSetup { return cookieChain(true) },
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				requireStreamHead(t, firstOf(f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-1").ID))))
			},
			assert: isCookie,
		},
		{
			name:  "a cookie with an unclaimed Authorization is a cookie",
			setup: func() signalsSetup { return cookieChain(false) },
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				requireStreamHead(t, firstOf(f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-1").ID), unclaimedAuthorization)))
			},
			assert: isCookie,
		},
		{
			name:  "a recording cookie with an unclaimed Authorization is a cookie",
			setup: func() signalsSetup { return cookieChain(true) },
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				requireStreamHead(t, firstOf(f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-1").ID), unclaimedAuthorization)))
			},
			assert: isCookie,
		},
		{
			name:  "an Authorization merely ending in a recorded cookie's value is a cookie",
			setup: func() signalsSetup { return cookieChain(true) },
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				sid := f.signIn(t, "u-1").ID
				endsInIt := func(req *http.Request) { req.Header.Set("Authorization", "Bearer xyz"+sid) }

				requireStreamHead(t, firstOf(f.openStream(t, "", withSignalsCookie(sid), endsInIt)))
			},
			assert: isCookie,
		},
		{
			name: "a consumer's bearer on a header of its own is judged as a cookie, the stricter",
			setup: func() signalsSetup {
				return signalsSetup{withoutBearer: true, opts: func(f *signalsFixture) []httpsec.Option {
					return []httpsec.Option{
						httpsec.WithSessions(f.sessions),
						httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
							sid := ex.Request.Header("X-Token")

							s, err := f.sessions.Load(ex.Context(), sid)
							if err != nil {
								return err
							}

							if err := ex.PublishSession(&authenticate.Authentication{
								Principal: identity.PrincipalFromDetails(storedUser()),
							}, s); err != nil {
								return err
							}

							ex.RecordPresentedToken(sid)

							return next(ex)
						}), httpsec.OrderBearerToken),
					}
				}}
			},
			open: func(t *testing.T, f *signalsFixture) {
				t.Helper()

				s := f.signIn(t, "u-1")

				requireStreamHead(t, firstOf(f.openStream(t, "", func(req *http.Request) { req.Header.Set("X-Token", s.ID) })))
			},
			assert: isCookie,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var byCookie atomic.Pointer[bool]

			setup := tc.setup()
			opts := setup.opts
			setup.opts = func(f *signalsFixture) []httpsec.Option {
				var own []httpsec.Option
				if opts != nil {
					own = opts(f)
				}

				return append(own, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						answer := httpsec.StreamByCookie(ex)
						byCookie.Store(&answer)

						return next(ex)
					}), httpsec.Before(httpsec.OrderSessionSignals)))
			}

			tc.open(t, newSignalsFixture(t, setup))

			require.NotNil(t, byCookie.Load(), "the spy ran")
			tc.assert(t, *byCookie.Load())
		})
	}
}

// firstOf drops openStream's cancel, for a row that leaves its stream to the test's end.
//
// The body is closed when the test ends, which the bodyclose linter cannot see, so the
// directive below marks the response as handled.
// bodyclose:handled
func firstOf(resp *http.Response, _ context.CancelFunc) *http.Response { return resp }

// bodyContextWriter records the context the endpoint hands Stream, and streams nothing.
type bodyContextWriter struct {
	*stubWriter

	got context.Context //nolint:containedctx // what the test is about
}

func (w *bodyContextWriter) Stream(ctx context.Context, _ func(context.Context, httpsec.EventWriter) error) error {
	w.got = ctx

	return httpsec.ErrStreamingUnsupported
}

// TestSessionSignals_Endpoint_BodyContext pins that a body reaches nothing of the request
// through its context, and still hears the request end.
func TestSessionSignals_Endpoint_BodyContext(t *testing.T) {
	t.Parallel()

	f := newSignalsFixture(t, signalsSetup{})
	s := f.signIn(t, "u-1")
	w := &bodyContextWriter{stubWriter: &stubWriter{}}

	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), signalsTenantKey{}, "t-1"))
	defer cancel()

	run := f.chain.Assemble(func(*httpsec.Exchange) error { return nil })

	require.ErrorIs(t, run(httpsec.NewExchange(ctx, stubRequest{
		method:   http.MethodGet,
		path:     httpsec.DefaultSessionSignalsPath,
		clientIP: "198.51.100.7",
		headers:  map[string]string{"Authorization": "Bearer " + s.ID},
	}, w)), httpsec.ErrStreamingUnsupported)
	require.NotNil(t, w.got)

	got, _ := httpsec.SessionFromContext(w.got)
	assert.Nil(t, got, "the body's context reaches the request's session, raw identifier included")

	_, hasCaller := identity.PrincipalFromContext(w.got)
	assert.False(t, hasCaller, "the body's context reaches the caller")
	assert.Nil(t, w.got.Value(signalsTenantKey{}), "the body's context reaches the request's values")

	require.NoError(t, w.got.Err())
	cancel()
	assert.ErrorIs(t, w.got.Err(), context.Canceled, "the body must still hear the request end")
}

// TestSessionSignals_Endpoint_BodyHoldsNoRawIdentifier pins what a body starts from: the
// upstream session as a digest, and no session identifier.
func TestSessionSignals_Endpoint_BodyHoldsNoRawIdentifier(t *testing.T) {
	t.Parallel()

	f := newSignalsFixture(t, signalsSetup{})
	s := f.signIn(t, "u-1")

	state := session.SignInState{
		IdleDeadline:      f.clk.Now().Add(time.Minute),
		AbsoluteDeadline:  f.clk.Now().Add(time.Hour),
		AuthenticatedAt:   f.clk.Now(),
		ExternalIssuer:    "https://idp.example/raw-issuer",
		ExternalSessionID: "raw-upstream-sid",
	}

	ex := httpsec.NewExchange(t.Context(), stubRequest{
		method: http.MethodGet, path: httpsec.DefaultSessionSignalsPath, clientIP: "198.51.100.7",
	}, &stubWriter{})

	start := httpsec.StreamStartFor(t.Context(), ex, s, state)

	assert.Equal(t, httpsec.UpstreamDigest(state.ExternalIssuer, state.ExternalSessionID), start.Upstream,
		"the digest is taken from the raw values")
	assert.Empty(t, start.State.ExternalIssuer)
	assert.Empty(t, start.State.ExternalSessionID)
	assert.True(t, state.IdleDeadline.Equal(start.State.IdleDeadline), "the deadlines stay for the first event")
	assert.True(t, state.AbsoluteDeadline.Equal(start.State.AbsoluteDeadline))
	assert.True(t, state.AuthenticatedAt.Equal(start.State.AuthenticatedAt))

	assert.NotContains(t, start.Everything, "raw-upstream-sid")
	assert.NotContains(t, start.Everything, "raw-issuer")
	assert.NotContains(t, start.Everything, s.ID)
}

func TestSessionSignals_StreamNoteEnd(t *testing.T) {
	t.Parallel()

	first := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	later := first.Add(time.Second)

	type testCase struct {
		name   string
		act    func(p *httpsec.SignalStreamProbe)
		assert func(t *testing.T, p *httpsec.SignalStreamProbe)
	}

	cases := []testCase{
		{
			name: "a notice is kept with its time, and wakes the stream",
			act:  func(p *httpsec.SignalStreamProbe) { p.NoteEnd("logout", first) },
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				reason, at := p.Notice()
				assert.Equal(t, "logout", reason)
				assert.True(t, first.Equal(at))
				assert.True(t, p.TakeWake())

				reuse, _ := p.Reuse()
				assert.Empty(t, reuse, "only reuse is kept apart")
			},
		},
		{
			name: "a reuse notice is kept apart, and wakes the stream",
			act:  func(p *httpsec.SignalStreamProbe) { p.NoteEnd("reuse", first) },
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				reason, at := p.Reuse()
				assert.Equal(t, "reuse", reason)
				assert.True(t, first.Equal(at))
				assert.True(t, p.TakeWake())

				other, _ := p.Notice()
				assert.Empty(t, other)
			},
		},
		{
			name: "a later report does not overwrite a reuse",
			act: func(p *httpsec.SignalStreamProbe) {
				p.NoteEnd("reuse", first)
				p.NoteEnd("logout", later)
			},
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				reason, at := p.Reuse()
				assert.Equal(t, "reuse", reason)
				assert.True(t, first.Equal(at))

				other, otherAt := p.Notice()
				assert.Equal(t, "logout", other)
				assert.True(t, later.Equal(otherAt))
			},
		},
		{
			name: "the latest of the other reports is the one kept",
			act: func(p *httpsec.SignalStreamProbe) {
				p.NoteEnd("logout", first)
				p.NoteEnd("all_ended", later)
			},
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				reason, _ := p.Notice()
				assert.Equal(t, "all_ended", reason)
			},
		},
		{
			name: "an empty reason keeps what was kept, and still wakes the stream",
			act: func(p *httpsec.SignalStreamProbe) {
				p.NoteEnd("logout", first)
				p.TakeWake()
				p.NoteEnd("", later)
			},
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				reason, at := p.Notice()
				assert.Equal(t, "logout", reason, "an unknown reason must not erase a real one")
				assert.True(t, first.Equal(at))
				assert.True(t, p.TakeWake())
			},
		},
		{
			name: "an empty reason alone stores no notice, and still wakes the stream",
			act:  func(p *httpsec.SignalStreamProbe) { p.NoteEnd("", first) },
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				reason, _ := p.Notice()
				assert.Empty(t, reason)

				reuse, _ := p.Reuse()
				assert.Empty(t, reuse)
				assert.True(t, p.TakeWake())
			},
		},
		{
			name: "several wake-ups coalesce into one, and none blocks",
			act: func(p *httpsec.SignalStreamProbe) {
				for range 10 {
					p.NoteEnd("logout", first)
				}
			},
			assert: func(t *testing.T, p *httpsec.SignalStreamProbe) {
				assert.True(t, p.TakeWake())
				assert.False(t, p.TakeWake(), "the wake-ups coalesce")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := httpsec.NewSignalStreamProbe()

			requireReturns(t, func() { tc.act(p) })
			tc.assert(t, p)
		})
	}
}

func TestSessionSignals_StreamOffer(t *testing.T) {
	t.Parallel()

	p := httpsec.NewSignalStreamProbe()

	requireReturns(t, func() {
		for i := range httpsec.StreamQueueSize {
			assert.True(t, p.Offer("app.a"), "offer %d fits", i)
		}

		assert.False(t, p.Offer("app.a"), "a full queue drops, and does not block")
	})

	assert.Equal(t, httpsec.StreamQueueSize, p.Queued())
}

// TestSessionSignals_StreamShared_Race has the registry's side and the bus's side at one
// stream at once, for -race to read.
func TestSessionSignals_StreamShared_Race(t *testing.T) {
	t.Parallel()

	p := httpsec.NewSignalStreamProbe()

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Go(func() {
			reason := "logout"
			if i%2 == 0 {
				reason = "reuse"
			}

			p.NoteEnd(reason, time.Now())
			p.Offer("app.a")
		})
	}

	requireReturns(t, wg.Wait)

	assert.True(t, p.TakeWake())
	assert.Equal(t, 8, p.Queued())

	reuse, _ := p.Reuse()
	other, _ := p.Notice()
	assert.Equal(t, "reuse", reuse)
	assert.Equal(t, "logout", other)
}
