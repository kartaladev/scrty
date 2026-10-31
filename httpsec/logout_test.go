package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// logoutRequest posts to path, carrying a bearer token when one is asked for.
func logoutRequest(ctx context.Context, method, path string, authorized bool) *http.Request {
	req := httptest.NewRequestWithContext(ctx, method, path, nil)
	if authorized {
		req.Header.Set("Authorization", "Bearer a-token")
	}

	return req
}

// statelessAuthentication stands in for a first factor that establishes no
// session, such as Basic: it publishes an authentication result and no
// session, which is what "a stateless authenticated request" means.
func statelessAuthentication() httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			ex.Authentication = &authenticate.Authentication{
				Principal: &identity.Principal{ID: "u-1", Username: testSubject},
				Time:      time.Now(),
			}

			return next(ex)
		}),
		httpsec.Before(httpsec.OrderLogout))
}

// TestLogout pins what ends a session, what it answers, and what it refuses.
func TestLogout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.LogoutOption
		extra   []httpsec.Option
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, chain *httpsec.Chain, s served)
	}

	endedCleanly := func(t *testing.T, _ *httpsec.Chain, s served) {
		t.Helper()

		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.Empty(t, s.rec.Body.String(), "logout answers with nothing to read")
		assert.False(t, s.handlerRan, "logout is this library's own endpoint")
	}

	authorizedLogout := func(ctx context.Context) *http.Request {
		return logoutRequest(ctx, http.MethodPost, httpsec.DefaultLogoutPath, true)
	}

	cases := []testCase{
		{
			name: "an authenticated POST revokes the session's family and answers 200 empty",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
					Return(storedUser(), nil).AnyTimes()

				// The session is there for the logout and gone afterwards, so
				// the token the caller still holds names nothing.
				gomock.InOrder(
					h.store.EXPECT().Load(gomock.Any(), testJTI).Return(familiedSession(), nil),
					h.store.EXPECT().Load(gomock.Any(), testJTI).
						Return(nil, session.ErrNotFound).AnyTimes(),
				)
				h.acceptsFirstPresentation()
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(1, nil).Times(1)
			},
			request: authorizedLogout,
			assert: func(t *testing.T, chain *httpsec.Chain, s served) {
				endedCleanly(t, chain, s)

				later := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.ErrorIs(t, later.err, httpsec.ErrAuthenticationRequired,
					"the token the caller kept names a session that no longer exists")
				assert.False(t, later.handlerRan)
			},
		},
		{
			// Every stored session belongs to a family, so one with none
			// reaching the chain is a store fault. It is refused where it is
			// published, before logout runs, rather than deleted alone, which
			// would leave a renewal's successor live.
			name: "a session with no family is refused, and not deleted alone",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				familyless := touchableSession()
				familyless.FamilyID = id.Nil
				h.expectResolvedSession(familyless)
			},
			request: authorizedLogout,
			assert: func(t *testing.T, _ *httpsec.Chain, s served) {
				require.Error(t, s.err, "a session with no family names no sign-in to end")
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a session of a family is ended by revoking the family",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(familiedSession())
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(2, nil).Times(1)
			},
			request: authorizedLogout,
			assert:  endedCleanly,
		},
		{
			name: "a family already gone is also 200",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(familiedSession())
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(0, nil).Times(1)
			},
			request: authorizedLogout,
			assert:  endedCleanly,
		},
		{
			name: "a family the store could not revoke is refused",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(familiedSession())
				h.acceptsActivityWriteBack()
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(0, errFixtureFailure)
			},
			request: authorizedLogout,
			assert: func(t *testing.T, _ *httpsec.Chain, s served) {
				require.ErrorIs(t, s.err, errFixtureFailure)
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "an anonymous POST is refused",
			// No expectation on the store: nothing is deleted for a caller who
			// never proved who they are.
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return logoutRequest(ctx, http.MethodPost, httpsec.DefaultLogoutPath, false)
			},
			assert: func(t *testing.T, _ *httpsec.Chain, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a stateless authenticated request is answered without deleting anything",
			// Again no store expectation: a caller who holds no session has
			// none to end, and asking the store to end one would be a guess.
			wire:  func(*testing.T, *authHarness) {},
			extra: []httpsec.Option{statelessAuthentication()},
			request: func(ctx context.Context) *http.Request {
				return logoutRequest(ctx, http.MethodPost, httpsec.DefaultLogoutPath, false)
			},
			assert: endedCleanly,
		},
		{
			name: "a GET on the logout path is not a logout",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.acceptsActivityWriteBack()
			},
			request: func(ctx context.Context) *http.Request {
				return logoutRequest(ctx, http.MethodGet, httpsec.DefaultLogoutPath, true)
			},
			assert: func(t *testing.T, _ *httpsec.Chain, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "a consumer path answers the logout",
			opts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/session/end")},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(familiedSession())
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(1, nil)
			},
			request: func(ctx context.Context) *http.Request {
				return logoutRequest(ctx, http.MethodPost, "/session/end", true)
			},
			assert: endedCleanly,
		},
		{
			name: "a consumer path leaves the default passing through",
			opts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/session/end")},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.acceptsActivityWriteBack()
			},
			request: authorizedLogout,
			assert: func(t *testing.T, _ *httpsec.Chain, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "the consumer moved the endpoint, so /logout is theirs")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			opts := append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, tc.opts...),
			}, tc.extra...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, chain, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestLogoutConstruction pins that a logout wired to nothing, or answering
// nothing, is refused before it serves a request.
func TestLogoutConstruction(t *testing.T) {
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
			name: "a fully wired logout builds",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
				}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no session manager",
			build: func(*authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{})}
			},
			assert: refused("EnableLogout", "session manager"),
		},
		{
			name: "an empty logout path",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions},
						httpsec.WithLogoutRequestPath("")),
				}
			},
			assert: refused("WithLogoutRequestPath"),
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

// TestLogout_EndsTheSignInWhenTheClientHangsUp pins that a logout the chain
// has accepted ends the sign-in even when the client disconnects before the
// revocation reaches a context-honouring store: the client that asked to be
// logged out is not there to see a failure and retry.
//
// Not a row of TestLogout: the store honours a context the client cancels.
func TestLogout_EndsTheSignInWhenTheClientHangsUp(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	held := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))

	// The store the chain sees holds everything in held, and honours the
	// context on the revocation as database/sql and pgx do.
	store := NewMockStore(gomock.NewController(t))
	store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(held.Load).AnyTimes()
	store.EXPECT().MarkPresented(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(held.MarkPresented).AnyTimes()
	store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(held.RecordActivity).AnyTimes()
	var seen error
	store.EXPECT().DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, family id.ID) (int, error) {
		seen = ctx.Err()
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		return held.DeleteFamily(ctx, family)
	}).Times(1)

	sessions, err := session.New(session.WithClock(clk), session.WithStore(store))
	require.NoError(t, err)

	signIn, err := session.New(session.WithClock(clk), session.WithStore(held))
	require.NoError(t, err)
	s, err := signIn.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	// The sign-in has been renewed: O is superseded by S1, and the client
	// presents the successor. Ending the sign-in ends every member.
	renewable, err := signIn.LoadForRenewal(t.Context(), s.ID)
	require.NoError(t, err)
	successor, _, err := signIn.RotateWithGrace(t.Context(), renewable, 30*time.Second)
	require.NoError(t, err)
	require.NotEqual(t, s.ID, successor.ID)
	_, err = held.Load(t.Context(), successor.ID)
	require.NoError(t, err, "the successor is live before the logout")

	ctx, hangUp := context.WithCancel(t.Context())
	defer hangUp()

	// The client hangs up once it has been authenticated: the logout itself
	// runs on a cancelled request.
	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			hangUp()
			return storedUser(), nil
		}).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultLogoutPath, nil)
	req.Header.Set("Authorization", "Bearer "+successor.ID)
	rec := httptest.NewRecorder()
	run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
	_ = run(httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(rec)))

	require.NoError(t, seen, "the revocation ran on the request's cancelled context, and a context-honouring store aborted it")
	for name, sessionID := range map[string]string{"the superseded original": s.ID, "the successor": successor.ID} {
		_, err = held.Load(t.Context(), sessionID)
		assert.ErrorIs(t, err, session.ErrNotFound, "%s of the renewed sign-in is still live", name)
	}
}

// TestLogoutEndSession is its own table rather than rows of TestLogout: every
// case here wires an end-session builder, a session of a chosen kind and a
// form-encoded body, which is a different setup shape from TestLogout's.

// logoutJSONRequest is an authorized logout whose body declares itself JSON,
// which logoutState never reads: only a form-encoded body carries a "state"
// this package will parse.
func logoutJSONRequest(ctx context.Context, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultLogoutPath,
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer a-token")
	req.Header.Set("Content-Type", "application/json")

	return req
}

// logoutOversizedFormRequest is an authorized logout whose form-encoded body
// is one byte past DefaultLoginBodyLimit, the bound logoutState reads under.
func logoutOversizedFormRequest(ctx context.Context) *http.Request {
	form := url.Values{"padding": {strings.Repeat("x", int(httpsec.DefaultLoginBodyLimit)+1)}}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultLogoutPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer a-token")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

// TestLogoutEndSession pins logout's optional end-session step: when it runs,
// what it is given, what logout answers, and that it never undoes a logout.
func TestLogoutEndSession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		session func() *session.Session
		// endSession wires the builder; nil leaves LogoutDeps.EndSession nil.
		endSession func(t *testing.T, b *MockEndSessionBuilder, log *callLog)
		// request builds the logout request; nil sends the default form
		// request carrying state "s-1".
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, h *authHarness, s served, calls []string)
	}

	endedCleanly := func(t *testing.T, _ *authHarness, s served, _ []string) {
		t.Helper()

		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.Empty(t, s.rec.Body.String(), "logout answers with nothing to read")
		assert.Empty(t, s.rec.Header().Get("Content-Type"))
		assert.False(t, s.handlerRan)
	}

	cases := []testCase{
		{
			name:    "a federated session with an end-session step answers its URL",
			session: federatedSession,
			endSession: func(t *testing.T, b *MockEndSessionBuilder, log *callLog) {
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, s *session.Session, state string) (string, error) {
						log.add("EndSessionURL")
						assert.Equal(t, "corp", s.ExternalProvider, "handed the session just deleted")
						assert.Equal(t, testJTI, s.ID)

						return "https://idp.example/logout?state=" + state, nil
					})
			},
			assert: func(t *testing.T, _ *authHarness, s served, calls []string) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))
				assert.JSONEq(t, `{"end_session_url":"https://idp.example/logout?state=s-1"}`,
					s.rec.Body.String())
				assert.Equal(t, []string{"DeleteFamily", "EndSessionURL"}, calls,
					"the session is deleted before the provider is asked for anything")
				assert.False(t, s.handlerRan)
			},
		},
		{
			name:    "a federated session whose provider offers no URL answers empty",
			session: federatedSession,
			endSession: func(_ *testing.T, b *MockEndSessionBuilder, log *callLog) {
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), "s-1").
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						log.add("EndSessionURL")

						return "", nil
					})
			},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Empty(t, s.rec.Header().Get("Cache-Control"))
				assert.Equal(t, []string{"DeleteFamily", "EndSessionURL"}, calls)
			},
		},
		{
			name:    "a password session never calls the end-session step",
			session: familiedSession,
			// No expectation on the builder: any call to it fails the test.
			endSession: func(*testing.T, *MockEndSessionBuilder, *callLog) {},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Equal(t, []string{"DeleteFamily"}, calls)
			},
		},
		{
			name:    "an end-session failure is logged and the logout still succeeds",
			session: federatedSession,
			endSession: func(_ *testing.T, b *MockEndSessionBuilder, log *callLog) {
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						log.add("EndSessionURL")

						return "", errors.New("discovery unavailable")
					})
			},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Equal(t, []string{"DeleteFamily", "EndSessionURL"}, calls)

				var logged bool
				for _, r := range h.logs.records() {
					if v, ok := attrValue(r, "provider"); ok && v.String() == "corp" {
						logged = true
					}

					r.Attrs(func(a slog.Attr) bool {
						assert.NotContains(t, a.Value.String(), "s-1", "the state is never logged")

						return true
					})
				}
				assert.True(t, logged, "the failure is logged with the provider it concerned")
			},
		},
		{
			name:    "no end-session step behaves exactly as before",
			session: federatedSession,
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Empty(t, s.rec.Header().Get("Cache-Control"),
					"no step ran to have anything not to cache")
				assert.Equal(t, []string{"DeleteFamily"}, calls)
			},
		},
		{
			name:    "a JSON body still calls the builder with state \"\"",
			session: federatedSession,
			request: func(ctx context.Context) *http.Request {
				return logoutJSONRequest(ctx, `{"state":"s-1"}`)
			},
			endSession: func(_ *testing.T, b *MockEndSessionBuilder, log *callLog) {
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), "").
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						log.add("EndSessionURL")

						return "", nil
					})
			},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Equal(t, []string{"DeleteFamily", "EndSessionURL"}, calls,
					"logoutState never parses a JSON body, so the step still runs with no state")
			},
		},
		{
			name:    "a body over DefaultLoginBodyLimit still calls the builder with state \"\"",
			session: federatedSession,
			request: func(ctx context.Context) *http.Request {
				return logoutOversizedFormRequest(ctx)
			},
			endSession: func(_ *testing.T, b *MockEndSessionBuilder, log *callLog) {
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), "").
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						log.add("EndSessionURL")

						return "", nil
					})
			},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Equal(t, []string{"DeleteFamily", "EndSessionURL"}, calls,
					"a body over the bound is refused unread, so the step still runs with no state")
			},
		},
		{
			name:    "a form with no state field still calls the builder with state \"\"",
			session: federatedSession,
			request: func(ctx context.Context) *http.Request {
				return logoutFormRequest(ctx, url.Values{"other": {"value"}})
			},
			endSession: func(_ *testing.T, b *MockEndSessionBuilder, log *callLog) {
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), "").
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						log.add("EndSessionURL")

						return "", nil
					})
			},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Equal(t, []string{"DeleteFamily", "EndSessionURL"}, calls,
					"a missing field reads as \"\", not as a reason to skip the step")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			log := &callLog{}
			h := newAuthHarness(t)
			h.expectVerified()
			h.expectResolvedSession(tc.session())
			h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).
				DoAndReturn(func(context.Context, id.ID) (int, error) {
					log.add("DeleteFamily")

					return 1, nil
				})

			deps := httpsec.LogoutDeps{Sessions: h.sessions}
			if tc.endSession != nil {
				b := NewMockEndSessionBuilder(gomock.NewController(t))
				tc.endSession(t, b, log)
				deps.EndSession = b
			}

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
				httpsec.EnableLogout(deps),
			)
			require.NoError(t, err)

			req := logoutFormRequest(t.Context(), url.Values{"state": {"s-1"}})
			if tc.request != nil {
				req = tc.request(t.Context())
			}

			s := serve(t, chain, req)
			tc.assert(t, h, s, log.all())
		})
	}
}

// TestLogoutEndsTheWholeSignIn pins that logging out with an identifier that
// was already renewed inside its window ends the successor too, because the
// sign-in is the family, not the one record.
//
// Not a row of TestLogout: it renews a session on a real manager first.
func TestLogoutEndsTheWholeSignIn(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))

	sessions, err := session.New(
		session.WithClock(clk),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	require.NoError(t, err)

	old, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	loaded, err := sessions.LoadForRenewal(t.Context(), old.ID)
	require.NoError(t, err)

	successor, _, err := sessions.RotateWithGrace(t.Context(), loaded, 30*time.Second)
	require.NoError(t, err)

	clk.Advance(5 * time.Second)

	bearing := func(method, path, credential string) served {
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		req.Header.Set("Authorization", "Bearer "+credential)

		return serve(t, chain, req)
	}

	out := bearing(http.MethodPost, httpsec.DefaultLogoutPath, old.ID)
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.rec.Code)

	later := bearing(http.MethodGet, "/resource", successor.ID)
	require.ErrorIs(t, later.err, httpsec.ErrAuthenticationRequired,
		"the successor belongs to the sign-in the logout ended")
	assert.False(t, later.handlerRan)
}

// The OIDC manager's end-session step is what EnableOIDCLogin hands logout, so
// it has to satisfy logout's port.
var _ httpsec.EndSessionBuilder = (&oidc.RelyingParty{}).EndSessionBuilder()

// consumerEndSessionURL is the URL a consumer's own end-session step answers.
const consumerEndSessionURL = "https://consumer.example/bye"

// TestOIDCRPInitiatedLogout pins how EnableOIDCLogin wires RP-initiated logout
// into EnableLogout: on by default, off on request, never over a consumer's
// own end-session step, and in whichever order the two options are given.
//
// Its own table: its rows build the chain over a real OIDC manager and vary how
// EnableOIDCLogin and EnableLogout combine, which TestLogout's rows fix.
func TestOIDCRPInitiatedLogout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// oidcFirst gives EnableOIDCLogin before EnableLogout.
		oidcFirst bool
		// noLogout leaves EnableLogout off the chain.
		noLogout bool
		// consumer supplies LogoutDeps.EndSession.
		consumer bool
		opts     []httpsec.OIDCOption
		assert   func(t *testing.T, provider *oidcTestProvider, s served)
	}

	answersProviderURL := func(t *testing.T, p *oidcTestProvider, s served) {
		t.Helper()

		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))

		var doc struct {
			EndSessionURL string `json:"end_session_url"`
		}
		require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &doc))

		u, err := url.Parse(doc.EndSessionURL)
		require.NoError(t, err)
		assert.Equal(t, p.srv.URL+"/logout", u.Scheme+"://"+u.Host+u.Path)
		assert.Equal(t, "app", u.Query().Get("client_id"))
		assert.Equal(t, oidcTestIDToken, u.Query().Get("id_token_hint"))
		assert.False(t, s.handlerRan)
	}

	answersConsumerURL := func(t *testing.T, _ *oidcTestProvider, s served) {
		t.Helper()

		require.NoError(t, s.err)
		assert.JSONEq(t, `{"end_session_url":"`+consumerEndSessionURL+`"}`, s.rec.Body.String())
	}

	cases := []testCase{
		{
			name:   "on by default when OIDC login is wired after logout",
			assert: answersProviderURL,
		},
		{
			name:      "on by default when OIDC login is wired before logout",
			oidcFirst: true,
			assert:    answersProviderURL,
		},
		{
			name: "the consumer turns it off",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCRPInitiatedLogout(false)},
			assert: func(t *testing.T, _ *oidcTestProvider, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Empty(t, s.rec.Body.String())
				assert.Empty(t, s.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name:      "the consumer turns it off with OIDC login wired first",
			oidcFirst: true,
			opts:      []httpsec.OIDCOption{httpsec.WithOIDCRPInitiatedLogout(false)},
			assert: func(t *testing.T, _ *oidcTestProvider, s served) {
				require.NoError(t, s.err)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name:     "a consumer end-session step takes precedence",
			consumer: true,
			assert:   answersConsumerURL,
		},
		{
			name:      "a consumer end-session step takes precedence with OIDC login wired first",
			oidcFirst: true,
			consumer:  true,
			assert:    answersConsumerURL,
		},
		{
			name:     "a consumer end-session step is kept when RP-initiated logout is off",
			consumer: true,
			opts:     []httpsec.OIDCOption{httpsec.WithOIDCRPInitiatedLogout(false)},
			assert:   answersConsumerURL,
		},
		{
			name:     "a chain without logout is unaffected",
			noLogout: true,
			assert: func(t *testing.T, _ *oidcTestProvider, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "with no logout wired the path is the application's")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ah := newAuthHarness(t)
			ah.expectVerified()

			s := federatedSession()
			s.ExternalProvider = testOIDCProvider
			s.ExternalIDToken = oidcTestIDToken
			ah.expectResolvedSession(s)

			if tc.noLogout {
				ah.acceptsActivityWriteBack()
			} else {
				ah.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(1, nil)
			}

			oh := newOIDCHarness(t)
			manager := oh.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)),
				func(p *oidc.Provider) { p.EndSessionEndpoint = oh.provider.srv.URL + "/logout" })

			deps := httpsec.LogoutDeps{Sessions: ah.sessions}
			if tc.consumer {
				b := NewMockEndSessionBuilder(gomock.NewController(t))
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						return consumerEndSessionURL, nil
					})
				deps.EndSession = b
			}

			enableOIDC := httpsec.EnableOIDCLogin(manager, oh.handoffs, append([]httpsec.OIDCOption{
				httpsec.WithOIDCTokens(ah.tokens),
				httpsec.WithOIDCSessions(ah.sessions),
			}, tc.opts...)...)

			opts := []httpsec.Option{
				httpsec.WithLogger(ah.logger()),
				httpsec.EnableBearerToken(ah.bearerTokenDeps()),
			}

			switch {
			case tc.noLogout:
				opts = append(opts, enableOIDC)
			case tc.oidcFirst:
				opts = append(opts, enableOIDC, httpsec.EnableLogout(deps))
			default:
				opts = append(opts, httpsec.EnableLogout(deps), enableOIDC)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, oh.provider, serve(t, chain, logoutFormRequest(t.Context(), url.Values{})))
		})
	}
}
