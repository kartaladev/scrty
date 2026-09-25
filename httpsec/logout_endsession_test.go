package httpsec_test

// TestLogoutEndSession is its own table rather than rows of TestLogout: every
// case here wires an end-session builder, a session of a chosen kind and a
// form-encoded body, which is a different setup shape from TestLogout's.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// federatedSession is touchableSession as a federated login would have created
// it: it records the identity provider the login came through.
func federatedSession() *session.Session {
	s := touchableSession()
	s.ExternalProvider = "corp"
	s.ExternalIssuer = "https://idp.example"
	s.ExternalSessionID = "sid-9"

	return s
}

// logoutFormRequest is an authorized logout carrying form, as a browser
// relaying the provider's state would send it.
func logoutFormRequest(ctx context.Context, form url.Values) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultLogoutPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer a-token")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

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
				assert.Equal(t, []string{"Delete", "EndSessionURL"}, calls,
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
				assert.Equal(t, []string{"Delete", "EndSessionURL"}, calls)
			},
		},
		{
			name:    "a password session never calls the end-session step",
			session: touchableSession,
			// No expectation on the builder: any call to it fails the test.
			endSession: func(*testing.T, *MockEndSessionBuilder, *callLog) {},
			assert: func(t *testing.T, h *authHarness, s served, calls []string) {
				endedCleanly(t, h, s, calls)
				assert.Equal(t, []string{"Delete"}, calls)
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
				assert.Equal(t, []string{"Delete", "EndSessionURL"}, calls)

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
				assert.Equal(t, []string{"Delete"}, calls)
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
				assert.Equal(t, []string{"Delete", "EndSessionURL"}, calls,
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
				assert.Equal(t, []string{"Delete", "EndSessionURL"}, calls,
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
				assert.Equal(t, []string{"Delete", "EndSessionURL"}, calls,
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
			h.store.EXPECT().Delete(gomock.Any(), testJTI).
				DoAndReturn(func(context.Context, string) error {
					log.add("Delete")

					return nil
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
