package httpsec_test

import (
	"context"
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
			name: "an authenticated POST deletes the session and answers 200 empty",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).
					Return(storedUser(), nil).AnyTimes()

				// The session is there for the logout and gone afterwards, so
				// the token the caller still holds names nothing.
				gomock.InOrder(
					h.store.EXPECT().Load(gomock.Any(), testJTI).Return(touchableSession(), nil),
					h.store.EXPECT().Load(gomock.Any(), testJTI).
						Return(nil, session.ErrSessionNotFound).AnyTimes(),
				)
				h.store.EXPECT().Delete(gomock.Any(), testJTI).Return(nil).Times(1)
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
			name: "a second logout for an already-deleted session is also 200",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.store.EXPECT().Delete(gomock.Any(), testJTI).
					Return(session.ErrSessionNotFound)
			},
			request: authorizedLogout,
			assert:  endedCleanly,
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
				h.expectResolvedSession(touchableSession())
				h.store.EXPECT().Delete(gomock.Any(), testJTI).Return(nil)
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
