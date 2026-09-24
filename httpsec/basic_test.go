package httpsec_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// basicRequest builds a request carrying the credential as a client would, and
// rawBasicRequest one carrying whatever a test wants after the prefix.
func basicRequest(ctx context.Context, username, password string) *http.Request {
	return rawBasicRequest(ctx, "Basic "+
		base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
}

func rawBasicRequest(ctx context.Context, header string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}

	return req
}

// TestBasicAuth pins that Basic authentication judges a credential on every
// request and leaves nothing behind: no session, no token, nothing to come
// back to.
func TestBasicAuth(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.BasicAuthOption
		engine  func(t *testing.T) *policy.Engine
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	noEngine := func(*testing.T) *policy.Engine { return nil }

	cases := []testCase{
		{
			name:   "correct credentials reach the handler with no session",
			engine: noEngine,
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				// No expectation on the session store: Basic mints nothing.
			},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "s3cret") },
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan)

				auth, ok := authenticate.AuthenticationFromContext(s.handled.Context())
				require.True(t, ok, "the handler must read who the caller is")
				assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)

				assert.Nil(t, s.handled.Session, "Basic authentication establishes no session")
				_, hasSession := httpsec.SessionFromContext(s.handled.Context())
				assert.False(t, hasSession)
				assert.Empty(t, s.rec.Header().Get("WWW-Authenticate"),
					"a credential that was accepted is not challenged")
			},
		},
		{
			name:    "a request with no Authorization header passes through untouched",
			engine:  noEngine,
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return rawBasicRequest(ctx, "") },
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name:    "another scheme is left for whoever claims it",
			engine:  noEngine,
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return rawBasicRequest(ctx, "Bearer abc.def.ghi") },
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name:    "the prefix is matched exactly, so a lowercase scheme is not claimed",
			engine:  noEngine,
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return rawBasicRequest(ctx, "basic YWRhOnMzY3JldA==") },
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan,
					"a loose match here would claim headers meant for a neighbouring scheme")
			},
		},
		{
			name:    "a credential that is not valid base64",
			engine:  noEngine,
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return rawBasicRequest(ctx, "Basic not-base64!!") },
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed,
					"a malformed header is a failed authentication, not a malformed request: "+
						"telling them apart tells a prober which guess was even parsed")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Equal(t, `Basic realm="Restricted"`, s.rec.Header().Get("WWW-Authenticate"))
			},
		},
		{
			name:   "a decoded credential with no separator",
			engine: noEngine,
			wire:   func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return rawBasicRequest(ctx, "Basic "+
					base64.StdEncoding.EncodeToString([]byte("adanopassword")))
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed)
				assert.False(t, s.handlerRan)
			},
		},
		{
			name:   "an incorrect password is refused, recorded and challenged",
			engine: noEngine,
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
					Return(nil).Times(1)
			},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "wrong") },
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.Equal(t, `Basic realm="Restricted"`, s.rec.Header().Get("WWW-Authenticate"))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name:   "a consumer realm",
			opts:   []httpsec.BasicAuthOption{httpsec.WithBasicAuthRealm("internal-api")},
			engine: noEngine,
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(nil)
			},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "wrong") },
			assert: func(t *testing.T, s served) {
				assert.Equal(t, `Basic realm="internal-api"`, s.rec.Header().Get("WWW-Authenticate"))
			},
		},
		{
			name: "the pre-authentication phase denies before the credential is checked",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.PreAuthentication, policy.ErrAccountLocked)
			},
			// No expectation on the authenticator: a locked account is never
			// probed over Basic either.
			wire:    func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "s3cret") },
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, policy.ErrAccountLocked)
				assert.Equal(t, http.StatusLocked, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "the stateless phase denies",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.StatelessAuthentication, policy.ErrMFARequired)
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
			},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "s3cret") },
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, policy.ErrMFARequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a stateless challenge carries no session and no token",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingIn(t, policy.StatelessAuthentication, policy.ChallengeMFA)
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				// No expectation on the session store or the generator.
			},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "s3cret") },
			assert: func(t *testing.T, s served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Nil(t, ch.Session,
					"there is no later request for this caller to answer the challenge on")
				assert.Empty(t, ch.Token)
				assert.False(t, s.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			opts := []httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBasicAuth(h.basicAuthDeps(), tc.opts...),
			}
			if e := tc.engine(t); e != nil {
				opts = append(opts, httpsec.WithPolicyEngine(e))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestBasicAuthConstruction pins that a Basic configuration that could not work
// is refused before the chain exists.
func TestBasicAuthConstruction(t *testing.T) {
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
			name: "a fully wired Basic builds",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableBasicAuth(h.basicAuthDeps())}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no authenticator",
			build: func(h *authHarness) []httpsec.Option {
				d := h.basicAuthDeps()
				d.Authenticator = nil

				return []httpsec.Option{httpsec.EnableBasicAuth(d)}
			},
			assert: refused("EnableBasicAuth", "authenticator"),
		},
		{
			name: "no attempt store",
			build: func(h *authHarness) []httpsec.Option {
				d := h.basicAuthDeps()
				d.Attempts = nil

				return []httpsec.Option{httpsec.EnableBasicAuth(d)}
			},
			assert: refused("EnableBasicAuth", "attempt store"),
		},
		{
			name: "an empty realm",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableBasicAuth(h.basicAuthDeps(), httpsec.WithBasicAuthRealm("")),
				}
			},
			assert: refused("WithBasicAuthRealm"),
		},
		{
			name: "a realm that could close the quote it is written in",
			build: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableBasicAuth(h.basicAuthDeps(),
						httpsec.WithBasicAuthRealm(`api", error="insufficient_scope`)),
				}
			},
			assert: refused("WithBasicAuthRealm"),
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
