package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// soToken is the provider-format access token every session-only case presents.
const soToken = "at.0123456789"

// soResourceServer covers every path with a resource server whose one source accepts every
// provider-format token, unbound, as an external caller, so no MFA requirement judges it.
func soResourceServer() httpsec.Option {
	return httpsec.EnableResourceServer("urn:api", httpsec.WithPathPrefix("/"),
		httpsec.WithStubSource(&httpsec.StubSource{Name: "provider", Provider: true, Unbound: true, External: true}))
}

// soRequest is method on path carrying the access token under Bearer.
func soRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.Header.Set("Authorization", "Bearer "+soToken)

	return req
}

// soCase is one session-only endpoint: the chain it is enabled on, the request reaching it, and
// what must still hold afterwards.
type soCase struct {
	opts      []httpsec.Option
	req       *http.Request
	unchanged func(t *testing.T)

	// handler, when set, is the application behind the chain, for an operation a handler calls.
	handler func(c **httpsec.Chain) func(ex *httpsec.Exchange) error
}

// TestSessionOnlyEndpoints pins that every endpoint and operation acting on the caller's sign-in
// session refuses a caller a resource server authenticated with the authentication-required error,
// 401, before changing anything; and that the session-signal stream keeps its settled answer for a
// caller with no sign-in. Each case was shown to fail once by publishing a fake session behind the
// resource server.
func TestSessionOnlyEndpoints(t *testing.T) {
	t.Parallel()

	refused := func(t *testing.T, out served) {
		t.Helper()
		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}

	mfaFamily := func(t *testing.T, method, path string) soCase {
		t.Helper()

		h := newPasskeyHarness(t)
		h.mfaOpts = append(h.mfaOpts, httpsec.WithMFAMethodListing())
		h.extra = append(h.extra, soResourceServer())

		return soCase{
			opts: h.chainOptions(t, nil),
			req:  soRequest(t, method, path),
			unchanged: func(t *testing.T) {
				t.Helper()
				_, enrolled := h.enrolment(t)
				assert.False(t, enrolled, "no enrolment begun")
				n, err := h.creds.Count(t.Context(), testMFAUser)
				require.NoError(t, err)
				assert.Zero(t, n, "no passkey registered")
				assert.Zero(t, h.notices.count(), "nothing sent")
			},
		}
	}

	recoveryFamily := func(t *testing.T, method, path string) soCase {
		t.Helper()

		h := newRecoveryHarness(t)
		h.withCodesEndpoint()
		h.chainOpts = append(h.chainOpts, soResourceServer())

		return soCase{
			opts: h.options(t),
			req:  soRequest(t, method, path),
			unchanged: func(t *testing.T) {
				t.Helper()
				n, err := h.codes.Remaining(t.Context(), e2eUser)
				require.NoError(t, err)
				assert.Zero(t, n.N, "no saved codes issued")
				assert.Zero(t, h.activeSessions(t), "no session created")
			},
		}
	}

	sessionsFamily := func(t *testing.T, endpoint httpsec.Option, method, path string) soCase {
		t.Helper()

		sessions, err := session.New()
		require.NoError(t, err)

		live, err := sessions.Create(t.Context(), "u-1")
		require.NoError(t, err)

		users := NewMockUserLoader(gomock.NewController(t))

		return soCase{
			opts: []httpsec.Option{
				soResourceServer(),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
				endpoint,
			},
			req: soRequest(t, method, path),
			unchanged: func(t *testing.T) {
				t.Helper()
				got, err := sessions.Load(t.Context(), live.ID)
				require.NoError(t, err, "the user's session still stands")
				assert.Equal(t, live.ID, got.ID)
			},
		}
	}

	type testCase struct {
		name   string
		build  func(t *testing.T) soCase
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:   "password change",
			build:  func(t *testing.T) soCase { return recoveryFamily(t, http.MethodPost, passwordResolvePath) },
			assert: refused,
		},
		{
			name:   "saved-code regeneration",
			build:  func(t *testing.T) soCase { return recoveryFamily(t, http.MethodPost, httpsec.DefaultRecoveryCodesPath) },
			assert: refused,
		},
		{
			name:   "passkey registration",
			build:  func(t *testing.T) soCase { return mfaFamily(t, http.MethodPost, passkeyBeginPath) },
			assert: refused,
		},
		{
			name: "passkey removal",
			build: func(t *testing.T) soCase {
				return mfaFamily(t, http.MethodPost, httpsec.DefaultPasskeyCredentialsPrefix+"/remove")
			},
			assert: refused,
		},
		{
			name:   "second-factor method listing",
			build:  func(t *testing.T) soCase { return mfaFamily(t, http.MethodGet, httpsec.DefaultMFAMethodListingPath) },
			assert: refused,
		},
		{
			name: "second-factor verification",
			build: func(t *testing.T) soCase {
				return mfaFamily(t, http.MethodPost, httpsec.DefaultMFAVerifyPrefix+"/totp")
			},
			assert: refused,
		},
		{
			name: "re-authentication",
			build: func(t *testing.T) soCase {
				return mfaFamily(t, http.MethodGet, httpsec.DefaultReauthenticationPrefix+"/methods")
			},
			assert: refused,
		},
		{
			name: "session renewal",
			build: func(t *testing.T) soCase {
				return sessionsFamily(t, httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: NewMockUserLoader(gomock.NewController(t))}),
					http.MethodPost, httpsec.DefaultSessionRenewalPath)
			},
			assert: refused,
		},
		{
			name: "session listing",
			build: func(t *testing.T) soCase {
				return sessionsFamily(t, httpsec.EnableSessionManagement(), http.MethodGet, httpsec.DefaultSessionManagementPrefix)
			},
			assert: refused,
		},
		{
			name: "ending the other sessions",
			build: func(t *testing.T) soCase {
				return sessionsFamily(t, httpsec.EnableSessionManagement(), http.MethodDelete, httpsec.DefaultSessionManagementPrefix)
			},
			assert: refused,
		},
		{
			name: "ending one session",
			build: func(t *testing.T) soCase {
				return sessionsFamily(t, httpsec.EnableSessionManagement(), http.MethodDelete,
					httpsec.DefaultSessionManagementPrefix+"/some-handle")
			},
			assert: refused,
		},
		{
			// The resume judges its pending-request handle before the caller, so a request naming
			// none is refused for that, before anything is read or changed.
			name:  "the provider's resume",
			build: func(t *testing.T) soCase { return providerCase(t, http.MethodPost, "/oauth2/authorize/resume") },
			assert: func(t *testing.T, out served) {
				t.Helper()
				require.Error(t, out.err)
				assert.GreaterOrEqual(t, httpsec.StatusForError(out.err), http.StatusBadRequest)
			},
		},
		{
			name:   "the provider's consents",
			build:  func(t *testing.T) soCase { return providerCase(t, http.MethodGet, "/oauth2/consents") },
			assert: refused,
		},
		{
			name: "active-role switch",
			build: func(t *testing.T) soCase {
				c := sessionsFamily(t, httpsec.WithSwitchableRoles(), http.MethodGet, "/account")
				c.handler = func(chain **httpsec.Chain) func(ex *httpsec.Exchange) error {
					return func(ex *httpsec.Exchange) error {
						return (*chain).SwitchActiveRole(ex.Context(), "admin")
					}
				}

				return c
			},
			assert: refused,
		},
		{
			name: "session-signal stream keeps its settled answer",
			build: func(t *testing.T) soCase {
				f := newSignalsFixture(t, signalsSetup{withoutSignals: true})

				c := sessionsFamily(t, httpsec.EnableSessionSignals(httpsec.SessionSignals{Users: f.users}),
					http.MethodGet, httpsec.DefaultSessionSignalsPath)
				c.req.Header.Set("Accept", "text/event-stream")

				return c
			},
			assert: func(t *testing.T, out served) {
				t.Helper()
				require.Error(t, out.err)
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "a caller with no sign-in, not no caller")
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.NotEqual(t, "text/event-stream", out.rec.Header().Get("Content-Type"), "no stream opened")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := tc.build(t)

			chain, err := httpsec.New(c.opts...)
			require.NoError(t, err)

			out := served{rec: httptest.NewRecorder()}
			terminal := func(*httpsec.Exchange) error {
				out.handlerRan = true

				return nil
			}
			if c.handler != nil {
				terminal = c.handler(&chain)
			}

			ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(c.req), httpsec.NewHTTPResponseWriter(out.rec))
			out.err = chain.Assemble(terminal)(ex)

			tc.assert(t, out)
			assert.False(t, out.handlerRan, "the application is not reached")

			if c.unchanged != nil {
				c.unchanged(t)
			}
		})
	}
}

// providerCase is a provider endpoint answered behind the bearer, on a chain whose resource server
// covers every path.
func providerCase(t *testing.T, method, path string) soCase {
	t.Helper()

	f := newOPFixture(t)
	p := f.provider(t)

	return soCase{
		opts: append(f.wired(t, p), httpsec.EnableOIDCProvider(p), soResourceServer()),
		req:  soRequest(t, method, path),
	}
}

// TestSessionOnlyEndpoints_EnrolmentBegin pins that second-factor enrolment refuses a caller a
// resource server authenticated, as every other session-only endpoint does. Enrolment answers only
// a session owing an enrolment and hands every other request on, so this is a real red, not a
// characterization.
func TestSessionOnlyEndpoints_EnrolmentBegin(t *testing.T) {
	t.Parallel()

	h := newPasskeyHarness(t)
	h.extra = append(h.extra, soResourceServer())

	chain, err := httpsec.New(h.chainOptions(t, nil)...)
	require.NoError(t, err)

	out := serve(t, chain, soRequest(t, http.MethodPost, enrolBeginPath))

	require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan, "the application is not reached")

	_, enrolled := h.enrolment(t)
	assert.False(t, enrolled, "no enrolment begun")
}
