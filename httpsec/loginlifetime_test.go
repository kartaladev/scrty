package httpsec_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// rememberLifetime asks for 30 days when the login carries remember set to
// true (a JSON boolean) or "true" (a form value), and for nothing otherwise.
func rememberLifetime(_ *httpsec.Exchange, f httpsec.LoginFields) time.Duration {
	if v, _ := f.Value("remember"); v == true || v == "true" {
		return 30 * day
	}

	return 0
}

func TestFormLogin_Lifetime(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		manager []session.ManagerOption
		opts    []httpsec.LoginOption
		req     func(t *testing.T) *http.Request
		// mockStore builds the manager over a mock store that expects no
		// Create, so a session created anyway fails the test.
		mockStore bool
		assert    func(t *testing.T, out served, s *session.Session)
	}

	remember := []httpsec.LoginOption{httpsec.WithLoginLifetime(rememberLifetime)}
	long := []session.ManagerOption{session.WithMaxAbsoluteLifetime(30 * day)}

	json := func(body string) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request { return jsonRequest(t.Context(), "/login", body) }
	}
	form := func(body string) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request { return formRequest(t.Context(), "/login", body) }
	}

	lives := func(d time.Duration) func(*testing.T, served, *session.Session) {
		return func(t *testing.T, out served, s *session.Session) {
			t.Helper()

			require.NoError(t, out.err)
			require.NotNil(t, s)
			assert.Equal(t, start.Add(d), s.AbsoluteExpiresAt)
		}
	}

	cases := []testCase{
		{
			name:   "no function gives the absolute timeout",
			req:    json(`{"username":"ada","password":"pw","remember":true}`),
			assert: lives(12 * time.Hour),
		},
		{
			name:    "a JSON boolean the function reads gives its lifetime",
			manager: long,
			opts:    remember,
			req:     json(`{"username":"ada","password":"pw","remember":true}`),
			assert:  lives(30 * day),
		},
		{
			name:    "a form value the function reads gives its lifetime",
			manager: long,
			opts:    remember,
			req:     form("username=ada&password=pw&remember=true"),
			assert:  lives(30 * day),
		},
		{
			name:    "a function returning nothing keeps the absolute timeout",
			manager: long,
			opts:    remember,
			req:     json(`{"username":"ada","password":"pw"}`),
			assert:  lives(12 * time.Hour),
		},
		{
			name:    "a function returning a negative lifetime keeps the absolute timeout",
			manager: long,
			opts: []httpsec.LoginOption{httpsec.WithLoginLifetime(
				func(*httpsec.Exchange, httpsec.LoginFields) time.Duration { return -time.Hour })},
			req:    json(`{"username":"ada","password":"pw"}`),
			assert: lives(12 * time.Hour),
		},
		{
			name:      "a lifetime above the lifetime maximum refuses the login and creates no session",
			opts:      remember,
			req:       json(`{"username":"ada","password":"pw","remember":true}`),
			mockStore: true,
			assert: func(t *testing.T, out served, s *session.Session) {
				require.ErrorIs(t, out.err, session.ErrConfig)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.Nil(t, s)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			clk := clockwork.NewFakeClockAt(start)
			h := newAuthHarness(t)

			var store session.Store = session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			if tc.mockStore {
				store = NewMockStore(ctrl) // no Create expected
			}

			var err error

			h.sessions, err = session.NewManager(append([]session.ManagerOption{
				session.WithClock(clk),
				session.WithStore(store),
				session.WithAbsoluteTimeout(12 * time.Hour),
			}, tc.manager...)...)
			require.NoError(t, err)

			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

			if !tc.mockStore {
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("tok", nil)
			}

			var got *session.Session

			chain, err := httpsec.New(
				httpsec.WithClock(clk),
				httpsec.EnableFormLogin(h.formLoginDeps(), append(tc.opts,
					httpsec.WithLoginResponder(func(ex *httpsec.Exchange, r httpsec.LoginResult) error {
						got = r.Session
						ex.Writer.WriteHeader(http.StatusOK)

						return nil
					}))...),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.req(t)), got)
		})
	}
}

func TestLoginFields_NeverShowsThePassword(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		opts  []httpsec.LoginOption
		param string
		req   func(t *testing.T) *http.Request
	}{
		{
			name:  "JSON, default parameter",
			param: "password",
			req: func(t *testing.T) *http.Request {
				return jsonRequest(t.Context(), "/login", `{"username":"ada","password":"pw","remember":true}`)
			},
		},
		{
			name:  "form, default parameter",
			param: "password",
			req: func(t *testing.T) *http.Request {
				return formRequest(t.Context(), "/login", "username=ada&password=pw&remember=true")
			},
		},
		{
			name:  "JSON, configured parameter",
			param: "secret",
			opts:  []httpsec.LoginOption{httpsec.WithLoginParams("who", "secret")},
			req: func(t *testing.T) *http.Request {
				return jsonRequest(t.Context(), "/login", `{"who":"ada","secret":"pw","remember":true}`)
			},
		},
		{
			name:  "form, configured parameter",
			param: "secret",
			opts:  []httpsec.LoginOption{httpsec.WithLoginParams("who", "secret")},
			req: func(t *testing.T) *http.Request {
				return formRequest(t.Context(), "/login", "who=ada&secret=pw&remember=true")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			h.expectSessionOpened("tok")

			var (
				called         bool
				password       any
				hasPassword    bool
				remember       any
				hasRemember    bool
				gotEx          *httpsec.Exchange
				missing, found bool
			)

			opts := append(tc.opts, httpsec.WithLoginLifetime(func(ex *httpsec.Exchange, f httpsec.LoginFields) time.Duration {
				called, gotEx = true, ex
				password, hasPassword = f.Value(tc.param)
				remember, hasRemember = f.Value("remember")
				_, found = f.Value("nonexistent")
				_, missing = f.Value("")

				return 0
			}))

			chain, err := httpsec.New(httpsec.EnableFormLogin(h.formLoginDeps(), opts...))
			require.NoError(t, err)

			out := serve(t, chain, tc.req(t))
			require.NoError(t, out.err)

			require.True(t, called)
			assert.NotNil(t, gotEx)
			assert.False(t, hasPassword, "the password parameter is not reported")
			assert.Nil(t, password)
			assert.True(t, hasRemember)
			assert.NotNil(t, remember)
			assert.False(t, found)
			assert.False(t, missing)
		})
	}
}

func TestWithLoginLifetime_NilFunctionIsRefused(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)

	chain, err := httpsec.New(httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginLifetime(nil)))

	require.ErrorIs(t, err, httpsec.ErrConfig)
	assert.Contains(t, err.Error(), "WithLoginLifetime")
	assert.Nil(t, chain)
}
