package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// otherManager is a session manager over a store of its own, standing in for
// the manager a built-in was wired to when it is not the chain's.
func otherManager(t *testing.T, f resolveFixture) *session.Sessions {
	t.Helper()

	m, err := session.New(session.WithClock(f.clk), session.WithStore(
		session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))))
	require.NoError(t, err)

	return m
}

// TestWithSessionManager pins which manager the chain records activity
// through: none for a chain no built-in gave one, the explicit one when given,
// whatever the option order and whichever manager a built-in brought.
func TestWithSessionManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, f resolveFixture) []httpsec.Option
		assert  func(t *testing.T, f resolveFixture, out served)
	}

	recorded := func(t *testing.T, f resolveFixture, out served) {
		t.Helper()

		require.NoError(t, out.err)

		stored, err := f.sessions.Load(t.Context(), f.session.ID)
		require.NoError(t, err)
		assert.True(t, stored.LastAccessedAt.Equal(f.clk.Now()),
			"activity is recorded through the explicit manager, got %s, want %s",
			stored.LastAccessedAt, f.clk.Now())
	}

	cases := []testCase{
		{
			name: "default: no built-in, no manager, nothing recorded",
			options: func(_ *testing.T, _ resolveFixture) []httpsec.Option {
				return nil
			},
			assert: func(t *testing.T, f resolveFixture, out served) {
				t.Helper()

				require.NoError(t, out.err)

				stored, err := f.sessions.Load(t.Context(), f.session.ID)
				require.NoError(t, err)
				assert.True(t, stored.LastAccessedAt.Before(f.clk.Now()),
					"a chain with no session manager records no activity, got %s", stored.LastAccessedAt)
			},
		},
		{
			name: "explicit manager alone",
			options: func(_ *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(f.sessions)}
			},
			assert: recorded,
		},
		{
			name: "explicit manager before a built-in with another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: otherManager(t, f)}),
				}
			},
			assert: recorded,
		},
		{
			name: "explicit manager after a built-in with another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: otherManager(t, f)}),
					httpsec.WithSessions(f.sessions),
				}
			},
			assert: recorded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			opts := append(tc.options(t, f),
				httpsec.RegisterInterceptor(consumerAuthenticating(f, false), httpsec.OrderBearerToken))

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, f, serve(t, chain, bearerRequest(t.Context(), "")))
		})
	}
}

// TestWithSessionManager_RefusesNil pins that a missing manager is a
// configuration error from New, typed nil included.
func TestWithSessionManager_RefusesNil(t *testing.T) {
	t.Parallel()

	for name, m := range map[string]*session.Sessions{"nil": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.WithSessions(m))
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)
		})
	}
}

// TestWithSessionManager_MustBeTheBearers pins that an explicit manager other
// than the one a built-in bearer loads sessions from is a configuration error,
// whatever the option order, and that the same manager, or no built-in bearer,
// builds.
func TestWithSessionManager_MustBeTheBearers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, f resolveFixture) []httpsec.Option
		assert  func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "WithSessionManager")
		assert.Nil(t, chain)
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}

	signed := func(t *testing.T, m *session.Sessions) httpsec.Option {
		t.Helper()

		ctrl := gomock.NewController(t)

		return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: NewMockVerifier(ctrl), Sessions: m, Users: NewMockUserLoader(ctrl),
		})
	}

	reference := func(t *testing.T, m *session.Sessions) httpsec.Option {
		t.Helper()

		ctrl := gomock.NewController(t)

		return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: m, Users: NewMockUserLoader(ctrl)})
	}

	cases := []testCase{
		{
			name: "signed-token bearer, explicit manager after, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{signed(t, f.sessions), httpsec.WithSessions(otherManager(t, f))}
			},
			assert: refused,
		},
		{
			name: "signed-token bearer, explicit manager before, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(otherManager(t, f)), signed(t, f.sessions)}
			},
			assert: refused,
		},
		{
			name: "session-reference bearer, explicit manager after, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{reference(t, f.sessions), httpsec.WithSessions(otherManager(t, f))}
			},
			assert: refused,
		},
		{
			name: "session-reference bearer, explicit manager before, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(otherManager(t, f)), reference(t, f.sessions)}
			},
			assert: refused,
		},
		{
			name: "signed-token bearer, the same manager",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{signed(t, f.sessions), httpsec.WithSessions(f.sessions)}
			},
			assert: built,
		},
		{
			name: "session-reference bearer, the same manager, manager before bearer",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(f.sessions), reference(t, f.sessions)}
			},
			assert: built,
		},
		{
			name: "session-reference bearer, the same manager, bearer before manager",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{reference(t, f.sessions), httpsec.WithSessions(f.sessions)}
			},
			assert: built,
		},
		{
			name: "no built-in bearer, an explicit manager is unchecked",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
					httpsec.WithSessions(otherManager(t, f)),
				}
			},
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			chain, err := httpsec.New(tc.options(t, f)...)
			tc.assert(t, chain, err)
		})
	}
}
