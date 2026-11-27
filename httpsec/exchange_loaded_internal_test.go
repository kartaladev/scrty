package httpsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestExchange_LoadedFor pins which session second-factor verification and
// re-authentication compare the stored record with (loadedFor): the copy
// taken when the session was published, unchanged by marks made on the
// session afterwards, whatever pointer now names that session; the session
// itself when it reached the exchange by direct assignment with no copy, or
// names another session than the copy; and, after a nested run returns, the
// copy of the run it returned to (restoreScope).
func TestExchange_LoadedFor(t *testing.T) {
	t.Parallel()

	type fixture struct {
		ex       *Exchange
		sessions *session.Sessions
		// a and b are two stored sessions of one user, as the store returned
		// them.
		a, b *session.Session
	}

	type testCase struct {
		name string
		// act changes the exchange and returns the session the endpoint
		// would rotate.
		act    func(t *testing.T, f *fixture) *session.Session
		assert func(t *testing.T, f *fixture, rotating, got *session.Session)
	}

	publish := func(t *testing.T, f *fixture, s *session.Session) {
		t.Helper()
		require.NoError(t, f.ex.publishSession(&authenticate.Authentication{}, s))
	}

	cases := []testCase{
		{
			name: "a published session is compared as published, not as marked since",
			act: func(t *testing.T, f *fixture) *session.Session {
				publish(t, f, f.a)
				f.a.PasswordChangePending = true

				return f.a
			},
			assert: func(t *testing.T, f *fixture, rotating, got *session.Session) {
				require.NotNil(t, got)
				assert.NotSame(t, rotating, got)
				assert.Equal(t, f.a.ID, got.ID)
				assert.False(t, got.PasswordChangePending, "the copy predates the mark")
			},
		},
		{
			name: "the published session reassigned as another pointer keeps the copy",
			act: func(t *testing.T, f *fixture) *session.Session {
				publish(t, f, f.a)
				f.a.PasswordChangePending = true
				again := *f.a
				f.ex.Session = &again

				return &again
			},
			assert: func(t *testing.T, _ *fixture, _, got *session.Session) {
				require.NotNil(t, got)
				assert.False(t, got.PasswordChangePending, "the copy predates the mark")
			},
		},
		{
			name: "a session assigned directly with nothing published is itself",
			act: func(_ *testing.T, f *fixture) *session.Session {
				f.ex.Session = f.a

				return f.a
			},
			assert: func(t *testing.T, _ *fixture, rotating, got *session.Session) {
				assert.Same(t, rotating, got)
			},
		},
		{
			name: "another session assigned directly after a publication is itself",
			act: func(t *testing.T, f *fixture) *session.Session {
				publish(t, f, f.a)
				f.ex.Session = f.b

				return f.b
			},
			assert: func(t *testing.T, _ *fixture, rotating, got *session.Session) {
				assert.Same(t, rotating, got)
			},
		},
		{
			name: "no session is nil",
			act: func(t *testing.T, f *fixture) *session.Session {
				publish(t, f, f.a)

				return nil
			},
			assert: func(t *testing.T, _ *fixture, _, got *session.Session) {
				assert.Nil(t, got)
			},
		},
		{
			name: "a nested run's publication is undone when it returns",
			act: func(t *testing.T, f *fixture) *session.Session {
				publish(t, f, f.a)
				f.a.PasswordChangePending = true

				scope := f.ex.saveScope()
				publish(t, f, f.b)
				require.Equal(t, f.b.ID, f.ex.loadedFor(f.b).ID, "the nested run compares its own session")
				f.ex.restoreScope(scope)

				return f.ex.Session
			},
			assert: func(t *testing.T, f *fixture, rotating, got *session.Session) {
				require.Same(t, f.a, rotating, "the outer run's session is back")
				require.NotNil(t, got)
				assert.NotSame(t, rotating, got)
				assert.False(t, got.PasswordChangePending, "the outer run's copy is back")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New()
			require.NoError(t, err)

			f := &fixture{ex: NewExchange(t.Context(), nil, nil), sessions: sessions}
			for _, s := range []**session.Session{&f.a, &f.b} {
				created, err := sessions.Create(t.Context(), identity.UserID("u1"))
				require.NoError(t, err)
				*s, err = sessions.Load(t.Context(), created.ID)
				require.NoError(t, err)
			}

			rotating := tc.act(t, f)
			tc.assert(t, f, rotating, f.ex.loadedFor(rotating))
		})
	}
}

// TestCredentialDelivery_RotateIssuingRefusesNoLoadedSession pins that a
// rotation of second-factor verification or re-authentication given no
// session as loaded is a configuration error that rotates nothing and runs no
// step, on the strict and the grace path alike.
func TestCredentialDelivery_RotateIssuingRefusesNoLoadedSession(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		deliver credentialDelivery
	}{
		{name: "strict", deliver: credentialDelivery{}},
		{name: "with a grace window", deliver: credentialDelivery{cookie: &sessionCookie{}, grace: 30 * time.Second}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New()
			require.NoError(t, err)
			s, err := sessions.Create(t.Context(), identity.UserID("u1"))
			require.NoError(t, err)

			stepped := false
			got, tok, err := tc.deliver.rotateIssuing(t.Context(), sessions, nil, s, func(*session.Session) (string, error) {
				stepped = true

				return "credential", nil
			})

			require.ErrorIs(t, err, ErrConfig)
			assert.Nil(t, got)
			assert.Empty(t, tok)
			assert.False(t, stepped, "no step runs")

			_, err = sessions.Load(t.Context(), s.ID)
			require.NoError(t, err, "the session is not rotated")
		})
	}
}
