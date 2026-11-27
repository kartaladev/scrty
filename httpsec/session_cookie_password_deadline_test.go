package httpsec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestSessionCookie_PasswordChangeDeadlines pins what a password change on a
// cookie chain does to the sign-in's deadlines: the successor the rotation
// stores keeps the fresh idle deadline the rotation gave it, a role switch
// inside the consumer's function leaves the latest successor with its own, a
// chain that opted out of the rotation keeps the idle deadline the stored
// session held, and a recovery-pending sign-in still saves the deadlines its
// resolution restored.
func TestSessionCookie_PasswordChangeDeadlines(t *testing.T) {
	t.Parallel()

	const (
		idle = 30 * time.Minute

		// lateRequest is nearly the idle timeout after the sign-in; a
		// recovery's lowered deadline is shorter, so its case asks sooner.
		lateRequest   = 29*time.Minute + 50*time.Second
		recoveryAsked = 5 * time.Minute
	)

	type testCase struct {
		name       string
		cookieOpts []httpsec.SessionCookieOption

		// recovery makes the sign-in a recovery-pending one, with a lowered
		// deadline, before the request.
		recovery bool

		// change is the consumer's function, given the world; nil succeeds.
		change func(w **switchCookieWorld) httpsec.ChangePasswordFunc

		// assert receives the stored session the browser ends on: the one the
		// response's cookie names, or the original when none was set.
		assert func(t *testing.T, w *switchCookieWorld, before, stored *session.Session)
	}

	cases := []testCase{
		{
			name: "the rotation's successor keeps its fresh idle deadline",
			assert: func(t *testing.T, w *switchCookieWorld, before, stored *session.Session) {
				t.Helper()

				assert.NotEqual(t, before.ID, stored.ID, "the sign-in rotated")
				assert.False(t, stored.PasswordChangePending)
				assert.Equal(t, w.clk.Now().Add(idle), stored.IdleExpiresAt,
					"the idle deadline runs from the change, not from the sign-in's last activity")
				assert.Equal(t, before.AbsoluteExpiresAt, stored.AbsoluteExpiresAt)
			},
		},
		{
			name: "a role switch inside the function leaves the latest successor its own idle deadline",
			change: func(w **switchCookieWorld) httpsec.ChangePasswordFunc {
				return func(ex *httpsec.Exchange) error { return (*w).chain.SwitchActiveRole(ex.Context(), "audit") }
			},
			assert: func(t *testing.T, w *switchCookieWorld, before, stored *session.Session) {
				t.Helper()

				assert.NotEqual(t, before.ID, stored.ID)
				assert.Equal(t, "audit", stored.SelectedRole)
				assert.False(t, stored.PasswordChangePending, "the resolution is saved on the latest successor")
				assert.Equal(t, w.clk.Now().Add(idle), stored.IdleExpiresAt)
			},
		},
		{
			name:       "without the rotation the session keeps the idle deadline it held",
			cookieOpts: []httpsec.SessionCookieOption{httpsec.WithoutSessionRotation(httpsec.RotateOnPasswordChange)},
			assert: func(t *testing.T, w *switchCookieWorld, before, stored *session.Session) {
				t.Helper()

				assert.Equal(t, before.ID, stored.ID, "no successor")
				assert.False(t, stored.PasswordChangePending)
				assert.Equal(t, before.IdleExpiresAt, stored.IdleExpiresAt, "the resolution moves no deadline")
				assert.Equal(t, before.AbsoluteExpiresAt, stored.AbsoluteExpiresAt)
			},
		},
		{
			name:     "a recovery-pending sign-in saves the deadlines its resolution restored",
			recovery: true,
			assert: func(t *testing.T, w *switchCookieWorld, before, stored *session.Session) {
				t.Helper()

				origin := before.EnrolmentOriginDeadline
				require.False(t, origin.IsZero(), "the recovery recorded the deadline to restore")

				assert.Equal(t, session.MFANone, stored.MFA)
				assert.False(t, stored.PasswordChangePending)
				assert.Equal(t, origin, stored.AbsoluteExpiresAt, "the recovery's lowered deadline is lifted")
				assert.Equal(t, w.clk.Now().Add(idle), stored.IdleExpiresAt)
				assert.True(t, stored.EnrolmentOriginDeadline.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var w *switchCookieWorld

			w = newSwitchCookieWorldWith(t,
				[]session.Option{session.WithIdleTimeout(idle), session.WithTouchInterval(idle - 5*time.Second)},
				nil, tc.cookieOpts,
				func(sessions *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithPasswordChangeEndpoint("/orders", func(ex *httpsec.Exchange) error {
							if tc.change == nil {
								return nil
							}

							return tc.change(&w)(ex)
						}))}
				})

			s := *w.signIn
			s.PasswordChangePending = true

			if tc.recovery {
				w.sessions.MarkRecoveryPending(&s, 15*time.Minute, s.CreatedAt)
			}

			require.NoError(t, w.sessions.Save(t.Context(), &s))

			before, err := w.store.Load(t.Context(), s.ID)
			require.NoError(t, err)

			elapsed := lateRequest
			if tc.recovery {
				elapsed = recoveryAsked
			}

			w.clk.Advance(elapsed)

			out := w.post(t, s.ID, func(*httpsec.Exchange) error { return nil })
			require.NoError(t, out.err)

			id := s.ID
			if set := sessionCookiesSet(t, out); len(set) > 0 {
				id = set[len(set)-1].Value
			}

			stored, err := w.store.Load(t.Context(), id)
			require.NoError(t, err)

			tc.assert(t, w, before, stored)
		})
	}
}
