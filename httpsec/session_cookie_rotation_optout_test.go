package httpsec_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// sessionCookiesSet is every session cookie out set, in order.
func sessionCookiesSet(t *testing.T, out served) []*http.Cookie {
	t.Helper()

	var set []*http.Cookie

	for _, line := range out.rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)

		if c.Name == httpsec.DefaultSessionCookieName {
			set = append(set, c)
		}
	}

	return set
}

// TestSessionCookie_WithoutRotation pins the named opt-outs of the rotations a
// cookie chain adds: with the role switch's rotation off, a switch records the
// role on the identifier the browser holds and sets no cookie; with the
// password change's off, the change is recorded on it likewise; each one left
// on still rotates, alone or inside the other; second-factor verification and
// re-authentication rotate whatever is off; and a point the option does not
// know, or none at all, is a configuration error, while a point named twice is
// the same opt-out.
func TestSessionCookie_WithoutRotation(t *testing.T) {
	t.Parallel()

	off := func(points ...httpsec.RotationPoint) []httpsec.SessionCookieOption {
		return []httpsec.SessionCookieOption{httpsec.WithoutSessionRotation(points...)}
	}

	noExtra := func(*session.Sessions) []httpsec.Option { return nil }

	// gated is a switch world over opts, its sign-in owing a password change,
	// whose password-change gate answers on the world's request path with
	// change.
	gated := func(t *testing.T, opts []httpsec.SessionCookieOption, change httpsec.ChangePasswordFunc) *switchCookieWorld {
		t.Helper()

		w := newSwitchCookieWorldWith(t, nil, nil, opts, func(sessions *session.Sessions) []httpsec.Option {
			return []httpsec.Option{httpsec.EnablePasswordChangeGate(sessions,
				httpsec.WithPasswordChangeEndpoint("/orders", change))}
		})

		s := *w.signIn
		s.PasswordChangePending = true
		require.NoError(t, w.sessions.Save(t.Context(), &s))

		return w
	}

	// unrotated asserts the sign-in w began with is still the stored head of
	// its family, never superseded and the user's only live session, and
	// returns it as stored.
	unrotated := func(t *testing.T, w *switchCookieWorld) *session.Session {
		t.Helper()

		raw, err := w.store.Load(t.Context(), w.signIn.ID)
		require.NoError(t, err)
		assert.True(t, raw.SupersededAt.IsZero(), "the identifier was not rotated")

		n, err := w.sessions.CountActiveByUser(t.Context(), testUserID)
		require.NoError(t, err)
		assert.Equal(t, 1, n, "no successor was stored")

		return raw
	}

	refused := func(t *testing.T, opts []httpsec.SessionCookieOption) {
		t.Helper()

		_, err := httpsec.New(httpsec.EnableCSRFProtection(), httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{
			Sessions: must.Must(session.New()),
			Users:    NewMockUserLoader(gomock.NewController(t)),
		}, opts...))
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "WithoutSessionRotation")
	}

	type testCase struct {
		name   string
		opts   []httpsec.SessionCookieOption
		assert func(t *testing.T, opts []httpsec.SessionCookieOption)
	}

	cases := []testCase{
		{
			name: "role switch off keeps the identifier and sets no cookie",
			opts: off(httpsec.RotateOnRoleSwitch),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				w := newSwitchCookieWorldWith(t, nil, nil, opts, noExtra)

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)
				require.NoError(t, out.err)
				noSessionCookie(t, out)

				assert.Equal(t, "audit", unrotated(t, w).SelectedRole,
					"the role is recorded on the identifier the browser holds")
				assert.Equal(t, "audit", w.activeRole(t, w.signIn.ID))
			},
		},
		{
			name: "role switch off, a switch on a context kept past its request still records the role",
			opts: off(httpsec.RotateOnRoleSwitch),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				w := newSwitchCookieWorldWith(t, nil, nil, opts, noExtra)

				var kept context.Context

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					kept = context.WithoutCancel(ex.Context())

					return nil
				})
				require.NoError(t, out.err)

				require.NoError(t, w.chain.SwitchActiveRole(kept, "audit"),
					"nothing is set on the response, so the switch does not need it")
				assert.Equal(t, "audit", unrotated(t, w).SelectedRole)
			},
		},
		{
			name: "password change off keeps the identifier and sets no cookie",
			opts: off(httpsec.RotateOnPasswordChange),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				var changed int

				w := gated(t, opts, func(*httpsec.Exchange) error {
					changed++

					return nil
				})

				out := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.NoError(t, out.err)
				assert.Equal(t, 1, changed)
				noSessionCookie(t, out)

				assert.False(t, unrotated(t, w).PasswordChangePending,
					"the change is recorded on the identifier the browser holds")
			},
		},
		{
			name: "role switch off, a switch inside a rotating password change records the role on its successor",
			opts: off(httpsec.RotateOnRoleSwitch),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				var w *switchCookieWorld

				w = gated(t, opts, func(ex *httpsec.Exchange) error {
					return w.chain.SwitchActiveRole(ex.Context(), "audit")
				})

				out := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.NoError(t, out.err, "the switch is made on the identifier the change rotated into")

				set := sessionCookiesSet(t, out)
				require.Len(t, set, 1, "only the password change re-sets the cookie")
				assert.NotEqual(t, w.signIn.ID, set[0].Value)

				raw, err := w.store.Load(t.Context(), set[0].Value)
				require.NoError(t, err)
				assert.Equal(t, "audit", raw.SelectedRole)
				assert.False(t, raw.PasswordChangePending)
			},
		},
		{
			name: "password change off, a switch inside it still rotates, once",
			opts: off(httpsec.RotateOnPasswordChange),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				var w *switchCookieWorld

				w = gated(t, opts, func(ex *httpsec.Exchange) error {
					return w.chain.SwitchActiveRole(ex.Context(), "audit")
				})

				out := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.NoError(t, out.err)

				set := sessionCookiesSet(t, out)
				require.Len(t, set, 1, "only the switch re-sets the cookie")
				assert.NotEqual(t, w.signIn.ID, set[0].Value)

				s, err := w.sessions.Load(t.Context(), set[0].Value)
				require.NoError(t, err)
				assert.Equal(t, "audit", s.SelectedRole)
				assert.False(t, s.PasswordChangePending, "the resolution is saved on the switch's successor")
			},
		},
		{
			name: "both off, second-factor verification and re-authentication still rotate",
			opts: off(httpsec.RotateOnRoleSwitch, httpsec.RotateOnPasswordChange),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				enrolled := newBrowserWorld(t)
				enrolled.cookieOpts = opts
				enrolled.enrol(t)
				enrolled.build(t)

				challenged := enrolled.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				verified := enrolled.post(t.Context(), t, testMFAVerifyPath, pending.Value,
					url.Values{"code": {enrolled.code(t)}})
				require.NoError(t, verified.err)
				reSetAs(t, enrolled.chain, verified, pending.Value)

				// A user with no second factor re-authenticates by password.
				w := newBrowserWorld(t)
				w.cookieOpts = opts
				w.build(t)

				id := w.signedIn(t)
				reauthed := w.post(t.Context(), t, reauthPasswordPath, id, url.Values{"password": {e2ePassword}})
				require.NoError(t, reauthed.err)
				reSetAs(t, w.chain, reauthed, id)
			},
		},
		{
			name: "a point named twice, and the option given twice, are the same opt-out",
			opts: append(off(httpsec.RotateOnRoleSwitch, httpsec.RotateOnRoleSwitch), off(httpsec.RotateOnRoleSwitch)...),
			assert: func(t *testing.T, opts []httpsec.SessionCookieOption) {
				t.Helper()

				w := newSwitchCookieWorldWith(t, nil, nil, opts, noExtra)

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)
				noSessionCookie(t, out)
				assert.Equal(t, "audit", unrotated(t, w).SelectedRole)
			},
		},
		{
			name:   "no point is a configuration error",
			opts:   off(),
			assert: refused,
		},
		{
			name:   "the zero point is a configuration error",
			opts:   off(httpsec.RotationPoint(0)),
			assert: refused,
		},
		{
			name:   "a point past the known ones is a configuration error",
			opts:   off(httpsec.RotateOnRoleSwitch, httpsec.RotationPoint(3)),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.opts)
		})
	}
}
