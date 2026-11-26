package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// reSetAs asserts out set exactly one session cookie, with the identifier
// replacing presented, and that it is the cookie chain sets for that
// identifier, attribute for attribute. It returns the identifier.
func reSetAs(t *testing.T, chain *httpsec.Chain, out served, presented string) string {
	t.Helper()

	var set []string

	for _, line := range out.rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)

		if c.Name == httpsec.DefaultSessionCookieName {
			set = append(set, line)
		}
	}

	require.Len(t, set, 1, "the session cookie is re-set once")

	c, err := http.ParseSetCookie(set[0])
	require.NoError(t, err)
	assert.NotEqual(t, presented, c.Value, "the cookie carries the rotated identifier")
	assert.Equal(t, httpsec.SessionCookieOf(chain, c.Value, 0).String(), set[0],
		"with every attribute the chain sets the cookie with")

	return c.Value
}

// TestSessionCookie_ExistingRotationsReset pins that the rotations a sign-in
// already went through before the cookie session existed, second-factor
// verification and re-authentication, re-set the cookie on a cookie chain:
// the response carries the rotated identifier under the chain's own
// attributes, the identifier presented no longer loads, and the rotated one
// does.
func TestSessionCookie_ExistingRotationsReset(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// rotate builds w's chain and runs the rotation, returning what it
		// answered and the identifier it presented.
		rotate func(t *testing.T, w *browserWorld) (out served, presented string)
	}

	cases := []testCase{
		{
			name: "second-factor verification",
			rotate: func(t *testing.T, w *browserWorld) (served, string) {
				t.Helper()

				w.enrol(t)
				w.build(t)

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				return w.post(t.Context(), t, testMFAVerifyPath, pending.Value,
					url.Values{"code": {w.code(t)}}), pending.Value
			},
		},
		{
			name: "re-authentication",
			rotate: func(t *testing.T, w *browserWorld) (served, string) {
				t.Helper()

				w.build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, reauthPasswordPath, id, url.Values{"password": {e2ePassword}}), id
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)
			// Attributes off the default, so the re-set cookie is shown to
			// carry the chain's own and not a fixed set.
			w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookieSameSite(http.SameSiteStrictMode))

			out, presented := tc.rotate(t, w)
			require.NoError(t, out.err)

			rotated := reSetAs(t, w.chain, out, presented)
			assert.Contains(t, out.rec.Header().Get("Set-Cookie"), "SameSite=Strict")

			_, err := w.sessions.Load(t.Context(), presented)
			require.Error(t, err, "the presented identifier no longer loads")

			s, err := w.sessions.Load(t.Context(), rotated)
			require.NoError(t, err, "the cookie names the stored successor")
			assert.Equal(t, e2eUser, s.UserID)
		})
	}
}

// cookiePasswordPath is where the password-change gate's resolve endpoint
// answers in the password-change rotation cases.
const cookiePasswordPath = "/account/password"

// TestSessionCookie_PasswordChangeRotates pins that on a cookie chain the
// password-change gate's resolve endpoint rotates the sign-in and re-sets the
// cookie before the consumer's change runs: the response carries the new
// identifier, on which the change is recorded, and the old one is reuse once
// its window ends; a rotation that cannot be written changes no password and
// sets no cookie, and the old cookie keeps working.
func TestSessionCookie_PasswordChangeRotates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// change is the consumer's change function, nil for one that succeeds.
		change func(ex *httpsec.Exchange) error

		// failSupersede fails the rotation's write.
		failSupersede bool

		assert func(t *testing.T, w *browserWorld, out served, presented string, changed int)
	}

	cases := []testCase{
		{
			name: "the change re-sets the cookie to the rotated sign-in",
			assert: func(t *testing.T, w *browserWorld, out served, presented string, changed int) {
				t.Helper()
				require.NoError(t, out.err)
				assert.Equal(t, 1, changed)

				rotated := reSetAs(t, w.chain, out, presented)

				s, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err)
				assert.False(t, s.PasswordChangePending, "the change is recorded on the rotated session")

				w.clk.Advance(session.DefaultRenewalGrace + time.Second)

				late := w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, presented, nil)
				require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, late.err, session.ErrReused, "the old identifier after its window is reuse")
			},
		},
		{
			name:   "a refused change leaves the browser on the rotated sign-in",
			change: func(*httpsec.Exchange) error { return errPasswordRefused },
			assert: func(t *testing.T, w *browserWorld, out served, presented string, changed int) {
				t.Helper()
				require.ErrorIs(t, out.err, errPasswordRefused)
				assert.Equal(t, 1, changed)

				rotated := reSetAs(t, w.chain, out, presented)
				_, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err, "the refusal still carries a cookie naming a stored session")
			},
		},
		{
			name:          "a rotation that cannot be written changes nothing and sets no cookie",
			failSupersede: true,
			assert: func(t *testing.T, w *browserWorld, out served, presented string, changed int) {
				t.Helper()
				require.ErrorIs(t, out.err, errBrowserStoreDown, "the store's failure stays reachable")
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err), "a dependency failure")
				assert.Zero(t, changed, "no password is changed on a request that is then refused")
				noSessionCookie(t, out)

				w.store.failSupersede = false

				again := w.post(t.Context(), t, reauthPasswordPath, presented, url.Values{"password": {e2ePassword}})
				require.NoError(t, again.err, "the old cookie still works")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var changed int

			change := tc.change
			if change == nil {
				change = func(*httpsec.Exchange) error { return nil }
			}

			w := newBrowserWorld(t)
			w.extra = append(w.extra, httpsec.EnablePasswordChangeGate(w.sessions,
				httpsec.WithPasswordChangeEndpoint(cookiePasswordPath, func(ex *httpsec.Exchange) error {
					changed++

					return change(ex)
				})))
			w.build(t)

			presented := w.signedIn(t)
			w.store.failSupersede = tc.failSupersede

			out := w.post(t.Context(), t, cookiePasswordPath, presented, url.Values{"password": {"n3w-Passw0rd!"}})

			tc.assert(t, w, out, presented, changed)
		})
	}
}

// errPasswordRefused is the refusal a consumer's change function returns.
var errPasswordRefused = errors.New("rotation_test: the new password is too weak")

// selectingStore is a browserStore that records selected roles through the
// memory store it forwards to.
type selectingStore struct{ *browserStore }

func (s selectingStore) SelectRole(ctx context.Context, id, role string) error {
	return s.Store.(session.RoleSelector).SelectRole(ctx, id, role) //nolint:forcetypeassert // the memory store selects roles
}

// switchCookieWorld is a cookie chain with CSRF protection and role switching
// on, over the browser world's failing store on a fake clock, with a live
// sign-in of ada, who holds sales (primary) and audit, carrying a CSRF token.
type switchCookieWorld struct {
	clk      *clockwork.FakeClock
	store    *browserStore
	sessions *session.Sessions
	chain    *httpsec.Chain
	signIn   *session.Session
}

func newSwitchCookieWorld(t *testing.T, extra ...httpsec.Option) *switchCookieWorld {
	t.Helper()

	return newSwitchCookieWorldOver(t, func(*session.Sessions) []httpsec.Option { return extra })
}

// newSwitchCookieWorldOver is newSwitchCookieWorld with options that need the
// world's session manager, such as the password-change gate.
func newSwitchCookieWorldOver(t *testing.T, extra func(*session.Sessions) []httpsec.Option) *switchCookieWorld {
	t.Helper()

	return newSwitchCookieWorldWith(t, nil, nil, extra)
}

// newSwitchCookieWorldWith is newSwitchCookieWorldOver with further session
// manager options, and create options for the sign-in, such as its timeouts
// and a persistent cookie.
func newSwitchCookieWorldWith(t *testing.T, sessionOpts []session.Option, createOpts []session.CreateOption,
	extra func(*session.Sessions) []httpsec.Option,
) *switchCookieWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC))
	store := &browserStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}

	sessions, err := session.New(append([]session.Option{
		session.WithClock(clk), session.WithStore(selectingStore{store}),
	}, sessionOpts...)...)
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), testUserID).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return adaWithGrants(), nil })

	chain, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithClock(clk),
		httpsec.WithLogger(discardLogger()),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.WithSwitchableRoles(),
	}, extra(sessions)...)...)
	require.NoError(t, err)

	signIn, err := sessions.Create(t.Context(), testUserID, append([]session.CreateOption{
		session.WithFirstFactor(factor.Password), session.WithCSRFToken(),
	}, createOpts...)...)
	require.NoError(t, err)

	return &switchCookieWorld{clk: clk, store: store, sessions: sessions, chain: chain, signIn: signIn}
}

// post sends an unsafe same-origin request presenting id as the session
// cookie and the sign-in's CSRF token, with handler as the application, and
// returns what the chain answered.
func (w *switchCookieWorld) post(t *testing.T, id string, handler func(ex *httpsec.Exchange) error) served {
	t.Helper()

	req := sessionCookieRequest(t.Context(), http.MethodPost, named(id),
		map[string]string{"X-CSRF-Token": w.signIn.CSRFToken})
	out := served{rec: httptest.NewRecorder()}

	run := w.chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true

		return handler(ex)
	})

	out.err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))

	return out
}

// switchTo switches the role of the request presenting id to role, and
// returns what the chain answered and what the switch returned.
func (w *switchCookieWorld) switchTo(t *testing.T, id, role string) (served, error) {
	t.Helper()

	var switched error

	out := w.post(t, id, func(ex *httpsec.Exchange) error {
		switched = w.chain.SwitchActiveRole(ex.Context(), role)

		return switched
	})
	require.True(t, out.handlerRan, "the request reached the application")

	return out, switched
}

// activeRole is the active role of a request presenting id, failing the test
// when the request is refused.
func (w *switchCookieWorld) activeRole(t *testing.T, id string) string {
	t.Helper()

	var name string

	out := w.post(t, id, func(ex *httpsec.Exchange) error {
		p, ok := identity.PrincipalFromContext(ex.Context())
		require.True(t, ok)

		if p.ActiveRole != nil {
			name = p.ActiveRole.Name
		}

		return nil
	})
	require.NoError(t, out.err)
	require.True(t, out.handlerRan)

	return name
}

// TestSessionCookie_RoleSwitchRotates pins that on a cookie chain an
// active-role switch rotates the sign-in with a grace window and re-sets the
// cookie: the new identifier carries the switched role and the sign-in's CSRF
// token, the old one works through its window and is reuse after it, which
// revokes the family; a rotation that cannot be written switches nothing and
// sets no cookie; and a switch called once its request is over is refused.
func TestSessionCookie_RoleSwitchRotates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, w *switchCookieWorld)
	}

	cases := []testCase{
		{
			name: "the switch re-sets the cookie, and the CSRF token still holds",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)
				require.NoError(t, out.err)

				rotated := reSetAs(t, w.chain, out, w.signIn.ID)
				assert.Equal(t, "audit", w.activeRole(t, rotated),
					"the next unsafe request with the new cookie and the same CSRF token is served under audit")

				s, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err)
				assert.Equal(t, w.signIn.CSRFToken, s.CSRFToken)
				assert.Equal(t, w.signIn.FamilyID, s.FamilyID, "the same sign-in")
			},
		},
		{
			name: "the old identifier works inside its window",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				_, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)

				w.clk.Advance(time.Second)
				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "an in-flight request is not signed out")
			},
		},
		{
			name: "the old identifier after its window is reuse, and the family is revoked",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)

				rotated := reSetAs(t, w.chain, out, w.signIn.ID)

				w.clk.Advance(session.DefaultRenewalGrace + time.Second)

				late := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, late.err, session.ErrReused)
				assert.False(t, late.handlerRan)

				_, err = w.sessions.Load(t.Context(), rotated)
				require.Error(t, err, "the family, the new identifier included, is revoked")
			},
		},
		{
			name: "a rotation that cannot be written switches nothing and sets no cookie",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				w.store.failSupersede = true

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.ErrorIs(t, err, errBrowserStoreDown, "the store's failure stays reachable")
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err), "a dependency failure")
				noSessionCookie(t, out)

				w.store.failSupersede = false

				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "the old cookie still works, unswitched")
			},
		},
		{
			name: "a second switch on one request rotates the first's successor",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				// onSuccessor asserts the request is now on the identifier the
				// last cookie it set names, in its exchange and its context.
				var set []string

				onSuccessor := func(t *testing.T, ex *httpsec.Exchange, first bool) {
					t.Helper()

					require.NotNil(t, ex.Session)
					assert.NotEqual(t, w.signIn.ID, ex.Session.ID, "the exchange is on the successor")

					inCtx, ok := httpsec.SessionFromContext(ex.Context())
					require.True(t, ok)
					assert.Equal(t, ex.Session.ID, inCtx.ID, "the context is on the successor")

					if !first {
						assert.NotEqual(t, set[0], ex.Session.ID, "the second switch moved on again")
					}

					set = append(set, ex.Session.ID)
				}

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					require.NoError(t, w.chain.SwitchActiveRole(ex.Context(), "audit"))
					onSuccessor(t, ex, true)
					require.NoError(t, w.chain.SwitchActiveRole(ex.Context(), "sales"))
					onSuccessor(t, ex, false)

					return nil
				})
				require.NoError(t, out.err)

				lines := out.rec.Header().Values("Set-Cookie")
				require.Len(t, lines, 2, "each switch re-sets the cookie")
				require.Len(t, set, 2)

				last, err := http.ParseSetCookie(lines[1])
				require.NoError(t, err)
				assert.NotEqual(t, w.signIn.ID, last.Value)
				assert.Equal(t, set[1], last.Value, "the final cookie names the latest successor")

				s, err := w.sessions.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.Equal(t, "sales", s.SelectedRole, "the browser keeps the last cookie, on the last selection")
			},
		},
		{
			name: "a switch called once its request is over is refused",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				var kept context.Context

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					kept = context.WithoutCancel(ex.Context())

					return nil
				})
				require.NoError(t, out.err)

				err := w.chain.SwitchActiveRole(kept, "audit")
				require.ErrorIs(t, err, httpsec.ErrConfig, "the response that would carry the cookie is gone")

				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "nothing was rotated or switched")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newSwitchCookieWorld(t))
		})
	}
}

// TestSessionCookie_RoleSwitchInPasswordChange pins how the password-change
// resolution is saved when the consumer's change function rotates the sign-in
// again or tampers with the exchange: a role switch it makes is made on the
// rotation's successor rather than refused; the resolution is saved on the
// latest successor the chain holds, without loading it, so its first
// presentation is still the browser's; a persistent recovery-pending
// sign-in's last cookie carries the deadline the saved session has; and a
// session the function puts on the exchange is never the one saved.
func TestSessionCookie_RoleSwitchInPasswordChange(t *testing.T) {
	t.Parallel()

	twelveHours := []session.Option{
		session.WithAbsoluteTimeout(12 * time.Hour), session.WithIdleTimeout(12 * time.Hour),
	}

	// fixture is one case's world, and another user's session where the case
	// has one.
	type fixture struct {
		w     *switchCookieWorld
		other *session.Session
	}

	type testCase struct {
		name string

		sessionOpts []session.Option
		createOpts  []session.CreateOption

		// prepare changes the stored sign-in before the request; nil marks it
		// as owing a password change.
		prepare func(t *testing.T, f *fixture)

		// change is the consumer's change function.
		change func(f *fixture) httpsec.ChangePasswordFunc

		// last is the last session cookie the response set.
		assert func(t *testing.T, f *fixture, out served, last *http.Cookie)
	}

	switchToAudit := func(f *fixture) httpsec.ChangePasswordFunc {
		return func(ex *httpsec.Exchange) error {
			return f.w.chain.SwitchActiveRole(ex.Context(), "audit")
		}
	}

	cases := []testCase{
		{
			name:   "a switch is made on the successor and the resolution saved on the latest one, unloaded",
			change: switchToAudit,
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err, "the switch on the rotated session is not refused")
				require.Len(t, out.rec.Header().Values("Set-Cookie"), 2,
					"the password change and the switch each re-set the cookie")

				raw, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.True(t, raw.FirstPresentedAt.IsZero(),
					"the chain did not load the successor the browser has not presented yet")

				s, err := f.w.sessions.Load(t.Context(), last.Value)
				require.NoError(t, err, "the final cookie names a live session")
				assert.Equal(t, "audit", s.SelectedRole, "the selection survives the change's save")
				assert.False(t, s.PasswordChangePending)
				assert.Equal(t, f.w.signIn.FamilyID, s.FamilyID)
			},
		},
		{
			name:        "a persistent recovery-pending sign-in's last cookie carries the restored deadline",
			sessionOpts: twelveHours,
			createOpts:  []session.CreateOption{session.WithPersistentCookie()},
			prepare: func(t *testing.T, f *fixture) {
				t.Helper()

				s, err := f.w.sessions.Load(t.Context(), f.w.signIn.ID)
				require.NoError(t, err)
				f.w.sessions.MarkRecoveryPending(s, 10*time.Minute, f.w.clk.Now())
				s.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), s))
			},
			change: switchToAudit,
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err)
				assert.Equal(t, 43200, last.MaxAge,
					"the deadline the saved session has, not the switch successor's lowered one")

				raw, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.False(t, raw.PasswordChangePending)
				assert.Equal(t, session.MFANone, raw.MFA)
				assert.Equal(t, f.w.clk.Now().Add(12*time.Hour), raw.AbsoluteExpiresAt,
					"the restored absolute deadline the cookie was set for")
				assert.Equal(t, "audit", raw.SelectedRole)
			},
		},
		{
			name: "a session the function puts on the exchange is not the one saved",
			prepare: func(t *testing.T, f *fixture) {
				t.Helper()

				owing := *f.w.signIn
				owing.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), &owing))

				var err error
				f.other, err = f.w.sessions.Create(t.Context(), identity.UserID("someone-else"),
					session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				f.other.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), f.other))
			},
			change: func(f *fixture) httpsec.ChangePasswordFunc {
				return func(ex *httpsec.Exchange) error {
					ex.Session = f.other

					return nil
				}
			},
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err)

				untouched, err := f.w.store.Load(t.Context(), f.other.ID)
				require.NoError(t, err)
				assert.True(t, untouched.PasswordChangePending, "another user's session is never resolved")

				own, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.False(t, own.PasswordChangePending, "the resolution is saved on the gate's own successor")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &fixture{}
			f.w = newSwitchCookieWorldWith(t, tc.sessionOpts, tc.createOpts,
				func(sessions *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithPasswordChangeEndpoint("/orders", func(ex *httpsec.Exchange) error {
							return tc.change(f)(ex)
						}))}
				})

			if tc.prepare != nil {
				tc.prepare(t, f)
			} else {
				owing := *f.w.signIn
				owing.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), &owing))
			}

			out := f.w.post(t, f.w.signIn.ID, func(*httpsec.Exchange) error { return nil })

			var last *http.Cookie

			for _, line := range out.rec.Header().Values("Set-Cookie") {
				c, err := http.ParseSetCookie(line)
				require.NoError(t, err)

				if c.Name == httpsec.DefaultSessionCookieName {
					last = c
				}
			}

			require.NotNil(t, last, "the session cookie is re-set")

			tc.assert(t, f, out, last)
		})
	}
}
