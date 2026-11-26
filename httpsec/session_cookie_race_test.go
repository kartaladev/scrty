package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// raceTimeout bounds how long a barrier test waits for a party to arrive. It
// is a guard against a hang, never a delay: every barrier releases on a
// signal, and a run that reaches the bound fails.
const raceTimeout = 10 * time.Second

// postAt sends an unsafe same-origin request to path on ctx, presenting id as
// the session cookie and the sign-in's CSRF token, with handler as the
// application, and returns what the chain answered. It calls nothing that
// fails a test, so it may run on a goroutine of the test's own.
func (w *switchCookieWorld) postAt(ctx context.Context, path, id string, handler func(ex *httpsec.Exchange) error) served {
	req := sessionCookieRequest(ctx, http.MethodPost, named(id),
		map[string]string{"X-CSRF-Token": w.signIn.CSRFToken})
	req.URL.Path = path
	out := served{rec: httptest.NewRecorder()}

	run := w.chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true

		return handler(ex)
	})

	out.err = run(httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))

	return out
}

// await waits for ch, failing the test when it does not come within
// raceTimeout.
func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(raceTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// familyGone asserts nothing of w's sign-in loads any more: not the identifier
// it began with, not ids, and no live session of the user.
func familyGone(t *testing.T, w *switchCookieWorld, ids ...string) {
	t.Helper()

	for _, id := range append([]string{w.signIn.ID}, ids...) {
		_, err := w.sessions.Load(t.Context(), id)
		require.Error(t, err, "nothing of the sign-in loads")
	}

	n, err := w.sessions.CountActiveByUser(t.Context(), testUserID)
	require.NoError(t, err)
	assert.Zero(t, n, "the user holds no live session")
}

// TestSessionCookie_ConcurrentRoleSwitch pins that two requests switching the
// role of one cookie sign-in at once, both holding the same identifier, rotate
// it once: the store's conditional write decides, the winner re-sets the
// cookie to the successor carrying its role, and the loser is refused as a
// lost race with no cookie set, while the identifier it holds keeps working
// through its grace window. Both requests are released into the superseding
// write together by a barrier, so both read the session before either writes.
func TestSessionCookie_ConcurrentRoleSwitch(t *testing.T) {
	t.Parallel()

	w := newSwitchCookieWorld(t)

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})

	w.store.onSupersede = func(ctx context.Context, write func() error) error {
		arrived <- struct{}{}

		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}

		return write()
	}

	var (
		wg       sync.WaitGroup
		outs     [2]served
		switched [2]error
	)

	for i := range outs {
		wg.Go(func() {
			outs[i] = w.postAt(t.Context(), "/orders", w.signIn.ID, func(ex *httpsec.Exchange) error {
				switched[i] = w.chain.SwitchActiveRole(ex.Context(), "audit")

				return switched[i]
			})
		})
	}

	await(t, arrived, "the first switch's write")
	await(t, arrived, "the second switch's write")
	close(release)
	wg.Wait()

	winner, loser := 0, 1
	if switched[0] != nil {
		winner, loser = 1, 0
	}

	require.NoError(t, switched[winner], "one rotation wins")
	require.ErrorIs(t, switched[loser], httpsec.ErrSessionRenewalConflict, "the other lost the race")
	assert.NotErrorIs(t, switched[loser], httpsec.ErrAuthenticationRequired, "a lost race is no refusal of the sign-in")

	rotated := reSetAs(t, w.chain, outs[winner], w.signIn.ID)
	noSessionCookie(t, outs[loser])

	w.store.onSupersede = nil

	assert.Equal(t, "audit", w.activeRole(t, rotated), "the winner's successor carries the switch")

	w.clk.Advance(time.Second)
	assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID),
		"the loser's identifier works through its window, unswitched")
}

// TestSessionCookie_RotationCancelled pins that a request whose context ends
// inside the rotation of a privilege change, before the superseding write
// lands, stores nothing and sets no cookie, and the identifier it presented
// keeps working unchanged: at the role switch and at the password change.
func TestSessionCookie_RotationCancelled(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// extra are chain options needing the world's session manager.
		extra func(*session.Sessions) []httpsec.Option

		// handler is the application, which switches the role where the case
		// does.
		handler func(w *switchCookieWorld) func(ex *httpsec.Exchange) error

		assert func(t *testing.T, w *switchCookieWorld, out served, changed bool)
	}

	var changedFlag sync.Map

	cases := []testCase{
		{
			name:  "at the role switch",
			extra: func(*session.Sessions) []httpsec.Option { return nil },
			handler: func(w *switchCookieWorld) func(ex *httpsec.Exchange) error {
				return func(ex *httpsec.Exchange) error { return w.chain.SwitchActiveRole(ex.Context(), "audit") }
			},
			assert: func(t *testing.T, w *switchCookieWorld, out served, _ bool) {
				t.Helper()
				require.ErrorIs(t, out.err, context.Canceled, "the request's own end")
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "the old identifier works, unswitched")
			},
		},
		{
			name: "at the password change",
			extra: func(sessions *session.Sessions) []httpsec.Option {
				return []httpsec.Option{httpsec.EnablePasswordChangeGate(sessions,
					httpsec.WithPasswordChangeEndpoint("/orders", func(ex *httpsec.Exchange) error {
						changedFlag.Store(ex.Session.FamilyID, true)

						return nil
					}))}
			},
			handler: func(*switchCookieWorld) func(ex *httpsec.Exchange) error {
				return func(*httpsec.Exchange) error { return nil }
			},
			assert: func(t *testing.T, w *switchCookieWorld, out served, changed bool) {
				t.Helper()
				require.ErrorIs(t, out.err, context.Canceled, "the request's own end")
				assert.False(t, changed, "no password is changed")

				raw, err := w.store.Load(t.Context(), w.signIn.ID)
				require.NoError(t, err)
				assert.True(t, raw.PasswordChangePending, "the change is still owed on the old identifier")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newSwitchCookieWorldOver(t, tc.extra)

			owing := *w.signIn
			owing.PasswordChangePending = tc.name == "at the password change"
			require.NoError(t, w.sessions.Save(t.Context(), &owing))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			var wrote bool

			// The request ends while its rotation is being written: the store
			// sees its context end and refuses the write, as a real store does.
			w.store.onSupersede = func(wctx context.Context, write func() error) error {
				cancel()
				<-wctx.Done()

				if err := wctx.Err(); err != nil {
					return err
				}

				wrote = true

				return write()
			}

			out := w.postAt(ctx, "/orders", w.signIn.ID, tc.handler(w))
			w.store.onSupersede = nil

			assert.False(t, wrote, "the superseding write never ran")
			noSessionCookie(t, out)

			raw, err := w.store.Load(t.Context(), w.signIn.ID)
			require.NoError(t, err)
			assert.True(t, raw.SupersededAt.IsZero(), "nothing was rotated")

			n, err := w.sessions.CountActiveByUser(t.Context(), testUserID)
			require.NoError(t, err)
			assert.Equal(t, 1, n, "no successor was stored")

			_, changed := changedFlag.Load(w.signIn.FamilyID)
			tc.assert(t, w, out, changed)
		})
	}
}

// TestSessionCookie_LogoutRacesRoleSwitch pins a logout of a cookie sign-in
// landing while another request of the same sign-in switches its role. Landing
// before the rotation, it leaves the switch refused as a sign-in that has
// ended, with no cookie set and nothing stored. Landing after the rotation's
// write and before the role is recorded, it still ends the whole sign-in, the
// successor included: the switch is refused the same way, and whatever cookie
// it set names nothing that loads. Each interleaving is placed by a barrier
// the logout, on a goroutine of its own, is released through.
func TestSessionCookie_LogoutRacesRoleSwitch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// place arranges for logout to run, once, at the case's point in the
		// switch, and returns the handler the switching request runs.
		place func(t *testing.T, w *switchCookieWorld, logout func()) func(ex *httpsec.Exchange) error

		assert func(t *testing.T, w *switchCookieWorld, out served, switched error)
	}

	cases := []testCase{
		{
			name: "logout lands after the request resolved and before its rotation",
			place: func(_ *testing.T, w *switchCookieWorld, logout func()) func(ex *httpsec.Exchange) error {
				return func(ex *httpsec.Exchange) error {
					logout()

					return w.chain.SwitchActiveRole(ex.Context(), "audit")
				}
			},
			assert: func(t *testing.T, w *switchCookieWorld, out served, switched error) {
				t.Helper()
				require.ErrorIs(t, switched, httpsec.ErrAuthenticationRequired)
				noSessionCookie(t, out)
				familyGone(t, w)
			},
		},
		{
			name: "logout lands between the rotation's write and the role's record",
			place: func(_ *testing.T, w *switchCookieWorld, logout func()) func(ex *httpsec.Exchange) error {
				w.store.onSupersede = func(_ context.Context, write func() error) error {
					err := write()
					logout()

					return err
				}

				return func(ex *httpsec.Exchange) error { return w.chain.SwitchActiveRole(ex.Context(), "audit") }
			},
			assert: func(t *testing.T, w *switchCookieWorld, out served, switched error) {
				t.Helper()
				require.ErrorIs(t, switched, httpsec.ErrAuthenticationRequired)

				var ids []string
				for _, c := range sessionCookiesSet(t, out) {
					ids = append(ids, c.Value)
				}

				familyGone(t, w, ids...)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newSwitchCookieWorldOver(t, func(sessions *session.Sessions) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions})}
			})

			start := make(chan struct{})
			done := make(chan struct{})

			var loggedOut served

			// The logout is another request, on a goroutine of its own, run
			// when the switching request reaches the case's point and waited
			// for there.
			go func() {
				defer close(done)

				select {
				case <-start:
				case <-t.Context().Done():
					return
				}

				loggedOut = w.postAt(t.Context(), httpsec.DefaultLogoutPath, w.signIn.ID,
					func(*httpsec.Exchange) error { return errors.New("race_test: logout passed on") })
			}()

			var once sync.Once

			logout := func() {
				once.Do(func() {
					close(start)
					<-done
				})
			}

			var switched error

			handler := tc.place(t, w, logout)
			out := w.postAt(t.Context(), "/orders", w.signIn.ID, func(ex *httpsec.Exchange) error {
				switched = handler(ex)

				return switched
			})

			await(t, done, "the logout")
			w.store.onSupersede = nil

			require.NoError(t, loggedOut.err, "the logout succeeded")
			assert.False(t, loggedOut.handlerRan, "logout answered the request itself")

			tc.assert(t, w, out, switched)
		})
	}
}
