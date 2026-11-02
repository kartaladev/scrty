package httpsec_test

// The session management tests run on a real session manager over the memory
// store and a fake clock, because what they pin is which families the store
// still holds after a request and how long ago the caller authenticated.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// managementFixture is a chain with the session bearer and the session
// management endpoints over one session manager on a fake clock.
type managementFixture struct {
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	chain    *httpsec.Chain
}

// failingListStore is a memory store whose listing fails with what fail
// returns.
type failingListStore struct {
	session.Store

	fail func() error
}

func (s *failingListStore) ListByUser(context.Context, identity.UserID, time.Time) ([]*session.Session, error) {
	return nil, s.fail()
}

func newManagementFixture(
	t *testing.T, wrap func(session.Store) session.Store, opts ...httpsec.SessionManagementOption,
) *managementFixture {
	t.Helper()

	f := &managementFixture{clk: clockwork.NewFakeClockAt(time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC))}

	var store session.Store = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk)))
	if wrap != nil {
		store = wrap(store)
	}

	var err error

	f.sessions, err = session.New(
		session.WithClock(f.clk),
		session.WithStore(store),
		session.WithIdleTimeout(7*24*time.Hour),
		session.WithAbsoluteTimeout(30*24*time.Hour),
	)
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	f.chain, err = httpsec.New(
		httpsec.WithClock(f.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
		httpsec.EnableSessionManagement(opts...),
	)
	require.NoError(t, err)

	return f
}

// signIn stores a new sign-in of user.
func (f *managementFixture) signIn(t *testing.T, user identity.UserID) *session.Session {
	t.Helper()

	s, err := f.sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s
}

// request runs method on path with credential as the session reference.
func (f *managementFixture) request(t *testing.T, method, path, credential string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, f.chain, req)
}

// loads reports whether the session s still loads.
func (f *managementFixture) loads(t *testing.T, s *session.Session) bool {
	t.Helper()

	_, err := f.sessions.Load(t.Context(), s.ID)

	return err == nil
}

// listedSignIn is one sign-in of the default listing, read back as a client
// would.
type listedSignIn struct {
	Handle      string  `json:"handle"`
	FirstFactor string  `json:"first_factor"`
	Pending     *string `json:"pending"`
	Current     bool    `json:"current"`
}

func listedSignIns(t *testing.T, out served) []listedSignIn {
	t.Helper()

	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	var doc struct {
		Sessions []listedSignIn `json:"sessions"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

	return doc.Sessions
}

func noStore(t *testing.T, out served) {
	t.Helper()

	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
	assert.False(t, out.handlerRan, "the endpoint answers itself")
}

// TestSessionManagement pins the endpoints' behaviour: what the listing
// shows, which families an end revokes, the recency an end needs, and the
// refusals.
func TestSessionManagement(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.SessionManagementOption
		assert func(t *testing.T, f *managementFixture)
	}

	cases := []testCase{
		{
			name: "the listing marks the current sign-in and carries no session identifier",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")
				foreign := f.signIn(t, "u-2")

				out := f.request(t, http.MethodGet, "/sessions", current.ID)
				noStore(t, out)

				list := listedSignIns(t, out)
				require.Len(t, list, 2)

				byHandle := map[string]listedSignIn{}
				for _, si := range list {
					byHandle[si.Handle] = si
				}
				assert.True(t, byHandle[current.FamilyID.String()].Current)
				assert.False(t, byHandle[other.FamilyID.String()].Current)
				assert.Equal(t, "password", byHandle[other.FamilyID.String()].FirstFactor)
				assert.Nil(t, byHandle[other.FamilyID.String()].Pending)

				body := out.rec.Body.String()
				for _, s := range []*session.Session{current, other, foreign} {
					assert.NotContains(t, body, s.ID, "no session identifier is listed")
				}
				assert.NotContains(t, body, foreign.FamilyID.String(), "another user's sign-in is not listed")
			},
		},
		{
			name: "Listing needs no recent authentication",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				f.clk.Advance(2 * time.Hour)

				out := f.request(t, http.MethodGet, "/sessions", current.ID)
				noStore(t, out)
				assert.Len(t, listedSignIns(t, out), 1)
			},
		},
		{
			name: "Sign out other devices",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				laptop := f.signIn(t, "u-1")
				phone := f.signIn(t, "u-1")
				foreign := f.signIn(t, "u-2")
				f.clk.Advance(2 * time.Minute)

				out := f.request(t, http.MethodDelete, "/sessions", current.ID)
				noStore(t, out)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)

				assert.True(t, f.loads(t, current))
				assert.False(t, f.loads(t, laptop))
				assert.False(t, f.loads(t, phone))
				assert.True(t, f.loads(t, foreign), "another user's sign-in is untouched")
			},
		},
		{
			name: "Only the current sign-in",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")

				out := f.request(t, http.MethodDelete, "/sessions", current.ID)
				noStore(t, out)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.True(t, f.loads(t, current))
			},
		},
		{
			name: "Stale session: ending one sign-in is refused and nothing is revoked",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")
				f.clk.Advance(2 * time.Hour)

				out := f.request(t, http.MethodDelete, "/sessions/"+other.FamilyID.String(), current.ID)
				noStore(t, out)
				require.ErrorIs(t, out.err, httpsec.ErrReauthenticationRequired)

				var reauth *httpsec.ReauthenticationRequiredError
				require.ErrorAs(t, out.err, &reauth)
				assert.Equal(t, httpsec.DefaultRecentAuthenticationWindow, reauth.Window)
				assert.True(t, f.loads(t, other))
			},
		},
		{
			name: "Stale session: ending the other sign-ins is refused and nothing is revoked",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")
				f.clk.Advance(2 * time.Hour)

				out := f.request(t, http.MethodDelete, "/sessions", current.ID)
				noStore(t, out)
				require.ErrorIs(t, out.err, httpsec.ErrReauthenticationRequired)
				assert.True(t, f.loads(t, other))
			},
		},
		{
			name: "the consumer's recency window replaces the default",
			opts: []httpsec.SessionManagementOption{httpsec.WithSessionManagementRecency(3 * time.Hour)},
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")
				f.clk.Advance(2 * time.Hour)

				out := f.request(t, http.MethodDelete, "/sessions/"+other.FamilyID.String(), current.ID)
				require.NoError(t, out.err)
				assert.False(t, f.loads(t, other))

				f.clk.Advance(2 * time.Hour)
				out = f.request(t, http.MethodDelete, "/sessions", current.ID)
				var reauth *httpsec.ReauthenticationRequiredError
				require.ErrorAs(t, out.err, &reauth)
				assert.Equal(t, 3*time.Hour, reauth.Window)
			},
		},
		{
			name: "ending one sign-in revokes its family and nothing else",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				laptop := f.signIn(t, "u-1")
				phone := f.signIn(t, "u-1")

				out := f.request(t, http.MethodDelete, "/sessions/"+laptop.FamilyID.String(), current.ID)
				noStore(t, out)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.False(t, f.loads(t, laptop))
				assert.True(t, f.loads(t, phone))
				assert.True(t, f.loads(t, current))
			},
		},
		{
			name: "Another user's handle is not found and nothing is revoked",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				foreign := f.signIn(t, "u-2")

				out := f.request(t, http.MethodDelete, "/sessions/"+foreign.FamilyID.String(), current.ID)
				noStore(t, out)
				require.ErrorIs(t, out.err, httpsec.ErrSessionHandleNotFound)
				assert.True(t, f.loads(t, foreign))
				assert.NotContains(t, out.err.Error(), foreign.FamilyID.String())
			},
		},
		{
			name: "a malformed handle, an unknown one and an extra segment are not found",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")

				for _, handle := range []string{"not-a-handle", id.Nil.String(), must.Must(id.NewV7Generator().NewID()).String(),
					other.FamilyID.String() + "/x"} {
					out := f.request(t, http.MethodDelete, "/sessions/"+handle, current.ID)
					noStore(t, out)
					require.ErrorIs(t, out.err, httpsec.ErrSessionHandleNotFound, handle)
				}
				assert.True(t, f.loads(t, other))
			},
		},
		{
			name: "Ending the current sign-in acts as a logout",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")

				out := f.request(t, http.MethodDelete, "/sessions/"+current.FamilyID.String(), current.ID)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)

				again := f.request(t, http.MethodGet, "/sessions", current.ID)
				require.ErrorIs(t, again.err, httpsec.ErrAuthenticationRequired,
					"the request's own session no longer authenticates")
			},
		},
		{
			name: "Current during the grace window",
			assert: func(t *testing.T, f *managementFixture) {
				previous := f.signIn(t, "u-1")
				_, _, err := f.sessions.RotateWithGrace(t.Context(), previous, time.Minute)
				require.NoError(t, err)

				list := listedSignIns(t, f.request(t, http.MethodGet, "/sessions", previous.ID))
				require.Len(t, list, 1)
				assert.True(t, list[0].Current)
			},
		},
		{
			name: "a pending sign-in is listed and marked",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				pending := f.signIn(t, "u-1")
				pending.MFA = session.MFAPending
				require.NoError(t, f.sessions.Save(t.Context(), pending))

				for _, si := range listedSignIns(t, f.request(t, http.MethodGet, "/sessions", current.ID)) {
					if si.Handle == pending.FamilyID.String() {
						require.NotNil(t, si.Pending)
						assert.Equal(t, "pending", *si.Pending)
					}
				}
			},
		},
		{
			name: "a second-factor-pending session is refused with the challenge it owes",
			assert: func(t *testing.T, f *managementFixture) {
				pending := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")
				pending.MFA = session.MFAPending
				require.NoError(t, f.sessions.Save(t.Context(), pending))

				for _, method := range []string{http.MethodGet, http.MethodDelete} {
					out := f.request(t, method, "/sessions", pending.ID)
					noStore(t, out)

					var ch *httpsec.ChallengeError
					require.ErrorAs(t, out.err, &ch, method)
					assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				}
				assert.True(t, f.loads(t, other))
			},
		},
		{
			name: "a recovery-pending session is refused with the challenge it owes",
			assert: func(t *testing.T, f *managementFixture) {
				pending := f.signIn(t, "u-1")
				f.sessions.MarkRecoveryPending(pending, 10*time.Minute, f.clk.Now())
				require.NoError(t, f.sessions.Save(t.Context(), pending))

				out := f.request(t, http.MethodGet, "/sessions", pending.ID)
				noStore(t, out)

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind)
			},
		},
		{
			name: "a request with no session is refused as unauthenticated",
			assert: func(t *testing.T, f *managementFixture) {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/sessions", nil)
				out := serve(t, f.chain, req)
				noStore(t, out)
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
			},
		},
		{
			name: "other paths and methods pass through",
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")

				for _, r := range [][2]string{
					{http.MethodGet, "/orders"}, {http.MethodPost, "/sessions"}, {http.MethodGet, "/sessionsx"},
				} {
					out := f.request(t, r[0], r[1], current.ID)
					require.NoError(t, out.err)
					assert.True(t, out.handlerRan, r)
				}
			},
		},
		{
			name: "a replaced prefix moves every endpoint",
			opts: []httpsec.SessionManagementOption{httpsec.WithSessionManagementPrefix("/account/sign-ins")},
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				other := f.signIn(t, "u-1")

				assert.Len(t, listedSignIns(t, f.request(t, http.MethodGet, "/account/sign-ins", current.ID)), 2)

				out := f.request(t, http.MethodDelete, "/account/sign-ins/"+other.FamilyID.String(), current.ID)
				require.NoError(t, out.err)
				assert.False(t, f.loads(t, other))

				out = f.request(t, http.MethodGet, "/sessions", current.ID)
				assert.True(t, out.handlerRan, "the default prefix is free")
			},
		},
		{
			name: "a refusal before the endpoints, for a deleted session reference, is not cached either",
			assert: func(t *testing.T, f *managementFixture) {
				gone := f.signIn(t, "u-1")
				require.NoError(t, f.sessions.Delete(t.Context(), gone.ID))

				for _, req := range []struct{ method, path string }{
					{http.MethodGet, "/sessions"},
					{http.MethodDelete, "/sessions"},
					{http.MethodDelete, "/sessions/anything"},
					{http.MethodPost, "/sessions/anything/else"},
				} {
					out := f.request(t, req.method, req.path, gone.ID)
					require.Error(t, out.err, "%s %s", req.method, req.path)
					assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"), "%s %s", req.method, req.path)
				}
			},
		},
		{
			name: "a request outside the prefix is left to its own caching",
			assert: func(t *testing.T, f *managementFixture) {
				gone := f.signIn(t, "u-1")
				require.NoError(t, f.sessions.Delete(t.Context(), gone.ID))

				for _, path := range []string{"/", "/sessionsx", "/account/sessions"} {
					out := f.request(t, http.MethodGet, path, gone.ID)
					assert.Empty(t, out.rec.Header().Get("Cache-Control"), path)
				}
			},
		},
		{
			name: "a moved prefix moves where every response is not cached",
			opts: []httpsec.SessionManagementOption{httpsec.WithSessionManagementPrefix("/account/devices")},
			assert: func(t *testing.T, f *managementFixture) {
				gone := f.signIn(t, "u-1")
				require.NoError(t, f.sessions.Delete(t.Context(), gone.ID))

				out := f.request(t, http.MethodGet, "/account/devices", gone.ID)
				require.Error(t, out.err)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				out = f.request(t, http.MethodGet, "/sessions", gone.ID)
				assert.Empty(t, out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "the consumer's responders replace the defaults",
			opts: []httpsec.SessionManagementOption{
				httpsec.WithSignInListResponder(func(ex *httpsec.Exchange, list []session.SignIn) error {
					ex.Writer.WriteHeader(http.StatusAccepted)
					_, err := ex.Writer.Write([]byte(strings.Repeat("x", len(list))))

					return err
				}),
				httpsec.WithSignInEndResponder(func(ex *httpsec.Exchange) error {
					ex.Writer.WriteHeader(http.StatusResetContent)

					return nil
				}),
			},
			assert: func(t *testing.T, f *managementFixture) {
				current := f.signIn(t, "u-1")
				f.signIn(t, "u-1")

				out := f.request(t, http.MethodGet, "/sessions", current.ID)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusAccepted, out.rec.Code)
				assert.Equal(t, "xx", out.rec.Body.String())
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				out = f.request(t, http.MethodDelete, "/sessions", current.ID)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusResetContent, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newManagementFixture(t, nil, tc.opts...))
		})
	}
}

// TestSessionManagement_HostRefusal pins that a client-resolution refusal,
// written before any interceptor runs, still carries no-store under the
// prefix, and only there.
func TestSessionManagement_HostRefusal(t *testing.T) {
	t.Parallel()

	proxy := httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
	}

	type testCase struct {
		name   string
		opts   []httpsec.SessionManagementOption
		path   string
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "a refused host under the prefix is not cached",
			path: "/sessions",
			assert: func(t *testing.T, out served) {
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a refused host below the prefix is not cached",
			path: "/sessions/anything",
			assert: func(t *testing.T, out served) {
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a refused host outside the prefix is left to its own caching",
			path: "/page",
			assert: func(t *testing.T, out served) {
				assert.Empty(t, out.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a moved prefix moves the refusal's no-store",
			opts: []httpsec.SessionManagementOption{httpsec.WithSessionManagementPrefix("/account/devices")},
			path: "/account/devices",
			assert: func(t *testing.T, out served) {
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions := must.Must(session.New())
			users := NewMockUserLoader(gomock.NewController(t))

			chain, err := httpsec.New(
				httpsec.EnableTrustedProxies(proxy),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
				httpsec.EnableSessionManagement(tc.opts...),
			)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil)
			req.RemoteAddr = "10.20.0.2:41000"
			req.Header.Set("X-Forwarded-For", "203.0.113.7")
			req.Header.Set("X-Forwarded-Host", "evil.example")

			out := serve(t, chain, req)
			require.False(t, out.handlerRan)
			require.ErrorIs(t, out.err, httpsec.ErrHostNotAllowed)

			tc.assert(t, out)
		})
	}
}

// TestSessionManagement_Outage pins that a store failure while listing or
// ending is a dependency failure with fixed text, and that a caller who hung
// up gets its context's error.
func TestSessionManagement_Outage(t *testing.T) {
	t.Parallel()

	const secret = "pq: connection to 10.0.0.7 refused"

	type testCase struct {
		name   string
		method string
		path   func(other *session.Session) string
		hangUp bool // the caller hangs up while the store lists
		assert func(t *testing.T, out served)
	}

	hungUp := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, context.Canceled)
		assert.NotErrorIs(t, out.err, session.ErrListUnavailable)
	}

	outage := func(t *testing.T, out served) {
		t.Helper()

		require.Error(t, out.err)
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
		assert.NotContains(t, out.err.Error(), secret, "the text is fixed library text")
		assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
	}

	cases := []testCase{
		{
			name:   "a listing outage is 500 with fixed text",
			method: http.MethodGet,
			path:   func(*session.Session) string { return "/sessions" },
			assert: func(t *testing.T, out served) {
				outage(t, out)
				require.ErrorIs(t, out.err, session.ErrListUnavailable)
				assert.Equal(t, "session: the user's sign-ins could not be listed", out.err.Error())
			},
		},
		{
			name:   "an outage while ending one sign-in is 500 with fixed text",
			method: http.MethodDelete,
			path:   func(other *session.Session) string { return "/sessions/" + other.FamilyID.String() },
			assert: outage,
		},
		{
			name:   "a hang-up while listing fails with the context's error",
			method: http.MethodGet,
			path:   func(*session.Session) string { return "/sessions" },
			hangUp: true,
			assert: hungUp,
		},
		{
			name:   "a hang-up while ending one sign-in fails with the context's error",
			method: http.MethodDelete,
			path:   func(other *session.Session) string { return "/sessions/" + other.FamilyID.String() },
			hangUp: true,
			assert: hungUp,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			failing := &failingListStore{fail: func() error { return errors.New(secret) }}

			f := newManagementFixture(t, func(s session.Store) session.Store {
				failing.Store = s

				return failing
			})
			current := f.signIn(t, "u-1")
			other := f.signIn(t, "u-1")

			ctx := t.Context()
			if tc.hangUp {
				var cancel context.CancelFunc

				ctx, cancel = context.WithCancel(ctx)
				failing.fail = func() error {
					cancel()

					return context.Canceled
				}
			}

			req := httptest.NewRequestWithContext(ctx, tc.method, tc.path(other), nil)
			req.Header.Set("Authorization", "Bearer "+current.ID)

			tc.assert(t, serveCtx(t, f.chain, ctx, req))
		})
	}
}

// serveCtx is serve with the exchange seeded from ctx.
func serveCtx(t *testing.T, chain *httpsec.Chain, ctx context.Context, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

// TestEnableSessionManagement_Construction pins the wiring the chain refuses.
func TestEnableSessionManagement_Construction(t *testing.T) {
	t.Parallel()

	sessions := must.Must(session.New())

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(want string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), want)
		}
	}

	cases := []testCase{
		{
			name:   "without a session manager",
			opts:   []httpsec.Option{httpsec.EnableSessionManagement()},
			assert: refused("EnableSessionManagement"),
		},
		{
			name:   "with the chain's session manager",
			opts:   []httpsec.Option{httpsec.WithSessions(sessions), httpsec.EnableSessionManagement()},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "given twice",
			opts: []httpsec.Option{
				httpsec.WithSessions(sessions), httpsec.EnableSessionManagement(), httpsec.EnableSessionManagement(),
			},
			assert: refused("EnableSessionManagement"),
		},
		{
			name: "a prefix ending in a slash",
			opts: []httpsec.Option{httpsec.WithSessions(sessions),
				httpsec.EnableSessionManagement(httpsec.WithSessionManagementPrefix("/sessions/"))},
			assert: refused("WithSessionManagementPrefix"),
		},
		{
			name: "a relative prefix",
			opts: []httpsec.Option{httpsec.WithSessions(sessions),
				httpsec.EnableSessionManagement(httpsec.WithSessionManagementPrefix("sessions"))},
			assert: refused("WithSessionManagementPrefix"),
		},
		{
			name: "a recency window of zero",
			opts: []httpsec.Option{httpsec.WithSessions(sessions),
				httpsec.EnableSessionManagement(httpsec.WithSessionManagementRecency(0))},
			assert: refused("WithSessionManagementRecency"),
		},
		{
			name: "a nil list responder",
			opts: []httpsec.Option{httpsec.WithSessions(sessions),
				httpsec.EnableSessionManagement(httpsec.WithSignInListResponder(nil))},
			assert: refused("WithSignInListResponder"),
		},
		{
			name: "a nil end responder",
			opts: []httpsec.Option{httpsec.WithSessions(sessions),
				httpsec.EnableSessionManagement(httpsec.WithSignInEndResponder(nil))},
			assert: refused("WithSignInEndResponder"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.opts...)
			tc.assert(t, err)
		})
	}
}
