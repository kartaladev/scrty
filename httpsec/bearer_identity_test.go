package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// bearerMode is which of the two bearer modes a chain authenticates with.
type bearerMode int

const (
	// signedBearer is EnableBearerToken: a signed token whose subject is the
	// username, reloaded by username.
	signedBearer bearerMode = iota

	// referenceBearer is EnableSessionBearer: the session's own identifier,
	// whose user is reloaded by the reference the session records.
	referenceBearer
)

func (m bearerMode) String() string {
	if m == signedBearer {
		return "signed bearer"
	}

	return "session reference"
}

// switchableUser is the user record a user loader answers with, which a case
// changes between requests to disable, re-enable or replace the user.
type switchableUser struct {
	current atomic.Pointer[identity.Details]
}

// set makes d what the loader answers with from now on.
func (u *switchableUser) set(d *identity.Details) { u.current.Store(d) }

// loader is a user loader answering every lookup, by username or by user
// reference, with a copy of the record u currently holds, or with neither a
// user nor an error once u was set to nil.
func (u *switchableUser) loader(t *testing.T) *MockUserLoader {
	t.Helper()

	answer := func() (*identity.Details, error) {
		current := u.current.Load()
		if current == nil {
			return nil, nil //nolint:nilnil // a loader that finds no user and reports no error is the case under test
		}

		d := *current

		return &d, nil
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return answer() })
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return answer() })

	return users
}

// userActive is storedUser, u-1, active or disabled.
func userActive(active bool) *identity.Details {
	d := storedUser()
	d.Active = active

	return d
}

// otherUser is an active u-2 under u-1's username: the username reassigned.
func otherUser() *identity.Details {
	d := storedUser()
	d.ID = "u-2"

	return d
}

// ownUserFixture is a chain in one bearer mode over a memory-store manager,
// with one live session of u-1's in it and a user loader whose answer a case
// switches.
type ownUserFixture struct {
	sessions *session.Sessions
	chain    *httpsec.Chain
	user     *switchableUser

	// sid is the live session's identifier.
	sid string
}

// newOwnUserFixture builds the fixture in mode, with the further chain options
// extra returns for the fixture's manager, when extra is not nil.
func newOwnUserFixture(
	t *testing.T,
	mode bearerMode,
	extra func(sessions *session.Sessions) []httpsec.Option,
) *ownUserFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC))

	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	f := &ownUserFixture{sessions: sessions, user: &switchableUser{}, sid: s.ID}
	f.user.set(userActive(true))
	users := f.user.loader(t)

	var auth httpsec.Option

	switch mode {
	case signedBearer:
		// Every token verifies as testSubject's, on the fixture's session.
		verifier := NewMockVerifier(gomock.NewController(t))
		verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
			Return(token.NewClaims(testSubject, s.ID), nil)

		auth = httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: users})
	case referenceBearer:
		auth = httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users})
	}

	opts := []httpsec.Option{httpsec.WithClock(clk), auth}
	if extra != nil {
		opts = append(opts, extra(sessions)...)
	}

	f.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	return f
}

// request runs method path through the chain bearing the session's
// credential: its identifier in the reference mode, and a token the verifier
// maps to it in the signed mode.
func (f *ownUserFixture) request(t *testing.T, method, path string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.Header.Set("Authorization", "Bearer "+f.sid)

	return serve(t, f.chain, req)
}

// get is an ordinary request on an application route.
func (f *ownUserFixture) get(t *testing.T) served {
	t.Helper()

	return f.request(t, http.MethodGet, "/orders")
}

// stillStored asserts the fixture's session was not revoked.
func (f *ownUserFixture) stillStored(t *testing.T) {
	t.Helper()

	stored, err := f.sessions.Load(t.Context(), f.sid)
	require.NoError(t, err, "the refused session is still stored")
	assert.Equal(t, identity.UserID("u-1"), stored.UserID)
}

// authenticatedAsOwner asserts out reached the handler as u-1.
func authenticatedAsOwner(t *testing.T, out served) {
	t.Helper()

	require.NoError(t, out.err)
	require.True(t, out.handlerRan)

	auth, ok := authenticate.AuthenticationFromContext(out.handled.Context())
	require.True(t, ok)
	assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)
}

// refusedBeforeHandler asserts out was refused as unauthenticated and the
// handler never ran, naming who it ran as, and why that is wrong, if it did.
func refusedBeforeHandler(t *testing.T, out served, why string) {
	t.Helper()

	if out.handlerRan {
		ran := "nobody"
		if auth, ok := authenticate.AuthenticationFromContext(out.handled.Context()); ok {
			ran = string(auth.Principal.ID)
		}

		t.Fatalf("handler ran as principal %q: %s", ran, why)
	}

	require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
}

// TestBearer_AuthenticatesOnlyOwnActiveUser pins that a resolved session
// authenticates only the user it records, and only while that user is
// active, in both bearer modes: a reassigned username, a loader answering
// with someone else, and a disabled user are refused, and the refusal revokes
// nothing, so a re-enabled user's session authenticates again.
func TestBearer_AuthenticatesOnlyOwnActiveUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   bearerMode
		extra  func(sessions *session.Sessions) []httpsec.Option
		assert func(t *testing.T, f *ownUserFixture)
	}

	var cases []testCase

	for _, mode := range []bearerMode{signedBearer, referenceBearer} {
		cases = append(cases,
			testCase{
				name: "own, active user authenticates",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					authenticatedAsOwner(t, f.get(t))
				},
			},
			testCase{
				// In the signed mode this is the username reassigned to u-2
				// after u-1's token was issued; in the reference mode, a loader
				// answering for the wrong user.
				name: "the reloaded user is another user: refused, and the handler does not run",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(otherUser())

					refusedBeforeHandler(t, f.get(t), "on u-1's session")
					f.stillStored(t)
				},
			},
			testCase{
				name: "disabled user is refused",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(userActive(false))

					refusedBeforeHandler(t, f.get(t), "a disabled user")
				},
			},
			testCase{
				name: "a loader answering with no user and no error is refused",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(nil)

					refusedBeforeHandler(t, f.get(t), "a loader that found no user")
				},
			},
			testCase{
				name: "re-enabled user authenticates again",
				mode: mode,
				assert: func(t *testing.T, f *ownUserFixture) {
					authenticatedAsOwner(t, f.get(t))

					f.user.set(userActive(false))
					refusedBeforeHandler(t, f.get(t), "a disabled user")
					f.stillStored(t)

					f.user.set(userActive(true))
					authenticatedAsOwner(t, f.get(t))
				},
			},
			testCase{
				name: "disabled user's logout is refused and revokes nothing",
				mode: mode,
				extra: func(sessions *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions})}
				},
				assert: func(t *testing.T, f *ownUserFixture) {
					f.user.set(userActive(false))

					out := f.request(t, http.MethodPost, httpsec.DefaultLogoutPath)
					require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
					assert.False(t, out.handlerRan)
					f.stillStored(t)
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.mode.String()+": "+tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newOwnUserFixture(t, tc.mode, tc.extra))
		})
	}
}
