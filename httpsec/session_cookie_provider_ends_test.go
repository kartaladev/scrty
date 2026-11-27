package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// errBrowsersDown is the outage a recordingBrowsers fails an end with.
var errBrowsersDown = errors.New("provider_ends_test: the browser-session store is unreachable")

// recordingBrowsers is the provider's browser-session store, keeping the
// digest of every record put, so a test can load one back, and failing the
// end of a sign-in's records when failEnd is set.
type recordingBrowsers struct {
	*oidcprovider.MemoryBrowserSessionStore

	mu      sync.Mutex
	digests [][]byte

	failEnd atomic.Bool
}

func (b *recordingBrowsers) Put(ctx context.Context, s *oidcprovider.BrowserSession) error {
	b.mu.Lock()
	b.digests = append(b.digests, append([]byte(nil), s.Digest...))
	b.mu.Unlock()

	return b.MemoryBrowserSessionStore.Put(ctx, s)
}

func (b *recordingBrowsers) DeleteBySignIn(ctx context.Context, sel oidcprovider.SignInSelector) (int, error) {
	if b.failEnd.Load() {
		return 0, errBrowsersDown
	}

	return b.MemoryBrowserSessionStore.DeleteBySignIn(ctx, sel)
}

// last is the digest of the record put last.
func (b *recordingBrowsers) last(t *testing.T) []byte {
	t.Helper()

	b.mu.Lock()
	defer b.mu.Unlock()

	require.NotEmpty(t, b.digests, "a browser session was put")

	return b.digests[len(b.digests)-1]
}

// cookieProviderWorld is a cookie chain running the provider and logout, its
// provider's browser sessions recorded, with a sign-in of u-1 that carries a
// CSRF token and a provider browser session of that sign-in.
type cookieProviderWorld struct {
	*opFlow

	browsers *recordingBrowsers
	signIn   *session.Session

	// digest is the provider browser session of signIn.
	digest []byte
}

func newCookieProviderWorld(t *testing.T) *cookieProviderWorld {
	t.Helper()

	browsers := &recordingBrowsers{MemoryBrowserSessionStore: must.Must(oidcprovider.NewMemoryBrowserSessionStore())}

	w, _, err := newCookieOP(t, func(setup *flowSetup) {
		setup.provider = append(setup.provider, oidcprovider.WithBrowserSessionStore(browsers))
		setup.chain = func(_ *testing.T, w *opFlow) []httpsec.Option {
			return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: w.sessions})}
		}
	})
	require.NoError(t, err)

	pw := &cookieProviderWorld{opFlow: w, browsers: browsers, signIn: w.session(t, session.WithCSRFToken())}

	w.browserSession(t, pw.signIn)
	pw.digest = browsers.last(t)

	return pw
}

// browserSessionLoads reports whether the provider still holds the sign-in's
// browser session, failing the test on any answer but the record or
// oidcprovider.ErrNotFound.
func (w *cookieProviderWorld) browserSessionLoads(t *testing.T) bool {
	t.Helper()

	_, err := w.browsers.Load(t.Context(), w.digest, w.clk.Now())
	if errors.Is(err, oidcprovider.ErrNotFound) {
		return false
	}

	require.NoError(t, err)

	return true
}

// logout posts a same-origin logout presenting id as the session cookie, with
// the sign-in's CSRF token.
func (w *cookieProviderWorld) logout(t *testing.T, id string) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+httpsec.DefaultLogoutPath, nil)

	return w.serve(t, r, []flowChange{withSessionCookie(id), func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("X-CSRF-Token", w.signIn.CSRFToken)
	}})
}

// TestSessionCookie_EndsProviderBrowserSessions pins that on a chain running
// the OpenID Provider with the cookie session, every explicit end of a cookie
// sign-in ends the provider's browser sessions of that sign-in: a logout,
// reuse detected when a superseded identifier is presented in the cookie after
// its window, and a revocation of the sign-in's family.
func TestSessionCookie_EndsProviderBrowserSessions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// end ends w's sign-in the case's way.
		end func(t *testing.T, w *cookieProviderWorld)
	}

	cases := []testCase{
		{
			name: "logout",
			end: func(t *testing.T, w *cookieProviderWorld) {
				t.Helper()

				a := w.logout(t, w.signIn.ID)
				require.NoError(t, a.err)
				require.Equal(t, http.StatusOK, a.status, a.body)
			},
		},
		{
			name: "reuse detected through the cookie",
			end: func(t *testing.T, w *cookieProviderWorld) {
				t.Helper()

				const grace = 30 * time.Second

				_, _, err := w.sessions.RotateWithGrace(t.Context(), w.signIn, grace)
				require.NoError(t, err)

				w.clk.Advance(grace + time.Second)

				a := w.at(t, http.MethodGet, "/orders", withSessionCookie(w.signIn.ID))
				require.ErrorIs(t, a.err, session.ErrReused, "the superseded identifier after its window is reuse")
			},
		},
		{
			name: "revocation",
			end: func(t *testing.T, w *cookieProviderWorld) {
				t.Helper()

				n, err := w.sessions.RevokeFamily(t.Context(), w.signIn.FamilyID)
				require.NoError(t, err)
				require.Positive(t, n, "the sign-in's family was revoked")
			},
		},
	}

	// starts are the ways the provider's browser session of the sign-in came
	// to be: written by the provider directly, and by the resume endpoint
	// reading the cookie sign-in.
	starts := []struct {
		name  string
		start func(w *cookieProviderWorld, t *testing.T)
	}{
		{name: "provider", start: func(*cookieProviderWorld, *testing.T) {}},
		{name: "cookie resume", start: (*cookieProviderWorld).resumeByCookie},
	}

	for _, tc := range cases {
		for _, st := range starts {
			t.Run(tc.name+"/"+st.name, func(t *testing.T) {
				t.Parallel()

				w := newCookieProviderWorld(t)
				st.start(w, t)
				require.True(t, w.browserSessionLoads(t), "the provider holds a browser session of the sign-in")

				tc.end(t, w)

				assert.False(t, w.browserSessionLoads(t), "no provider browser session of the sign-in loads afterwards")
			})
		}
	}
}

// resumeByCookie resumes a new authorization through the resume endpoint with
// the sign-in's cookie and CSRF token, and makes the browser session it wrote
// the one the world watches.
func (w *cookieProviderWorld) resumeByCookie(t *testing.T) {
	t.Helper()

	before := w.digest
	handle, flow := w.park(t, flowFirstParty)

	a := w.cookieResume(t, handle, flow, w.signIn.ID, w.signIn.CSRFToken)
	require.NoError(t, a.err)
	require.Equal(t, http.StatusOK, a.status, a.body)
	require.NotNil(t, a.cookie(flowSession), "the resume wrote a browser session")

	w.digest = w.browsers.last(t)
	require.NotEqual(t, before, w.digest, "the watched browser session is the one the resume wrote")
}
