package oidcprovider_test

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// The provider is what T8's ports are given: each declares this one method, with the cause as a
// string, as none of them imports this package.
var _ interface {
	RevokeUserGrants(ctx context.Context, user identity.UserID, cause string) error
} = (*oidcprovider.Provider)(nil)

// The provider is what a session manager reports its ends to.
var _ session.EndObserver = (*oidcprovider.Provider)(nil)

// hookedBrowsers is a real browser-session store that fails its deletions at a row's request, and
// remembers what they selected.
type hookedBrowsers struct {
	oidcprovider.BrowserSessionStore

	fail atomic.Bool
	// sawDelete is told the context of each deletion, and is set before the request starts.
	sawDelete func(context.Context)

	mu        sync.Mutex
	selectors []oidcprovider.SignInSelector
}

// DeleteBySignIn implements oidcprovider.BrowserSessionStore.
func (h *hookedBrowsers) DeleteBySignIn(ctx context.Context, sel oidcprovider.SignInSelector) (int, error) {
	h.mu.Lock()
	h.selectors = append(h.selectors, sel)
	h.mu.Unlock()
	if h.sawDelete != nil {
		h.sawDelete(ctx)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if h.fail.Load() {
		return 0, errOutage
	}

	return h.BrowserSessionStore.DeleteBySignIn(ctx, sel)
}

func (h *hookedBrowsers) seen() []oidcprovider.SignInSelector {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]oidcprovider.SignInSelector(nil), h.selectors...)
}

// endFixture is a refresh fixture that also watches browser sessions, and what leaves for delivery.
type endFixture struct {
	*refreshFixture

	browsers *hookedBrowsers

	// box is what a row's arrange hands to its assert.
	box struct {
		first, second   *refreshScene
		signIns         []oidcprovider.SignIn
		online, offline issuedCode
		digest          []byte
		sel             oidcprovider.SignInSelector
		budgeted        bool
	}

	mu      sync.Mutex
	notices [][]oidcprovider.ClientToNotify
}

func newEndFixture(t *testing.T, opts ...oidcprovider.Option) *endFixture {
	t.Helper()

	memory, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	e := &endFixture{browsers: &hookedBrowsers{BrowserSessionStore: memory}}
	e.refreshFixture = newRefreshFixture(t, append([]oidcprovider.Option{
		oidcprovider.WithBrowserSessionStore(e.browsers),
		oidcprovider.WithLogoutNoticesForTest(func(_ context.Context, clients []oidcprovider.ClientToNotify) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.notices = append(e.notices, clients)
		}),
	}, opts...)...)

	return e
}

// queued is what left for delivery, one list per end.
func (e *endFixture) queued() [][]oidcprovider.ClientToNotify {
	e.mu.Lock()
	defer e.mu.Unlock()

	return append([][]oidcprovider.ClientToNotify(nil), e.notices...)
}

// signInOf is a sign-in of user through the upstream session named.
func (e *endFixture) signInOf(user identity.UserID, upstream, upstreamSession string) oidcprovider.SignIn {
	s := testSignIn(e.parkFixture, user)
	s.ExternalIssuer, s.ExternalSessionID = upstream, upstreamSession

	return s
}

// grantFrom is a grant of a client that may refresh, from signIn, for scopes.
func (e *endFixture) grantFrom(t *testing.T, signIn oidcprovider.SignIn, clientID, redirectURI string, scopes ...string) *refreshScene {
	t.Helper()

	c := issueCodeFor(t, e.parkFixture, clientID, func(v url.Values) {
		asClient(v, clientID, redirectURI)
		v.Set("scope", strings.Join(scopes, " "))
	}, signIn, scopes...)
	again := func(raw string) oidcprovider.TokenRequest { return refreshRequest(clientID, raw, nil) }

	return sceneOf(t, e.refreshFixture, c, confidentialExchange(clientID, redirectURI, c, nil), again)
}

// online is a billing-web grant holding no offline_access.
func (e *endFixture) online(t *testing.T, signIn oidcprovider.SignIn) *refreshScene {
	t.Helper()

	return e.grantFrom(t, signIn, "billing-web", authzRedirect, "openid", "profile")
}

// offline is a billing-web grant holding offline_access.
func (e *endFixture) offline(t *testing.T, signIn oidcprovider.SignIn) *refreshScene {
	t.Helper()

	return e.grantFrom(t, signIn, "billing-web", authzRedirect, "openid", "offline_access")
}

// browserOf puts a browser session for signIn, and returns its digest.
func (e *endFixture) browserOf(t *testing.T, signIn oidcprovider.SignIn) []byte {
	t.Helper()

	digest := []byte(signIn.Family.String())
	require.NoError(t, e.browsers.Put(t.Context(), &oidcprovider.BrowserSession{
		Digest: digest, SignIn: signIn,
		IdleExpiresAt: e.clk.Now().Add(time.Hour), AbsoluteExpiresAt: e.clk.Now().Add(time.Hour),
	}))

	return digest
}

// browserHeld says whether the browser session is still there.
func (e *endFixture) browserHeld(t *testing.T, digest []byte) bool {
	t.Helper()

	_, err := e.browsers.Load(t.Context(), digest, e.clk.Now())
	if err != nil {
		require.ErrorIs(t, err, oidcprovider.ErrNotFound)

		return false
	}

	return true
}

// grantStands reads a scene's grant from the store underneath the hooks.
func (e *endFixture) grantStands(t *testing.T, s *refreshScene) *oidcprovider.Grant {
	t.Helper()

	return grantNow(t, e.refreshFixture, s)
}

// TestProvider_EndSignIn_Selectors runs each of T3's selectors over the same three sign-ins, and
// judges which of them ended, in the grants, the browser sessions and the clients returned.
func TestProvider_EndSignIn_Selectors(t *testing.T) {
	t.Parallel()

	const (
		upstreamX = "https://x.example.com"
		upstreamY = "https://y.example.com"
	)

	type world struct {
		a, b, c oidcprovider.SignIn
	}

	type testCase struct {
		name  string
		sel   func(world) oidcprovider.SignInSelector
		ended string
	}

	cases := []testCase{
		{
			name:  "a family ends that one sign-in",
			sel:   func(w world) oidcprovider.SignInSelector { return oidcprovider.SignInSelector{Family: w.a.Family} },
			ended: "a",
		},
		{
			name:  "a user ends all of the user's",
			sel:   func(world) oidcprovider.SignInSelector { return oidcprovider.SignInSelector{User: "u-1"} },
			ended: "ab",
		},
		{
			name: "a user except a family spares that family",
			sel: func(w world) oidcprovider.SignInSelector {
				return oidcprovider.SignInSelector{User: "u-1", ExceptFamily: w.a.Family}
			},
			ended: "b",
		},
		{
			name: "an upstream session ends what came through it, whoever's it is",
			sel: func(world) oidcprovider.SignInSelector {
				return oidcprovider.SignInSelector{ExternalIssuer: upstreamX, ExternalSessionID: "shared"}
			},
			ended: "ac",
		},
		{
			name: "a user and an upstream issuer end the user's through that issuer",
			sel: func(world) oidcprovider.SignInSelector {
				return oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: upstreamY}
			},
			ended: "b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			w := world{
				a: e.signInOf("u-1", upstreamX, "shared"),
				b: e.signInOf("u-1", upstreamY, "other"),
				c: e.signInOf("u-2", upstreamX, "shared"),
			}
			type part struct {
				signIn oidcprovider.SignIn
				scene  *refreshScene
				digest []byte
			}
			parts := map[string]part{}
			for name, signIn := range map[string]oidcprovider.SignIn{"a": w.a, "b": w.b, "c": w.c} {
				parts[name] = part{signIn, e.online(t, signIn), e.browserOf(t, signIn)}
			}

			clients, err := e.p.EndSignIn(t.Context(), tc.sel(w))
			require.NoError(t, err)

			var want []oidcprovider.ClientToNotify
			for _, name := range []string{"a", "b", "c"} {
				part := parts[name]
				ended := strings.Contains(tc.ended, name)
				grant := e.grantStands(t, part.scene)
				assert.Equal(t, ended, grant.Revoked, "the grant of sign-in %s", name)
				if ended {
					assert.Equal(t, oidcprovider.CauseSignInEnded, grant.RevokeCause)
					assertRefreshRefused(t, e.refreshFixture, part.scene, part.scene.first.RefreshToken)
					want = append(want, oidcprovider.ClientToNotify{
						ClientID: "billing-web", User: part.signIn.User, SignInFamily: part.signIn.Family,
					})
				} else {
					assertRefreshWorks(t, e.refreshFixture, part.scene, part.scene.first.RefreshToken)
				}
				assert.Equal(t, !ended, e.browserHeld(t, part.digest), "the browser session of sign-in %s", name)
			}
			assert.ElementsMatch(t, want, clients)
			require.Len(t, e.queued(), 1)
			assert.ElementsMatch(t, want, e.queued()[0], "what is returned is what is queued")
		})
	}
}

// TestProvider_EndSignIn is the table of what one end does beyond choosing its sign-ins.
func TestProvider_EndSignIn(t *testing.T) {
	t.Parallel()

	type outcome struct {
		clients []oidcprovider.ClientToNotify
		err     error
	}

	type testCase struct {
		name string
		ctx  func(context.Context) context.Context
		// arrange returns what the row ends.
		arrange func(*testing.T, *endFixture) oidcprovider.SignInSelector
		assert  func(*testing.T, *endFixture, outcome)
	}

	cancelled := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithCancel(ctx)
		cancel()

		return ctx
	}

	cases := []testCase{
		{
			name: "an online grant ends, and an offline one of the same sign-in survives, marked",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				box := &e.box
				box.first, box.second = e.online(t, signIn), e.offline(t, signIn)

				return oidcprovider.SignInSelector{Family: signIn.Family}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				box := &e.box
				assert.True(t, e.grantStands(t, box.first).Revoked)
				survivor := e.grantStands(t, box.second)
				assert.False(t, survivor.Revoked)
				assert.False(t, survivor.SignInEndedAt.IsZero())
				assertRefreshWorks(t, e.refreshFixture, box.second, box.second.first.RefreshToken)
				assert.Len(t, got.clients, 1, "two grants of one client from one sign-in are one notice")
			},
		},
		{
			name: "a client tied to its sign-in loses its offline grant too",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				e.box.first = e.grantFrom(t, signIn, tiedClient, tiedRedirect, "openid", "offline_access")

				return oidcprovider.SignInSelector{Family: signIn.Family}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				scene := e.box.first
				grant := e.grantStands(t, scene)
				assert.True(t, grant.Offline)
				assert.True(t, grant.Revoked)
				assertRefreshRefused(t, e.refreshFixture, scene, scene.first.RefreshToken)
			},
		},
		{
			name: "each client of a sign-in is returned once, and each sign-in of a client once",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				one, two := e.signInOf("u-1", "", ""), e.signInOf("u-1", "", "")
				e.online(t, one)
				e.offline(t, one)
				e.grantFrom(t, one, tiedClient, tiedRedirect, "openid")
				e.online(t, two)
				e.box.signIns = []oidcprovider.SignIn{one, two}

				return oidcprovider.SignInSelector{User: "u-1"}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				signIns := e.box.signIns
				assert.ElementsMatch(t, []oidcprovider.ClientToNotify{
					{ClientID: "billing-web", User: "u-1", SignInFamily: signIns[0].Family},
					{ClientID: tiedClient, User: "u-1", SignInFamily: signIns[0].Family},
					{ClientID: "billing-web", User: "u-1", SignInFamily: signIns[1].Family},
				}, got.clients)
			},
		},
		{
			name: "a client with no refresh grant is returned too (R10)",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				c := issueCodeFor(t, e.parkFixture, "code-only", func(v url.Values) {
					asClient(v, "code-only", "https://code-only.example.com/cb")
					v.Set("scope", "openid")
				}, signIn, "openid")
				_, err := e.p.Token(t.Context(), confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil))
				require.NoError(t, err)

				return oidcprovider.SignInSelector{Family: signIn.Family}
			},
			assert: func(t *testing.T, _ *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				require.Len(t, got.clients, 1)
				assert.Equal(t, "code-only", got.clients[0].ClientID)
			},
		},
		{
			name: "a grant whose lineage went idle still reports its client, as nothing removes it (R19)",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				e.box.first = e.offline(t, signIn)
				e.clk.Advance(31 * 24 * time.Hour)
				_, err := e.lineage.DeleteExpired(t.Context())
				require.NoError(t, err)
				require.Zero(t, e.liveHeads(t))

				return oidcprovider.SignInSelector{Family: signIn.Family}
			},
			assert: func(t *testing.T, _ *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				require.Len(t, got.clients, 1)
				assert.Equal(t, "billing-web", got.clients[0].ClientID)
			},
		},
		{
			name: "the same end again returns and queues nothing",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				e.online(t, signIn)
				sel := oidcprovider.SignInSelector{Family: signIn.Family}
				clients, err := e.p.EndSignIn(t.Context(), sel)
				require.NoError(t, err)
				require.Len(t, clients, 1)

				return sel
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				assert.Empty(t, got.clients)
				assert.Len(t, e.queued(), 1, "only the first end queued anything")
			},
		},
		{
			name: "a code outstanding at the end cannot make a live grant, and an offline one can (R7)",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				box := &e.box
				box.online = issueCodeFor(t, e.parkFixture, "billing-web", nil, signIn, "openid", "profile")
				box.offline = issueCodeFor(t, e.parkFixture, "billing-web", func(v url.Values) {
					v.Set("scope", "openid offline_access")
				}, signIn, "openid", "offline_access")

				return oidcprovider.SignInSelector{Family: signIn.Family}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				box := &e.box
				_, err := e.p.Token(t.Context(), billingExchange(box.online, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				_, err = e.p.Token(t.Context(), billingExchange(box.offline, nil))
				require.NoError(t, err)
			},
		},
		{
			name: "a selector of no valid shape fails as a wiring mistake, and touches nothing",
			arrange: func(*testing.T, *endFixture) oidcprovider.SignInSelector {
				return oidcprovider.SignInSelector{}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.ErrorIs(t, got.err, oidcprovider.ErrConfig)
				assert.NotErrorIs(t, got.err, oidcprovider.ErrDependency)
				assert.Empty(t, e.grants.selectors)
				assert.Empty(t, e.browsers.seen())
			},
		},
		{
			name: "a grant store failure fails the call, and the browser sessions still go",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				box := &e.box
				box.first, box.digest = e.online(t, signIn), e.browserOf(t, signIn)
				e.grants.failBulk.Store(true)
				box.sel = oidcprovider.SignInSelector{Family: signIn.Family}

				return box.sel
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				assertDependencyFailure(t, got.err)
				box := &e.box
				assert.Empty(t, got.clients)
				assert.False(t, e.browserHeld(t, box.digest))

				e.grants.failBulk.Store(false)
				clients, err := e.p.EndSignIn(t.Context(), box.sel)
				require.NoError(t, err, "the end can be asked for again")
				assert.Len(t, clients, 1)
			},
		},
		{
			name: "a browser store failure fails the call, and the clients of the grants it did end are not lost",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				box := &e.box
				box.first, box.digest = e.online(t, signIn), e.browserOf(t, signIn)
				e.browsers.fail.Store(true)
				box.sel = oidcprovider.SignInSelector{Family: signIn.Family}

				return box.sel
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				assertDependencyFailure(t, got.err)
				box := &e.box
				assert.Len(t, got.clients, 1)
				require.Len(t, e.queued(), 1)
				assert.True(t, e.grantStands(t, box.first).Revoked)
				assert.True(t, e.browserHeld(t, box.digest))

				e.browsers.fail.Store(false)
				clients, err := e.p.EndSignIn(t.Context(), box.sel)
				require.NoError(t, err)
				assert.Empty(t, clients)
				assert.False(t, e.browserHeld(t, box.digest), "asking again finishes it")
				assert.Len(t, e.queued(), 1, "and tells no one twice")
			},
		},
		{
			name: "a caller who has left does not spare the end, and its writes have a deadline",
			ctx:  cancelled,
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				signIn := e.signInOf("u-1", "", "")
				box := &e.box
				box.first, box.digest = e.online(t, signIn), e.browserOf(t, signIn)
				e.grants.sawBulk = func(ctx context.Context) {
					_, box.budgeted = ctx.Deadline()
				}

				return oidcprovider.SignInSelector{Family: signIn.Family}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				box := &e.box
				assert.True(t, e.grantStands(t, box.first).Revoked)
				assert.False(t, e.browserHeld(t, box.digest))
				assert.True(t, box.budgeted)
			},
		},
		{
			name: "a client holding several grants in each of two sign-ins is told once of each, however the store orders them",
			arrange: func(t *testing.T, e *endFixture) oidcprovider.SignInSelector {
				t.Helper()

				box := &e.box
				box.signIns = []oidcprovider.SignIn{e.signInOf("u-1", "", ""), e.signInOf("u-1", "", "")}
				for _, signIn := range box.signIns {
					e.online(t, signIn)
					e.offline(t, signIn)
				}
				// Interleaved, so that equal notices are never next to each other as the store gave them.
				e.grants.reorderEnded = func(grants []oidcprovider.Grant) {
					slices.SortStableFunc(grants, func(a, b oidcprovider.Grant) int {
						return cmp.Compare(a.SignInFamily.String(), b.SignInFamily.String())
					})
					half := len(grants) / 2
					woven := make([]oidcprovider.Grant, 0, len(grants))
					for i := range half {
						woven = append(woven, grants[i], grants[half+i])
					}
					copy(grants, woven)
				}

				return oidcprovider.SignInSelector{User: "u-1"}
			},
			assert: func(t *testing.T, e *endFixture, got outcome) {
				t.Helper()

				require.NoError(t, got.err)
				families := []string{e.box.signIns[0].Family.String(), e.box.signIns[1].Family.String()}
				slices.Sort(families)
				require.Len(t, got.clients, 2, "one notice per client per sign-in")
				for i, c := range got.clients {
					assert.Equal(t, "billing-web", c.ClientID)
					assert.Equal(t, families[i], c.SignInFamily.String(), "ordered by sign-in within a client")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			sel := tc.arrange(t, e)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			clients, err := e.p.EndSignIn(ctx, sel)
			tc.assert(t, e, outcome{clients: clients, err: err})
		})
	}
}

// TestProvider_EndSignIn_BudgetsApart is apart because it runs in a synctest bubble, where the
// budget of ten seconds passes in no time and the clock cannot differ between two reads. A grant
// store hanging until its budget ends must leave the browser sessions' store a live context with
// time still to run, which one budget shared by both would not.
func TestProvider_EndSignIn_BudgetsApart(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		e := newEndFixture(t)
		signIn := e.signInOf("u-1", "", "")
		grant, digest := e.online(t, signIn), e.browserOf(t, signIn)

		var browserErr error
		var browserLeft time.Duration
		e.grants.sawBulk = func(ctx context.Context) { <-ctx.Done() }
		e.browsers.sawDelete = func(ctx context.Context) {
			browserErr = ctx.Err()
			if by, ok := ctx.Deadline(); ok {
				browserLeft = time.Until(by)
			}
		}

		started := time.Now()
		_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: signIn.Family})

		assertDependencyFailure(t, err)
		assert.GreaterOrEqual(t, time.Since(started), 10*time.Second, "the grant store spent its whole budget")
		require.NoError(t, browserErr, "the browser sessions' store was given a live context")
		assert.Positive(t, browserLeft, "with a budget of its own to spend")
		assert.False(t, e.browserHeld(t, digest), "and the browser sessions ended")
		assert.False(t, e.grantStands(t, grant).Revoked, "while the grant store, which hung, ended nothing")
	})
}

// TestProvider_EndSignIn_ReportsByField pins that a report's selector comes from its fields and not
// from its cause, so that a cause added later needs no change here: every row with a made-up cause
// stands for one.
func TestProvider_EndSignIn_ReportsByField(t *testing.T) {
	t.Parallel()

	const (
		upstream = "https://x.example.com"
		later    = session.EndCause(200)
	)
	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	kept, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	type testCase struct {
		name   string
		report session.EndReport
		// want is the selector a report comes to, and nil for a report naming nobody.
		want *oidcprovider.SignInSelector
	}

	cases := []testCase{
		{
			name:   "reuse names a family",
			report: session.EndReport{Cause: session.EndReuse, User: "u-1", Family: family},
			want:   &oidcprovider.SignInSelector{Family: family},
		},
		{
			name:   "a revoked family has no user",
			report: session.EndReport{Cause: session.EndFamilyRevoked, Family: family},
			want:   &oidcprovider.SignInSelector{Family: family},
		},
		{
			name:   "a deleted session ends its family's grants",
			report: session.EndReport{Cause: session.EndDeleted, User: "u-1", Family: family},
			want:   &oidcprovider.SignInSelector{Family: family},
		},
		{name: "a deleted session with no family known names nobody", report: session.EndReport{Cause: session.EndDeleted}},
		{
			name:   "an end by handle names a family",
			report: session.EndReport{Cause: session.EndByHandle, User: "u-1", Family: family},
			want:   &oidcprovider.SignInSelector{Family: family},
		},
		{
			name:   "a user's sessions name the user",
			report: session.EndReport{Cause: session.EndUserSessions, User: "u-1"},
			want:   &oidcprovider.SignInSelector{User: "u-1"},
		},
		{
			name:   "a user's sessions but one spare it",
			report: session.EndReport{Cause: session.EndUserSessionsExcept, User: "u-1", KeptFamily: kept},
			want:   &oidcprovider.SignInSelector{User: "u-1", ExceptFamily: kept},
		},
		{
			name:   "a nil kept family spares nothing",
			report: session.EndReport{Cause: session.EndUserSessionsExcept, User: "u-1"},
			want:   &oidcprovider.SignInSelector{User: "u-1"},
		},
		{
			name:   "other sign-ins spare the current one",
			report: session.EndReport{Cause: session.EndOtherSignIns, User: "u-1", KeptFamily: kept},
			want:   &oidcprovider.SignInSelector{User: "u-1", ExceptFamily: kept},
		},
		{
			name:   "other sign-ins with a nil kept family spare nothing",
			report: session.EndReport{Cause: session.EndOtherSignIns, User: "u-1"},
			want:   &oidcprovider.SignInSelector{User: "u-1"},
		},
		{
			name:   "an upstream session names itself",
			report: session.EndReport{Cause: session.EndExternalSession, ExternalIssuer: upstream, ExternalSessionID: "x-9"},
			want:   &oidcprovider.SignInSelector{ExternalIssuer: upstream, ExternalSessionID: "x-9"},
		},
		{
			name:   "a user and an upstream issuer name that pair",
			report: session.EndReport{Cause: session.EndUserExternalIssuer, User: "u-1", ExternalIssuer: upstream},
			want:   &oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: upstream},
		},
		{
			name:   "a cause added later naming a family still ends it",
			report: session.EndReport{Cause: later, User: "u-1", Family: family},
			want:   &oidcprovider.SignInSelector{Family: family},
		},
		{
			name:   "a cause added later naming a user still ends the user's",
			report: session.EndReport{Cause: later, User: "u-1"},
			want:   &oidcprovider.SignInSelector{User: "u-1"},
		},
		{
			name:   "a cause added later keeping a family still spares it",
			report: session.EndReport{Cause: later, User: "u-1", KeptFamily: kept},
			want:   &oidcprovider.SignInSelector{User: "u-1", ExceptFamily: kept},
		},
		{
			name:   "a cause added later naming an upstream session still ends it",
			report: session.EndReport{Cause: later, ExternalIssuer: upstream, ExternalSessionID: "x-9"},
			want:   &oidcprovider.SignInSelector{ExternalIssuer: upstream, ExternalSessionID: "x-9"},
		},
		{
			name:   "a user beside an upstream session takes the narrower selection",
			report: session.EndReport{Cause: later, User: "u-1", ExternalIssuer: upstream, ExternalSessionID: "x-9"},
			want:   &oidcprovider.SignInSelector{ExternalIssuer: upstream, ExternalSessionID: "x-9"},
		},
		{name: "a cause and nothing else names nobody", report: session.EndReport{Cause: later}},
		{
			name:   "a session with no issuer, beside a user, names nobody and not the user's sign-ins",
			report: session.EndReport{Cause: later, User: "u-1", ExternalSessionID: "x-9"},
		},
		{
			name:   "a session with no issuer, beside a user and a kept family, names nobody",
			report: session.EndReport{Cause: later, User: "u-1", KeptFamily: kept, ExternalSessionID: "x-9"},
		},
		{name: "a session with no issuer or user names nobody", report: session.EndReport{Cause: later, ExternalSessionID: "x-9"}},
		{
			name:   "a family beside a session with no issuer still names the family, the narrowest first",
			report: session.EndReport{Cause: later, User: "u-1", Family: family, ExternalSessionID: "x-9"},
			want:   &oidcprovider.SignInSelector{Family: family},
		},
		{name: "an empty report names nobody", report: session.EndReport{}},
		{name: "an upstream issuer alone names nobody", report: session.EndReport{Cause: later, ExternalIssuer: upstream}},
		{name: "an upstream session alone names nobody", report: session.EndReport{Cause: later, ExternalSessionID: "x-9"}},
		{name: "a kept family alone names nobody", report: session.EndReport{Cause: later, KeptFamily: kept}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			e.p.SignInsEnded(t.Context(), tc.report)

			if tc.want == nil {
				assert.Empty(t, e.grants.selectors, "it ends nothing")
				assert.Empty(t, e.browsers.seen())
				assert.Contains(t, e.logs.String(), "level=WARN")
				assert.Contains(t, e.logs.String(), "names no one")

				return
			}
			assert.Equal(t, []oidcprovider.SignInSelector{*tc.want}, e.grants.selectors)
			assert.Equal(t, []oidcprovider.SignInSelector{*tc.want}, e.browsers.seen())
			assert.Empty(t, e.logs.String())
		})
	}
}

// TestProvider_EndSignIn_ObserverFailure pins that a report's failure is logged and reported as
// an event naming the user: it has no error to return, and the end it describes has already
// happened.
func TestProvider_EndSignIn_ObserverFailure(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(*endFixture)
		assert  func(*testing.T, *endFixture, *refreshScene, []byte)
	}

	cases := []testCase{
		{
			name:    "a grant store failure is logged once at ERROR, and the browser session still goes",
			arrange: func(e *endFixture) { e.grants.failBulk.Store(true) },
			assert: func(t *testing.T, e *endFixture, s *refreshScene, digest []byte) {
				t.Helper()

				assert.False(t, e.grantStands(t, s).Revoked)
				assert.False(t, e.browserHeld(t, digest))
				assert.Empty(t, e.queued())
			},
		},
		{
			name:    "a browser store failure is logged once at ERROR, and the grant's client is still queued",
			arrange: func(e *endFixture) { e.browsers.fail.Store(true) },
			assert: func(t *testing.T, e *endFixture, s *refreshScene, digest []byte) {
				t.Helper()

				assert.True(t, e.grantStands(t, s).Revoked)
				assert.True(t, e.browserHeld(t, digest))
				assert.Len(t, e.queued(), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var log eventLog
			e := newEndFixture(t, oidcprovider.WithSecurityEvents(log.sink))
			signIn := e.signInOf("u-1", "https://x.example.com", "the-upstream-session")
			s, digest := e.online(t, signIn), e.browserOf(t, signIn)
			tc.arrange(e)

			assert.NotPanics(t, func() {
				e.p.SignInsEnded(t.Context(), session.EndReport{Cause: session.EndByHandle, User: signIn.User, Family: signIn.Family})
			})

			logs := e.logs.String()
			assert.Equal(t, 1, strings.Count(logs, "level=ERROR"), logs)
			assert.NotContains(t, logs, errOutage.Error())
			assert.NotContains(t, logs, "the-upstream-session")
			tc.assert(t, e, s, digest)

			require.NoError(t, e.p.Shutdown(t.Context()))
			failed := named(log.all(), event.GrantEndFailed)
			require.Len(t, failed, 1, "the failed end is reported once")
			assert.Equal(t, event.OutcomeFailure, failed[0].Outcome)
			assert.Equal(t, signIn.User, failed[0].User)
			assert.Empty(t, failed[0].Cause, "a store's error is never carried")
			assert.NotContains(t, fmt.Sprintf("%+v", failed[0]), errOutage.Error())
		})
	}
}

// TestProvider_EndSignIn_ThroughAManager wires a real session manager to the provider, so what is
// pinned is the reports it really sends, including none for a sign-in that merely expires.
func TestProvider_EndSignIn_ThroughAManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// end acts on the manager, for a session of the sign-in the grant came from.
		end func(context.Context, *session.Sessions, *session.Session) error
		// keep says the grant is to stay live.
		keep bool
		// advance moves the clock before the end.
		advance time.Duration
		// notified says a client leaves for delivery.
		notified bool
	}

	cases := []testCase{
		{
			name: "a deleted session ends its family's grants",
			end: func(ctx context.Context, m *session.Sessions, s *session.Session) error {
				return m.Delete(ctx, s.ID)
			},
			notified: true,
		},
		{
			name: "a revoked family ends its grants",
			end: func(ctx context.Context, m *session.Sessions, s *session.Session) error {
				_, err := m.RevokeFamily(ctx, s.FamilyID)

				return err
			},
			notified: true,
		},
		{
			name: "a user's deleted sessions end the user's grants",
			end: func(ctx context.Context, m *session.Sessions, s *session.Session) error {
				return m.DeleteByUser(ctx, s.UserID)
			},
			notified: true,
		},
		{
			name: "deleting a user's sessions but this one keeps its grants",
			end: func(ctx context.Context, m *session.Sessions, s *session.Session) error {
				_, err := m.DeleteByUserExcept(ctx, s.UserID, s.ID)

				return err
			},
			keep: true,
		},
		{
			name: "a sign-in that merely expires, and its sweep, send nothing and end nothing",
			end: func(ctx context.Context, m *session.Sessions, _ *session.Session) error {
				_, err := m.DeleteExpired(ctx)

				return err
			},
			advance: 13 * time.Hour,
			keep:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			store, err := session.NewMemoryStore(session.WithMemoryStoreClock(e.clk))
			require.NoError(t, err)
			manager, err := session.New(
				session.WithStore(store),
				session.WithClock(e.clk),
				session.WithEndObserver(e.p),
			)
			require.NoError(t, err)
			require.True(t, manager.ReportsEndsTo(e.p))

			signedIn, err := manager.Create(t.Context(), "u-1")
			require.NoError(t, err)
			signIn := e.signInOf("u-1", "", "")
			signIn.Family = signedIn.FamilyID
			signIn.AbsoluteExpiresAt = e.clk.Now().Add(24 * time.Hour)
			s := e.online(t, signIn)

			e.clk.Advance(tc.advance)
			require.NoError(t, tc.end(t.Context(), manager, signedIn))

			assert.Equal(t, !tc.keep, e.grantStands(t, s).Revoked)
			if tc.notified {
				assert.Len(t, e.queued(), 1)
			} else {
				assert.Empty(t, e.queued())
			}
		})
	}
}

// TestProvider_RevokeUserGrants is the table of revocations by user, with their causes.
func TestProvider_RevokeUserGrants(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		user   identity.UserID
		cause  string
		ctx    func(context.Context) context.Context
		before func(*endFixture)
		assert func(t *testing.T, e *endFixture, mine, offline, theirs *refreshScene, code issuedCode, err error)
	}

	cases := []testCase{
		{
			name:  "every grant of the user goes with the cause, offline ones and outstanding codes too",
			user:  "u-1",
			cause: string(oidcprovider.CauseRecovery),
			assert: func(t *testing.T, e *endFixture, mine, offline, theirs *refreshScene, code issuedCode, err error) {
				t.Helper()

				require.NoError(t, err)
				for _, s := range []*refreshScene{mine, offline} {
					grant := e.grantStands(t, s)
					assert.True(t, grant.Revoked)
					assert.Equal(t, oidcprovider.CauseRecovery, grant.RevokeCause)
					assertRefreshRefused(t, e.refreshFixture, s, s.first.RefreshToken)
				}
				_, err = e.p.Token(t.Context(), billingExchange(code, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.False(t, e.grantStands(t, theirs).Revoked, "another user's grant is not touched")
				assert.Empty(t, e.queued(), "no sign-in ended, so no one is told one did")
			},
		},
		{
			name:  "a cause the provider does not name is kept as given",
			user:  "u-1",
			cause: "a-consumers-own",
			assert: func(t *testing.T, e *endFixture, mine, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, oidcprovider.RevocationCause("a-consumers-own"), e.grantStands(t, mine).RevokeCause)
			},
		},
		{
			name:  "no user is a wiring mistake, and touches nothing",
			cause: string(oidcprovider.CauseRecovery),
			assert: func(t *testing.T, e *endFixture, mine, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.False(t, e.grantStands(t, mine).Revoked)
			},
		},
		{
			name: "no cause is a wiring mistake, and touches nothing",
			user: "u-1",
			assert: func(t *testing.T, e *endFixture, mine, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.False(t, e.grantStands(t, mine).Revoked)
			},
		},
		{
			name:   "a store failure is a dependency failure",
			user:   "u-1",
			cause:  string(oidcprovider.CauseRecovery),
			before: func(e *endFixture) { e.grants.failBulk.Store(true) },
			assert: func(t *testing.T, _ *endFixture, _, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
			},
		},
		{
			name:  "a caller who has left does not spare the revocation",
			user:  "u-1",
			cause: string(oidcprovider.CauseRecovery),
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			assert: func(t *testing.T, e *endFixture, mine, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, e.grantStands(t, mine).Revoked)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			signIn := e.signInOf("u-1", "", "")
			mine, offline := e.online(t, signIn), e.offline(t, signIn)
			theirs := e.online(t, e.signInOf("u-2", "", ""))
			code := issueCodeFor(t, e.parkFixture, "billing-web", func(v url.Values) {
				v.Set("scope", "openid offline_access")
			}, signIn, "openid", "offline_access")
			if tc.before != nil {
				tc.before(e)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			err := e.p.RevokeUserGrants(ctx, tc.user, tc.cause)
			tc.assert(t, e, mine, offline, theirs, code, err)
		})
	}
}

// hookedConsents is a real consent store that fails at a row's request.
type hookedConsents struct {
	oidcprovider.ConsentStore

	failLoad, failRevoke, failList atomic.Bool
	// afterLoad runs after each read, and is set before the request starts.
	afterLoad func()
}

// Load implements oidcprovider.ConsentStore.
func (h *hookedConsents) Load(ctx context.Context, user identity.UserID, clientID string) (*oidcprovider.Consent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.failLoad.Load() {
		return nil, errOutage
	}
	consent, err := h.ConsentStore.Load(ctx, user, clientID)
	if h.afterLoad != nil {
		h.afterLoad()
	}

	return consent, err
}

// Revoke implements oidcprovider.ConsentStore.
func (h *hookedConsents) Revoke(ctx context.Context, user identity.UserID, clientID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if h.failRevoke.Load() {
		return false, errOutage
	}

	return h.ConsentStore.Revoke(ctx, user, clientID)
}

// ListByUser implements oidcprovider.ConsentStore.
func (h *hookedConsents) ListByUser(ctx context.Context, user identity.UserID) ([]oidcprovider.Consent, error) {
	if h.failList.Load() {
		return nil, errOutage
	}

	return h.ConsentStore.ListByUser(ctx, user)
}

// TestProvider_RevokeUserGrants_Consent is revoking a consent, over real grants.
const (
	firstPartyClient   = "first-party-web"
	firstPartyRedirect = "https://first.example.com/cb"
)

func TestProvider_RevokeUserGrants_Consent(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		user   identity.UserID
		client string
		// firstParty registers a first-party client with u-1 holding a grant of it and no consent;
		// that grant is the fixture's box.first.
		firstParty bool
		assert     func(t *testing.T, e *endFixture, billing, offline, tied *refreshScene, code issuedCode, err error)
	}

	cases := []testCase{
		{
			name:       "a first-party client holds no consent, and its grant for that user still ends, others' standing",
			user:       "u-1",
			client:     firstPartyClient,
			firstParty: true,
			assert: func(t *testing.T, e *endFixture, billing, offline, tied *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.NoError(t, err)
				first := e.box.first
				grant := e.grantStands(t, first)
				assert.True(t, grant.Revoked)
				assert.Equal(t, oidcprovider.CauseConsentRevoked, grant.RevokeCause)
				assertRefreshRefused(t, e.refreshFixture, first, first.first.RefreshToken)
				for _, s := range []*refreshScene{billing, offline, tied} {
					assert.False(t, e.grantStands(t, s).Revoked, "another client's grant stands")
				}
			},
		},
		{
			name:       "another user's first-party grant is foreign, and ends nothing",
			user:       "u-2",
			client:     firstPartyClient,
			firstParty: true,
			assert: func(t *testing.T, e *endFixture, _, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrForeignConsent)
				assert.False(t, e.grantStands(t, e.box.first).Revoked)
			},
		},
		{
			name:   "that user's and client's grants go, offline ones and outstanding codes too, and the consent is forgotten",
			user:   "u-1",
			client: "billing-web",
			assert: func(t *testing.T, e *endFixture, billing, offline, tied *refreshScene, code issuedCode, err error) {
				t.Helper()

				require.NoError(t, err)
				for _, s := range []*refreshScene{billing, offline} {
					grant := e.grantStands(t, s)
					assert.True(t, grant.Revoked)
					assert.Equal(t, oidcprovider.CauseConsentRevoked, grant.RevokeCause)
					assertRefreshRefused(t, e.refreshFixture, s, s.first.RefreshToken)
				}
				_, err = e.p.Token(t.Context(), billingExchange(code, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.False(t, e.grantStands(t, tied).Revoked, "another client of the user keeps its grant")

				_, err = e.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				_, err = e.consents.Load(t.Context(), "u-1", tiedClient)
				require.NoError(t, err, "another client's consent stands")
			},
		},
		{
			name:   "a consent the user never gave is refused as foreign, and ends nothing",
			user:   "u-1",
			client: opaqueClient,
			assert: func(t *testing.T, e *endFixture, billing, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrForeignConsent)
				assert.False(t, e.grantStands(t, billing).Revoked)
			},
		},
		{
			name:   "another user's client is refused as foreign, and ends nothing of the other user's",
			user:   "u-2",
			client: "billing-web",
			assert: func(t *testing.T, e *endFixture, billing, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrForeignConsent)
				assert.False(t, e.grantStands(t, billing).Revoked)
			},
		},
		{
			name:   "no user is a wiring mistake",
			client: "billing-web",
			assert: func(t *testing.T, _ *endFixture, _, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
		{
			name: "no client is a wiring mistake",
			user: "u-1",
			assert: func(t *testing.T, _ *endFixture, _, _, _ *refreshScene, _ issuedCode, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			signIn := e.signInOf("u-1", "", "")
			billing, offline := e.online(t, signIn), e.offline(t, signIn)
			tied := e.grantFrom(t, signIn, tiedClient, tiedRedirect, "openid", "offline_access")
			code := issueCodeFor(t, e.parkFixture, "billing-web", func(v url.Values) {
				v.Set("scope", "openid offline_access")
			}, signIn, "openid", "offline_access")

			if tc.firstParty {
				require.NoError(t, e.registry.Put(t.Context(), oidcprovider.Client{
					ID: firstPartyClient, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret),
					RedirectURIs: []string{firstPartyRedirect}, Scopes: []string{"openid", "profile"}, FirstParty: true,
					GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
				}))
				e.box.first = e.grantFrom(t, signIn, firstPartyClient, firstPartyRedirect, "openid", "profile")
				// issueCodeFor gives a consent the first-party flow never would: drop it.
				_, err := e.consents.Revoke(t.Context(), "u-1", firstPartyClient)
				require.NoError(t, err)
			}

			err := e.p.RevokeConsent(t.Context(), tc.user, tc.client)
			tc.assert(t, e, billing, offline, tied, code, err)
		})
	}
}

// consentFixture is a provider whose consent store a row can fail, with one consent held. It
// exchanges nothing, as a row about the store needs no grant.
func consentFixture(t *testing.T) (*endFixture, *hookedConsents) {
	t.Helper()

	memory, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	consents := &hookedConsents{ConsentStore: memory}
	e := newEndFixture(t, oidcprovider.WithConsentStore(consents))
	require.NoError(t, consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "offline_access"}, true, e.clk.Now()))

	return e, consents
}

// TestProvider_RevokeUserGrants_ConsentStore pins the order of a consent's revocation: the grants go
// first, so a failure leaves the consent to be revoked again, and neither failure is a success.
func TestProvider_RevokeUserGrants_ConsentStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		ctx     func(context.Context, *hookedConsents) context.Context
		arrange func(*endFixture, *hookedConsents)
		assert  func(*testing.T, *endFixture, *hookedConsents, error)
	}

	consentHeld := func(t *testing.T, consents *hookedConsents) {
		t.Helper()

		_, err := consents.ConsentStore.Load(t.Context(), "u-1", "billing-web")
		require.NoError(t, err, "the consent stays, to be revoked again")
	}

	cases := []testCase{
		{
			name:    "grants that cannot be revoked are a dependency failure, and the consent stays",
			arrange: func(e *endFixture, _ *hookedConsents) { e.grants.failBulk.Store(true) },
			assert: func(t *testing.T, _ *endFixture, c *hookedConsents, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
				consentHeld(t, c)
			},
		},
		{
			name:    "a consent that cannot be forgotten is a dependency failure, and asking again finishes",
			arrange: func(_ *endFixture, c *hookedConsents) { c.failRevoke.Store(true) },
			assert: func(t *testing.T, e *endFixture, c *hookedConsents, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
				consentHeld(t, c)
				c.failRevoke.Store(false)
				require.NoError(t, e.p.RevokeConsent(t.Context(), "u-1", "billing-web"))
			},
		},
		{
			name: "a caller already gone does not spare the writes",
			ctx: func(ctx context.Context, _ *hookedConsents) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			arrange: func(*endFixture, *hookedConsents) {},
			assert: func(t *testing.T, _ *endFixture, c *hookedConsents, err error) {
				t.Helper()

				require.NoError(t, err)
				_, err = c.ConsentStore.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, consents := consentFixture(t)
			tc.arrange(e, consents)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, consents)
			}

			tc.assert(t, e, consents, e.p.RevokeConsent(ctx, "u-1", "billing-web"))
		})
	}
}

// TestProvider_RevokeUserGrants_Consents is the list a user's consents page reads.
func TestProvider_RevokeUserGrants_Consents(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(*testing.T, *endFixture, *hookedConsents)
		assert  func(*testing.T, *endFixture, []oidcprovider.ConsentView, error)
	}

	cases := []testCase{
		{
			name: "a user's consents, each with its client's name, and no one else's",
			arrange: func(t *testing.T, e *endFixture, c *hookedConsents) {
				t.Helper()

				require.NoError(t, c.Give(t.Context(), "u-2", tiedClient, []string{"openid"}, false, e.clk.Now()))
			},
			assert: func(t *testing.T, e *endFixture, views []oidcprovider.ConsentView, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []oidcprovider.ConsentView{{
					ClientID: "billing-web", ClientName: "Billing", Scopes: []string{"openid", "offline_access"},
					Offline: true, LastGivenAt: e.clk.Now(),
				}}, views)
			},
		},
		{
			name: "a consent to a client since removed stays listed, so that it can be revoked",
			arrange: func(t *testing.T, e *endFixture, c *hookedConsents) {
				t.Helper()

				_, err := c.Revoke(t.Context(), "u-1", "billing-web")
				require.NoError(t, err)
				require.NoError(t, c.Give(t.Context(), "u-1", "no-longer-registered", []string{"openid"}, false, e.clk.Now()))
			},
			assert: func(t *testing.T, _ *endFixture, views []oidcprovider.ConsentView, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, views, 1)
				assert.Equal(t, "no-longer-registered", views[0].ClientID)
				assert.Empty(t, views[0].ClientName)
			},
		},
		{
			name:    "a store failure is a dependency failure",
			arrange: func(_ *testing.T, _ *endFixture, c *hookedConsents) { c.failList.Store(true) },
			assert: func(t *testing.T, _ *endFixture, views []oidcprovider.ConsentView, err error) {
				t.Helper()

				assertDependencyFailure(t, err)
				assert.Nil(t, views)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, consents := consentFixture(t)
			tc.arrange(t, e, consents)

			views, err := e.p.Consents(t.Context(), "u-1")
			tc.assert(t, e, views, err)
		})
	}
}

// A hand-on hook that spends its whole budget must leave the browser delete a live context of its own.
func TestProvider_EndSignIn_HandOnHangsBrowserKeepsABudget(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newEndFixture(t, oidcprovider.WithLogoutNoticesForTest(func(ctx context.Context, _ []oidcprovider.ClientToNotify) { <-ctx.Done() }))
		signIn := e.signInOf("u-1", "", "")
		_ = e.online(t, signIn)
		var browserErr error
		e.browsers.sawDelete = func(ctx context.Context) { browserErr = ctx.Err() }
		started := time.Now()
		_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: signIn.Family})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, time.Since(started), 10*time.Second)
		assert.NoError(t, browserErr, "the browser delete has a budget of its own")
	})
}
