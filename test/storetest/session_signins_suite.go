package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// Sign-in state the suite's sessions carry, so a store that drops a field, or
// lets a save change one, is caught.
const (
	signInClientIP  = "203.0.113.7"
	signInUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	signInJKT       = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	signInX5TS256   = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
	signInCSRFToken = "Zm9yLXRoZS1zdWl0ZS1hLWNzcmYtdG9rZW4tMzItYnl0ZXM"
)

// withSignInState gives s the suite's sign-in metadata, a DPoP key binding and
// a CSRF token, and returns it.
func withSignInState(s *session.Session) *session.Session {
	s.ClientIP = signInClientIP
	s.UserAgent = signInUserAgent
	s.KeyBinding = session.KeyBinding{JKT: signInJKT}
	s.CSRFToken = signInCSRFToken
	return s
}

// assertSignInState compares the sign-in state of a loaded session with the
// one stored, one check per field so a failure names what was lost.
func assertSignInState(t *testing.T, want, got *session.Session) {
	t.Helper()

	require.NotNil(t, got)
	assert.Equal(t, want.ClientIP, got.ClientIP, "the sign-in's client address must round-trip unchanged")
	assert.Equal(t, want.UserAgent, got.UserAgent, "the sign-in's user agent must round-trip unchanged")
	assert.Equal(t, want.KeyBinding, got.KeyBinding, "the key binding must round-trip unchanged")
	assert.Equal(t, want.CSRFToken, got.CSRFToken, "the CSRF token must round-trip unchanged")
}

// assertListed compares a listed session with the one stored. A listing needs
// no sealed field, so a store sealing the provider ID token and the CSRF token
// may list without opening them: both are left out of the comparison. Nor
// does it need the session identifier, which a durable store never stores
// and so cannot return: a sign-in is told apart by its family. Every other
// field must match as a load's would.
func assertListed(t *testing.T, want, got *session.Session) {
	t.Helper()

	require.NotNil(t, got)
	w, g := *want, *got
	w.ID, w.ExternalIDToken, w.CSRFToken = "", "", ""
	g.ID, g.ExternalIDToken, g.CSRFToken = "", "", ""
	assertSession(t, &w, &g)
}

// listedFamilies lists user at now and returns the family of each session
// listed, failing the case on an error. A listing is compared by family, not
// by identifier, which a durable store cannot return.
func listedFamilies(ctx context.Context, t *testing.T, s session.Store, user identity.UserID, now time.Time) []id.ID {
	t.Helper()

	listed, err := s.ListByUser(ctx, user, now)
	require.NoError(t, err)
	families := make([]id.ID, 0, len(listed))
	for _, l := range listed {
		require.NotNil(t, l, "a listing holds no nil session")
		families = append(families, l.FamilyID)
	}
	return families
}

// sessionSignInCases are the cases of listing a user's sign-ins and of the
// sign-in state (metadata, key binding, CSRF token) a session carries.
func sessionSignInCases() []suiteCase[session.Store] {
	// supersede supersedes old by successor at at, with a thirty-second
	// window, observing no successor.
	supersede := func(ctx context.Context, t *testing.T, s session.Store, old, successor *session.Session, at time.Time) {
		t.Helper()

		require.NoError(t, s.Supersede(ctx, session.Supersession{
			Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: sessionRetainUntil,
			Successor: successor, Now: at,
		}))
	}

	return []suiteCase[session.Store]{
		{
			name: "listing returns one live head per family, without superseded or expired members",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				renewedOld := withSignInState(familySession("sess-a", "u-1", suiteID(1)))
				require.NoError(t, s.Create(ctx, renewedOld))
				at := suiteStart.Add(2 * time.Minute)
				head := withSignInState(successorOf(renewedOld, "sess-a2", at))
				supersede(ctx, t, s, renewedOld, head, at)

				idle := idleExpiredSession("sess-b", "u-1")
				live := sessionRecord("sess-c", "u-1")
				other := sessionRecord("sess-d", "u-2")
				createSessions(ctx, t, s, idle, live, other)

				listed, err := s.ListByUser(ctx, "u-1", suiteStart.Add(5*time.Minute))
				require.NoError(t, err)
				byFamily := map[id.ID][]*session.Session{}
				for _, l := range listed {
					require.NotNil(t, l)
					byFamily[l.FamilyID] = append(byFamily[l.FamilyID], l)
				}
				assert.ElementsMatch(t, []id.ID{suiteID(1), idle.FamilyID, live.FamilyID}, keysOf(byFamily),
					"every family with a live head is listed, and no other user's")
				if got := byFamily[suiteID(1)]; assert.Len(t, got, 1,
					"inside its window the superseded member is not listed; its successor is") {
					assertListed(t, head, got[0])
				}
				if got := byFamily[live.FamilyID]; assert.Len(t, got, 1) {
					assertListed(t, live, got[0])
				}
			},
		},
		{
			name: "listing judges expiry by the time the caller passes, not the store's clock",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				idle := idleExpiredSession("sess-b", "u-1") // idle deadline 09:10
				live := sessionRecord("sess-c", "u-1")      // idle deadline 09:30
				createSessions(ctx, t, s, idle, live)

				assert.ElementsMatch(t, []id.ID{idle.FamilyID, live.FamilyID},
					listedFamilies(ctx, t, s, "u-1", suiteStart), "before either deadline both are listed")
				assert.ElementsMatch(t, []id.ID{live.FamilyID},
					listedFamilies(ctx, t, s, "u-1", suiteStart.Add(10*time.Minute)),
					"a session is not listed at its idle deadline")
				assert.Empty(t, listedFamilies(ctx, t, s, "u-1", suiteStart.Add(sessionAbsolute)),
					"no session is listed at its absolute deadline")
			},
		},
		{
			name: "listing returns only the user's own sessions, matching the reference exactly",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				upper, lower := sessionRecord("sess-upper", "Alice"), sessionRecord("sess-lower", "alice")
				createSessions(ctx, t, s, upper, lower,
					sessionRecord("sess-padded", "alice "),
					sessionRecord("sess-other", "u-2"))

				assert.ElementsMatch(t, []id.ID{upper.FamilyID}, listedFamilies(ctx, t, s, "Alice", suiteStart),
					"the listing returned another user's session")
				assert.ElementsMatch(t, []id.ID{lower.FamilyID}, listedFamilies(ctx, t, s, "alice", suiteStart),
					"the listing returned another user's session")
				assert.Empty(t, listedFamilies(ctx, t, s, "nobody", suiteStart), "no match is an empty listing")
			},
		},
		{
			name: "a listed session is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, want))

				listed, err := s.ListByUser(ctx, "u-1", suiteStart)
				require.NoError(t, err)
				require.Len(t, listed, 1)
				listed[0].Data["tenant"] = "changed by the caller"
				listed[0].UserAgent = "changed by the caller"

				assertSessionsLoad(ctx, t, s, want)
			},
		},
		{
			name: "sign-in metadata, a DPoP key binding and the CSRF token round trip",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := withSignInState(sessionRecord("sess-a", "u-1"))
				require.NoError(t, s.Create(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSession(t, want, got)
				assertSignInState(t, want, got)
			},
		},
		{
			name: "a certificate key binding round trips",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := withSignInState(sessionRecord("sess-a", "u-1"))
				want.KeyBinding = session.KeyBinding{X5TS256: signInX5TS256}
				require.NoError(t, s.Create(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSignInState(t, want, got)
			},
		},
		{
			name: "a session with no sign-in state loads unbound, without metadata or token",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSignInState(t, want, got)
			},
		},
		{
			name: "a save keeps the key binding",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				created := withSignInState(sessionRecord("sess-a", "u-1"))
				require.NoError(t, s.Create(ctx, created))

				for _, binding := range []session.KeyBinding{{}, {X5TS256: signInX5TS256}, {JKT: "another-key"}} {
					saved := withSignInState(sessionRecord("sess-a", "u-1"))
					saved.KeyBinding = binding
					require.NoError(t, s.Save(ctx, saved))

					got, err := s.Load(ctx, "sess-a")
					require.NoError(t, err)
					assert.Equal(t, created.KeyBinding, got.KeyBinding,
						"a save of a copy bound to %+v changed the stored key binding", binding)
				}
			},
		},
		{
			name: "a save keeps the sign-in metadata and the CSRF token",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				created := withSignInState(sessionRecord("sess-a", "u-1"))
				require.NoError(t, s.Create(ctx, created))

				cleared := sessionRecord("sess-a", "u-1")
				cleared.KeyBinding = created.KeyBinding
				require.NoError(t, s.Save(ctx, cleared))
				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSignInState(t, created, got)

				changed := withSignInState(sessionRecord("sess-a", "u-1"))
				changed.ClientIP, changed.UserAgent, changed.CSRFToken = "198.51.100.1", "curl/8", "another-token"
				require.NoError(t, s.Save(ctx, changed))
				got, err = s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSignInState(t, created, got)
			},
		},
		{
			// Both values arrive from the client. The manager makes them safe
			// to store, so a durable store's text columns never refuse them.
			name: "client metadata with a NUL byte and invalid UTF-8 is recorded, cleaned, through a manager",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				m, err := session.New(session.WithStore(s), session.WithClock(clk), session.WithSessionMetadata())
				require.NoError(t, err)

				created, err := m.Create(ctx, "u-1",
					session.WithClientMetadata("203.0.113.7\x00", "agent/1 \xff\xfe\x00(probe)"))
				require.NoError(t, err, "the store refused metadata the manager should have cleaned")

				got, err := s.Load(ctx, created.ID)
				require.NoError(t, err)
				assert.Equal(t, "203.0.113.7", got.ClientIP, "the NUL byte must be dropped from the address")
				assert.Equal(t, "agent/1 \uFFFD(probe)", got.UserAgent,
					"invalid UTF-8 must become U+FFFD and the NUL byte must be dropped")
			},
		},
		{
			name: "a supersession inserts its successor with the successor's sign-in state",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := withSignInState(familySession("sess-a", "u-1", suiteID(1)))
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(time.Minute)
				successor := withSignInState(successorOf(old, "sess-b", at))
				supersede(ctx, t, s, old, successor, at)

				got, err := s.Load(ctx, "sess-b")
				require.NoError(t, err)
				assertSession(t, successor, got)
				assertSignInState(t, successor, got)

				oldGot, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSignInState(t, old, oldGot)
			},
		},
	}
}

// keysOf returns m's keys, in no particular order.
func keysOf[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
