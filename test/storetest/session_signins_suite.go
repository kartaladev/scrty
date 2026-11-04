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
	signInCSRFToken = "Zm9yLXRoZS1zdWl0ZS1hLWNzcmYtdG9rZW4tMzItYnl0ZXM" //nolint:gosec // G101: a test fixture value, not a credential
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
			// A long-lived observer follows a sign-in by this listing alone
			// (session.Sessions.SignInState), so each field it reads must be
			// listed, on a session from a provider too.
			name: "listing carries a sign-in's deadlines, authentication time and upstream identifiers",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := federatedSession("sess-a", "u-1", "https://idp.example.com", "upstream-session")
				require.NoError(t, s.Create(ctx, want))

				listed, err := s.ListByUser(ctx, "u-1", suiteStart)
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assertTimeEqual(t, want.IdleExpiresAt, listed[0].IdleExpiresAt, "IdleExpiresAt")
				assertTimeEqual(t, want.AbsoluteExpiresAt, listed[0].AbsoluteExpiresAt, "AbsoluteExpiresAt")
				assertTimeEqual(t, want.AuthenticatedAt, listed[0].AuthenticatedAt, "AuthenticatedAt")
				assert.Equal(t, want.ExternalIssuer, listed[0].ExternalIssuer, "ExternalIssuer")
				assert.Equal(t, want.ExternalSessionID, listed[0].ExternalSessionID, "ExternalSessionID")
			},
		},
		{
			name: "listing follows a family through a strict rotation, inside and past its window",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(2601))
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(time.Minute)
				successor := successorOf(old, "sess-b", at)
				successor.AuthenticatedAt = at
				window := at.Add(30 * time.Second)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: window, RetainUntil: window, Successor: successor, Now: at, Strict: true,
				}))

				for name, now := range map[string]time.Time{"inside": at, "past": window.Add(time.Minute)} {
					listed, err := s.ListByUser(ctx, "u-1", now)
					require.NoError(t, err, name)
					require.Len(t, listed, 1, "%s the window, the family is listed once, by its new session", name)
					assertListed(t, successor, listed[0])
				}
			},
		},
		{
			// The read the listing exists to serve, through a manager, so a
			// backend's renewal and rotation are what it follows.
			name: "a manager's sign-in state follows a family and leaves it as it was",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				const issuer, upstream = "https://idp.example.com", "upstream-session"

				told := 0
				m, err := session.New(session.WithStore(s), session.WithClock(clk),
					session.WithReuseObserver(func(context.Context, session.ReuseReport) { told++ }))
				require.NoError(t, err)

				first, err := m.Create(ctx, "u-1", session.WithExternalSession("idp", issuer, upstream, "an-id-token"))
				require.NoError(t, err)

				state, err := m.SignInState(ctx, "u-1", first.FamilyID)
				require.NoError(t, err, "a session never presented")
				assertTimeEqual(t, first.IdleExpiresAt, state.IdleDeadline, "IdleDeadline")
				assertTimeEqual(t, first.AbsoluteExpiresAt, state.AbsoluteDeadline, "AbsoluteDeadline")
				assertTimeEqual(t, first.AuthenticatedAt, state.AuthenticatedAt, "AuthenticatedAt")
				assert.Equal(t, issuer, state.ExternalIssuer)
				assert.Equal(t, upstream, state.ExternalSessionID)
				stored, err := s.Load(ctx, first.ID)
				require.NoError(t, err)
				assert.True(t, stored.FirstPresentedAt.IsZero(), "the read recorded a presentation")

				// A renewal past its grace window.
				clk.Advance(5 * time.Minute)
				renewed, _, err := m.RotateWithGrace(ctx, first, session.DefaultRenewalGrace)
				require.NoError(t, err)
				clk.Advance(session.DefaultRenewalGrace + time.Second)

				state, err = m.SignInState(ctx, "u-1", first.FamilyID)
				require.NoError(t, err, "a renewed sign-in past its grace window")
				assertTimeEqual(t, renewed.IdleExpiresAt, state.IdleDeadline, "IdleDeadline after a renewal")
				assert.Equal(t, upstream, state.ExternalSessionID, "a renewal keeps the upstream session")
				stored, err = s.Load(ctx, renewed.ID)
				require.NoError(t, err)
				assert.True(t, stored.FirstPresentedAt.IsZero(), "the read presented the successor")
				_, err = m.Load(ctx, renewed.ID)
				require.NoError(t, err, "the read must leave the renewed sign-in live")

				// A strict rotation, as a step-up makes.
				clk.Advance(time.Minute)
				reproved := *renewed
				reproved.AuthenticatedAt = clk.Now()
				rotated, err := m.Rotate(ctx, &reproved)
				require.NoError(t, err)

				state, err = m.SignInState(ctx, "u-1", first.FamilyID)
				require.NoError(t, err, "a strictly rotated sign-in")
				assertTimeEqual(t, rotated.AuthenticatedAt, state.AuthenticatedAt, "AuthenticatedAt after a step-up")

				_, err = m.SignInState(ctx, "someone-else", first.FamilyID)
				require.ErrorIs(t, err, session.ErrNotFound, "another user's family")
				assert.Zero(t, told, "the read reported reuse")

				// Ended.
				_, err = m.Logout(ctx, "u-1", first.FamilyID)
				require.NoError(t, err)
				_, err = m.SignInState(ctx, "u-1", first.FamilyID)
				require.ErrorIs(t, err, session.ErrNotFound, "an ended sign-in")
			},
		},
		{
			name: "a manager's sign-in state ends at a deadline, by the manager's clock",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				m, err := session.New(session.WithStore(s), session.WithClock(clk))
				require.NoError(t, err)

				created, err := m.Create(ctx, "u-1")
				require.NoError(t, err)
				clk.Advance(m.IdleTimeout() - time.Second)
				_, err = m.SignInState(ctx, "u-1", created.FamilyID)
				require.NoError(t, err, "a second before the idle deadline")

				clk.Advance(time.Second)
				_, err = m.SignInState(ctx, "u-1", created.FamilyID)
				require.ErrorIs(t, err, session.ErrNotFound, "at the idle deadline")
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

// RunSessionListAcrossReplicas holds a durable session store to listing a
// user's sign-ins from the database, not from the instance that created them.
// It creates one sign-in through the store h.New returns and another, for the
// same user, through a second instance h.NewReplica returns, then lists the
// user through each and requires both families on both, and no other user's.
//
// It fails at once, naming every missing input, when h is missing one.
func RunSessionListAcrossReplicas[S session.Store](t *testing.T, h DurableHarness[S]) {
	t.Helper()

	h.Require(t)

	t.Run("a user signed in through two replicas is listed by both", func(t *testing.T) {
		first, replica := h.New(t), h.NewReplica(t)
		const user = identity.UserID("replicas-user")
		viaFirst := withSignInState(familySession("replicas-first", user, suiteID(2501)))
		viaReplica := withSignInState(familySession("replicas-second", user, suiteID(2502)))
		stranger := familySession("replicas-stranger", "replicas-other-user", suiteID(2503))
		require.NoError(t, first.Create(t.Context(), viaFirst))
		require.NoError(t, replica.Create(t.Context(), viaReplica))
		require.NoError(t, replica.Create(t.Context(), stranger))

		now := suiteStart.Add(time.Minute)
		for name, s := range map[string]session.Store{"the first replica": first, "the second replica": replica} {
			listed, err := s.ListByUser(t.Context(), user, now)
			require.NoError(t, err, name)
			byFamily := map[id.ID]*session.Session{}
			for _, l := range listed {
				require.NotNil(t, l, "%s: a listing holds no nil session", name)
				byFamily[l.FamilyID] = l
			}
			require.ElementsMatch(t, []id.ID{suiteID(2501), suiteID(2502)}, keysOf(byFamily),
				"%s must list the sign-in made through either replica, and no other user's", name)
			assertListed(t, viaFirst, byFamily[suiteID(2501)])
			assertListed(t, viaReplica, byFamily[suiteID(2502)])
		}
	})
}
