package storetest

import (
	"cmp"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// familyReadCase is a case for session.Store.ListByFamily. Every store has the
// family read, so every case runs.
func familyReadCase(
	name string, assert func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock),
) suiteCase[session.Store] {
	return suiteCase[session.Store]{name: name, assert: assert}
}

// inOrder sorts sessions by what a sign-in's members differ in, so two reads
// whose order is unspecified can be compared pairwise.
func inOrder(sessions []*session.Session) {
	slices.SortStableFunc(sessions, func(a, b *session.Session) int {
		return cmp.Or(
			a.CreatedAt.Compare(b.CreatedAt),
			a.LastAccessedAt.Compare(b.LastAccessedAt),
			a.IdleExpiresAt.Compare(b.IdleExpiresAt),
		)
	})
}

// assertReadsAgree holds a store's family read to its listing at now: the read
// answers exactly the sessions of family the listing answers, field by field,
// and it returns them.
func assertReadsAgree(
	ctx context.Context, t *testing.T, s session.Store,
	user identity.UserID, family id.ID, now time.Time, moment string,
) []*session.Session {
	t.Helper()

	listed, err := s.ListByUser(ctx, user, now)
	require.NoError(t, err, moment)
	want := []*session.Session{}
	for _, l := range listed {
		require.NotNil(t, l, "%s: a listing holds no nil session", moment)
		if l.FamilyID == family {
			want = append(want, l)
		}
	}

	got, err := s.ListByFamily(ctx, user, family, now)
	require.NoError(t, err, moment)
	for _, g := range got {
		require.NotNil(t, g, "%s: a family read holds no nil session", moment)
	}

	require.Len(t, got, len(want), "%s: the family read and the listing must answer the same sessions", moment)
	inOrder(want)
	inOrder(got)
	for i := range want {
		assertListed(t, want[i], got[i])
	}

	return got
}

// sessionFamilyReadCases are the cases of the family read: that it is
// the listing's contract narrowed to one family, and that it never disagrees
// with the store's own listing.
func sessionFamilyReadCases() []suiteCase[session.Store] {
	return []suiteCase[session.Store]{
		familyReadCase("a family read agrees with the listing across a renewal, a strict rotation and an end",
			func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				const user = identity.UserID("u-1")

				family := suiteID(2701)
				first := familySession("sess-a", user, family)
				neighbour := familySession("sess-neighbour", user, suiteID(2702))
				stranger := familySession("sess-stranger", "u-2", suiteID(2703))
				createSessions(ctx, t, s, first, neighbour, stranger)

				read := func(now time.Time, moment string) []*session.Session {
					t.Helper()

					return assertReadsAgree(ctx, t, s, user, family, now, moment)
				}

				// A sign-in still owing a second factor is live, and both reads list it.
				pending := familySession("sess-pending", user, suiteID(2704))
				pending.MFA = session.MFAPending
				require.NoError(t, s.Create(ctx, pending))
				require.Len(t, assertReadsAgree(ctx, t, s, user, pending.FamilyID, suiteStart, "pending"), 1,
					"a sign-in owing a second factor is live")

				got := read(suiteStart, "created")
				require.Len(t, got, 1, "a new sign-in is read by its one session")
				assertListed(t, first, got[0])

				// A renewal: the predecessor stays inside its window, and past it.
				renewedAt := suiteStart.Add(2 * time.Minute)
				window := renewedAt.Add(30 * time.Second)
				renewed := successorOf(first, "sess-b", renewedAt)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: first.ID, AcceptUntil: window, RetainUntil: sessionRetainUntil, Successor: renewed, Now: renewedAt,
				}))
				for moment, now := range map[string]time.Time{
					"inside a renewal's window": renewedAt, "past a renewal's window": window.Add(time.Minute),
				} {
					got = read(now, moment)
					require.Len(t, got, 1, "%s the family is read by its successor alone", moment)
					assertListed(t, renewed, got[0])
				}

				// Recorded activity moves what the read answers.
				activeAt := renewedAt.Add(5 * time.Minute)
				require.NoError(t, s.RecordActivity(ctx, renewed.ID, activeAt, activeAt.Add(sessionIdle), activeAt))
				got = read(activeAt, "after recorded activity")
				require.Len(t, got, 1)
				assertTimeEqual(t, activeAt.Add(sessionIdle), got[0].IdleExpiresAt, "IdleExpiresAt after activity")

				// A strict rotation, inside and past its window.
				rotatedAt := activeAt.Add(time.Minute)
				rotation := rotatedAt.Add(30 * time.Second)
				rotated := successorOf(renewed, "sess-c", rotatedAt)
				rotated.AuthenticatedAt = rotatedAt
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: renewed.ID, AcceptUntil: rotation, RetainUntil: rotation, Successor: rotated, Now: rotatedAt, Strict: true,
				}))
				for moment, now := range map[string]time.Time{
					"inside a strict rotation's window": rotatedAt, "past a strict rotation's window": rotation.Add(time.Minute),
				} {
					got = read(now, moment)
					require.Len(t, got, 1, "%s the family is read by its new session alone", moment)
					assertTimeEqual(t, rotatedAt, got[0].AuthenticatedAt, "AuthenticatedAt after a strict rotation")
				}

				// Past the head's own deadline, a superseded member still in its
				// retention shows in neither.
				assert.Empty(t, read(suiteStart.Add(sessionAbsolute), "past the head's deadline"),
					"a superseded member is not read, however long it is retained")

				// Ended.
				_, err := s.DeleteFamily(ctx, family)
				require.NoError(t, err)
				assert.Empty(t, read(rotatedAt, "ended"), "an ended family is read as nothing")

				got = assertReadsAgree(ctx, t, s, user, neighbour.FamilyID, rotatedAt, "the neighbour, after the end")
				require.Len(t, got, 1, "ending one family leaves the user's other sign-in")
			}),
		familyReadCase("a family read returns only that family, of that user, matching the reference exactly",
			func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				family := suiteID(2711)
				upper := familySession("sess-upper", "Alice", family)
				lower := familySession("sess-lower", "alice", family)
				neighbour := familySession("sess-neighbour", "Alice", suiteID(2712))
				createSessions(ctx, t, s, upper, lower, neighbour)

				got, err := s.ListByFamily(ctx, "Alice", family, suiteStart)
				require.NoError(t, err)
				require.Len(t, got, 1, "another user's session of the family, or another family of the user, was read")
				assert.Equal(t, identity.UserID("Alice"), got[0].UserID)
				assert.Equal(t, family, got[0].FamilyID)

				for name, user := range map[string]identity.UserID{
					"a user with none of the family": "nobody",
					"text PostgreSQL cannot hold":    "Alice\x00",
				} {
					got, err = s.ListByFamily(ctx, user, family, suiteStart)
					require.NoError(t, err, "%s: no match is an empty result, not an error", name)
					assert.Empty(t, got, name)
				}

				got, err = s.ListByFamily(ctx, "Alice", suiteID(2713), suiteStart)
				require.NoError(t, err, "a family that is not there is an empty result, not an error")
				assert.Empty(t, got)

				got, err = s.ListByFamily(ctx, "Alice", id.Nil, suiteStart)
				require.NoError(t, err, "the nil family is an empty result, not an error")
				assert.Empty(t, got, "the nil family names none, so it reads none")
			}),
		familyReadCase("a family read judges expiry by the time the caller passes, not the store's clock",
			func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				idle := idleExpiredSession("sess-b", "u-1") // idle deadline 09:10
				require.NoError(t, s.Create(ctx, idle))

				read := func(now time.Time) []*session.Session {
					t.Helper()

					return assertReadsAgree(ctx, t, s, "u-1", idle.FamilyID, now, now.String())
				}

				assert.Len(t, read(suiteStart), 1, "before its deadline it is read")
				assert.Empty(t, read(suiteStart.Add(10*time.Minute)), "at its idle deadline it is not")

				live := sessionRecord("sess-c", "u-1")
				require.NoError(t, s.Create(ctx, live))
				got, err := s.ListByFamily(ctx, "u-1", live.FamilyID, suiteStart.Add(sessionAbsolute))
				require.NoError(t, err)
				assert.Empty(t, got, "at its absolute deadline it is not")

				// An idle deadline set past the absolute one must not keep it alive.
				pastAbsolute := sessionRecord("sess-d", "u-1")
				pastAbsolute.IdleExpiresAt = suiteStart.Add(sessionAbsolute + time.Hour)
				require.NoError(t, s.Create(ctx, pastAbsolute))
				assert.Empty(t, assertReadsAgree(ctx, t, s, "u-1", pastAbsolute.FamilyID, suiteStart.Add(sessionAbsolute), "absolute only"),
					"at its absolute deadline, with its idle deadline ahead, it is not")
			}),
		familyReadCase("a family read carries a sign-in's deadlines, authentication time and upstream identifiers",
			func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := federatedSession("sess-a", "u-1", "https://idp.example.com", "upstream-session")
				require.NoError(t, s.Create(ctx, want))

				got, err := s.ListByFamily(ctx, "u-1", want.FamilyID, suiteStart)
				require.NoError(t, err)
				require.Len(t, got, 1)
				assertTimeEqual(t, want.IdleExpiresAt, got[0].IdleExpiresAt, "IdleExpiresAt")
				assertTimeEqual(t, want.AbsoluteExpiresAt, got[0].AbsoluteExpiresAt, "AbsoluteExpiresAt")
				assertTimeEqual(t, want.AuthenticatedAt, got[0].AuthenticatedAt, "AuthenticatedAt")
				assert.Equal(t, want.ExternalIssuer, got[0].ExternalIssuer, "ExternalIssuer")
				assert.Equal(t, want.ExternalSessionID, got[0].ExternalSessionID, "ExternalSessionID")
			}),
		familyReadCase("a session a family read answers is the caller's own copy",
			func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, want))

				got, err := s.ListByFamily(ctx, "u-1", want.FamilyID, suiteStart)
				require.NoError(t, err)
				require.Len(t, got, 1)
				got[0].Data["tenant"] = "changed by the caller"
				got[0].UserAgent = "changed by the caller"

				assertSessionsLoad(ctx, t, s, want)
			}),
	}
}

// RunSessionFamilyRead holds a durable session store's family read
// (session.Store.ListByFamily) to what only a database row can show. It checks,
// writing the rows through harness.Raw, that:
//   - a row of another family that will not decode fails neither the family read
//     nor a manager's SignInState for this family, and does fail a read of the
//     family holding it, and the listing, as the contract asks;
//   - the read opens no sealed field: columns holding what no cipher would open
//     do not fail it, and its sessions carry neither token;
//   - the nil family reads nothing, even where a row is stored in it, which the
//     listing still lists;
//   - the read comes from the database, not the instance that wrote the row.
//
// It fails at once, naming every missing input, when harness is missing one.
func RunSessionFamilyRead[S session.Store](t *testing.T, harness DurableHarness[S]) {
	t.Helper()

	harness.Require(t)

	now := suiteStart.Add(time.Minute)

	t.Run("a row of another family that will not decode fails only its own family's read", func(t *testing.T) {
		s := harness.New(t)
		const user = identity.UserID("family-read-undecodable-user")
		healthy := familySession("family-read-healthy", user, suiteID(2801))
		holding := familySession("family-read-holding", user, suiteID(2802))
		require.NoError(t, s.Create(t.Context(), healthy))
		require.NoError(t, s.Create(t.Context(), holding))
		_, err := harness.Raw.ExecContext(t.Context(), `UPDATE scrty_sessions SET data = '[1]' WHERE id_digest = $1`,
			sessionDigest(holding.ID))
		require.NoError(t, err)

		_, err = s.ListByUser(t.Context(), user, now)
		require.Error(t, err, "the row was meant not to decode, so this proves nothing")

		got, err := s.ListByFamily(t.Context(), user, healthy.FamilyID, now)
		require.NoError(t, err, "another family's row must not fail this read")
		require.Len(t, got, 1)
		assertListed(t, healthy, got[0])

		_, err = s.ListByFamily(t.Context(), user, holding.FamilyID, now)
		require.Error(t, err, "a read of the family holding the row fails rather than skipping it")

		clk := clockwork.NewFakeClockAt(now)
		m, err := session.New(session.WithStore(s), session.WithClock(clk))
		require.NoError(t, err)
		_, err = m.SignInState(t.Context(), user, healthy.FamilyID)
		require.NoError(t, err, "another sign-in's row must not fail this sign-in's state")
		_, err = m.SignInState(t.Context(), user, holding.FamilyID)
		require.ErrorIs(t, err, session.ErrListUnavailable, "the sign-in holding the row is an outage, not an end")
		assert.NotErrorIs(t, err, session.ErrNotFound)
	})

	t.Run("a family read opens no sealed field", func(t *testing.T) {
		s := harness.New(t)
		const user = identity.UserID("family-read-sealed-user")
		want := withSignInState(federatedSession("family-read-sealed", user, "https://idp.example.com", "upstream-session"))
		want.FamilyID = suiteID(2811)
		require.NoError(t, s.Create(t.Context(), want))
		_, err := harness.Raw.ExecContext(t.Context(),
			`UPDATE scrty_sessions SET external_id_token = 'not-an-envelope', csrf_token = 'not-an-envelope' WHERE id_digest = $1`,
			sessionDigest(want.ID))
		require.NoError(t, err)

		got, err := s.ListByFamily(t.Context(), user, want.FamilyID, now)
		require.NoError(t, err, "the read opened a sealed column")
		require.Len(t, got, 1)
		assert.Empty(t, got[0].ExternalIDToken, "the read handed back a sealed column")
		assert.Empty(t, got[0].CSRFToken, "the read handed back a sealed column")
		assert.Equal(t, want.ExternalSessionID, got[0].ExternalSessionID, "what is not sealed is read")
	})

	t.Run("the nil family reads nothing, even where a row is stored in it", func(t *testing.T) {
		s := harness.New(t)
		const user = identity.UserID("family-read-nil-user")
		inNone := familySession("family-read-nil", user, suiteID(2821))
		require.NoError(t, s.Create(t.Context(), inNone))
		_, err := harness.Raw.ExecContext(t.Context(),
			`UPDATE scrty_sessions SET family_id = '00000000-0000-0000-0000-000000000000' WHERE id_digest = $1`,
			sessionDigest(inNone.ID))
		require.NoError(t, err)

		listed, err := s.ListByUser(t.Context(), user, now)
		require.NoError(t, err)
		require.Len(t, listed, 1, "the row was meant to stay listed, so this proves nothing")

		got, err := s.ListByFamily(t.Context(), user, id.Nil, now)
		require.NoError(t, err, "the nil family is an empty result, not an error")
		assert.Empty(t, got, "the nil family names none, so it reads none")
	})

	t.Run("a family written through one replica is read by another", func(t *testing.T) {
		first, replica := harness.New(t), harness.NewReplica(t)
		const user = identity.UserID("family-read-replica-user")
		want := familySession("family-read-replica", user, suiteID(2831))
		require.NoError(t, first.Create(t.Context(), want))

		got, err := replica.ListByFamily(t.Context(), user, want.FamilyID, now)
		require.NoError(t, err)
		require.Len(t, got, 1, "the read must come from the database")
		assertListed(t, want, got[0])
	})
}
