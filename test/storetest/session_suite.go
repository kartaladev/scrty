package storetest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// Issuers and a provider session identifier the federation cases share.
const (
	sessionIssuerA = "https://a.example"
	sessionIssuerB = "https://b.example"
	sessionSID     = "sid-1"
)

// sessionIdle and sessionAbsolute are every suite session's deadlines,
// relative to suiteStart.
const (
	sessionIdle     = 30 * time.Minute
	sessionAbsolute = 8 * time.Hour
)

// sessionRetainUntil is the retention deadline the suite's supersessions
// give, 21:00 on the suite's day: later than any suite session's own absolute
// deadline, as the family maximum a manager computes it from is.
var sessionRetainUntil = suiteStart.Add(11 * time.Hour)

// sessionFamily returns the family sessionRecord gives a session: one of its
// own, derived from its identifier, so two suite sessions share a family only
// when a case puts them in one.
func sessionFamily(sessionID string) id.ID {
	sum := sha256.Sum256([]byte("family:" + sessionID))
	return id.ID(sum[:16])
}

// sessionRecord returns a session for user, created at suiteStart in a family
// of its own, with every field set so a store that drops one is caught. It
// authenticated five minutes before its record was written, so a store that
// reads the creation time back as the authentication time is caught too.
func sessionRecord(sessionID string, user identity.UserID) *session.Session {
	return &session.Session{
		ID:                    sessionID,
		UserID:                user,
		CreatedAt:             suiteStart,
		AuthenticatedAt:       suiteStart.Add(-5 * time.Minute),
		FamilyID:              sessionFamily(sessionID),
		FamilyCreatedAt:       suiteStart,
		LastAccessedAt:        suiteStart.Add(time.Minute),
		IdleExpiresAt:         suiteStart.Add(sessionIdle),
		AbsoluteExpiresAt:     suiteStart.Add(sessionAbsolute),
		FirstFactor:           factor.Password,
		MFA:                   session.MFASatisfied,
		MFASatisfiedAt:        suiteStart.Add(2 * time.Minute),
		PasswordChangePending: true,
		// EnrolmentOriginDeadline and EnrolmentGeneration are left zero: a
		// satisfied session was never marked, or its mark was cleared on the
		// upgrade. enrolmentSession sets them.
		Data: map[string]string{
			"tenant": "t-9",
			"flags":  "a,b",
			"":       "empty key",
			"ключ":   "值",
		},
	}
}

// federatedSession returns a session established through issuer, carrying the
// provider's session identifier sid. It was established on one factor, so
// its second-factor state is the zero MFANone, which a store must not read
// back as any other state.
func federatedSession(sessionID string, user identity.UserID, issuer, sid string) *session.Session {
	s := sessionRecord(sessionID, user)
	s.FirstFactor = factor.OIDC
	s.MFA = session.MFANone
	s.MFASatisfiedAt = time.Time{}
	s.ExternalProvider = "corp"
	s.ExternalIssuer = issuer
	s.ExternalSessionID = sid
	s.ExternalIDToken = "header.payload.signature"
	return s
}

// enrolmentSession returns an enrolment-only session for user: pending
// enrolment, its absolute deadline lowered, and marked with the deadline it
// held before, 21:00 on the suite's day, and with the enrolment generation
// gen.
func enrolmentSession(sessionID string, user identity.UserID, gen id.ID) *session.Session {
	s := sessionRecord(sessionID, user)
	s.AbsoluteExpiresAt = suiteStart.Add(15 * time.Minute)
	s.MFA = session.MFAEnrolmentPending
	s.MFASatisfiedAt = time.Time{}
	s.EnrolmentOriginDeadline = suiteStart.Add(11 * time.Hour)
	s.EnrolmentGeneration = gen
	return s
}

// recoveryPendingSession returns a recovery-pending session for user: an
// account recovery's kind and confinement, its absolute deadline lowered, and
// marked with the deadline it held before, 21:00 on the suite's day, and the
// time the recovery completed, 09:00.
func recoveryPendingSession(sessionID string, user identity.UserID) *session.Session {
	s := sessionRecord(sessionID, user)
	s.FirstFactor = factor.Recovery
	s.AbsoluteExpiresAt = suiteStart.Add(15 * time.Minute)
	s.MFA = session.MFARecoveryPending
	s.MFASatisfiedAt = time.Time{}
	s.EnrolmentOriginDeadline = suiteStart.Add(11 * time.Hour)
	s.RecoveredAt = suiteStart.Add(-time.Hour)
	return s
}

// secondFactorAtLoginSession returns a satisfied session for user whose
// second factor was met at the first factor: the marker set, the first factor a
// passkey, and the satisfied time the creation time.
func secondFactorAtLoginSession(sessionID string, user identity.UserID) *session.Session {
	s := sessionRecord(sessionID, user)
	s.FirstFactor = factor.Passkey
	s.MFA = session.MFASatisfied
	s.MFASatisfiedAt = s.CreatedAt
	s.PasswordChangePending = false
	s.MFAAtFirstFactor = true
	return s
}

// idleExpiredSession returns a session whose idle deadline has passed by the
// time the suite's clock reaches suiteStart plus sessionIdle.
func idleExpiredSession(sessionID string, user identity.UserID) *session.Session {
	s := sessionRecord(sessionID, user)
	s.IdleExpiresAt = suiteStart.Add(10 * time.Minute)
	return s
}

// familySession returns sessionRecord's session as a member of family, which
// started at the session's creation.
func familySession(sessionID string, user identity.UserID, family id.ID) *session.Session {
	s := sessionRecord(sessionID, user)
	s.FamilyID = family
	s.FamilyCreatedAt = s.CreatedAt
	return s
}

// successorOf returns the session a rotation at at would insert in place of
// old: a new identifier in old's family, with old's family start and
// absolute deadline, created and last accessed at at.
func successorOf(old *session.Session, sessionID string, at time.Time) *session.Session {
	s := sessionRecord(sessionID, old.UserID)
	s.AuthenticatedAt = old.AuthenticatedAt
	s.FamilyID = old.FamilyID
	s.FamilyCreatedAt = old.FamilyCreatedAt
	s.CreatedAt = at
	s.LastAccessedAt = at
	s.IdleExpiresAt = at.Add(sessionIdle)
	s.AbsoluteExpiresAt = old.AbsoluteExpiresAt
	return s
}

// sessionDigest is the digest a store records as a superseded session's
// successor: the SHA-256 of the successor's identifier.
func sessionDigest(sessionID string) []byte {
	sum := sha256.Sum256([]byte(sessionID))
	return sum[:]
}

// supersededAs returns old as a store must hold it once superseded at now,
// with its window ending at acceptUntil, successor as its current successor
// and the suite's retention deadline, sessionRetainUntil.
func supersededAs(old *session.Session, successor string, now, acceptUntil time.Time) *session.Session {
	return supersededUntil(old, successor, now, acceptUntil, sessionRetainUntil)
}

// supersededUntil is supersededAs with the retention deadline retain: both
// deadlines become retain, and nothing else changes.
func supersededUntil(old *session.Session, successor string, now, acceptUntil, retain time.Time) *session.Session {
	s := *old
	s.SupersededAt = now
	s.AcceptUntil = acceptUntil
	s.SuccessorDigest = sessionDigest(successor)
	s.IdleExpiresAt, s.AbsoluteExpiresAt = retain, retain
	return &s
}

// knockedOutAs returns previous, a successor a re-rotation superseded at now,
// as a store must hold it: superseded with a window that ended at now, no
// successor of its own, and the retention deadline retain as both deadlines.
func knockedOutAs(previous *session.Session, now, retain time.Time) *session.Session {
	s := *previous
	s.SupersededAt, s.AcceptUntil = now, now
	s.IdleExpiresAt, s.AbsoluteExpiresAt = retain, retain
	return &s
}

// assertSession compares a loaded session with the one stored, field by
// field. A Data map with no entries, nil or empty, must load as one with no
// entries.
func assertSession(t *testing.T, want, got *session.Session) {
	t.Helper()

	require.NotNil(t, got, "a loaded session must not be nil")
	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.UserID, got.UserID, "the user reference must round-trip byte for byte")
	assertTimeEqual(t, want.CreatedAt, got.CreatedAt, "CreatedAt")
	assertTimeEqual(t, want.LastAccessedAt, got.LastAccessedAt, "LastAccessedAt")
	assertTimeEqual(t, want.IdleExpiresAt, got.IdleExpiresAt, "IdleExpiresAt")
	assertTimeEqual(t, want.AbsoluteExpiresAt, got.AbsoluteExpiresAt, "AbsoluteExpiresAt")
	assert.Equal(t, want.FirstFactor, got.FirstFactor)
	assert.Equal(t, want.MFA, got.MFA, "MFA is %v, want %v", got.MFA, want.MFA)
	assertTimeEqual(t, want.MFASatisfiedAt, got.MFASatisfiedAt, "MFASatisfiedAt")
	assert.Equal(t, want.PasswordChangePending, got.PasswordChangePending)
	assertTimeEqual(t, want.EnrolmentOriginDeadline, got.EnrolmentOriginDeadline, "EnrolmentOriginDeadline")
	assert.Equal(t, want.EnrolmentGeneration, got.EnrolmentGeneration, "EnrolmentGeneration")
	assertTimeEqual(t, want.RecoveredAt, got.RecoveredAt, "RecoveredAt")
	assert.Equal(t, want.MFAAtFirstFactor, got.MFAAtFirstFactor, "MFAAtFirstFactor")
	assertTimeEqual(t, want.AuthenticatedAt, got.AuthenticatedAt, "AuthenticatedAt")
	if len(want.FederatedAMR) == 0 {
		assert.Empty(t, got.FederatedAMR, "a session stored without amr must load with none")
	} else {
		assert.Equal(t, want.FederatedAMR, got.FederatedAMR, "the asserted amr must round-trip in order")
	}
	assert.Equal(t, want.FederatedACR, got.FederatedACR, "the asserted acr must round-trip unchanged")
	assert.Equal(t, want.FamilyID, got.FamilyID, "FamilyID")
	assertTimeEqual(t, want.FamilyCreatedAt, got.FamilyCreatedAt, "FamilyCreatedAt")
	assertTimeEqual(t, want.SupersededAt, got.SupersededAt, "SupersededAt")
	assertTimeEqual(t, want.AcceptUntil, got.AcceptUntil, "AcceptUntil")
	assertTimeEqual(t, want.FirstPresentedAt, got.FirstPresentedAt, "FirstPresentedAt")
	if len(want.SuccessorDigest) == 0 {
		assert.Empty(t, got.SuccessorDigest, "a session never superseded must load with no successor")
	} else {
		assert.Equal(t, want.SuccessorDigest, got.SuccessorDigest, "SuccessorDigest")
	}
	assert.Equal(t, want.ExternalProvider, got.ExternalProvider)
	assert.Equal(t, want.ExternalIssuer, got.ExternalIssuer)
	assert.Equal(t, want.ExternalSessionID, got.ExternalSessionID)
	assert.Equal(t, want.ExternalIDToken, got.ExternalIDToken)
	if len(want.Data) == 0 {
		assert.Empty(t, got.Data, "a session stored with no data must load with no data")
	} else {
		assert.Equal(t, want.Data, got.Data, "the consumer's data must round-trip unchanged")
	}
}

// createSessions stores every session, failing the case at the first error.
func createSessions(ctx context.Context, t *testing.T, s session.Store, sessions ...*session.Session) {
	t.Helper()

	for _, sess := range sessions {
		require.NoError(t, s.Create(ctx, sess), "create %s", sess.ID)
	}
}

// assertSessionsLoad requires each session to load unchanged.
func assertSessionsLoad(ctx context.Context, t *testing.T, s session.Store, sessions ...*session.Session) {
	t.Helper()

	for _, want := range sessions {
		got, err := s.Load(ctx, want.ID)
		if assert.NoError(t, err, "session %s must still load", want.ID) {
			assertSession(t, want, got)
		}
	}
}

// assertSessionsGone requires each identifier to be not found.
func assertSessionsGone(ctx context.Context, t *testing.T, s session.Store, ids ...string) {
	t.Helper()

	for _, sessionID := range ids {
		_, err := s.Load(ctx, sessionID)
		assert.ErrorIs(t, err, session.ErrSessionNotFound, "session %s must be gone", sessionID)
	}
}

// sessionTextWrite is which write a textCase exercises.
type sessionTextWrite int

const (
	// sessionTextCreate writes the tainted session directly with Create.
	sessionTextCreate sessionTextWrite = iota
	// sessionTextSave creates a clean session first, then writes the tainted
	// copy with Save.
	sessionTextSave
)

// RunSessionStoreSuite checks a session.Store against the contract the
// session manager relies on: a session round-trips every field, its Data map
// included, and its user reference byte for byte; what is handed over and
// handed back is the caller's own copy; text a PostgreSQL text column cannot
// hold (a NUL byte, invalid UTF-8) in the data or the user reference is either
// refused, with an error that does not echo it, or round-trips unchanged, and
// is never altered; Create never replaces, and Save
// replaces the record whole but never inserts; Load judges both deadlines by the store's clock; the
// active count and every deletion are exact; and the federation deletions
// match nothing on an empty issuer or provider session identifier.
//
// newStore is called once per case and must return an empty store that reads
// time from clk. The suite advances clk itself and never waits.
//
// A consumer implementing session.Store over their own database calls this
// from a test in their own module:
//
//	func TestMySessionStoreConformance(t *testing.T) {
//	    storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
//	        return newMySessionStore(t, clk)
//	    })
//	}
func RunSessionStoreSuite(t *testing.T, newStore func(t *testing.T, clk clock.Clock) session.Store) {
	t.Helper()

	type sessionCase = suiteCase[session.Store]

	dataCase := func(name string, data map[string]string) sessionCase {
		return sessionCase{
			name: name,
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "u-1")
				want.Data = data
				require.NoError(t, s.Create(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSession(t, want, got)
			},
		}
	}

	// mfaSaveCase saves over a session satisfied at its creation one whose
	// second factor is in state, satisfied at at, which may be zero.
	mfaSaveCase := func(name string, state session.MFAState, at time.Time) sessionCase {
		return sessionCase{
			name: name,
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, sessionRecord("sess-a", "u-1")))

				saved := sessionRecord("sess-a", "u-1")
				saved.MFA = state
				saved.MFASatisfiedAt = at
				require.NoError(t, s.Save(ctx, saved))

				assertSessionsLoad(ctx, t, s, saved)
			},
		}
	}

	// textCase creates the session sessionRecord returns, changed by with to
	// carry text a PostgreSQL text column cannot hold, marked by canary. The
	// store either refuses it, with an error that does not echo it, and
	// stores nothing; or stores it and loads it byte for byte. Anything else
	// altered the consumer's value.
	//
	// write chooses whether the tainted session is written by Create, storing
	// it directly, or Save, replacing a session already created clean: a
	// store may refuse or alter text on either write, and this exercises
	// both. On a Save refusal, the clean session created beforehand must
	// still load unchanged — Save must never leave a partial update behind.
	//
	// On a Save write, want also moves fields besides the tainted one —
	// LastAccessedAt, IdleExpiresAt, MFA, MFASatisfiedAt,
	// PasswordChangePending — away from clean's. A store that commits those
	// columns before refusing the tainted text would otherwise look
	// unchanged: want's untainted fields would equal clean's already, and
	// the refusal check below would compare clean against itself.
	textCase := func(write sessionTextWrite, name, canary string, with func(*session.Session)) sessionCase {
		return sessionCase{
			name: name,
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				var clean *session.Session
				if write == sessionTextSave {
					clean = sessionRecord("sess-a", "u-1")
					require.NoError(t, s.Create(ctx, clean))
				}

				want := sessionRecord("sess-a", "u-1")
				if write == sessionTextSave {
					want.LastAccessedAt = want.LastAccessedAt.Add(10 * time.Minute)
					want.IdleExpiresAt = want.IdleExpiresAt.Add(10 * time.Minute)
					want.MFA = session.MFAPending
					want.MFASatisfiedAt = time.Time{}
					want.PasswordChangePending = false
				}
				with(want)

				var err error
				if write == sessionTextSave {
					err = s.Save(ctx, want)
				} else {
					err = s.Create(ctx, want)
				}

				if err != nil {
					assert.NotContains(t, err.Error(), canary, "the refusal must not echo the value")
					if write == sessionTextSave {
						assertSessionsLoad(ctx, t, s, clean)
					} else {
						assertSessionsGone(ctx, t, s, "sess-a")
					}
					return
				}
				assertSessionsLoad(ctx, t, s, want)
			},
		}
	}

	cases := []sessionCase{
		dataCase("a created session loads with every field unchanged, non-ASCII data included",
			sessionRecord("sess-a", "u-1").Data),
		dataCase("a session created with a nil data map loads with an empty one", nil),
		dataCase("a session created with an empty data map loads with an empty one", map[string]string{}),
		{
			name: "a federated session loads with its provider fields unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				require.NoError(t, s.Create(ctx, want))

				assertSessionsLoad(ctx, t, s, want)
			},
		},
		{
			name: "a federated session loads with its asserted assurance unchanged, in order",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				want.FederatedAMR = []string{"pwd", "mfa"}
				want.FederatedACR = "urn:corp:loa:2"
				require.NoError(t, s.Create(ctx, want))

				assertSessionsLoad(ctx, t, s, want)
			},
		},
		{
			name: "a session created with an empty amr list loads with none",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "u-1")
				want.FederatedAMR = []string{}
				require.NoError(t, s.Create(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSession(t, want, got)
				assert.Empty(t, got.FederatedACR)
			},
		},
		{
			name: "a save keeps the asserted assurance a loaded session carries",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				want.FederatedAMR = []string{"mfa"}
				want.FederatedACR = "urn:corp:loa:2"
				require.NoError(t, s.Create(ctx, want))

				loaded, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				loaded.LastAccessedAt = loaded.LastAccessedAt.Add(time.Minute)
				require.NoError(t, s.Save(ctx, loaded))

				again, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assert.Equal(t, []string{"mfa"}, again.FederatedAMR)
				assert.Equal(t, "urn:corp:loa:2", again.FederatedACR)
			},
		},
		{
			name: "a save replaces the asserted assurance, and a save with none clears it",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				first := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				first.FederatedAMR = []string{"pwd"}
				first.FederatedACR = "a"
				require.NoError(t, s.Create(ctx, first))

				replaced := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				replaced.FederatedAMR = []string{"mfa"}
				replaced.FederatedACR = "b"
				require.NoError(t, s.Save(ctx, replaced))
				assertSessionsLoad(ctx, t, s, replaced)

				cleared := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				cleared.FederatedAMR = nil
				cleared.FederatedACR = ""
				require.NoError(t, s.Save(ctx, cleared))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assert.Empty(t, got.FederatedAMR, "a save with no amr must leave none")
				assert.Empty(t, got.FederatedACR, "a save with no acr must leave none")
			},
		},
		{
			name: "a user reference round-trips byte for byte and is matched exactly",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "Alice@Example.COM ")
				require.NoError(t, s.Create(ctx, want))

				assertSessionsLoad(ctx, t, s, want)
				for _, other := range []identity.UserID{"alice@example.com", "Alice@Example.COM", "alice@example.com "} {
					n, err := s.CountActiveByUser(ctx, other)
					require.NoError(t, err)
					assert.Zero(t, n, "%q is another user", other)
				}
			},
		},
		textCase(sessionTextCreate, "session data holding a NUL byte is refused or round-trips, never altered",
			"canary-7f3a", func(sess *session.Session) { sess.Data["nul"] = "before\x00canary-7f3a" }),
		textCase(sessionTextCreate, "session data holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-9c1e", func(sess *session.Session) { sess.Data["latin1"] = "caf\xe9 canary-9c1e" }),
		textCase(sessionTextCreate, "a user reference holding a NUL byte is refused or round-trips, never altered",
			"canary-51d2", func(sess *session.Session) { sess.UserID = "u\x00canary-51d2" }),
		textCase(sessionTextSave, "a saved session's data holding a NUL byte is refused or round-trips, never altered",
			"canary-6a1f", func(sess *session.Session) { sess.Data["nul"] = "before\x00canary-6a1f" }),
		textCase(sessionTextSave,
			"a saved session's data holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-2d4c", func(sess *session.Session) { sess.Data["latin1"] = "caf\xe9 canary-2d4c" }),
		textCase(sessionTextSave,
			"a saved session's user reference holding a NUL byte is refused or round-trips, never altered",
			"canary-8e93", func(sess *session.Session) { sess.UserID = "u\x00canary-8e93" }),
		textCase(sessionTextCreate, "an asserted amr holding a NUL byte is refused or round-trips, never altered",
			"canary-a41b", func(sess *session.Session) { sess.FederatedAMR = []string{"pwd", "x\x00canary-a41b"} }),
		textCase(sessionTextCreate, "an asserted amr holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-b52c", func(sess *session.Session) { sess.FederatedAMR = []string{"caf\xe9 canary-b52c"} }),
		textCase(sessionTextCreate, "an asserted acr holding a NUL byte is refused or round-trips, never altered",
			"canary-c63d", func(sess *session.Session) { sess.FederatedACR = "x\x00canary-c63d" }),
		textCase(sessionTextCreate, "an asserted acr holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-d74e", func(sess *session.Session) { sess.FederatedACR = "caf\xe9 canary-d74e" }),
		textCase(sessionTextSave, "a saved session's amr holding a NUL byte is refused or round-trips, never altered",
			"canary-e85f", func(sess *session.Session) { sess.FederatedAMR = []string{"pwd", "x\x00canary-e85f"} }),
		textCase(sessionTextSave,
			"a saved session's amr holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-f960", func(sess *session.Session) { sess.FederatedAMR = []string{"caf\xe9 canary-f960"} }),
		textCase(sessionTextSave, "a saved session's acr holding a NUL byte is refused or round-trips, never altered",
			"canary-0a71", func(sess *session.Session) { sess.FederatedACR = "x\x00canary-0a71" }),
		textCase(sessionTextSave,
			"a saved session's acr holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-1b82", func(sess *session.Session) { sess.FederatedACR = "caf\xe9 canary-1b82" }),
		{
			name: "a duplicate create errors and leaves the original unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				original := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, original))

				usurper := sessionRecord("sess-a", "u-2")
				usurper.Data = map[string]string{"tenant": "other"}
				require.Error(t, s.Create(ctx, usurper), "creating over a stored identifier must fail")

				assertSessionsLoad(ctx, t, s, original)
			},
		},
		{
			// Save replaces the record whole, so every field Create round-trips
			// is changed here: a store updating a partial column list keeps
			// the ones it left out, and loads them back.
			name: "a saved session loads with every field saved, its user and provider included",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)))

				saved := sessionRecord("sess-a", "u-2")
				saved.CreatedAt = suiteStart.Add(-time.Minute)
				saved.LastAccessedAt = suiteStart.Add(5 * time.Minute)
				saved.IdleExpiresAt = suiteStart.Add(35 * time.Minute)
				saved.AbsoluteExpiresAt = suiteStart.Add(4 * time.Hour)
				saved.FirstFactor = factor.Password
				saved.MFA = session.MFAPending
				saved.MFASatisfiedAt = time.Time{}
				saved.PasswordChangePending = false
				saved.ExternalProvider = "partner"
				saved.ExternalIssuer = sessionIssuerB
				saved.ExternalSessionID = "sid-2"
				saved.ExternalIDToken = "header.payload2.signature2"
				saved.Data = map[string]string{"tenant": "t-10"}
				require.NoError(t, s.Save(ctx, saved))

				assertSessionsLoad(ctx, t, s, saved)
			},
		},
		mfaSaveCase("a save moves the second-factor time to the one saved",
			session.MFASatisfied, suiteStart.Add(5*time.Minute)),
		mfaSaveCase("a save that clears the second-factor time loads it cleared", session.MFAPending, time.Time{}),
		{
			// The authentication time is the sign-in's, written by Create:
			// a save of a copy that moved it leaves it as it was.
			name: "save keeps the authentication time",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				created := sessionRecord("sess-a", "u-1")
				created.AuthenticatedAt = suiteStart.Add(-2 * time.Hour)
				require.NoError(t, s.Create(ctx, created))

				loaded, err := s.Load(ctx, created.ID)
				require.NoError(t, err)
				loaded.AuthenticatedAt = suiteStart.Add(time.Minute)
				require.NoError(t, s.Save(ctx, loaded))

				got, err := s.Load(ctx, created.ID)
				require.NoError(t, err)
				assertTimeEqual(t, created.AuthenticatedAt, got.AuthenticatedAt, "AuthenticatedAt after a save")
			},
		},
		{
			// Created marked, then saved marked again with a new marker and
			// generation, as a second begin in the session moves them: both
			// writes must carry the three fields.
			name: "Enrolment-only session round trip",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				created := enrolmentSession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, created))
				assertSessionsLoad(ctx, t, s, created)

				saved := enrolmentSession("sess-a", "u-1", suiteID(2))
				saved.EnrolmentOriginDeadline = suiteStart.Add(7 * time.Hour)
				require.NoError(t, s.Save(ctx, saved))
				assertSessionsLoad(ctx, t, s, saved)
			},
		},
		{
			name: "Unmarked session",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				unmarked := sessionRecord("sess-a", "u-1")
				unmarked.MFA = session.MFAPending
				unmarked.MFASatisfiedAt = time.Time{}
				require.NoError(t, s.Create(ctx, unmarked))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSession(t, unmarked, got)
				assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "an unmarked session loads with no marker")
				assert.Equal(t, id.Nil, got.EnrolmentGeneration, "an unmarked session loads with no generation")

				require.NoError(t, s.Save(ctx, unmarked))
				assertSessionsLoad(ctx, t, s, unmarked)
			},
		},
		{
			// The upgrade restores the deadline and clears the marker and the
			// generation: a save must replace them with the zero values, not
			// read the zero values as "not given".
			name: "Marker cleared on upgrade",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, enrolmentSession("sess-a", "u-1", suiteID(1))))

				upgraded := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Save(ctx, upgraded))

				assertSessionsLoad(ctx, t, s, upgraded)
			},
		},
		{
			// Created recovery-pending, with its confinement marker and
			// recovery time set, mirroring the enrolment path's own round
			// trip: both are stored in columns of their own, and both must
			// come back unchanged.
			name: "Recovery-pending session round trip",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := recoveryPendingSession("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, want))

				assertSessionsLoad(ctx, t, s, want)
			},
		},
		{
			// The marker is stored in a column of its own, and comes back
			// with the state and satisfied time it was created beside.
			name: "marker round trip",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := secondFactorAtLoginSession("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, want))
				require.NoError(t, s.Save(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertSession(t, want, got)
				assert.True(t, got.MFAAtFirstFactor)
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assertTimeEqual(t, want.MFASatisfiedAt, got.MFASatisfiedAt, "MFASatisfiedAt")
			},
		},
		{
			name: "unmarked",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				totp := sessionRecord("sess-a", "u-1")
				totp.FirstFactor = factor.Password
				require.NoError(t, s.Create(ctx, totp))
				require.NoError(t, s.Save(ctx, totp))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.False(t, got.MFAAtFirstFactor, "a session saved without the marker loads unmarked")
			},
		},
		{
			// Only Create writes the marker: a save keeps the stored value,
			// so a later save can never set it.
			name: "a save does not set the marker",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, sess))

				sess.MFAAtFirstFactor = true
				require.NoError(t, s.Save(ctx, sess))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assert.False(t, got.MFAAtFirstFactor, "a save must not set the marker")
			},
		},
		{
			name: "a save does not clear the marker",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				sess := secondFactorAtLoginSession("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, sess))

				sess.MFAAtFirstFactor = false
				require.NoError(t, s.Save(ctx, sess))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assert.True(t, got.MFAAtFirstFactor, "a save keeps the stored marker")
			},
		},
		{
			name: "never recovered reads with zero RecoveredAt",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				never := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, never))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assert.True(t, got.RecoveredAt.IsZero(), "a session never recovered loads with a zero RecoveredAt")
			},
		},
		{
			// Save replaces the record whole, so an absent map and empty
			// provider fields replace what was stored: a store reading them as
			// "not given" keeps a federated session's provider after it is
			// saved as a password one.
			name: "a save that clears the data and provider fields loads them cleared",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)))

				cleared := federatedSession("sess-a", "u-1", "", "")
				cleared.ExternalProvider = ""
				cleared.ExternalIDToken = ""
				cleared.Data = nil
				require.NoError(t, s.Save(ctx, cleared))

				assertSessionsLoad(ctx, t, s, cleared)
			},
		},
		{
			name: "session times keep at least microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				want := sessionRecord("sess-a", "u-1")
				want.CreatedAt = preciseStart
				want.LastAccessedAt = preciseStart.Add(time.Minute)
				want.IdleExpiresAt = preciseStart.Add(sessionIdle)
				want.AbsoluteExpiresAt = preciseStart.Add(sessionAbsolute)
				want.MFASatisfiedAt = preciseStart.Add(2 * time.Minute)
				require.NoError(t, s.Create(ctx, want))

				got, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				assertTimeMicro(t, want.CreatedAt, got.CreatedAt, "CreatedAt")
				assertTimeMicro(t, want.LastAccessedAt, got.LastAccessedAt, "LastAccessedAt")
				assertTimeMicro(t, want.IdleExpiresAt, got.IdleExpiresAt, "IdleExpiresAt")
				assertTimeMicro(t, want.AbsoluteExpiresAt, got.AbsoluteExpiresAt, "AbsoluteExpiresAt")
				assertTimeMicro(t, want.MFASatisfiedAt, got.MFASatisfiedAt, "MFASatisfiedAt")
			},
		},
		{
			name: "a created, saved or loaded session is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				created := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, created))
				created.Data["tenant"] = "written after create"
				assertSessionsLoad(ctx, t, s, sessionRecord("sess-a", "u-1"))

				saved := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Save(ctx, saved))
				saved.Data["tenant"] = "written after save"
				assertSessionsLoad(ctx, t, s, sessionRecord("sess-a", "u-1"))

				loaded, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				loaded.Data["tenant"] = "written after load"
				assertSessionsLoad(ctx, t, s, sessionRecord("sess-a", "u-1"))
			},
		},
		{
			name: "saving a deleted session is not found and does not bring it back",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, sess))
				require.NoError(t, s.Delete(ctx, "sess-a"))

				require.ErrorIs(t, s.Save(ctx, sess), session.ErrSessionNotFound,
					"a save must never insert: a revoked session would come back")
				assertSessionsGone(ctx, t, s, "sess-a")
			},
		},
		{
			name: "saving a session never created is not found",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.ErrorIs(t, s.Save(ctx, sessionRecord("sess-a", "u-1")), session.ErrSessionNotFound)
				assertSessionsGone(ctx, t, s, "sess-a")
			},
		},
		{
			name: "loading an unknown session is not found",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, sessionRecord("sess-a", "u-1")))

				assertSessionsGone(ctx, t, s, "sess-missing")
			},
		},
		{
			name: "deleting removes only that session, and deleting an absent one is not an error",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				keep := sessionRecord("sess-b", "u-1")
				createSessions(ctx, t, s, sessionRecord("sess-a", "u-1"), keep)

				require.NoError(t, s.Delete(ctx, "sess-a"))
				require.NoError(t, s.Delete(ctx, "sess-a"))
				require.NoError(t, s.Delete(ctx, "sess-missing"))

				assertSessionsGone(ctx, t, s, "sess-a")
				assertSessionsLoad(ctx, t, s, keep)
			},
		},
		{
			name: "a session loads before its idle deadline and is expired at it",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, sess))

				clock.Advance((sess.IdleExpiresAt.Add(-time.Second)).Sub(clock.Now()))
				assertSessionsLoad(ctx, t, s, sess)

				clock.Advance((sess.IdleExpiresAt).Sub(clock.Now()))
				_, err := s.Load(ctx, "sess-a")
				require.ErrorIs(t, err, session.ErrSessionExpired, "the idle deadline is judged by the store's clock")
			},
		},
		{
			name: "a session is expired at its absolute deadline even before its idle one",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				sess.IdleExpiresAt = suiteStart.Add(2 * time.Hour)
				sess.AbsoluteExpiresAt = suiteStart.Add(time.Hour)
				require.NoError(t, s.Create(ctx, sess))

				clock.Advance((sess.AbsoluteExpiresAt.Add(-time.Second)).Sub(clock.Now()))
				assertSessionsLoad(ctx, t, s, sess)

				clock.Advance((sess.AbsoluteExpiresAt).Sub(clock.Now()))
				_, err := s.Load(ctx, "sess-a")
				require.ErrorIs(t, err, session.ErrSessionExpired, "either deadline ends a session")
			},
		},
		{
			name: "the active count is exactly the user's unexpired sessions",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				absoluteExpired := sessionRecord("sess-e", "u-1")
				absoluteExpired.IdleExpiresAt = suiteStart.Add(2 * time.Hour)
				absoluteExpired.AbsoluteExpiresAt = suiteStart.Add(10 * time.Minute)
				createSessions(ctx, t, s,
					sessionRecord("sess-a", "u-1"),
					sessionRecord("sess-b", "u-1"),
					idleExpiredSession("sess-c", "u-1"),
					sessionRecord("sess-d", "u-2"),
					absoluteExpired,
				)
				clock.Advance((suiteStart.Add(10 * time.Minute)).Sub(clock.Now()))

				for user, want := range map[identity.UserID]int{"u-1": 2, "u-2": 1, "U-1": 0, "u-missing": 0} {
					n, err := s.CountActiveByUser(ctx, user)
					require.NoError(t, err)
					assert.Equal(t, want, n,
						"active sessions of %q: one past its idle deadline and one past its absolute deadline are out", user)
				}
			},
		},
		{
			name: "deleting by user removes every session of that user, expired ones included, and no other",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				keep := []*session.Session{sessionRecord("sess-d", "u-2"), sessionRecord("sess-e", "U-1")}
				createSessions(ctx, t, s, sessionRecord("sess-a", "u-1"), sessionRecord("sess-b", "u-1"),
					idleExpiredSession("sess-c", "u-1"))
				createSessions(ctx, t, s, keep...)
				clock.Advance((suiteStart.Add(10 * time.Minute)).Sub(clock.Now()))

				require.NoError(t, s.DeleteByUser(ctx, "u-1"))

				clock.Advance((suiteStart).Sub(clock.Now()))
				assertSessionsGone(ctx, t, s, "sess-a", "sess-b", "sess-c")
				assertSessionsLoad(ctx, t, s, keep...)
			},
		},
		{
			name: "deleting by user except one removes the user's other sessions, expired ones included, and keeps that one",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				kept := sessionRecord("sess-x1", "u-x")
				others := []*session.Session{sessionRecord("sess-y", "u-y"), sessionRecord("sess-x9", "U-X")}
				createSessions(ctx, t, s, kept, sessionRecord("sess-x2", "u-x"), idleExpiredSession("sess-x3", "u-x"))
				createSessions(ctx, t, s, others...)
				clock.Advance((suiteStart.Add(10 * time.Minute)).Sub(clock.Now()))

				n, err := s.DeleteByUserExcept(ctx, "u-x", "sess-x1")
				require.NoError(t, err)

				assert.Equal(t, 2, n, "the count is of the sessions removed, expired ones included")
				clock.Advance((suiteStart).Sub(clock.Now()))
				assertSessionsGone(ctx, t, s, "sess-x2", "sess-x3")
				assertSessionsLoad(ctx, t, s, append(others, kept)...)
			},
		},
		{
			name: "deleting by user except an expired session keeps it, still expired, and removes the user's other sessions",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				kept := idleExpiredSession("sess-k1", "u-k")
				other := sessionRecord("sess-k2", "u-k")
				absoluteExpired := sessionRecord("sess-k3", "u-k")
				absoluteExpired.IdleExpiresAt = suiteStart.Add(2 * time.Hour)
				absoluteExpired.AbsoluteExpiresAt = suiteStart.Add(10 * time.Minute)
				createSessions(ctx, t, s, kept, other, absoluteExpired)
				clock.Advance((suiteStart.Add(10 * time.Minute)).Sub(clock.Now()))

				n, err := s.DeleteByUserExcept(ctx, "u-k", "sess-k1")
				require.NoError(t, err)

				assert.Equal(t, 2, n, "the kept session is not counted, expired or not")
				_, err = s.Load(ctx, "sess-k1")
				assert.ErrorIs(t, err, session.ErrSessionExpired, "the kept session stays stored and stays expired, not gone")
				clock.Advance((suiteStart).Sub(clock.Now()))
				assertSessionsGone(ctx, t, s, "sess-k2", "sess-k3")
			},
		},
		{
			name: "deleting by user except one for a user reference no store could hold removes nothing and touches no other user",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				other := sessionRecord("sess-n1", "u-n")
				createSessions(ctx, t, s, other, sessionRecord("sess-n2", "u-n"))

				n, err := s.DeleteByUserExcept(ctx, "u\x00n", "sess-n1")
				require.NoError(t, err)

				assert.Zero(t, n)
				assertSessionsLoad(ctx, t, s, other, sessionRecord("sess-n2", "u-n"))
			},
		},
		{
			name: "deleting by user except another user's session removes every session of the user and touches no other",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				foreign := sessionRecord("sess-z9", "u-z2")
				createSessions(ctx, t, s, sessionRecord("sess-z1", "u-z"), sessionRecord("sess-z2", "u-z"), foreign)

				n, err := s.DeleteByUserExcept(ctx, "u-z", "sess-z9")
				require.NoError(t, err)

				assert.Equal(t, 2, n)
				assertSessionsGone(ctx, t, s, "sess-z1", "sess-z2")
				assertSessionsLoad(ctx, t, s, foreign)
			},
		},
		{
			name: "deleting by user except an identifier naming no session removes every session of the user",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				createSessions(ctx, t, s, sessionRecord("sess-w1", "u-w"), sessionRecord("sess-w2", "u-w"))

				n, err := s.DeleteByUserExcept(ctx, "u-w", "sess-none")
				require.NoError(t, err)

				assert.Equal(t, 2, n)
				assertSessionsGone(ctx, t, s, "sess-w1", "sess-w2")
			},
		},
		{
			name: "deleting by user except one matches the user reference exactly, case included",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				cased := sessionRecord("sess-c9", "U-C")
				createSessions(ctx, t, s, sessionRecord("sess-c1", "u-c"), sessionRecord("sess-c2", "u-c"), cased)

				n, err := s.DeleteByUserExcept(ctx, "u-c", "sess-c1")
				require.NoError(t, err)

				assert.Equal(t, 1, n)
				assertSessionsGone(ctx, t, s, "sess-c2")
				assertSessionsLoad(ctx, t, s, cased)
			},
		},
		{
			name: "a kept identifier no store could hold still deletes the user's other sessions",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				for i, keep := range []string{"bad\x00id", "bad\xffid"} {
					user := identity.UserID(fmt.Sprintf("u-v%d", i))
					first, second := fmt.Sprintf("sess-v%da", i), fmt.Sprintf("sess-v%db", i)
					createSessions(ctx, t, s, sessionRecord(first, user), sessionRecord(second, user))

					n, err := s.DeleteByUserExcept(ctx, user, keep)
					require.NoError(t, err, "keep %q", keep)

					assert.Equal(t, 2, n, "keep %q names no session, so both go", keep)
					assertSessionsGone(ctx, t, s, first, second)
				}
			},
		},
		{
			name: "deleting expired sessions removes exactly the expired ones",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				absoluteExpired := sessionRecord("sess-b", "u-2")
				absoluteExpired.IdleExpiresAt = suiteStart.Add(2 * time.Hour)
				absoluteExpired.AbsoluteExpiresAt = suiteStart.Add(10 * time.Minute)
				live := sessionRecord("sess-c", "u-1")
				createSessions(ctx, t, s, idleExpiredSession("sess-a", "u-1"), absoluteExpired, live)
				clock.Advance((suiteStart.Add(10 * time.Minute)).Sub(clock.Now()))

				n, err := s.DeleteExpired(ctx)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "the count is of the sessions removed")

				clock.Advance((suiteStart).Sub(clock.Now()))
				assertSessionsGone(ctx, t, s, "sess-a", "sess-b")
				assertSessionsLoad(ctx, t, s, live)
			},
		},
		{
			name: "deleting by provider session matches nothing on an empty issuer or session identifier",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				sessions := []*session.Session{
					sessionRecord("sess-password", "u-1"),
					federatedSession("sess-a-nosid", "u-1", sessionIssuerA, ""),
					federatedSession("sess-a-sid", "u-1", sessionIssuerA, sessionSID),
				}
				createSessions(ctx, t, s, sessions...)

				for _, call := range [][2]string{{"", sessionSID}, {sessionIssuerA, ""}, {"", ""}} {
					n, err := s.DeleteByExternalSession(ctx, call[0], call[1])
					require.NoError(t, err)
					assert.Zero(t, n, "issuer %q, session %q must match nothing", call[0], call[1])
				}
				assertSessionsLoad(ctx, t, s, sessions...)
			},
		},
		{
			name: "deleting by provider session matches the issuer as well as the session identifier",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				fromB := federatedSession("sess-b", "u-2", sessionIssuerB, sessionSID)
				createSessions(ctx, t, s,
					federatedSession("sess-a1", "u-1", sessionIssuerA, sessionSID),
					federatedSession("sess-a2", "u-2", sessionIssuerA, sessionSID),
					fromB,
				)

				n, err := s.DeleteByExternalSession(ctx, sessionIssuerA, sessionSID)
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				assertSessionsGone(ctx, t, s, "sess-a1", "sess-a2")
				assertSessionsLoad(ctx, t, s, fromB)
			},
		},
		{
			name: "deleting by user and issuer removes only that user's sessions from that issuer",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				keep := []*session.Session{
					federatedSession("sess-b", "u-1", sessionIssuerB, sessionSID),
					sessionRecord("sess-password", "u-1"),
					federatedSession("sess-other", "u-2", sessionIssuerA, sessionSID),
				}
				createSessions(ctx, t, s,
					federatedSession("sess-a1", "u-1", sessionIssuerA, sessionSID),
					federatedSession("sess-a2", "u-1", sessionIssuerA, "sid-2"),
				)
				createSessions(ctx, t, s, keep...)

				n, err := s.DeleteByUserAndExternalIssuer(ctx, "u-1", "")
				require.NoError(t, err)
				assert.Zero(t, n, "an empty issuer must match nothing, password sessions included")

				n, err = s.DeleteByUserAndExternalIssuer(ctx, "u-1", sessionIssuerA)
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				assertSessionsGone(ctx, t, s, "sess-a1", "sess-a2")
				assertSessionsLoad(ctx, t, s, keep...)
			},
		},
		{
			// This proves newStore built its store on the clk the suite hands
			// it, and not some clock of its own: a factory that silently
			// falls back to clock.System() would leave this session loading
			// forever, since advancing clk would never move its own clock.
			name: "a session loads before the factory's clock advances past its idle deadline, and is refused after",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				sess.IdleExpiresAt = suiteStart.Add(time.Minute)
				require.NoError(t, s.Create(ctx, sess))

				assertSessionsLoad(ctx, t, s, sess)

				clk.Advance(2 * time.Minute)

				_, err := s.Load(ctx, "sess-a")
				require.ErrorIs(t, err, session.ErrSessionExpired,
					"the store's clock must be the one the suite advances")
			},
		},
	}

	cases = append(cases, sessionActivityCases()...)
	cases = append(cases, sessionFamilyCases()...)

	runSuite(t, cases, newStore)
}

// sessionActivityCases are the cases of the narrow activity write.
func sessionActivityCases() []suiteCase[session.Store] {
	return []suiteCase[session.Store]{
		{
			name: "activity write leaves a fresher record unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				fresh := sessionRecord("sess-a", "u-1")
				fresh.LastAccessedAt = suiteStart.Add(19*time.Minute + 30*time.Second)
				require.NoError(t, s.Create(ctx, fresh))

				require.NoError(t, s.RecordActivity(ctx, "sess-a",
					suiteStart.Add(20*time.Minute), suiteStart.Add(50*time.Minute), suiteStart.Add(19*time.Minute)))
				assertSessionsLoad(ctx, t, s, fresh)

				// A record last accessed one second after the threshold is
				// still fresher than it.
				require.NoError(t, s.RecordActivity(ctx, "sess-a",
					suiteStart.Add(20*time.Minute), suiteStart.Add(50*time.Minute),
					fresh.LastAccessedAt.Add(-time.Second)))
				assertSessionsLoad(ctx, t, s, fresh)
			},
		},
		{
			name: "activity write at the threshold is written",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				stored := sessionRecord("sess-a", "u-1")
				stored.LastAccessedAt = suiteStart.Add(19 * time.Minute)
				require.NoError(t, s.Create(ctx, stored))

				// The threshold is the stored last access itself: not later
				// than it, so the write applies.
				lastAccessed, idle := suiteStart.Add(20*time.Minute), suiteStart.Add(50*time.Minute)
				require.NoError(t, s.RecordActivity(ctx, "sess-a", lastAccessed, idle, stored.LastAccessedAt))

				want := *stored
				want.LastAccessedAt, want.IdleExpiresAt = lastAccessed, idle
				assertSessionsLoad(ctx, t, s, &want)
			},
		},
		{
			name: "activity write leaves other fields",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, sessionRecord("sess-a", "u-1")))

				first, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				second, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				second.Data = map[string]string{"tenant": "changed by another request"}
				second.PasswordChangePending = false
				require.NoError(t, s.Save(ctx, second))

				lastAccessed, idle := first.LastAccessedAt.Add(4*time.Minute), first.IdleExpiresAt.Add(4*time.Minute)
				require.NoError(t, s.RecordActivity(ctx, first.ID, lastAccessed, idle, lastAccessed.Add(-time.Minute)))

				want := *second
				want.LastAccessedAt, want.IdleExpiresAt = lastAccessed, idle
				assertSessionsLoad(ctx, t, s, &want)
			},
		},
		{
			name: "activity write on a deleted session is not found and inserts nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, sessionRecord("sess-a", "u-1")))
				require.NoError(t, s.Delete(ctx, "sess-a"))

				for _, sessionID := range []string{"sess-a", "sess-never"} {
					err := s.RecordActivity(ctx, sessionID,
						suiteStart.Add(5*time.Minute), suiteStart.Add(35*time.Minute), suiteStart.Add(4*time.Minute))
					require.ErrorIs(t, err, session.ErrSessionNotFound, "session %s", sessionID)
				}
				assertSessionsGone(ctx, t, s, "sess-a", "sess-never")
			},
		},
		{
			name: "activity write never stores an idle deadline past the stored absolute deadline",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, sessionRecord("sess-a", "u-1")))

				// Another request lowers the absolute deadline after this
				// request loaded its copy, whose idle deadline is still later.
				lowered, err := s.Load(ctx, "sess-a")
				require.NoError(t, err)
				lowered.AbsoluteExpiresAt = suiteStart.Add(15 * time.Minute)
				lowered.IdleExpiresAt = suiteStart.Add(15 * time.Minute)
				require.NoError(t, s.Save(ctx, lowered))

				lastAccessed := suiteStart.Add(2 * time.Minute)
				require.NoError(t, s.RecordActivity(ctx, "sess-a",
					lastAccessed, suiteStart.Add(31*time.Minute), lastAccessed))

				want := *lowered
				want.LastAccessedAt = lastAccessed
				assertSessionsLoad(ctx, t, s, &want)
			},
		},
		{
			name: "activity write on a superseded session changes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				successor := successorOf(old, "sess-b", suiteStart)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: suiteStart.Add(time.Minute), RetainUntil: sessionRetainUntil, Successor: successor, Now: suiteStart,
				}))
				superseded := supersededAs(old, successor.ID, suiteStart, suiteStart.Add(time.Minute))

				// The stored last access, 10:01, is older than the threshold, so
				// only the supersession can leave the record unchanged.
				require.NoError(t, s.RecordActivity(ctx, old.ID,
					suiteStart.Add(5*time.Minute), suiteStart.Add(35*time.Minute), suiteStart.Add(5*time.Minute)))

				assertSessionsLoad(ctx, t, s, superseded)
			},
		},
	}
}

// sessionFamilyCases are the cases of supersession, family revocation and
// first presentation.
func sessionFamilyCases() []suiteCase[session.Store] {
	// rotate supersedes old by a successor named successorID at at, with a
	// thirty-second window and the suite's retention deadline, having
	// observed observed, and returns the successor.
	rotate := func(ctx context.Context, t *testing.T, s session.Store,
		old *session.Session, successorID string, observed []byte, at time.Time,
	) *session.Session {
		t.Helper()

		successor := successorOf(old, successorID, at)
		require.NoError(t, s.Supersede(ctx, session.Supersession{
			Old: old.ID, ObservedSuccessor: observed, AcceptUntil: at.Add(30 * time.Second),
			RetainUntil: sessionRetainUntil, Successor: successor, Now: at,
		}))
		return successor
	}

	return []suiteCase[session.Store]{
		{
			name: "successor stored in the family with its start time",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				old.FamilyCreatedAt = suiteStart.Add(-time.Hour)
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(5 * time.Minute)

				successor := rotate(ctx, t, s, old, "sess-b", nil, at)

				assertSessionsLoad(ctx, t, s, supersededAs(old, successor.ID, at, at.Add(30*time.Second)), successor)
				got, err := s.Load(ctx, successor.ID)
				require.NoError(t, err)
				assert.Equal(t, old.FamilyID, got.FamilyID, "the successor is in the old session's family")
				assertTimeEqual(t, old.FamilyCreatedAt, got.FamilyCreatedAt, "the successor's FamilyCreatedAt")
			},
		},
		{
			name: "renewed sign-in counts once",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *clockwork.FakeClock) {
				head := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, head))
				for i, successorID := range []string{"sess-b", "sess-c", "sess-d"} {
					head = rotate(ctx, t, s, head, successorID, nil, suiteStart.Add(time.Duration(i+1)*time.Minute))
				}
				require.NoError(t, s.Create(ctx, sessionRecord("sess-other", "u-2")))

				// Every superseded window has ended, yet each superseded
				// record's deadlines are still ahead.
				clock.Advance(suiteStart.Add(10 * time.Minute).Sub(clock.Now()))

				n, err := s.CountActiveByUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 1, n, "one sign-in renewed three times holds one live session")
				n, err = s.CountActiveByUser(ctx, "u-2")
				require.NoError(t, err)
				assert.Equal(t, 1, n, "another user's session still counts")
			},
		},
		{
			name: "stale observation is refused and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)

				late := successorOf(old, "sess-c", suiteStart.Add(time.Minute))
				for _, observed := range [][]byte{nil, sessionDigest("sess-other")} {
					err := s.Supersede(ctx, session.Supersession{
						Old: old.ID, ObservedSuccessor: observed, AcceptUntil: suiteStart.Add(2 * time.Minute),
						RetainUntil: sessionRetainUntil, Successor: late, Now: suiteStart.Add(time.Minute),
					})
					require.ErrorIs(t, err, session.ErrSessionRenewalConflict, "observed %x", observed)
				}

				assertSessionsGone(ctx, t, s, late.ID)
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, first.ID, suiteStart, suiteStart.Add(30*time.Second)), first)
			},
		},
		{
			name: "re-rotation supersedes the previous successor with a window that has ended",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				again := suiteStart.Add(10 * time.Second)

				second := rotate(ctx, t, s, old, "sess-c", sessionDigest(first.ID), again)

				assertSessionsLoad(ctx, t, s,
					supersededAs(old, second.ID, again, again.Add(30*time.Second)),
					knockedOutAs(first, again, sessionRetainUntil), second)
			},
		},
		{
			name: "re-rotation observing a successor already superseded is refused and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				// The first successor rotates on its own before old does again.
				rotatedAt := suiteStart.Add(5 * time.Second)
				onward := rotate(ctx, t, s, first, "sess-c", nil, rotatedAt)
				again := suiteStart.Add(10 * time.Second)

				late := successorOf(old, "sess-d", again)
				err := s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID),
					AcceptUntil: again.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: late, Now: again,
				})

				require.ErrorIs(t, err, session.ErrSuccessorAdvanced)
				assertSessionsGone(ctx, t, s, late.ID)
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, first.ID, suiteStart, suiteStart.Add(30*time.Second)),
					supersededAs(first, onward.ID, rotatedAt, rotatedAt.Add(30*time.Second)), onward)
			},
		},
		{
			name: "a stale observation is a renewal conflict even when the successor moved on",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				require.NoError(t, s.Delete(ctx, first.ID))
				again := suiteStart.Add(10 * time.Second)

				late := successorOf(old, "sess-c", again)
				err := s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest("sess-other"), RequireUnpresentedSuccessor: true,
					AcceptUntil: again.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: late, Now: again,
				})

				require.ErrorIs(t, err, session.ErrSessionRenewalConflict)
				assertSessionsGone(ctx, t, s, late.ID)
			},
		},
		{
			name: "re-rotation observing a successor no longer stored is refused and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				require.NoError(t, s.Delete(ctx, first.ID))
				again := suiteStart.Add(10 * time.Second)

				late := successorOf(old, "sess-c", again)
				err := s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID),
					AcceptUntil: again.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: late, Now: again,
				})

				require.ErrorIs(t, err, session.ErrSuccessorAdvanced)
				assertSessionsGone(ctx, t, s, late.ID, first.ID)
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, first.ID, suiteStart, suiteStart.Add(30*time.Second)))
			},
		},
		{
			name: "supersession requiring an unpresented successor is refused once it was presented",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				presentedAt := suiteStart.Add(5 * time.Second)
				require.NoError(t, s.MarkPresented(ctx, first.ID, presentedAt))
				later := suiteStart.Add(time.Hour)

				late := successorOf(old, "sess-c", later)
				err := s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID), RequireUnpresentedSuccessor: true,
					AcceptUntil: suiteStart.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: late, Now: later,
				})

				require.ErrorIs(t, err, session.ErrSuccessorAdvanced)
				assertSessionsGone(ctx, t, s, late.ID)
				presented := *first
				presented.FirstPresentedAt = presentedAt
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, first.ID, suiteStart, suiteStart.Add(30*time.Second)), &presented)
			},
		},
		{
			name: "supersession requiring an unpresented successor supersedes one never presented",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				later := suiteStart.Add(time.Hour)

				second := successorOf(old, "sess-c", later)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID), RequireUnpresentedSuccessor: true,
					AcceptUntil: suiteStart.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: second, Now: later,
				}))

				assertSessionsLoad(ctx, t, s,
					supersededAs(old, second.ID, later, suiteStart.Add(30*time.Second)),
					knockedOutAs(first, later, sessionRetainUntil), second)
			},
		},
		{
			name: "load returns a superseded record past its window",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				successor := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)

				// Past the window, and past the idle deadline the session held
				// before it was superseded.
				clk.Advance(2 * time.Hour)

				got, err := s.Load(ctx, old.ID)
				require.NoError(t, err, "a superseded session is returned until its absolute deadline")
				assertSession(t, supersededAs(old, successor.ID, suiteStart, suiteStart.Add(30*time.Second)), got)
			},
		},
		{
			// O is superseded at 10:00 with a retention deadline of 21:00:
			// swept at 12:00 it stays; its successor, whose own deadline is
			// 18:00, goes at 18:00, and O only at 21:00.
			name: "sweep keeps a superseded record until its retention deadline",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				successor := successorOf(old, "sess-b", suiteStart)
				successor.IdleExpiresAt = old.AbsoluteExpiresAt
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: suiteStart.Add(30 * time.Second), RetainUntil: sessionRetainUntil,
					Successor: successor, Now: suiteStart,
				}))

				clk.Advance(2 * time.Hour)
				n, err := s.DeleteExpired(ctx)
				require.NoError(t, err)
				assert.Zero(t, n, "nothing of the family is expired before either deadline")
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, successor.ID, suiteStart, suiteStart.Add(30*time.Second)), successor)

				clk.Advance(successor.AbsoluteExpiresAt.Sub(clk.Now()))
				n, err = s.DeleteExpired(ctx)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the successor is swept at its own deadline, the superseded record kept")
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, successor.ID, suiteStart, suiteStart.Add(30*time.Second)))

				clk.Advance(sessionRetainUntil.Sub(clk.Now()))
				n, err = s.DeleteExpired(ctx)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the superseded record is swept at its retention deadline")
			},
		},
		{
			// O's own deadline is 18:00 and its retention deadline 21:00. O
			// is superseded at 11:00 by S1, whose deadline is 16:00, and
			// re-rotated at 11:00:10 by S2, which supersedes S1. Both are
			// held to 21:00, not to their own deadline nor to a successor's,
			// so both still load as superseded at 20:00.
			name: "a superseded record keeps the retention deadline",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				at, again := suiteStart.Add(time.Hour), suiteStart.Add(time.Hour+10*time.Second)

				first := successorOf(old, "sess-b", at)
				first.AbsoluteExpiresAt = suiteStart.Add(6 * time.Hour)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: sessionRetainUntil,
					Successor: first, Now: at,
				}))
				second := successorOf(old, "sess-c", again)
				second.AbsoluteExpiresAt = suiteStart.Add(6 * time.Hour)
				second.IdleExpiresAt = second.AbsoluteExpiresAt
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID), AcceptUntil: at.Add(30 * time.Second),
					RetainUntil: sessionRetainUntil, Successor: second, Now: again,
				}))

				clk.Advance(suiteStart.Add(10 * time.Hour).Sub(clk.Now()))
				assertSessionsLoad(ctx, t, s,
					supersededUntil(old, second.ID, again, at.Add(30*time.Second), sessionRetainUntil),
					knockedOutAs(first, again, sessionRetainUntil))
			},
		},
		{
			// O is superseded by S1 at 11:00 with a retention deadline of
			// 21:00, S1 by S2 at 12:00 with 22:00, and S2 by S3 at 13:00
			// with 23:00, each successor extending the family. O is not one
			// of the records the later supersessions supersede, so it stays
			// exactly as S1's supersession left it.
			name: "earlier superseded sessions are untouched by later supersessions",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))

				head := old
				var want []*session.Session
				for i, successorID := range []string{"sess-b", "sess-c", "sess-d"} {
					at := suiteStart.Add(time.Duration(i+1) * time.Hour)
					retain := sessionRetainUntil.Add(time.Duration(i) * time.Hour)
					next := successorOf(head, successorID, at)
					next.IdleExpiresAt, next.AbsoluteExpiresAt = retain, retain
					require.NoError(t, s.Supersede(ctx, session.Supersession{
						Old: head.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: retain,
						Successor: next, Now: at,
					}))
					want = append(want, supersededUntil(head, successorID, at, at.Add(30*time.Second), retain))
					head = next
				}

				clk.Advance(suiteStart.Add(10 * time.Hour).Sub(clk.Now()))
				assertSessionsLoad(ctx, t, s, append(want, head)...)
			},
		},
		{
			// O's successor S1 was presented, and O is renewed again
			// observing S1 without requiring an unpresented successor, as a
			// re-rotation inside O's window does: S1 is superseded with its
			// window ending at once, its presentation kept.
			name: "re-rotation not requiring an unpresented successor supersedes one presented",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				presentedAt := suiteStart.Add(5 * time.Second)
				require.NoError(t, s.MarkPresented(ctx, first.ID, presentedAt))
				again := suiteStart.Add(10 * time.Second)

				second := successorOf(old, "sess-c", again)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID), RequireUnpresentedSuccessor: false,
					AcceptUntil: again.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: second, Now: again,
				}))

				previous := knockedOutAs(first, again, sessionRetainUntil)
				previous.FirstPresentedAt = presentedAt
				assertSessionsLoad(ctx, t, s,
					supersededAs(old, second.ID, again, again.Add(30*time.Second)), previous, second)
			},
		},
		{
			// Family B's superseded session keeps the retention deadline
			// 21:00 its supersession gave. Family A's supersession, retaining
			// to 03:00 the next day, leaves it unchanged.
			name: "a supersession leaves another family's superseded session unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				other := familySession("sess-z", "u-1", suiteID(2))
				require.NoError(t, s.Create(ctx, other))
				otherSuccessor := rotate(ctx, t, s, other, "sess-y", nil, suiteStart)
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(time.Hour)

				successor := successorOf(old, "sess-b", at)
				successor.AbsoluteExpiresAt = suiteStart.Add(17 * time.Hour)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: suiteStart.Add(17 * time.Hour),
					Successor: successor, Now: at,
				}))

				assertSessionsLoad(ctx, t, s,
					supersededAs(other, otherSuccessor.ID, suiteStart, suiteStart.Add(30*time.Second)),
					otherSuccessor)
			},
		},
		{
			// M is a member of O's family that was never superseded. O's
			// supersession retains to 03:00 the next day; M keeps its own
			// deadlines.
			name: "a supersession leaves an unsuperseded member of the family unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				member := familySession("sess-m", "u-1", suiteID(1))
				createSessions(ctx, t, s, old, member)
				at := suiteStart.Add(time.Hour)
				retain := suiteStart.Add(17 * time.Hour)

				successor := successorOf(old, "sess-b", at)
				successor.AbsoluteExpiresAt = retain
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: retain,
					Successor: successor, Now: at,
				}))

				assertSessionsLoad(ctx, t, s, member,
					supersededUntil(old, successor.ID, at, at.Add(30*time.Second), retain), successor)
			},
		},
		{
			name: "family delete counts one family",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				other := familySession("sess-z", "u-1", suiteID(2))
				createSessions(ctx, t, s, old, other)
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				second := rotate(ctx, t, s, old, "sess-c", sessionDigest(first.ID), suiteStart.Add(time.Second))

				n, err := s.DeleteFamily(ctx, suiteID(1))
				require.NoError(t, err)

				assert.Equal(t, 3, n, "the superseded session and both successors")
				assertSessionsGone(ctx, t, s, old.ID, first.ID, second.ID)
				assertSessionsLoad(ctx, t, s, other)

				n, err = s.DeleteFamily(ctx, suiteID(3))
				require.NoError(t, err)
				assert.Zero(t, n, "a family with no sessions removes nothing")
			},
		},
		{
			name: "family delete removes expired members",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clk *clockwork.FakeClock) {
				expired := familySession("sess-a", "u-1", suiteID(1))
				expired.IdleExpiresAt = suiteStart.Add(time.Minute)
				createSessions(ctx, t, s, expired, familySession("sess-b", "u-1", suiteID(1)))
				clk.Advance(2 * time.Minute)

				n, err := s.DeleteFamily(ctx, suiteID(1))
				require.NoError(t, err)

				assert.Equal(t, 2, n)
				clk.Advance(suiteStart.Sub(clk.Now()))
				assertSessionsGone(ctx, t, s, "sess-a", "sess-b")
			},
		},
		{
			name: "first presentation keeps the first time",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				sess := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, sess))

				require.NoError(t, s.MarkPresented(ctx, sess.ID, suiteStart))
				require.NoError(t, s.MarkPresented(ctx, sess.ID, suiteStart.Add(5*time.Minute)))

				want := *sess
				want.FirstPresentedAt = suiteStart
				assertSessionsLoad(ctx, t, s, &want)
			},
		},
		{
			name: "first presentation of a missing session is not found and inserts nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				require.ErrorIs(t, s.MarkPresented(ctx, "sess-never", suiteStart), session.ErrSessionNotFound)
				assertSessionsGone(ctx, t, s, "sess-never")
			},
		},
		{
			name: "family and supersession values round-trip at microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				old.FamilyCreatedAt = preciseStart.Add(-time.Hour)
				require.NoError(t, s.Create(ctx, old))
				at := preciseStart.Add(time.Minute)
				successor := successorOf(old, "sess-b", at)
				retain := preciseStart.Add(11 * time.Hour)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: retain, Successor: successor, Now: at,
				}))
				presented := preciseStart.Add(2 * time.Minute)
				require.NoError(t, s.MarkPresented(ctx, successor.ID, presented))

				gotOld, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				assert.Equal(t, old.FamilyID, gotOld.FamilyID)
				assertTimeMicro(t, old.FamilyCreatedAt, gotOld.FamilyCreatedAt, "old FamilyCreatedAt")
				assertTimeMicro(t, at, gotOld.SupersededAt, "old SupersededAt")
				assertTimeMicro(t, at.Add(30*time.Second), gotOld.AcceptUntil, "old AcceptUntil")
				assert.Equal(t, sessionDigest(successor.ID), gotOld.SuccessorDigest, "old SuccessorDigest")
				assert.True(t, gotOld.FirstPresentedAt.IsZero(), "a session never presented reports none")
				assertTimeMicro(t, retain, gotOld.IdleExpiresAt, "old IdleExpiresAt, the retention deadline")
				assertTimeMicro(t, retain, gotOld.AbsoluteExpiresAt, "old AbsoluteExpiresAt, the retention deadline")

				gotNew, err := s.Load(ctx, successor.ID)
				require.NoError(t, err)
				assert.Equal(t, old.FamilyID, gotNew.FamilyID)
				assertTimeMicro(t, old.FamilyCreatedAt, gotNew.FamilyCreatedAt, "successor FamilyCreatedAt")
				assertTimeMicro(t, presented, gotNew.FirstPresentedAt, "successor FirstPresentedAt")
				assert.True(t, gotNew.SupersededAt.IsZero(), "a session never superseded reports no supersession")
				assert.True(t, gotNew.AcceptUntil.IsZero(), "a session never superseded reports no window")
				assert.Empty(t, gotNew.SuccessorDigest, "a session never superseded reports no successor")
			},
		},
		{
			// Save keeps the family, supersession and presentation state
			// whatever the saved copy says: a copy loaded before the
			// supersession, saved after it, must not undo it.
			name: "save leaves supersession state unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				require.NoError(t, s.MarkPresented(ctx, old.ID, suiteStart))
				stale, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				successor := rotate(ctx, t, s, old, "sess-b", nil, suiteStart.Add(time.Minute))

				loaded, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				want := *loaded
				loaded.Data = map[string]string{"tenant": "saved after supersession"}
				require.NoError(t, s.Save(ctx, loaded))
				want.Data = loaded.Data
				assertSessionsLoad(ctx, t, s, &want)

				stale.Data = map[string]string{"tenant": "saved from before"}
				stale.FamilyID = suiteID(9)
				stale.FamilyCreatedAt = time.Time{}
				stale.FirstPresentedAt = time.Time{}
				stale.IdleExpiresAt = suiteStart.Add(5 * time.Minute)
				stale.AbsoluteExpiresAt = suiteStart.Add(time.Hour)
				require.NoError(t, s.Save(ctx, stale))
				got, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				assertTimeEqual(t, sessionRetainUntil, got.IdleExpiresAt, "IdleExpiresAt of a superseded record after a save")
				assertTimeEqual(t, sessionRetainUntil, got.AbsoluteExpiresAt, "AbsoluteExpiresAt of a superseded record after a save")
				assert.Equal(t, old.FamilyID, got.FamilyID, "a save must not move the family")
				assertTimeEqual(t, old.FamilyCreatedAt, got.FamilyCreatedAt, "FamilyCreatedAt after a save")
				assertTimeEqual(t, suiteStart, got.FirstPresentedAt, "FirstPresentedAt after a save")
				assertTimeEqual(t, suiteStart.Add(time.Minute), got.SupersededAt, "SupersededAt after a save")
				assertTimeEqual(t, suiteStart.Add(time.Minute+30*time.Second), got.AcceptUntil,
					"AcceptUntil after a save")
				assert.Equal(t, sessionDigest(successor.ID), got.SuccessorDigest, "SuccessorDigest after a save")
			},
		},
		{
			// The previous successor a re-rotation supersedes is a superseded
			// record too, and a copy loaded before it keeps its deadlines.
			name: "save keeps the deadlines of a successor superseded by a re-rotation",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				stale, err := s.Load(ctx, first.ID)
				require.NoError(t, err)
				rotate(ctx, t, s, old, "sess-c", sessionDigest(first.ID), suiteStart.Add(10*time.Second))

				stale.IdleExpiresAt = suiteStart.Add(5 * time.Minute)
				stale.AbsoluteExpiresAt = suiteStart.Add(time.Hour)
				require.NoError(t, s.Save(ctx, stale))

				got, err := s.Load(ctx, first.ID)
				require.NoError(t, err)
				assertTimeEqual(t, sessionRetainUntil, got.IdleExpiresAt, "IdleExpiresAt after a stale save")
				assertTimeEqual(t, sessionRetainUntil, got.AbsoluteExpiresAt, "AbsoluteExpiresAt after a stale save")
				assertTimeEqual(t, suiteStart.Add(10*time.Second), got.SupersededAt, "SupersededAt after a stale save")
			},
		},
		{
			name: "family delete of the nil family is refused and deletes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				a, b := sessionRecord("sess-a", "u-1"), sessionRecord("sess-b", "u-2")
				createSessions(ctx, t, s, a, b)

				n, err := s.DeleteFamily(ctx, id.Nil)

				require.Error(t, err, "the nil family names no family, and must not match sessions created without one")
				assert.Zero(t, n)
				assertSessionsLoad(ctx, t, s, a, b)
			},
		},
		{
			name: "supersede after family revocation is not found and inserts nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				observed, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				n, err := s.DeleteFamily(ctx, old.FamilyID)
				require.NoError(t, err)
				require.Equal(t, 1, n)

				successor := successorOf(old, "sess-b", suiteStart)
				err = s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: observed.SuccessorDigest,
					AcceptUntil: suiteStart.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: successor, Now: suiteStart,
				})

				require.ErrorIs(t, err, session.ErrSessionNotFound)
				assertSessionsGone(ctx, t, s, old.ID, successor.ID)
			},
		},
		{
			// O's successor S1 was knocked out: O was superseded again,
			// observing S1, so S1 is superseded with no successor. Renewing
			// S1 as if it were a fresh head, observing none, would give the
			// family a second live head beside O's newest successor.
			name: "knocked-out successor renewed as if fresh is a renewal conflict and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				first := rotate(ctx, t, s, old, "sess-b", nil, suiteStart)
				again := suiteStart.Add(10 * time.Second)
				second := successorOf(old, "sess-c", again)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID),
					AcceptUntil: again.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: second, Now: again,
				}))
				knockedOut := knockedOutAs(first, again, sessionRetainUntil)
				require.Empty(t, knockedOut.SuccessorDigest)

				late := suiteStart.Add(20 * time.Second)
				renewal := successorOf(first, "sess-d", late)
				err := s.Supersede(ctx, session.Supersession{
					Old: first.ID, AcceptUntil: late.Add(30 * time.Second), RetainUntil: sessionRetainUntil, Successor: renewal, Now: late,
				})

				require.ErrorIs(t, err, session.ErrSessionRenewalConflict)
				assertSessionsGone(ctx, t, s, renewal.ID)
				assertSessionsLoad(ctx, t, s, knockedOut,
					supersededAs(old, second.ID, again, again.Add(30*time.Second)), second)
			},
		},
		{
			// Sessions with no family would all share the nil family, so one
			// family revocation or supersession could reach unrelated users'
			// sessions: no store holds one.
			name: "creating a session with no family is refused and stores nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				orphan := sessionRecord("sess-a", "u-1")
				orphan.FamilyID = id.Nil

				err := s.Create(ctx, orphan)

				require.Error(t, err, "a session with no family must be refused at creation")
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
				assertSessionsGone(ctx, t, s, orphan.ID)
			},
		},
		{
			// O's absolute deadline is 21:00. It is superseded at 16:00 with
			// a retention deadline of 18:00 and a window ending at 16:00:30:
			// the retention is after the window but below what O holds, so
			// both of O's deadlines stay 21:00.
			name: "a supersession never lowers a deadline",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				old.IdleExpiresAt, old.AbsoluteExpiresAt = sessionRetainUntil, sessionRetainUntil
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(6 * time.Hour)
				successor := successorOf(old, "sess-b", at)

				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: suiteStart.Add(8 * time.Hour),
					Successor: successor, Now: at,
				}))

				got, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				assertTimeEqual(t, sessionRetainUntil, got.IdleExpiresAt, "IdleExpiresAt after a lower retention")
				assertTimeEqual(t, sessionRetainUntil, got.AbsoluteExpiresAt, "AbsoluteExpiresAt after a lower retention")
			},
		},
		{
			// O's idle deadline is 16:30 and its absolute deadline 21:00. It
			// is superseded at 16:00 with a retention deadline of 18:00: the
			// record is held to one deadline, 21:00, as both.
			name: "a superseded record keeps one deadline",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				old.IdleExpiresAt, old.AbsoluteExpiresAt = suiteStart.Add(6*time.Hour+30*time.Minute), sessionRetainUntil
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(6 * time.Hour)
				successor := successorOf(old, "sess-b", at)

				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: suiteStart.Add(8 * time.Hour),
					Successor: successor, Now: at,
				}))

				got, err := s.Load(ctx, old.ID)
				require.NoError(t, err)
				assertTimeEqual(t, sessionRetainUntil, got.IdleExpiresAt, "IdleExpiresAt of a superseded record")
				assertTimeEqual(t, sessionRetainUntil, got.AbsoluteExpiresAt, "AbsoluteExpiresAt of a superseded record")
			},
		},
		{
			// O is superseded by S1, whose idle deadline is 16:30 and
			// absolute deadline 21:00, and re-rotated at 16:00 with a
			// retention deadline of 18:00: S1 is superseded in turn and
			// keeps 21:00 as both deadlines, never lowered to 18:00.
			name: "re-rotation never lowers the previous successor's deadlines",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				at := suiteStart.Add(time.Hour)
				first := successorOf(old, "sess-b", at)
				first.IdleExpiresAt, first.AbsoluteExpiresAt = suiteStart.Add(6*time.Hour+30*time.Minute), sessionRetainUntil
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: at.Add(30 * time.Second), RetainUntil: suiteStart.Add(8 * time.Hour),
					Successor: first, Now: at,
				}))
				again := suiteStart.Add(6 * time.Hour)
				second := successorOf(old, "sess-c", again)

				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID), AcceptUntil: again.Add(30 * time.Second),
					RetainUntil: suiteStart.Add(8 * time.Hour), Successor: second, Now: again,
				}))

				got, err := s.Load(ctx, first.ID)
				require.NoError(t, err)
				assertTimeEqual(t, sessionRetainUntil, got.IdleExpiresAt, "previous successor IdleExpiresAt")
				assertTimeEqual(t, sessionRetainUntil, got.AbsoluteExpiresAt, "previous successor AbsoluteExpiresAt")
			},
		},
		{
			name: "a retention deadline before the window is refused and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				successor := successorOf(old, "sess-b", suiteStart)

				err := s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: suiteStart.Add(time.Minute), RetainUntil: suiteStart.Add(30 * time.Second),
					Successor: successor, Now: suiteStart,
				})

				require.Error(t, err, "a retention deadline before the window's end must be refused")
				assert.NotErrorIs(t, err, session.ErrSessionRenewalConflict)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
				assert.NotErrorIs(t, err, session.ErrSuccessorAdvanced)
				assertSessionsGone(ctx, t, s, successor.ID)
				assertSessionsLoad(ctx, t, s, old)
			},
		},
		{
			name: "a successor with no family is refused and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				old := familySession("sess-a", "u-1", suiteID(1))
				require.NoError(t, s.Create(ctx, old))
				successor := successorOf(old, "sess-b", suiteStart)
				successor.FamilyID = id.Nil

				err := s.Supersede(ctx, session.Supersession{
					Old: old.ID, AcceptUntil: suiteStart.Add(30 * time.Second), RetainUntil: sessionRetainUntil,
					Successor: successor, Now: suiteStart,
				})

				require.Error(t, err, "a successor in no family must be refused")
				assert.NotErrorIs(t, err, session.ErrSessionRenewalConflict)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
				assert.NotErrorIs(t, err, session.ErrSuccessorAdvanced)
				assertSessionsGone(ctx, t, s, successor.ID)
				assertSessionsLoad(ctx, t, s, old)
			},
		},
		{
			name: "deleting a session removes it from its family",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *clockwork.FakeClock) {
				a := familySession("sess-a", "u-1", suiteID(1))
				b := familySession("sess-b", "u-1", suiteID(1))
				createSessions(ctx, t, s, a, b)
				require.NoError(t, s.Delete(ctx, a.ID))

				n, err := s.DeleteFamily(ctx, suiteID(1))

				require.NoError(t, err)
				assert.Equal(t, 1, n, "only the session still stored is in the family")
				assertSessionsGone(ctx, t, s, a.ID, b.ID)
			},
		},
	}
}
