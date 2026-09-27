package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
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

// sessionRecord returns a session for user, created at suiteStart, with every
// field set so a store that drops one is caught.
func sessionRecord(sessionID string, user identity.UserID) *session.Session {
	return &session.Session{
		ID:                    sessionID,
		UserID:                user,
		CreatedAt:             suiteStart,
		LastAccessedAt:        suiteStart.Add(time.Minute),
		IdleExpiresAt:         suiteStart.Add(sessionIdle),
		AbsoluteExpiresAt:     suiteStart.Add(sessionAbsolute),
		FirstFactor:           factor.Password,
		MFA:                   session.MFASatisfied,
		MFASatisfiedAt:        suiteStart.Add(2 * time.Minute),
		PasswordChangePending: true,
		// EnrolmentOriginDeadline and EnrolmentGeneration are left zero here:
		// the enrolment-path suite extension asserts them, not this suite.
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

// idleExpiredSession returns a session whose idle deadline has passed by the
// time the suite's clock reaches suiteStart plus sessionIdle.
func idleExpiredSession(sessionID string, user identity.UserID) *session.Session {
	s := sessionRecord(sessionID, user)
	s.IdleExpiresAt = suiteStart.Add(10 * time.Minute)
	return s
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
	// EnrolmentOriginDeadline and EnrolmentGeneration are asserted by the
	// enrolment-path suite extension, not here.
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
// time from now. The suite moves now itself and never waits.
//
// A consumer implementing session.Store over their own database calls this
// from a test in their own module:
//
//	func TestMySessionStoreConformance(t *testing.T) {
//	    storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
//	        return newMySessionStore(t, now)
//	    })
//	}
func RunSessionStoreSuite(t *testing.T, newStore func(t *testing.T, now func() time.Time) session.Store) {
	t.Helper()

	type sessionCase = suiteCase[session.Store]

	dataCase := func(name string, data map[string]string) sessionCase {
		return sessionCase{
			name: name,
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
				want := federatedSession("sess-a", "u-1", sessionIssuerA, sessionSID)
				require.NoError(t, s.Create(ctx, want))

				assertSessionsLoad(ctx, t, s, want)
			},
		},
		{
			name: "a user reference round-trips byte for byte and is matched exactly",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
		{
			name: "a duplicate create errors and leaves the original unchanged",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			// Save replaces the record whole, so an absent map and empty
			// provider fields replace what was stored: a store reading them as
			// "not given" keeps a federated session's provider after it is
			// saved as a password one.
			name: "a save that clears the data and provider fields loads them cleared",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
				require.ErrorIs(t, s.Save(ctx, sessionRecord("sess-a", "u-1")), session.ErrSessionNotFound)
				assertSessionsGone(ctx, t, s, "sess-a")
			},
		},
		{
			name: "loading an unknown session is not found",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
				require.NoError(t, s.Create(ctx, sessionRecord("sess-a", "u-1")))

				assertSessionsGone(ctx, t, s, "sess-missing")
			},
		},
		{
			name: "deleting removes only that session, and deleting an absent one is not an error",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *fakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				require.NoError(t, s.Create(ctx, sess))

				clock.Set(sess.IdleExpiresAt.Add(-time.Second))
				assertSessionsLoad(ctx, t, s, sess)

				clock.Set(sess.IdleExpiresAt)
				_, err := s.Load(ctx, "sess-a")
				require.ErrorIs(t, err, session.ErrSessionExpired, "the idle deadline is judged by the store's clock")
			},
		},
		{
			name: "a session is expired at its absolute deadline even before its idle one",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *fakeClock) {
				sess := sessionRecord("sess-a", "u-1")
				sess.IdleExpiresAt = suiteStart.Add(2 * time.Hour)
				sess.AbsoluteExpiresAt = suiteStart.Add(time.Hour)
				require.NoError(t, s.Create(ctx, sess))

				clock.Set(sess.AbsoluteExpiresAt.Add(-time.Second))
				assertSessionsLoad(ctx, t, s, sess)

				clock.Set(sess.AbsoluteExpiresAt)
				_, err := s.Load(ctx, "sess-a")
				require.ErrorIs(t, err, session.ErrSessionExpired, "either deadline ends a session")
			},
		},
		{
			name: "the active count is exactly the user's unexpired sessions",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *fakeClock) {
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
				clock.Set(suiteStart.Add(10 * time.Minute))

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
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *fakeClock) {
				keep := []*session.Session{sessionRecord("sess-d", "u-2"), sessionRecord("sess-e", "U-1")}
				createSessions(ctx, t, s, sessionRecord("sess-a", "u-1"), sessionRecord("sess-b", "u-1"),
					idleExpiredSession("sess-c", "u-1"))
				createSessions(ctx, t, s, keep...)
				clock.Set(suiteStart.Add(10 * time.Minute))

				require.NoError(t, s.DeleteByUser(ctx, "u-1"))

				clock.Set(suiteStart)
				assertSessionsGone(ctx, t, s, "sess-a", "sess-b", "sess-c")
				assertSessionsLoad(ctx, t, s, keep...)
			},
		},
		{
			name: "deleting expired sessions removes exactly the expired ones",
			assert: func(t *testing.T, ctx context.Context, s session.Store, clock *fakeClock) {
				absoluteExpired := sessionRecord("sess-b", "u-2")
				absoluteExpired.IdleExpiresAt = suiteStart.Add(2 * time.Hour)
				absoluteExpired.AbsoluteExpiresAt = suiteStart.Add(10 * time.Minute)
				live := sessionRecord("sess-c", "u-1")
				createSessions(ctx, t, s, idleExpiredSession("sess-a", "u-1"), absoluteExpired, live)
				clock.Set(suiteStart.Add(10 * time.Minute))

				n, err := s.DeleteExpired(ctx)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "the count is of the sessions removed")

				clock.Set(suiteStart)
				assertSessionsGone(ctx, t, s, "sess-a", "sess-b")
				assertSessionsLoad(ctx, t, s, live)
			},
		},
		{
			name: "deleting by provider session matches nothing on an empty issuer or session identifier",
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s session.Store, _ *fakeClock) {
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
	}

	runSuite(t, cases, newStore)
}
