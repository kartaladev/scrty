package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// familyOf returns storedSession's session as a member of family.
func familyOf(sessionID string, family id.ID) *session.Session {
	s := storedSession(sessionID)
	s.FamilyID = family
	s.FamilyCreatedAt = s.CreatedAt

	return s
}

// firstRotation supersedes old by successor at createdAt with a one-minute
// window and a retention deadline at storedSession's absolute deadline, as a
// first rotation observes no successor.
func firstRotation(old string, successor *session.Session) session.Supersession {
	return session.Supersession{
		Old:         old,
		AcceptUntil: createdAt.Add(time.Minute),
		RetainUntil: createdAt.Add(12 * time.Hour),
		Successor:   successor,
		Now:         createdAt,
	}
}

func TestEncryptedStoreFamilyOperations(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01926a4e-0000-7000-8000-000000000001")

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore)
	}

	cases := []testCase{
		{
			name: "supersede seals the successor's ID token, bound to the successor, and leaves the caller's plaintext",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				oldSession := federatedSession("old")
				oldSession.FamilyID = family
				require.NoError(t, sealing.Create(ctx, oldSession))
				successor := federatedSession("new")
				successor.FamilyID = family

				require.NoError(t, sealing.Supersede(ctx, firstRotation("old", successor)))

				assert.Equal(t, federatedPlaintext, successor.ExternalIDToken, "the caller's successor was sealed in place")
				stored, err := inner.Load(ctx, "new")
				require.NoError(t, err)
				assert.NotContains(t, stored.ExternalIDToken, "provider-id-token-payload", "the successor's token reached the store in the clear")
				opened, err := sealing.Load(ctx, "new")
				require.NoError(t, err)
				assert.Equal(t, federatedPlaintext, opened.ExternalIDToken)
				old, err := sealing.Load(ctx, "old")
				require.NoError(t, err)
				assert.Equal(t, createdAt, old.SupersededAt)
			},
		},
		{
			name: "a lost supersession keeps the renewal-conflict error, and a missing one the not-found error",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, _ *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, familyOf("old", family)))
				require.NoError(t, sealing.Supersede(ctx, firstRotation("old", storedSession("first"))))

				err := sealing.Supersede(ctx, firstRotation("old", storedSession("second")))
				require.ErrorIs(t, err, session.ErrSessionRenewalConflict)

				err = sealing.Supersede(ctx, firstRotation("missing", storedSession("third")))
				require.ErrorIs(t, err, session.ErrSessionNotFound)
			},
		},
		{
			name: "record activity reaches the inner store",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, storedSession("s")))
				at := createdAt.Add(5 * time.Minute)

				require.NoError(t, sealing.RecordActivity(ctx, "s", at, at.Add(30*time.Minute), at))

				stored, err := inner.Load(ctx, "s")
				require.NoError(t, err)
				assert.Equal(t, at, stored.LastAccessedAt)
				require.ErrorIs(t, sealing.RecordActivity(ctx, "missing", at, at, at), session.ErrSessionNotFound)
			},
		},
		{
			name: "mark presented reaches the inner store",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, storedSession("s")))

				require.NoError(t, sealing.MarkPresented(ctx, "s", createdAt))

				stored, err := inner.Load(ctx, "s")
				require.NoError(t, err)
				assert.Equal(t, createdAt, stored.FirstPresentedAt)
				require.ErrorIs(t, sealing.MarkPresented(ctx, "missing", createdAt), session.ErrSessionNotFound)
			},
		},
		{
			name: "delete family reaches the inner store and reports its count",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(ctx, familyOf("a", family)))
				require.NoError(t, sealing.Create(ctx, familyOf("b", family)))
				require.NoError(t, sealing.Create(ctx, storedSession("other")))

				n, err := sealing.DeleteFamily(ctx, family)
				require.NoError(t, err)

				assert.Equal(t, 2, n)
				assert.Equal(t, 1, inner.Len())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealing, inner := sealingStore(t, 0x2a)
			tc.assert(t, t.Context(), sealing, inner)
		})
	}
}

// A store refusing a supersession with a sentinel of this package bare hands
// back that same value through the sealing store, as Load and Save do, so a
// caller comparing it by identity still matches.
func TestEncryptedStoreSupersedeReturnsSentinelsBare(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		sentinel error
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:     "renewal conflict",
			sentinel: session.ErrSessionRenewalConflict,
			assert:   isBare(session.ErrSessionRenewalConflict),
		},
		{
			name:     "not found",
			sentinel: session.ErrSessionNotFound,
			assert:   isBare(session.ErrSessionNotFound),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := NewMockStore(gomock.NewController(t))
			inner.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(tc.sentinel)
			sealing, err := session.NewEncryptedStore(inner, fakeCipher{key: 0x2a})
			require.NoError(t, err)

			err = sealing.Supersede(t.Context(), firstRotation("old", storedSession("new")))

			tc.assert(t, err)
		})
	}
}

// A supersession with no successor has nothing to insert, so both stores
// refuse it and write nothing, the sealing store as the store it wraps.
func TestSupersedeRefusesANilSuccessor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, store session.Store, inner *session.MemoryStore)
	}

	nilSuccessor := firstRotation("old", nil)

	check := func(t *testing.T, ctx context.Context, store session.Store, inner *session.MemoryStore) {
		t.Helper()

		require.NoError(t, store.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))

		err := store.Supersede(ctx, nilSuccessor)

		require.Error(t, err)
		require.NotErrorIs(t, err, session.ErrSessionRenewalConflict)
		require.NotErrorIs(t, err, session.ErrSessionNotFound)
		old, err := store.Load(ctx, "old")
		require.NoError(t, err)
		assert.True(t, old.SupersededAt.IsZero(), "a refused supersession marked the session")
		assert.Empty(t, old.SuccessorDigest)
		assert.Equal(t, 1, inner.Len(), "a refused supersession inserted something")
	}

	cases := []testCase{
		{
			name: "memory store",
			assert: func(t *testing.T, ctx context.Context, _ session.Store, inner *session.MemoryStore) {
				check(t, ctx, inner, inner)
			},
		},
		{
			name: "sealing store",
			assert: func(t *testing.T, ctx context.Context, sealing session.Store, inner *session.MemoryStore) {
				check(t, ctx, sealing, inner)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealing, inner := sealingStore(t, 0x2a)
			tc.assert(t, t.Context(), sealing, inner)
		})
	}
}

func TestMemoryStoreSupersession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, store *session.MemoryStore)
	}

	cases := []testCase{
		{
			// The durable stores key their rows by this digest, so a successor
			// digest the memory store records reads the same in any store.
			name: "the successor digest is the durable stores' session digest",
			assert: func(t *testing.T, ctx context.Context, store *session.MemoryStore) {
				require.NoError(t, store.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))
				require.NoError(t, store.Supersede(ctx, firstRotation("old", storedSession("new"))))

				old, err := store.Load(ctx, "old")
				require.NoError(t, err)
				assert.Equal(t, storekit.SessionDigest("new"), old.SuccessorDigest)
			},
		},
		{
			name: "a loaded successor digest is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, store *session.MemoryStore) {
				require.NoError(t, store.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))
				require.NoError(t, store.Supersede(ctx, firstRotation("old", storedSession("new"))))

				loaded, err := store.Load(ctx, "old")
				require.NoError(t, err)
				loaded.SuccessorDigest[0] ^= 0xff

				again, err := store.Load(ctx, "old")
				require.NoError(t, err)
				assert.Equal(t, storekit.SessionDigest("new"), again.SuccessorDigest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, inner := sealingStore(t, 0x2a)
			tc.assert(t, t.Context(), inner)
		})
	}
}

func TestCreateStartsAFamily(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)

	first, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	second, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	assert.NotEqual(t, id.Nil, first.FamilyID, "a new session starts a family")
	assert.NotEqual(t, first.FamilyID, second.FamilyID, "every sign-in starts a family of its own")
	assert.Equal(t, first.CreatedAt, first.FamilyCreatedAt, "the family starts when its first session is created")
	stored, err := store.Load(t.Context(), first.ID)
	require.NoError(t, err)
	assert.Equal(t, first.FamilyID, stored.FamilyID, "the family is stored by the creating write")
	assert.Equal(t, first.FamilyCreatedAt, stored.FamilyCreatedAt)
}

// TestMemoryStoreReRotationIgnoresAnUnindexedSuccessor pins that a successor
// digest the store no longer indexes names no record, even one stored under
// the empty identifier: the successor is gone, so the re-rotation is refused
// as advanced and the unrelated record is left alone.
func TestMemoryStoreReRotationIgnoresAnUnindexedSuccessor(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	s := session.NewMemoryStore(session.WithMemoryStoreClock(clockwork.NewFakeClockAt(createdAt)))
	require.NoError(t, s.Create(ctx, storedSession("")))
	require.NoError(t, s.Create(ctx, familyOf("old", id.MustParse("01926a4e-0000-7000-8000-000000000001"))))
	require.NoError(t, s.Supersede(ctx, firstRotation("old", storedSession("n1"))))
	require.NoError(t, s.Delete(ctx, "n1"))

	old, err := s.Load(ctx, "old")
	require.NoError(t, err)

	op := firstRotation("old", storedSession("n2"))
	op.ObservedSuccessor = old.SuccessorDigest
	require.ErrorIs(t, s.Supersede(ctx, op), session.ErrSuccessorAdvanced)

	unrelated, err := s.Load(ctx, "")
	require.NoError(t, err)
	assert.True(t, unrelated.SupersededAt.IsZero(), "an unrelated record was superseded")
}

// TestSupersedeRefusals pins the supersessions a store refuses with a plain
// error and writes nothing for, through the memory store and the sealing
// store over it: a successor with no family, and a retention deadline before
// the window's end.
func TestSupersedeRefusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		op     func() session.Supersession
		assert func(t *testing.T, err error, store *session.MemoryStore, old *session.Session)
	}

	refusedWithNothingWritten := func(t *testing.T, err error, store *session.MemoryStore, old *session.Session) {
		t.Helper()

		require.Error(t, err)
		require.NotErrorIs(t, err, session.ErrSessionRenewalConflict)
		require.NotErrorIs(t, err, session.ErrSessionNotFound)
		require.NotErrorIs(t, err, session.ErrSuccessorAdvanced)
		assert.Equal(t, 1, store.Len(), "a refused supersession inserted something")
		stored, err := store.Load(t.Context(), old.ID)
		require.NoError(t, err)
		assert.True(t, stored.SupersededAt.IsZero(), "a refused supersession marked the session")
		assert.Equal(t, old.AbsoluteExpiresAt, stored.AbsoluteExpiresAt)
	}

	cases := []testCase{
		{
			name: "a successor with no family",
			op: func() session.Supersession {
				successor := storedSession("new")
				successor.FamilyID = id.Nil

				return firstRotation("old", successor)
			},
			assert: refusedWithNothingWritten,
		},
		{
			name: "a retention deadline before the window's end",
			op: func() session.Supersession {
				op := firstRotation("old", storedSession("new"))
				op.RetainUntil = op.AcceptUntil.Add(-time.Second)

				return op
			},
			assert: refusedWithNothingWritten,
		},
	}

	for _, tc := range cases {
		for _, sealed := range []bool{false, true} {
			name := tc.name + " on the memory store"
			if sealed {
				name = tc.name + " on the sealing store"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				var store session.Store
				sealing, inner := sealingStore(t, 0x2a)
				store = inner
				if sealed {
					store = sealing
				}
				old := storedSession("old")
				require.NoError(t, store.Create(t.Context(), old))

				err := store.Supersede(t.Context(), tc.op())

				tc.assert(t, err, inner, old)
			})
		}
	}
}

// TestMemoryStoreSupersessionNeverLowersADeadline pins that a retention
// deadline below the absolute deadline a record already holds leaves it as it
// was, and the idle deadline becomes that same deadline, for Old and for Old's
// previous successor alike.
func TestMemoryStoreSupersessionNeverLowersADeadline(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	require.NoError(t, store.Create(t.Context(), storedSession("old")))

	first := firstRotation("old", storedSession("n1"))
	first.RetainUntil = createdAt.Add(2 * time.Hour) // below the absolute deadline, 12 hours
	require.NoError(t, store.Supersede(t.Context(), first))

	second := firstRotation("old", storedSession("n2"))
	second.ObservedSuccessor = storekit.SessionDigest("n1")
	second.RetainUntil = createdAt.Add(2 * time.Hour)
	require.NoError(t, store.Supersede(t.Context(), second))

	for _, sessionID := range []string{"old", "n1"} {
		got, err := store.Load(t.Context(), sessionID)
		require.NoError(t, err)
		assert.Equal(t, createdAt.Add(12*time.Hour), got.AbsoluteExpiresAt, "%s: absolute deadline lowered", sessionID)
		assert.Equal(t, createdAt.Add(12*time.Hour), got.IdleExpiresAt, "%s: a superseded record keeps one deadline, its absolute", sessionID)
	}
}

// TestEncryptedStoreCreatePassesOnTheNilFamilyRefusal pins that the sealing
// store neither hides nor works around the inner store's refusal of a
// session in no family: the error comes back and nothing is stored.
func TestEncryptedStoreCreatePassesOnTheNilFamilyRefusal(t *testing.T) {
	t.Parallel()

	sealing, inner := sealingStore(t, 0x2a)
	orphan := storedSession("orphan")
	orphan.FamilyID = id.Nil

	err := sealing.Create(t.Context(), orphan)

	require.Error(t, err)
	assert.NotErrorIs(t, err, session.ErrSessionNotFound)
	assert.Zero(t, inner.Len(), "a refused session was stored")
}
