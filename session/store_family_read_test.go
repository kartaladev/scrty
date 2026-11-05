package session_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

var (
	familyAsked = id.MustParse("0192d2a0-0000-7000-8000-00000000a001")
	familyOther = id.MustParse("0192d2a0-0000-7000-8000-00000000a002")
)

// familyMember is a live session of family, carrying both sealed fields as a
// listing must never hand them back.
func familyMember(sid string, user identity.UserID, family id.ID) *session.Session {
	return &session.Session{
		ID:                sid,
		UserID:            user,
		FamilyID:          family,
		FamilyCreatedAt:   createdAt,
		CreatedAt:         createdAt,
		AuthenticatedAt:   createdAt,
		LastAccessedAt:    createdAt,
		IdleExpiresAt:     createdAt.Add(time.Hour),
		AbsoluteExpiresAt: createdAt.Add(2 * time.Hour),
		ExternalIssuer:    "https://idp.example.com",
		ExternalIDToken:   "an-envelope-in-the-column",
		CSRFToken:         "another-envelope-in-the-column",
	}
}

func TestStore_MemoryListByFamily(t *testing.T) {
	t.Parallel()

	// A deadline past the read's time, a superseded predecessor, a neighbouring
	// sign-in and a stranger sharing the family: each must stay out.
	seed := func(t *testing.T, store *session.MemoryStore) {
		t.Helper()

		ctx := t.Context()
		predecessor := familyMember("predecessor", testUser, familyAsked)
		require.NoError(t, store.Create(ctx, predecessor))
		head := familyMember("head", testUser, familyAsked)
		require.NoError(t, store.Supersede(ctx, session.Supersession{
			Old: predecessor.ID, AcceptUntil: createdAt.Add(time.Minute), RetainUntil: createdAt.Add(2 * time.Hour),
			Successor: head, Now: createdAt,
		}))
		require.NoError(t, store.Create(ctx, familyMember("neighbour", testUser, familyOther)))
		require.NoError(t, store.Create(ctx, familyMember("stranger", "another-user", familyAsked)))
	}

	type testCase struct {
		name   string
		user   identity.UserID
		family id.ID
		now    time.Time
		assert func(t *testing.T, store *session.MemoryStore, listed []*session.Session, err error)
	}

	none := func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
		t.Helper()

		require.NoError(t, err, "no match is an empty result, not an error")
		assert.Empty(t, listed)
	}

	cases := []testCase{
		{
			name: "the family's live head alone", user: testUser, family: familyAsked, now: createdAt,
			assert: func(t *testing.T, _ *session.MemoryStore, listed []*session.Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, "head", listed[0].ID)
			},
		},
		{
			name: "a session handed back is the caller's own", user: testUser, family: familyAsked, now: createdAt,
			assert: func(t *testing.T, store *session.MemoryStore, listed []*session.Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, listed, 1)
				listed[0].UserAgent = "changed by the caller"
				stored, loadErr := store.Load(t.Context(), "head")
				require.NoError(t, loadErr)
				assert.Empty(t, stored.UserAgent)
			},
		},
		{name: "past the head's idle deadline at the time passed", user: testUser, family: familyAsked, now: createdAt.Add(time.Hour), assert: none},
		{name: "an unknown family", user: testUser, family: id.MustParse("0192d2a0-0000-7000-8000-00000000a0ff"), now: createdAt, assert: none},
		{name: "the nil family names none", user: testUser, family: id.Nil, now: createdAt, assert: none},
		{name: "a user with no session of the family", user: "nobody", family: familyAsked, now: createdAt, assert: none},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clockwork.NewFakeClockAt(createdAt))))
			seed(t, store)

			reader, ok := any(store).(session.FamilyReader)
			require.True(t, ok, "the memory store must offer the family read")

			listed, err := reader.ListByFamily(t.Context(), tc.user, tc.family, tc.now)
			tc.assert(t, store, listed, err)
		})
	}
}

// TestStore_EncryptedListByFamily pins the decorator's read over what it wraps.
// Its cipher expects no call, so opening or sealing anything fails the row, and
// the wrapped store expects only the read the row names.
func TestStore_EncryptedListByFamily(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		family id.ID
		// inner returns the wrapped store, with what it is expected to answer.
		inner  func(ctrl *gomock.Controller) session.Store
		assert func(t *testing.T, listed []*session.Session, err error)
	}

	reading := func(answer []*session.Session, failure error) func(*gomock.Controller) session.Store {
		return func(ctrl *gomock.Controller) session.Store {
			family := NewMockFamilyReader(ctrl)
			family.EXPECT().ListByFamily(gomock.Any(), testUser, familyAsked, createdAt).Return(answer, failure)

			return struct {
				*MockStore
				*MockFamilyReader
			}{NewMockStore(ctrl), family}
		}
	}
	listing := func(answer []*session.Session, failure error) func(*gomock.Controller) session.Store {
		return func(ctrl *gomock.Controller) session.Store {
			store := NewMockStore(ctrl)
			store.EXPECT().ListByUser(gomock.Any(), testUser, createdAt).Return(answer, failure)

			return store
		}
	}
	askedNothing := func(ctrl *gomock.Controller) session.Store { return NewMockStore(ctrl) }

	theHeadAlone := func(t *testing.T, listed []*session.Session, err error) {
		t.Helper()

		require.NoError(t, err)
		require.Len(t, listed, 1)
		assert.Equal(t, "head", listed[0].ID)
		assert.Equal(t, familyAsked, listed[0].FamilyID)
		assert.Equal(t, "https://idp.example.com", listed[0].ExternalIssuer, "what is not sealed is kept")
		assert.Empty(t, listed[0].ExternalIDToken, "an envelope must not stand in for the token")
		assert.Empty(t, listed[0].CSRFToken, "an envelope must not stand in for the token")
	}
	aFailure := func(t *testing.T, listed []*session.Session, err error) {
		t.Helper()

		require.ErrorIs(t, err, errStoreQuotes, "the store's error stays reachable")
		assert.NotContains(t, err.Error(), "alice@example.com", "the store's own words reached the error")
		assert.Empty(t, listed)
	}

	cases := []testCase{
		{
			name:   "over a store with a family read: its answer, with no envelope",
			family: familyAsked,
			inner:  reading([]*session.Session{familyMember("head", testUser, familyAsked)}, nil),
			assert: theHeadAlone,
		},
		{
			name:   "over a store with a family read: its failure, behind fixed text",
			family: familyAsked,
			inner:  reading(nil, errStoreQuotes),
			assert: aFailure,
		},
		{
			name:   "over a store with a family read: nil in its answer is passed on untouched",
			family: familyAsked,
			inner:  reading([]*session.Session{nil}, nil),
			assert: func(t *testing.T, listed []*session.Session, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []*session.Session{nil}, listed)
			},
		},
		{
			name:   "over a store with none: the listing narrowed to the family, with no envelope",
			family: familyAsked,
			inner: listing([]*session.Session{
				familyMember("neighbour", testUser, familyOther),
				familyMember("head", testUser, familyAsked),
				nil,
				familyMember("other-neighbour", testUser, familyOther),
			}, nil),
			assert: theHeadAlone,
		},
		{
			name:   "over a store with none: no member of the family is an empty answer",
			family: familyAsked,
			inner:  listing([]*session.Session{familyMember("neighbour", testUser, familyOther)}, nil),
			assert: func(t *testing.T, listed []*session.Session, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, listed)
			},
		},
		{
			name:   "over a store with none: the listing's failure, behind fixed text",
			family: familyAsked,
			inner:  listing(nil, errStoreQuotes),
			assert: aFailure,
		},
		{
			name:   "the nil family asks nothing of what it wraps",
			family: id.Nil,
			inner:  askedNothing,
			assert: func(t *testing.T, listed []*session.Session, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, listed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store := must.Must(session.NewEncryptedStore(tc.inner(ctrl), NewMockCipher(ctrl)))

			reader, ok := store.(session.FamilyReader)
			require.True(t, ok, "the sealing store must offer the family read, whatever it wraps")

			listed, err := reader.ListByFamily(t.Context(), testUser, tc.family, createdAt)
			tc.assert(t, listed, err)
		})
	}
}

// BenchmarkSignInState_OneFamily measures what a stream's reload costs against
// how many sign-ins the user holds and how many other users the store holds.
func BenchmarkSignInState_OneFamily(b *testing.B) {
	reads := []struct {
		name string
		wrap func(s session.Store) session.Store
	}{
		{name: "family read", wrap: func(s session.Store) session.Store { return s }},
		// Embedding only the Store hides the family read, as a consumer's own
		// store has none: this is the default's cost.
		{name: "listing", wrap: func(s session.Store) session.Store { return struct{ session.Store }{s} }},
	}

	for _, read := range reads {
		for _, size := range []struct{ signIns, others int }{{1, 0}, {5, 0}, {50, 0}, {1, 1000}, {50, 1000}} {
			b.Run(fmt.Sprintf("%s/sign-ins=%d/other-users=%d", read.name, size.signIns, size.others), func(b *testing.B) {
				ctx := b.Context()
				store := must.Must(session.NewMemoryStore())
				traffic := must.Must(session.New(session.WithStore(store)))

				var family id.ID
				for i := range size.signIns {
					s, err := traffic.Create(ctx, "u-1", session.WithFirstFactor(factor.Password))
					require.NoError(b, err)
					if i == 0 {
						family = s.FamilyID
					}
				}
				for i := range size.others {
					_, err := traffic.Create(ctx, identity.UserID(fmt.Sprintf("o-%d", i)), session.WithFirstFactor(factor.Password))
					require.NoError(b, err)
				}

				reader := must.Must(session.New(session.WithStore(read.wrap(store))))

				b.ReportAllocs()
				for b.Loop() {
					if _, err := reader.SignInState(ctx, "u-1", family); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
