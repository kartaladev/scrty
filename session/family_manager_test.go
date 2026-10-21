package session_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

func TestCreate_StartsAFamilyOfItsOwn(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	a, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	b, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	assert.NotEqual(t, a.FamilyID, b.FamilyID)
	assert.False(t, a.FamilyID.IsZero())
	assert.Equal(t, a.CreatedAt, a.FamilyCreatedAt)
}

func TestRotate_KeepsTheFamily(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)

	first, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	clk.Advance(5 * time.Minute)
	second, err := m.Rotate(t.Context(), first)
	require.NoError(t, err)
	third, err := m.Rotate(t.Context(), second)
	require.NoError(t, err)

	for _, s := range []*session.Session{second, third} {
		assert.Equal(t, first.FamilyID, s.FamilyID)
		assert.Equal(t, first.FamilyCreatedAt, s.FamilyCreatedAt)
	}
}

func TestRevokeFamily(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, _ := managerOnClock(t, clk)
	ctx := t.Context()

	one, err := m.Create(ctx, testUser)
	require.NoError(t, err)
	oneRotated, err := m.Rotate(ctx, one)
	require.NoError(t, err)
	other, err := m.Create(ctx, testUser)
	require.NoError(t, err)

	n, err := m.RevokeFamily(ctx, one.FamilyID)

	require.NoError(t, err)
	assert.Equal(t, 1, n, "the rotated session is the only one left in the family")
	_, err = m.Load(ctx, oneRotated.ID)
	require.ErrorIs(t, err, session.ErrSessionNotFound)
	_, err = m.Load(ctx, other.ID)
	require.NoError(t, err, "revoking one family took another family of the same user")
}

func TestRevokeFamily_StoreFailure(t *testing.T) {
	t.Parallel()

	store := NewMockStore(gomock.NewController(t))
	family := id.MustParse("01926a4e-0000-7000-8000-0000000000aa")
	store.EXPECT().DeleteFamily(gomock.Any(), family).Return(0, errStoreWrite)
	m := managerFor(t, session.WithStore(store))

	_, err := m.RevokeFamily(t.Context(), family)

	require.ErrorIs(t, err, errStoreWrite)
}

func TestRevokeFamily_RefusesTheNilFamily(t *testing.T) {
	t.Parallel()

	// The mock expects no call: the nil family never reaches the store.
	store := NewMockStore(gomock.NewController(t))
	m := managerFor(t, session.WithStore(store))

	n, err := m.RevokeFamily(t.Context(), id.Nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil family")
	assert.Zero(t, n)
}

type failingGenerator struct{ err error }

func (g failingGenerator) NewID() (id.ID, error) { return id.ID{}, g.err }

func TestCreate_RefusesAnUnusableFamilyIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		gen  id.Generator
		// assert receives the error and how many sessions reached the store.
		assert func(t *testing.T, err error, stored int)
	}

	errGen := errors.New("generator down")
	cases := []testCase{
		{
			name: "a generator error fails Create",
			gen:  failingGenerator{err: errGen},
			assert: func(t *testing.T, err error, stored int) {
				require.ErrorIs(t, err, errGen)
				assert.Zero(t, stored)
			},
		},
		{
			name: "the nil identifier fails Create",
			gen:  fixedGenerator{value: id.Nil},
			assert: func(t *testing.T, err error, stored int) {
				require.ErrorIs(t, err, session.ErrConfig, "a generator returning the nil identifier is a wiring fault")
				assert.Zero(t, stored, "a session with no family reached the store")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := session.NewMemoryStore()
			m := managerFor(t, session.WithStore(store), session.WithFamilyIDGenerator(tc.gen))

			_, err := m.Create(t.Context(), testUser)

			n, countErr := store.CountActiveByUser(t.Context(), testUser)
			require.NoError(t, countErr)
			tc.assert(t, err, n)
		})
	}
}
