package oidcprovider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// errReadOutage is what a session store whose reads fail answers.
var errReadOutage = errors.New("the session store cannot be reached")

// readsFailingSessions is a session store whose Load fails once failing is set,
// while its writes still work.
type readsFailingSessions struct {
	*session.MemoryStore

	failing bool
}

func (s *readsFailingSessions) Load(ctx context.Context, id string) (*session.Session, error) {
	if s.failing {
		return nil, errReadOutage
	}

	return s.MemoryStore.Load(ctx, id)
}

// TestProvider_FailedEndReportRead pins what a failed read for an end's report means to the
// provider, over a real manager: the end did not happen, so every grant stands and no client is
// told of it. A report saying less than it should would have left the deleted sign-in's grants
// live with its session gone, or widened to the sign-in the caller meant to keep.
func TestProvider_FailedEndReportRead(t *testing.T) {
	t.Parallel()

	// scene is what a row's assert looks at once the end has failed.
	type scene struct {
		e                       *endFixture
		memory                  *session.MemoryStore
		first, second           *session.Session
		firstGrant, secondGrant *refreshScene
	}

	type testCase struct {
		name string
		// act ends something of the user's, naming session s of the first sign-in.
		act    func(ctx context.Context, m *session.Sessions, s *session.Session) error
		assert func(t *testing.T, sc scene, err error)
	}

	changedNothing := func(t *testing.T, sc scene, err error) {
		t.Helper()

		assert.ErrorIs(t, err, errReadOutage)
		assert.False(t, sc.e.grantStands(t, sc.firstGrant).Revoked, "the named sign-in's grant stands")
		assert.False(t, sc.e.grantStands(t, sc.secondGrant).Revoked, "the other sign-in's grant stands")
		assert.Empty(t, sc.e.queued(), "no client is told of an end that did not happen")

		for _, s := range []*session.Session{sc.first, sc.second} {
			_, loadErr := sc.memory.Load(t.Context(), s.ID)
			assert.NoError(t, loadErr, "the session is still stored, so asking again can end it")
		}
	}

	cases := []testCase{
		{
			name: "deleting a session leaves it stored and its sign-in's grants live",
			act: func(ctx context.Context, m *session.Sessions, s *session.Session) error {
				return m.Delete(ctx, s.ID)
			},
			assert: changedNothing,
		},
		{
			name: "deleting all but a session leaves every sign-in's grants live",
			act: func(ctx context.Context, m *session.Sessions, s *session.Session) error {
				_, err := m.DeleteByUserExcept(ctx, s.UserID, s.ID)

				return err
			},
			assert: changedNothing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEndFixture(t)
			memory, err := session.NewMemoryStore(session.WithMemoryStoreClock(e.clk))
			require.NoError(t, err)
			store := &readsFailingSessions{MemoryStore: memory}
			manager, err := session.New(
				session.WithStore(store),
				session.WithClock(e.clk),
				session.WithEndObserver(e.p),
			)
			require.NoError(t, err)
			require.True(t, manager.ReportsEndsTo(e.p))

			first, err := manager.Create(t.Context(), "u-1")
			require.NoError(t, err)
			second, err := manager.Create(t.Context(), "u-1")
			require.NoError(t, err)

			firstIn := e.signInOf("u-1", "", "")
			firstIn.Family = first.FamilyID
			secondIn := e.signInOf("u-1", "", "")
			secondIn.Family = second.FamilyID
			firstGrant, secondGrant := e.online(t, firstIn), e.online(t, secondIn)

			store.failing = true
			err = tc.act(t.Context(), manager, first)

			tc.assert(t, scene{
				e: e, memory: memory, first: first, second: second, firstGrant: firstGrant, secondGrant: secondGrant,
			}, err)
		})
	}
}
