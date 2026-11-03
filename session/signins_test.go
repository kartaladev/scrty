package session_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/session"
)

// listCountingStore counts the listings it serves, so a test can tell one query
// from one per family.
type listCountingStore struct {
	session.Store
	listings atomic.Int64
}

func (s *listCountingStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	s.listings.Add(1)

	return s.Store.ListByUser(ctx, user, now)
}

// listFixture is what one listing case is run against.
type listFixture struct {
	m       *session.Sessions
	user    identity.UserID
	current *session.Session
	// sessions are every session the case created or renewed, predecessors
	// included, for asserting that no identifier leaks into the listing.
	sessions []*session.Session
	counter  *listCountingStore
}

// renewed renews s with no grace window, one clock step after it was used.
func renewed(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, s *session.Session, grace time.Duration) *session.Session {
	t.Helper()

	clk.Advance(time.Second)
	next, _, err := m.RotateWithGrace(t.Context(), s, grace)
	require.NoError(t, err)

	return next
}

// assertNoIdentifiers fails when the rendered listing carries any session's
// identifier or its digest, in any encoding a log or a response would use.
func assertNoIdentifiers(t *testing.T, listed []session.SignIn, sessions []*session.Session) {
	t.Helper()

	rendered := fmt.Sprintf("%+v %#v", listed, listed)
	for _, s := range sessions {
		digest := storekit.SessionDigest(s.ID)
		assert.NotContains(t, rendered, s.ID)
		assert.NotContains(t, rendered, hex.EncodeToString(digest))
		assert.NotContains(t, rendered, base64.RawURLEncoding.EncodeToString(digest))
		assert.False(t, strings.Contains(rendered, string(digest)))
	}
}

func TestSessions_List(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) listFixture
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, f listFixture, listed []session.SignIn, err error)
	}

	cases := []testCase{
		{
			name: "renewals are one sign-in: two devices, one renewed twice",
			setup: func(t *testing.T) listFixture {
				clk := clockwork.NewFakeClockAt(createdAt)
				m, _ := managerOnClock(t, clk)
				laptop, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)
				phone, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Passkey))
				require.NoError(t, err)
				second := renewed(t, m, clk, laptop, 0)
				third := renewed(t, m, clk, second, 0)

				return listFixture{
					m: m, user: testUser, current: phone,
					sessions: []*session.Session{laptop, second, third, phone},
				}
			},
			assert: func(t *testing.T, f listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 2)

				byHandle := map[string]session.SignIn{}
				for _, in := range listed {
					byHandle[in.Handle.String()] = in
				}
				laptop, phone := f.sessions[0], f.sessions[3]
				require.Contains(t, byHandle, laptop.FamilyID.String())
				require.Contains(t, byHandle, phone.FamilyID.String())

				l := byHandle[laptop.FamilyID.String()]
				assert.True(t, l.CreatedAt.Equal(laptop.FamilyCreatedAt))
				assert.True(t, l.LastUsedAt.Equal(f.sessions[2].LastAccessedAt))
				assert.Equal(t, factor.Password, l.FirstFactor)
				assert.Equal(t, session.MFANone, l.Pending)
				assert.False(t, l.Current)

				p := byHandle[phone.FamilyID.String()]
				assert.Equal(t, factor.Passkey, p.FirstFactor)
				assert.True(t, p.Current, "the caller's own sign-in is marked current")

				assertNoIdentifiers(t, listed, f.sessions)
			},
		},
		{
			name: "a family whose members have all expired is not listed",
			setup: func(t *testing.T) listFixture {
				clk := clockwork.NewFakeClockAt(createdAt)
				m, _ := managerOnClock(t, clk)
				_, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				clk.Advance(31 * time.Minute)
				live, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)

				return listFixture{m: m, user: testUser, sessions: []*session.Session{live}}
			},
			assert: func(t *testing.T, f listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, f.sessions[0].FamilyID, listed[0].Handle)
			},
		},
		{
			name: "within the grace window the sign-in is listed once, with the successor's last use",
			setup: func(t *testing.T) listFixture {
				clk := clockwork.NewFakeClockAt(createdAt)
				m, _ := managerOnClock(t, clk)
				old, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				clk.Advance(time.Minute)
				next := renewed(t, m, clk, old, 30*time.Second)
				clk.Advance(5 * time.Second)

				return listFixture{m: m, user: testUser, current: next, sessions: []*session.Session{old, next}}
			},
			assert: func(t *testing.T, f listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.True(t, listed[0].LastUsedAt.Equal(f.sessions[1].LastAccessedAt),
					"last use %s, the successor's is %s", listed[0].LastUsedAt, f.sessions[1].LastAccessedAt)
				assert.False(t, listed[0].LastUsedAt.Equal(f.sessions[0].LastAccessedAt))
				assert.True(t, listed[0].Current)
				assertNoIdentifiers(t, listed, f.sessions)
			},
		},
		{
			name: "a sign-in still owing a second factor is listed and marked",
			setup: func(t *testing.T) listFixture {
				m := managerFor(t)
				p, err := m.Prepare(testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)
				p.Session().MFA = session.MFAPending
				pending, err := p.Commit(t.Context())
				require.NoError(t, err)

				return listFixture{m: m, user: testUser, sessions: []*session.Session{pending}}
			},
			assert: func(t *testing.T, _ listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, session.MFAPending, listed[0].Pending)
				assert.False(t, listed[0].Current)
			},
		},
		{
			name: "a sign-in that met its second factor owes nothing",
			setup: func(t *testing.T) listFixture {
				m := managerFor(t)
				s, err := m.Create(t.Context(), testUser, session.WithSecondFactorAtLogin())
				require.NoError(t, err)

				return listFixture{m: m, user: testUser, sessions: []*session.Session{s}}
			},
			assert: func(t *testing.T, _ listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, session.MFANone, listed[0].Pending)
			},
		},
		{
			name: "another user's sessions are not listed",
			setup: func(t *testing.T) listFixture {
				m := managerFor(t)
				mine, err := m.Create(t.Context(), "u-1")
				require.NoError(t, err)
				theirs, err := m.Create(t.Context(), "u-2")
				require.NoError(t, err)

				return listFixture{m: m, user: "u-1", sessions: []*session.Session{mine, theirs}}
			},
			assert: func(t *testing.T, f listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, f.sessions[0].FamilyID, listed[0].Handle)
			},
		},
		{
			// The manager does not trust a store to have filtered: a record
			// of another user, a superseded one or one expired by the
			// manager's clock is never reported.
			name: "a store answering with what it should have filtered lists none of it",
			setup: func(t *testing.T) listFixture {
				store := NewMockStore(gomock.NewController(t))
				m := managerFor(t, session.WithStore(store), session.WithClock(fixedClock{at: createdAt.Add(time.Minute)}))
				foreign := familyOf("foreign", graceFamily)
				foreign.UserID = "u-2"
				superseded := familyOf("superseded", graceFamily)
				superseded.SupersededAt = createdAt
				expired := familyOf("expired", graceFamily)
				expired.IdleExpiresAt = createdAt
				store.EXPECT().ListByUser(gomock.Any(), testUser, createdAt.Add(time.Minute)).
					Return([]*session.Session{foreign, superseded, expired}, nil)

				return listFixture{m: m, user: testUser, sessions: []*session.Session{foreign, superseded, expired}}
			},
			assert: func(t *testing.T, _ listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				assert.Empty(t, listed)
			},
		},
		{
			name: "a store failure is a dependency failure with fixed text",
			setup: func(t *testing.T) listFixture {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().ListByUser(gomock.Any(), testUser, gomock.Any()).Return(nil, errStoreQuotes)

				return listFixture{m: managerFor(t, session.WithStore(store)), user: testUser}
			},
			assert: func(t *testing.T, _ listFixture, listed []session.SignIn, err error) {
				require.ErrorIs(t, err, session.ErrListUnavailable)
				require.ErrorIs(t, err, errStoreQuotes)
				assert.Equal(t, session.ErrListUnavailable.Error(), err.Error())
				assert.Nil(t, listed)
			},
		},
		{
			// The store met a deadline of its own while the caller was still
			// there: an outage, not a hang-up.
			name: "a store's own timeout is a dependency failure",
			setup: func(t *testing.T) listFixture {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().ListByUser(gomock.Any(), testUser, gomock.Any()).
					Return(nil, fmt.Errorf("pool: %w", context.DeadlineExceeded))

				return listFixture{m: managerFor(t, session.WithStore(store)), user: testUser}
			},
			assert: func(t *testing.T, _ listFixture, _ []session.SignIn, err error) {
				require.ErrorIs(t, err, session.ErrListUnavailable)
			},
		},
		{
			name: "a caller that hung up gets its context's error, not a dependency failure",
			setup: func(t *testing.T) listFixture {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().ListByUser(gomock.Any(), testUser, gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ time.Time) ([]*session.Session, error) {
						return nil, fmt.Errorf("query: %w", ctx.Err())
					})

				return listFixture{m: managerFor(t, session.WithStore(store)), user: testUser}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ listFixture, listed []session.SignIn, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, session.ErrListUnavailable)
				assert.Nil(t, listed)
			},
		},
		{
			// Review focus: a user with many renewed sign-ins costs one store
			// query, not one per family.
			name: "100 families renewed 10 times each are 100 entries from one listing",
			setup: func(t *testing.T) listFixture {
				clk := clockwork.NewFakeClockAt(createdAt)
				inner, err := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
				require.NoError(t, err)
				counter := &listCountingStore{Store: inner}
				m := managerFor(t, session.WithStore(counter), session.WithClock(clk))
				for range 100 {
					s, err := m.Create(t.Context(), testUser)
					require.NoError(t, err)
					for range 10 {
						s = renewedQuietly(t, m, s)
					}
				}

				return listFixture{m: m, user: testUser, counter: counter}
			},
			assert: func(t *testing.T, f listFixture, listed []session.SignIn, err error) {
				require.NoError(t, err)
				assert.Len(t, listed, 100)
				assert.Equal(t, int64(1), f.counter.listings.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := tc.setup(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			listed, err := f.m.ListSignIns(ctx, f.user, f.current)
			tc.assert(t, f, listed, err)
		})
	}
}

// renewedQuietly renews s with no grace window and no clock step.
func renewedQuietly(t *testing.T, m *session.Sessions, s *session.Session) *session.Session {
	t.Helper()

	next, _, err := m.RotateWithGrace(t.Context(), s, 0)
	require.NoError(t, err)

	return next
}
