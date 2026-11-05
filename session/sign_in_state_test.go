package session_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// signInStateFixture holds a sign-in's ordinary traffic apart from the read
// under test. traffic renews and ends through the real store; reader, the
// manager the read goes through, sees it through a mocked store expecting only
// the one read its mode offers, ListByUser or ListByFamily, so a read that
// reached Load, MarkPresented, DeleteFamily or any other store call fails the
// case.
type signInStateFixture struct {
	clk     *clockwork.FakeClock
	traffic *session.Sessions
	inner   *session.MemoryStore

	// through is the store reader's read is served by.
	through session.Store
	// answer, when set by arrange, replaces what through would answer.
	answer func(ctx context.Context) ([]*session.Session, error)
	// retired is the store under the key the fixture's sessions were not sealed
	// with, when the case seals. It is nil otherwise.
	retired session.Store

	listings atomic.Int64
	tracked  []string
}

// create signs user in through traffic and tracks the session.
func (f *signInStateFixture) create(ctx context.Context, t *testing.T, user identity.UserID, opts ...session.CreateOption) *session.Session {
	t.Helper()

	s, err := f.traffic.Create(ctx, user, opts...)
	require.NoError(t, err)
	f.tracked = append(f.tracked, s.ID)

	return s
}

// renew renews s through traffic with the default window and tracks the
// successor.
func (f *signInStateFixture) renew(ctx context.Context, t *testing.T, s *session.Session) *session.Session {
	t.Helper()

	next, _, err := f.traffic.RotateWithGrace(ctx, s, session.DefaultRenewalGrace)
	require.NoError(t, err)
	f.tracked = append(f.tracked, next.ID)

	return next
}

// storedRecord is what the store holds under one identifier, as it answered.
type storedRecord struct {
	session *session.Session
	err     error
}

// snapshot reads every tracked identifier straight from the store.
func (f *signInStateFixture) snapshot(ctx context.Context) map[string]storedRecord {
	records := make(map[string]storedRecord, len(f.tracked))
	for _, sid := range f.tracked {
		s, err := f.inner.Load(ctx, sid)
		records[sid] = storedRecord{session: s, err: err}
	}

	return records
}

func TestSessions_SignInState(t *testing.T) {
	t.Parallel()

	const (
		user     = identity.UserID("signed-in-user")
		other    = identity.UserID("another-user")
		issuer   = "https://idp.example.com"
		upstream = "upstream-session-x-9"
		idToken  = "a-sealed-id-token" //nolint:gosec // G101: a test fixture value, not a credential
	)

	unknownFamily := id.MustParse("0192d2a0-0000-7000-8000-00000000f00d")

	// query is whom a row reads for.
	type query struct {
		user   identity.UserID
		family id.ID
	}

	type testCase struct {
		name string
		// opts configure both managers, so their deadlines agree.
		opts []session.Option
		// sealed puts the sealing decorator over the store: traffic seals under
		// one key, and the read goes through a cipher with no key at all.
		sealed bool
		ctx    func(ctx context.Context) context.Context
		// arrange runs before the read and returns what to read for.
		arrange func(ctx context.Context, t *testing.T, f *signInStateFixture) query
		assert  func(t *testing.T, f *signInStateFixture, got session.SignInState, err error)
	}

	// head is a stored answer for the rows that make a store misbehave: a
	// member of family, used and idling out at offsets from createdAt.
	head := func(u identity.UserID, family id.ID, lastAccessed, idle time.Duration) *session.Session {
		return &session.Session{
			UserID:            u,
			FamilyID:          family,
			FamilyCreatedAt:   createdAt,
			CreatedAt:         createdAt,
			AuthenticatedAt:   createdAt,
			LastAccessedAt:    createdAt.Add(lastAccessed),
			IdleExpiresAt:     createdAt.Add(idle),
			AbsoluteExpiresAt: createdAt.Add(12 * time.Hour),
		}
	}
	listing := func(listed ...*session.Session) func(context.Context) ([]*session.Session, error) {
		return func(context.Context) ([]*session.Session, error) { return listed, nil }
	}
	failing := func(failure error) func(context.Context) ([]*session.Session, error) {
		return func(context.Context) ([]*session.Session, error) { return nil, failure }
	}

	notFound := func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrNotFound)
		assert.Zero(t, got, "an answer of not found carries no state")
	}
	notFoundUnasked := func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
		t.Helper()

		notFound(t, f, got, err)
		assert.Zero(t, f.listings.Load(), "a read that cannot match anything has no reason to ask the store")
	}
	storeFailure := func(failure error) func(*testing.T, *signInStateFixture, session.SignInState, error) {
		return func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
			t.Helper()

			require.ErrorIs(t, err, session.ErrListUnavailable)
			require.ErrorIs(t, err, failure, "the store's error stays reachable")
			assert.NotErrorIs(t, err, session.ErrNotFound, "an outage must not read as a sign-in that ended")
			assert.NotContains(t, err.Error(), "alice@example.com", "the store's own words reached the error")
			assert.Zero(t, got)
		}
	}

	cases := []testCase{
		{
			name: "a session never presented answers, and stays never presented",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				stored, loadErr := f.inner.Load(t.Context(), f.tracked[0])
				require.NoError(t, loadErr)
				assert.True(t, stored.FirstPresentedAt.IsZero(), "the read recorded a presentation at %s", stored.FirstPresentedAt)
				assert.True(t, got.IdleDeadline.Equal(stored.IdleExpiresAt))
				assert.True(t, got.AbsoluteDeadline.Equal(stored.AbsoluteExpiresAt))
				assert.True(t, got.AuthenticatedAt.Equal(stored.AuthenticatedAt))
				assert.Empty(t, got.ExternalIssuer)
				assert.Empty(t, got.ExternalSessionID)
			},
		},
		{
			name: "after a renewal past its grace window: the successor's deadlines, and the family stays live",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user, session.WithExternalSession("idp", issuer, upstream, idToken))
				f.clk.Advance(10 * time.Minute)
				f.renew(ctx, t, s)
				f.clk.Advance(session.DefaultRenewalGrace + time.Second)

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				successor, loadErr := f.inner.Load(t.Context(), f.tracked[1])
				require.NoError(t, loadErr)
				original, loadErr := f.inner.Load(t.Context(), f.tracked[0])
				require.NoError(t, loadErr)
				require.False(t, successor.IdleExpiresAt.Equal(original.IdleExpiresAt), "the renewal moved nothing, so this proves nothing")
				assert.True(t, got.IdleDeadline.Equal(successor.IdleExpiresAt), "got %s, the successor's is %s", got.IdleDeadline, successor.IdleExpiresAt)
				assert.True(t, got.AbsoluteDeadline.Equal(successor.AbsoluteExpiresAt))
				assert.Equal(t, issuer, got.ExternalIssuer)
				assert.Equal(t, upstream, got.ExternalSessionID)
				assert.True(t, successor.FirstPresentedAt.IsZero(), "the read presented the successor, which would spend a recovery")

				_, liveErr := f.traffic.Load(t.Context(), successor.ID)
				assert.NoError(t, liveErr, "the renewed sign-in the user is using must still load")
			},
		},
		{
			name: "inside a renewal's grace window: already the successor's deadlines",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				f.clk.Advance(10 * time.Minute)
				f.renew(ctx, t, s)

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				successor, loadErr := f.inner.Load(t.Context(), f.tracked[1])
				require.NoError(t, loadErr)
				assert.True(t, got.IdleDeadline.Equal(successor.IdleExpiresAt))
			},
		},
		{
			name: "after a strict rotation: the new session's authentication time",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				f.clk.Advance(time.Minute)
				reproved := *s
				reproved.AuthenticatedAt = f.clk.Now()
				next, err := f.traffic.Rotate(ctx, &reproved)
				require.NoError(t, err)
				f.tracked = append(f.tracked, next.ID)

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, got.AuthenticatedAt.Equal(createdAt.Add(time.Minute)),
					"got %s, the step-up was at %s", got.AuthenticatedAt, createdAt.Add(time.Minute))
			},
		},
		{
			name: "recorded activity moves the idle deadline, and the read follows",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				f.clk.Advance(5 * time.Minute)
				require.NoError(t, f.traffic.Touch(ctx, s))

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, got.IdleDeadline.Equal(f.clk.Now().Add(f.traffic.IdleTimeout())),
					"got %s", got.IdleDeadline)
			},
		},
		{
			name: "the family asked for, among the user's other sign-ins",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				asked := f.create(ctx, t, user, session.WithExternalSession("idp", issuer, upstream, idToken))
				f.create(ctx, t, user)
				f.create(ctx, t, other)

				return query{user, asked.FamilyID}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, upstream, got.ExternalSessionID)
			},
		},
		{
			name: "one instant before the idle deadline is still live",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				f.clk.Advance(f.traffic.IdleTimeout() - time.Nanosecond)

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, _ *signInStateFixture, _ session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "at the idle deadline",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				f.clk.Advance(f.traffic.IdleTimeout())

				return query{user, s.FamilyID}
			},
			assert: notFound,
		},
		{
			name: "at the absolute deadline",
			opts: []session.Option{session.WithIdleTimeout(12 * time.Hour), session.WithAbsoluteTimeout(2 * time.Hour)},
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				f.clk.Advance(2 * time.Hour)

				return query{user, s.FamilyID}
			},
			assert: notFound,
		},
		{
			name: "a logged out sign-in",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				_, err := f.traffic.Logout(ctx, user, s.FamilyID)
				require.NoError(t, err)

				return query{user, s.FamilyID}
			},
			assert: notFound,
		},
		{
			name: "a sign-in whose whole user was ended",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				require.NoError(t, f.traffic.DeleteByUser(ctx, user))

				return query{user, s.FamilyID}
			},
			assert: notFound,
		},
		{
			name: "a family whose head was deleted, its predecessor still inside the window",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user)
				next := f.renew(ctx, t, s)
				require.NoError(t, f.traffic.Delete(ctx, next.ID))

				return query{user, s.FamilyID}
			},
			assert: notFound,
		},
		{
			name: "another user's family",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				theirs := f.create(ctx, t, other)
				f.create(ctx, t, user)

				return query{user, theirs.FamilyID}
			},
			assert: func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				notFound(t, f, got, err)
				_, liveErr := f.inner.Load(t.Context(), f.tracked[0])
				assert.NoError(t, liveErr, "asking about another user's family must leave it live")
			},
		},
		{
			name: "a family that is not there, for a user who has another",
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				f.create(ctx, t, user)

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "the nil family, even when a store lists a session with none",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, id.Nil, 0, time.Hour))

				return query{user, id.Nil}
			},
			assert: notFoundUnasked,
		},
		{
			name: "an empty user",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head("", unknownFamily, 0, time.Hour))

				return query{"", unknownFamily}
			},
			assert: notFoundUnasked,
		},
		{
			name: "a store answering neither sessions nor an error",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing()

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "a store answering only another family's session is not believed",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, id.MustParse("0192d2a0-0000-7000-8000-00000000beef"), 0, time.Hour))

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "a nil in a store's listing is passed over",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(nil)

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "a store listing another user's session of the family is not believed",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(other, unknownFamily, 0, time.Hour))

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "a store listing a superseded member is not believed",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				superseded := head(user, unknownFamily, 0, time.Hour)
				superseded.SupersededAt = createdAt
				f.answer = listing(superseded)

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "a store listing a session past its idle deadline is not believed",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, unknownFamily, 0, 0))

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "a store listing a session past its absolute deadline is not believed",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				past := head(user, unknownFamily, 0, time.Hour)
				past.AbsoluteExpiresAt = createdAt
				f.answer = listing(past)

				return query{user, unknownFamily}
			},
			assert: notFound,
		},
		{
			name: "two live sessions of one family: the one used last, listed first",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, unknownFamily, time.Minute, time.Hour), head(user, unknownFamily, 0, 2*time.Hour))

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, got.IdleDeadline.Equal(createdAt.Add(time.Hour)), "got %s", got.IdleDeadline)
			},
		},
		{
			name: "two live sessions of one family: the one used last, listed second",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, unknownFamily, 0, 2*time.Hour), head(user, unknownFamily, time.Minute, time.Hour))

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, got.IdleDeadline.Equal(createdAt.Add(time.Hour)), "got %s", got.IdleDeadline)
			},
		},
		{
			name: "two live sessions used at the same instant: the later idle deadline, listed first",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, unknownFamily, 0, 2*time.Hour), head(user, unknownFamily, 0, time.Hour))

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, got.IdleDeadline.Equal(createdAt.Add(2*time.Hour)), "got %s", got.IdleDeadline)
			},
		},
		{
			name: "two live sessions used at the same instant: the later idle deadline, listed second",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = listing(head(user, unknownFamily, 0, time.Hour), head(user, unknownFamily, 0, 2*time.Hour))

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, got.IdleDeadline.Equal(createdAt.Add(2*time.Hour)), "got %s", got.IdleDeadline)
			},
		},
		{
			name: "a store failure is not ErrNotFound",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = failing(errStoreQuotes)

				return query{user, unknownFamily}
			},
			assert: storeFailure(errStoreQuotes),
		},
		{
			// A listing has no not-found to answer: no match is an empty
			// result. A store saying so anyway is failing, and reading that as
			// an ended sign-in would close a live stream.
			name: "a store failing with ErrNotFound is still not ErrNotFound",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = failing(session.ErrNotFound)

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.ErrorIs(t, err, session.ErrListUnavailable)
				assert.NotErrorIs(t, err, session.ErrNotFound)
				assert.Zero(t, got)
			},
		},
		{
			name: "a store failing with a wrapped ErrNotFound is still not ErrNotFound",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = failing(fmt.Errorf("listing for alice@example.com: %w", session.ErrNotFound))

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.ErrorIs(t, err, session.ErrListUnavailable)
				assert.NotErrorIs(t, err, session.ErrNotFound)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Zero(t, got)
			},
		},
		{
			name: "a caller that hung up matches its context's error, and is no outage",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = func(ctx context.Context) ([]*session.Session, error) { return nil, ctx.Err() }

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, session.ErrListUnavailable)
				assert.NotErrorIs(t, err, session.ErrNotFound)
				assert.Zero(t, got)
			},
		},
		{
			name: "a read that ran out of time matches its context's error, and is not ErrNotFound",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithDeadline(ctx, createdAt)
				t.Cleanup(cancel)

				return cctx
			},
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = func(ctx context.Context) ([]*session.Session, error) { return nil, ctx.Err() }

				return query{user, unknownFamily}
			},
			assert: func(t *testing.T, _ *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.NotErrorIs(t, err, session.ErrNotFound)
				assert.Zero(t, got)
			},
		},
		{
			name: "a store failure on a live context that happens to be a context error is an outage",
			arrange: func(_ context.Context, _ *testing.T, f *signInStateFixture) query {
				f.answer = failing(context.DeadlineExceeded)

				return query{user, unknownFamily}
			},
			assert: storeFailure(context.DeadlineExceeded),
		},
		{
			// The read goes through a cipher expecting no call at all, so
			// opening a sealed field fails the case.
			name:   "a sealed store whose key was retired answers, opening nothing",
			sealed: true,
			arrange: func(ctx context.Context, t *testing.T, f *signInStateFixture) query {
				s := f.create(ctx, t, user, session.WithExternalSession("idp", issuer, upstream, idToken))

				_, err := f.retired.Load(ctx, s.ID)
				require.True(t, errors.Is(err, session.ErrUnreadable),
					"the key is not retired, so this proves nothing: %v", err)

				return query{user, s.FamilyID}
			},
			assert: func(t *testing.T, f *signInStateFixture, got session.SignInState, err error) {
				t.Helper()

				require.NoError(t, err)
				stored, loadErr := f.inner.Load(t.Context(), f.tracked[0])
				require.NoError(t, loadErr)
				assert.True(t, got.IdleDeadline.Equal(stored.IdleExpiresAt))
				assert.True(t, got.AbsoluteDeadline.Equal(stored.AbsoluteExpiresAt))
				assert.Equal(t, issuer, got.ExternalIssuer)
				assert.Equal(t, upstream, got.ExternalSessionID, "the upstream session is not sealed")
			},
		},
	}

	// Every row runs over each way a store can answer: its listing, the default,
	// and its family read. The rows do not know which, so the answers are the
	// same or a row fails. A mode expects only its own read, so reaching the
	// other fails the row too.
	modes := []struct {
		name string
		// reader returns the store the read goes through, whose one expected
		// call is answered by the fixture.
		reader func(t *testing.T, ctrl *gomock.Controller, f *signInStateFixture, q *query) session.Store
	}{
		{
			name: "over a store's listing",
			reader: func(t *testing.T, ctrl *gomock.Controller, f *signInStateFixture, _ *query) session.Store {
				t.Helper()

				store := NewMockStore(ctrl)
				store.EXPECT().ListByUser(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, u identity.UserID, now time.Time) ([]*session.Session, error) {
						f.listings.Add(1)
						assert.True(t, now.Equal(f.clk.Now()), "the listing must be judged at the manager's clock")
						if f.answer != nil {
							return f.answer(ctx)
						}

						return f.through.ListByUser(ctx, u, now)
					}).AnyTimes()

				return store
			},
		},
		{
			name: "over a store's family read",
			reader: func(t *testing.T, ctrl *gomock.Controller, f *signInStateFixture, q *query) session.Store {
				t.Helper()

				family := NewMockFamilyReader(ctrl)
				family.EXPECT().ListByFamily(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, u identity.UserID, asked id.ID, now time.Time) ([]*session.Session, error) {
						f.listings.Add(1)
						assert.True(t, now.Equal(f.clk.Now()), "the family read must be judged at the manager's clock")
						assert.Equal(t, q.user, u, "the family read must ask for the user being read")
						assert.Equal(t, q.family, asked, "the family read must ask for the family being read")
						if f.answer != nil {
							return f.answer(ctx)
						}

						through, ok := f.through.(session.FamilyReader)
						require.True(t, ok, "this repository's stores all offer the family read")

						return through.ListByFamily(ctx, u, asked, now)
					}).AnyTimes()

				return struct {
					*MockStore
					*MockFamilyReader
				}{NewMockStore(ctrl), family}
			},
		},
	}

	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					f := &signInStateFixture{clk: clockwork.NewFakeClockAt(createdAt)}
					f.inner = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk)))

					ctrl := gomock.NewController(t)
					write, read := session.Store(f.inner), session.Store(f.inner)
					if tc.sealed {
						write = must.Must(session.NewEncryptedStore(f.inner, fakeCipher{key: 0x2a}))
						read = must.Must(session.NewEncryptedStore(f.inner, NewMockCipher(ctrl)))
						f.retired = must.Must(session.NewEncryptedStore(f.inner, fakeCipher{key: 0x5c}))
					}
					f.through = read

					f.traffic = managerFor(t, append([]session.Option{session.WithStore(write), session.WithClock(f.clk)}, tc.opts...)...)

					var q query
					store := mode.reader(t, ctrl, f, &q)

					var ends []session.EndReport
					var reuses []session.ReuseReport
					reader := managerFor(t, append([]session.Option{
						session.WithStore(store),
						session.WithClock(f.clk),
						session.WithEndObserver(session.EndObserverFunc(func(_ context.Context, r session.EndReport) { ends = append(ends, r) })),
						session.WithReuseObserver(func(_ context.Context, r session.ReuseReport) { reuses = append(reuses, r) }),
					}, tc.opts...)...)

					q = tc.arrange(t.Context(), t, f)

					ctx := t.Context()
					if tc.ctx != nil {
						ctx = tc.ctx(ctx)
					}

					before := f.snapshot(t.Context())
					got, err := reader.SignInState(ctx, q.user, q.family)
					after := f.snapshot(t.Context())

					assert.Equal(t, before, after, "the read changed what the store holds")
					assert.Empty(t, ends, "the read ended something")
					assert.Empty(t, reuses, "the read reported reuse")

					tc.assert(t, f, got, err)
				})
			}
		})
	}
}

// oneUnreadableRowStore is a consumer's own store holding a row it cannot
// decode, in unreadable: a listing fails on it, as the Store contract asks,
// whichever of the user's sign-ins was being looked for. It offers no family
// read.
type oneUnreadableRowStore struct {
	session.Store

	unreadable id.ID
}

func (s oneUnreadableRowStore) ListByUser(context.Context, identity.UserID, time.Time) ([]*session.Session, error) {
	return nil, errStoreQuotes
}

// listingOverrideStore is a consumer's store that embeds the Store interface,
// not a MemoryStore, and answers a listing from its own source of truth. The
// interface hides any family read of what it embeds, so SignInState lists, and
// the listing it overrides is the one it reads.
type listingOverrideStore struct {
	session.Store

	truth session.Store
}

func (s listingOverrideStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	return s.truth.ListByUser(ctx, user, now)
}

// familyReadingStore is the same store offering the family read: only a read of
// the family holding the row fails on it.
type familyReadingStore struct{ oneUnreadableRowStore }

func (s familyReadingStore) ListByFamily(ctx context.Context, user identity.UserID, family id.ID, now time.Time) ([]*session.Session, error) {
	if family == s.unreadable {
		return nil, errStoreQuotes
	}

	listed, err := s.Store.ListByUser(ctx, user, now)
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(listed, func(l *session.Session) bool { return l.FamilyID != family }), nil
}

// TestSessions_SignInState_ConsumerStore pins what a consumer's own store gets:
// one with no family read keeps working by listing, and keeps the limit that
// comes with it; one offering the read loses the limit for its other sign-ins.
// The sealing decorator gives the same answers over either.
func TestSessions_SignInState_ConsumerStore(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("consumer-user")

	type wrap = func(t *testing.T, s session.Store) session.Store

	plain := func(_ *testing.T, s session.Store) session.Store { return s }
	sealed := func(t *testing.T, s session.Store) session.Store {
		t.Helper()

		return must.Must(session.NewEncryptedStore(s, fakeCipher{key: 0x2a}))
	}

	unavailable := func(t *testing.T, got session.SignInState, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrListUnavailable)
		assert.NotErrorIs(t, err, session.ErrNotFound, "an unreadable row must not read as a sign-in that ended")
		assert.NotContains(t, err.Error(), "alice@example.com", "the store's own words reached the error")
		assert.Zero(t, got)
	}
	answered := func(t *testing.T, got session.SignInState, err error) {
		t.Helper()

		require.NoError(t, err, "a row of another sign-in must not fail this one")
		assert.False(t, got.IdleDeadline.IsZero())
	}

	type testCase struct {
		name string
		wrap wrap
		// familyRead is whether the consumer's store offers the read.
		familyRead bool
		// readUnreadable reads the sign-in holding the row, not its neighbour.
		readUnreadable bool
		// overridesListing is a store embedding the Store interface, over an
		// empty store, whose own listing holds the sign-ins.
		overridesListing bool
		assert           func(t *testing.T, got session.SignInState, err error)
	}

	cases := []testCase{
		{name: "with a family read, another sign-in's unreadable row fails nothing", wrap: plain, familyRead: true, assert: answered},
		{name: "with a family read, the sign-in holding the row fails", wrap: plain, familyRead: true, readUnreadable: true, assert: unavailable},
		{name: "without one, the default lists, and the row fails every sign-in", wrap: plain, assert: unavailable},
		{name: "without one, the sign-in holding the row fails too", wrap: plain, readUnreadable: true, assert: unavailable},
		{name: "sealed, with a family read, another sign-in's unreadable row fails nothing", wrap: sealed, familyRead: true, assert: answered},
		{name: "sealed, with a family read, the sign-in holding the row fails", wrap: sealed, familyRead: true, readUnreadable: true, assert: unavailable},
		{name: "sealed, without one, the decorator lists, and the row fails every sign-in", wrap: sealed, assert: unavailable},
		{name: "embedding the Store interface, an overridden listing is the read that answers", wrap: plain, overridesListing: true, assert: answered},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			memory := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
			traffic := managerFor(t, session.WithStore(memory), session.WithClock(clk))
			healthy, err := traffic.Create(t.Context(), user)
			require.NoError(t, err)
			holding, err := traffic.Create(t.Context(), user)
			require.NoError(t, err)

			var store session.Store = oneUnreadableRowStore{Store: memory, unreadable: holding.FamilyID}
			if tc.familyRead {
				store = familyReadingStore{oneUnreadableRowStore{Store: memory, unreadable: holding.FamilyID}}
			}
			if tc.overridesListing {
				empty := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
				store = listingOverrideStore{Store: empty, truth: memory}
			}
			reader := managerFor(t, session.WithStore(tc.wrap(t, store)), session.WithClock(clk))

			family := healthy.FamilyID
			if tc.readUnreadable {
				family = holding.FamilyID
			}
			got, err := reader.SignInState(t.Context(), user, family)
			tc.assert(t, got, err)
		})
	}
}
