package session_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// errIssue stands in for a credential that could not be issued, such as a
// token whose signing key is unreachable.
var errIssue = errors.New("the credential could not be issued")

// probeStore is a real store that counts the creating and saving writes it
// receives, and, when told to, refuses the creating write or honours a
// cancelled context as a database driver does.
type probeStore struct {
	session.Store

	creates atomic.Int32
	saves   atomic.Int32

	// refuseCreate, when set, is what every Create returns after counting.
	refuseCreate error
	// honourContext makes Create, Load and Supersede fail with the context's
	// error once it has ended, writing nothing.
	honourContext bool
}

func (s *probeStore) Create(ctx context.Context, sess *session.Session) error {
	s.creates.Add(1)
	if s.refuseCreate != nil {
		return s.refuseCreate
	}
	if s.honourContext && ctx.Err() != nil {
		return ctx.Err()
	}

	return s.Store.Create(ctx, sess)
}

func (s *probeStore) Save(ctx context.Context, sess *session.Session) error {
	s.saves.Add(1)

	return s.Store.Save(ctx, sess)
}

func (s *probeStore) Load(ctx context.Context, id string) (*session.Session, error) {
	if s.honourContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return s.Store.Load(ctx, id)
}

func (s *probeStore) Supersede(ctx context.Context, op session.Supersession) error {
	if s.honourContext && ctx.Err() != nil {
		return ctx.Err()
	}

	return s.Store.Supersede(ctx, op)
}

// cancelled is the ctx modifier of a request whose client has gone.
func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// prepareFixture is a manager on a fake clock over a probe store.
type prepareFixture struct {
	m     *session.Sessions
	clk   *clockwork.FakeClock
	store *probeStore
}

func newPrepareFixture(t *testing.T, store *probeStore, opts ...session.Option) *prepareFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(createdAt)
	store.Store = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	all := append([]session.Option{session.WithStore(store), session.WithClock(clk)}, opts...)

	return &prepareFixture{m: managerFor(t, all...), clk: clk, store: store}
}

// TestPrepare pins that building a session stores nothing: the session it
// builds is complete, and loads nothing until it is committed.
func TestPrepare(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mgr    []session.Option
		opts   []session.CreateOption
		assert func(t *testing.T, f *prepareFixture, p *session.Prepared, err error)
	}

	cases := []testCase{
		{
			name: "a built session is complete and loads nothing",
			opts: []session.CreateOption{session.WithFirstFactor(factor.Password)},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				s := p.Session()
				require.NotNil(t, s)
				assert.True(t, session.ValidIdentifier(s.ID), "the identifier is one the manager issues")
				assert.Equal(t, testUser, s.UserID)
				assert.Equal(t, factor.Password, s.FirstFactor, "the create options were applied")
				assert.False(t, s.FamilyID.IsZero(), "the session starts a family")
				assert.Equal(t, createdAt, s.CreatedAt)
				assert.Equal(t, createdAt.Add(30*time.Minute), s.IdleExpiresAt)
				assert.Equal(t, createdAt.Add(12*time.Hour), s.AbsoluteExpiresAt)

				assert.Zero(t, f.store.creates.Load(), "building wrote to the store")
				_, loadErr := f.m.Load(t.Context(), s.ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound, "a built session loaded before it was stored")
				n, countErr := f.m.CountActiveByUser(t.Context(), testUser)
				require.NoError(t, countErr)
				assert.Zero(t, n)
			},
		},
		{
			name: "a lifetime outside the maximum is refused before anything is built",
			opts: []session.CreateOption{session.WithAbsoluteLifetime(13 * time.Hour)},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, p)
				assert.Zero(t, f.store.creates.Load())
			},
		},
		{
			name: "a failing random source builds nothing",
			mgr:  []session.Option{session.WithRandom(iotest.ErrReader(errNoEntropy))},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, err error) {
				require.ErrorIs(t, err, errNoEntropy)
				assert.Nil(t, p)
				assert.Zero(t, f.store.creates.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newPrepareFixture(t, &probeStore{}, tc.mgr...)

			p, err := f.m.Prepare(testUser, tc.opts...)
			tc.assert(t, f, p, err)
		})
	}
}

// TestPreparedCommit pins that committing is the one creating write: what the
// caller marked on the built session is stored with it, a failed write stores
// nothing, and a prepared session is committed at most once.
func TestPreparedCommit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		store *probeStore
		ctx   func(ctx context.Context) context.Context
		// before acts on the prepared session before the commit under test.
		before func(t *testing.T, f *prepareFixture, p *session.Prepared)
		assert func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "a committed session loads",
			store: &probeStore{},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Same(t, p.Session(), got, "the session committed is the one built")
				assert.Equal(t, int32(1), f.store.creates.Load())

				loaded, loadErr := f.m.Load(t.Context(), got.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, testUser, loaded.UserID)
			},
		},
		{
			// A challenge mark and the consumer's data made before the
			// commit land in the creating write, never in a second one.
			name:  "marks made before the commit are stored in the one write",
			store: &probeStore{},
			before: func(_ *testing.T, f *prepareFixture, p *session.Prepared) {
				s := p.Session()
				f.m.MarkRecoveryPending(s, 10*time.Minute, createdAt)
				s.PasswordChangePending = true
				s.Data = map[string]string{"tenant": "acme"}
			},
			assert: func(t *testing.T, f *prepareFixture, _ *session.Prepared, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, int32(1), f.store.creates.Load(), "one creating write")
				assert.Zero(t, f.store.saves.Load(), "no second write")

				loaded, loadErr := f.m.Load(t.Context(), got.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, session.MFARecoveryPending, loaded.MFA)
				assert.Equal(t, createdAt, loaded.RecoveredAt)
				assert.Equal(t, createdAt.Add(10*time.Minute), loaded.AbsoluteExpiresAt, "the confinement was stored")
				assert.True(t, loaded.PasswordChangePending)
				assert.Equal(t, map[string]string{"tenant": "acme"}, loaded.Data)
			},
		},
		{
			name:  "a second commit is refused and writes nothing",
			store: &probeStore{},
			before: func(t *testing.T, _ *prepareFixture, p *session.Prepared) {
				_, err := p.Commit(t.Context())
				require.NoError(t, err)
			},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				isBare(session.ErrAlreadyCommitted)(t, err)
				assert.Nil(t, got)
				assert.Equal(t, int32(1), f.store.creates.Load(), "the second commit reached the store")

				_, loadErr := f.m.Load(t.Context(), p.Session().ID)
				require.NoError(t, loadErr, "the first commit's session is untouched")
			},
		},
		{
			// A failed write may have reached the store before it failed,
			// so a prepared session is never offered for a second attempt.
			name:  "a commit after a failed commit is refused and writes nothing",
			store: &probeStore{refuseCreate: errStoreWrite},
			before: func(t *testing.T, _ *prepareFixture, p *session.Prepared) {
				_, err := p.Commit(t.Context())
				require.ErrorIs(t, err, errStoreWrite)
			},
			assert: func(t *testing.T, f *prepareFixture, _ *session.Prepared, got *session.Session, err error) {
				isBare(session.ErrAlreadyCommitted)(t, err)
				assert.Nil(t, got)
				assert.Equal(t, int32(1), f.store.creates.Load(), "the second commit reached the store")
			},
		},
		{
			name:  "a store that refuses the write stores nothing",
			store: &probeStore{refuseCreate: errStoreQuotes},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreQuotes)
				assert.NotContains(t, err.Error(), "alice@example.com", "the store's text reached the error")
				assert.Nil(t, got)

				_, loadErr := f.m.Load(t.Context(), p.Session().ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound)
			},
		},
		{
			// Prepare refuses a lifetime past the maximum; a caller that
			// moves the deadline afterwards must meet the same limit.
			name:  "a deadline moved past the maximum lifetime is refused and writes nothing",
			store: &probeStore{},
			before: func(_ *testing.T, _ *prepareFixture, p *session.Prepared) {
				s := p.Session()
				s.AbsoluteExpiresAt = s.CreatedAt.Add(200 * 365 * 24 * time.Hour)
			},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, got)
				assert.Zero(t, f.store.creates.Load(), "the refused commit reached the store")

				_, loadErr := f.m.Load(t.Context(), p.Session().ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound)
			},
		},
		{
			// A refusal of the deadlines is not a commit: the once-only mark
			// is set only once the checks have passed, so a session the
			// caller corrects commits.
			name:  "a commit refused for its deadlines may be repeated once the session is corrected",
			store: &probeStore{},
			before: func(t *testing.T, _ *prepareFixture, p *session.Prepared) {
				s := p.Session()
				corrected := s.AbsoluteExpiresAt
				s.AbsoluteExpiresAt = s.CreatedAt.Add(200 * 365 * 24 * time.Hour)

				_, err := p.Commit(t.Context())
				require.ErrorIs(t, err, session.ErrConfig)

				s.AbsoluteExpiresAt = corrected
			},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.NoError(t, err, "a refused commit used up the prepared session")
				assert.Same(t, p.Session(), got)
				assert.Equal(t, int32(1), f.store.creates.Load())

				_, loadErr := f.m.Load(t.Context(), got.ID)
				require.NoError(t, loadErr)
			},
		},
		{
			name:  "an absolute deadline at or before the creation is refused and writes nothing",
			store: &probeStore{},
			before: func(_ *testing.T, _ *prepareFixture, p *session.Prepared) {
				s := p.Session()
				s.AbsoluteExpiresAt = s.CreatedAt
				s.IdleExpiresAt = s.CreatedAt
			},
			assert: func(t *testing.T, f *prepareFixture, _ *session.Prepared, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, got)
				assert.Zero(t, f.store.creates.Load(), "the refused commit reached the store")
			},
		},
		{
			name:  "an idle deadline beyond the absolute one is refused and writes nothing",
			store: &probeStore{},
			before: func(_ *testing.T, _ *prepareFixture, p *session.Prepared) {
				s := p.Session()
				s.IdleExpiresAt = s.AbsoluteExpiresAt.Add(time.Second)
			},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, got)
				assert.Zero(t, f.store.creates.Load(), "the refused commit reached the store")

				_, loadErr := f.m.Load(t.Context(), p.Session().ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound)
			},
		},
		{
			name:  "a confinement that only shortens the deadlines still commits",
			store: &probeStore{},
			before: func(_ *testing.T, f *prepareFixture, p *session.Prepared) {
				f.m.MarkEnrolmentPending(p.Session(), 10*time.Minute)
			},
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, int32(1), f.store.creates.Load())
				assert.Equal(t, createdAt.Add(10*time.Minute), got.AbsoluteExpiresAt)

				_, loadErr := f.m.Load(t.Context(), p.Session().ID)
				require.NoError(t, loadErr)
			},
		},
		{
			name:  "a cancelled request stores nothing",
			store: &probeStore{honourContext: true},
			ctx:   cancelled,
			assert: func(t *testing.T, f *prepareFixture, p *session.Prepared, got *session.Session, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)

				_, loadErr := f.m.Load(t.Context(), p.Session().ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			f := newPrepareFixture(t, tc.store)
			p, err := f.m.Prepare(testUser)
			require.NoError(t, err)

			if tc.before != nil {
				tc.before(t, f, p)
			}

			got, err := p.Commit(ctx)
			tc.assert(t, f, p, got, err)
		})
	}
}

// TestPreparedCommit_ConcurrentCommitsWriteOnce pins that two commits of one
// prepared session racing each other reach the store once: one stores it and
// the other is refused. Its shape, goroutines racing one call, is not the
// table's.
func TestPreparedCommit_ConcurrentCommitsWriteOnce(t *testing.T) {
	t.Parallel()

	f := newPrepareFixture(t, &probeStore{})
	p, err := f.m.Prepare(testUser)
	require.NoError(t, err)

	var (
		wg   sync.WaitGroup
		errs [2]error
	)
	for i := range 2 {
		wg.Go(func() {
			_, errs[i] = p.Commit(t.Context())
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), f.store.creates.Load(), "both commits reached the store")
	refused := 0
	for _, err := range errs {
		if errors.Is(err, session.ErrAlreadyCommitted) {
			refused++
		} else {
			require.NoError(t, err)
		}
	}
	assert.Equal(t, 1, refused, "exactly one commit is refused")
}

// TestCreateIssuing pins that a session is created only once the caller's
// step on it, such as issuing its credential, has succeeded: a step that
// fails stores nothing, the session loads nothing while the step runs, and a
// credential is never handed out for a session that was not stored.
func TestCreateIssuing(t *testing.T) {
	t.Parallel()

	// result is what one creation came back with, and the session the step
	// was handed, nil when no step ran.
	type result struct {
		got   *session.Session
		tok   string
		given *session.Session
		// loadedInStep is the error of a load of the session's identifier
		// made inside the step, by cases that make one.
		loadedInStep error
	}

	type testCase struct {
		name  string
		store *probeStore
		opts  []session.CreateOption
		ctx   func(ctx context.Context) context.Context
		// issue is the caller's step; nil creates with no step.
		issue func(ctx context.Context, m *session.Sessions, s *session.Session, r *result) (string, error)
		// noStep passes a nil step.
		noStep bool
		assert func(t *testing.T, f *prepareFixture, r result, err error)
	}

	issueFor := func(_ context.Context, _ *session.Sessions, s *session.Session, _ *result) (string, error) {
		return "credential-for:" + s.ID, nil
	}

	cases := []testCase{
		{
			name:  "a step that succeeds is handed the session that is then stored, and its credential is returned",
			store: &probeStore{},
			issue: issueFor,
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				require.NoError(t, err)
				require.NotNil(t, r.given, "the step ran")
				require.NotNil(t, r.got)
				assert.Equal(t, r.given.ID, r.got.ID, "the step was handed the session that was stored")
				assert.Equal(t, "credential-for:"+r.got.ID, r.tok)
				assert.Equal(t, int32(1), f.store.creates.Load())

				loaded, loadErr := f.m.Load(t.Context(), r.got.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, testUser, loaded.UserID)
			},
		},
		{
			// "The caller's step fails at creation".
			name:  "a step that fails fails the creation with its error and stores nothing",
			store: &probeStore{},
			issue: func(context.Context, *session.Sessions, *session.Session, *result) (string, error) {
				return "", errIssue
			},
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				isBare(errIssue)(t, err)
				assert.Nil(t, r.got)
				assert.Empty(t, r.tok)
				require.NotNil(t, r.given, "the step ran")
				assert.Zero(t, f.store.creates.Load(), "the store was written")

				n, countErr := f.m.CountActiveByUser(t.Context(), testUser)
				require.NoError(t, countErr)
				assert.Zero(t, n, "the store holds a session for the user")
				_, loadErr := f.m.Load(t.Context(), r.given.ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound)
			},
		},
		{
			// "A built session loads nothing until stored".
			name:  "the session loads nothing while the step runs, and loads once stored",
			store: &probeStore{},
			issue: func(ctx context.Context, m *session.Sessions, s *session.Session, r *result) (string, error) {
				_, r.loadedInStep = m.Load(ctx, s.ID)

				return "credential-for:" + s.ID, nil
			},
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				require.NoError(t, err)
				require.ErrorIs(t, r.loadedInStep, session.ErrNotFound, "the session loaded before it was stored")

				_, loadErr := f.m.Load(t.Context(), r.got.ID)
				require.NoError(t, loadErr, "the stored session does not load")
			},
		},
		{
			// Review Focus 4: the step succeeded and the write then failed.
			// The credential names a session that was never stored, so it is
			// not handed back.
			name:  "a step that succeeds while the store refuses the write returns no credential and the store's error",
			store: &probeStore{refuseCreate: errStoreWrite},
			issue: issueFor,
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				require.ErrorIs(t, err, errStoreWrite)
				assert.Nil(t, r.got)
				assert.Empty(t, r.tok, "a credential for a session that was never stored was returned")
				require.NotNil(t, r.given, "the step ran before the write")
				assert.Equal(t, int32(1), f.store.creates.Load())

				_, loadErr := f.m.Load(t.Context(), r.given.ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound, "the credential names no session")
			},
		},
		{
			name:  "a request cancelled before the write returns no credential and stores nothing",
			store: &probeStore{honourContext: true},
			ctx:   cancelled,
			issue: issueFor,
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, r.got)
				assert.Empty(t, r.tok)
				require.NotNil(t, r.given)

				_, loadErr := f.m.Load(t.Context(), r.given.ID)
				require.ErrorIs(t, loadErr, session.ErrNotFound)
			},
		},
		{
			name:   "no step creates the session as Create does",
			store:  &probeStore{},
			noStep: true,
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				require.NoError(t, err)
				require.NotNil(t, r.got)
				assert.Empty(t, r.tok)
				assert.Equal(t, int32(1), f.store.creates.Load())

				_, loadErr := f.m.Load(t.Context(), r.got.ID)
				require.NoError(t, loadErr)
			},
		},
		{
			name:  "refused create options never call the step",
			store: &probeStore{},
			opts:  []session.CreateOption{session.WithAbsoluteLifetime(-time.Second)},
			issue: issueFor,
			assert: func(t *testing.T, f *prepareFixture, r result, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, r.given, "the step was called")
				assert.Nil(t, r.got)
				assert.Empty(t, r.tok)
				assert.Zero(t, f.store.creates.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			f := newPrepareFixture(t, tc.store)

			var (
				r     result
				issue func(*session.Session) (string, error)
				err   error
			)
			if !tc.noStep {
				issue = func(s *session.Session) (string, error) {
					r.given = snapshot(s)

					return tc.issue(t.Context(), f.m, s, &r)
				}
			}
			r.got, r.tok, err = f.m.CreateIssuing(ctx, testUser, issue, tc.opts...)
			tc.assert(t, f, r, err)
		})
	}
}
