package session_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// pointerObserver is an observer whose identity is its address. The field
// keeps it from being zero-sized, whose pointers may compare equal.
type pointerObserver struct{ name string }

func (*pointerObserver) SignInsEnded(context.Context, session.EndReport) {}

// holdingObserver compares as far as what it holds does: holding a func, its
// value cannot be compared, and == on two of them panics.
type holdingObserver struct{ held any }

func (holdingObserver) SignInsEnded(context.Context, session.EndReport) {}

// funcObserver is an observer that is a struct with a func in it, which no
// == can compare.
type funcObserver struct{ fn func() }

func (funcObserver) SignInsEnded(context.Context, session.EndReport) {}

func TestSessions_EndObserverConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, m *session.Sessions, err error)
	}

	refused := func(t *testing.T, m *session.Sessions, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrConfig)
		assert.Contains(t, err.Error(), "end observer")
		assert.Nil(t, m)
	}
	built := func(t *testing.T, m *session.Sessions, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, m)
	}

	cases := []testCase{
		{
			name:   "no observer builds",
			assert: built,
		},
		{
			name:   "a nil observer is a configuration error",
			opts:   []session.Option{session.WithEndObserver(nil)},
			assert: refused,
		},
		{
			name:   "a typed-nil pointer is a configuration error",
			opts:   []session.Option{session.WithEndObserver((*pointerObserver)(nil))},
			assert: refused,
		},
		{
			name:   "a nil func adapter is a configuration error",
			opts:   []session.Option{session.WithEndObserver(session.EndObserverFunc(nil))},
			assert: refused,
		},
		{
			name: "a nil observer after a good one is a configuration error",
			opts: []session.Option{
				session.WithEndObserver(&pointerObserver{name: "good"}),
				session.WithEndObserver(nil),
			},
			assert: refused,
		},
		{
			name: "several observers build",
			opts: []session.Option{
				session.WithEndObserver(&pointerObserver{name: "one"}),
				session.WithEndObserver(&pointerObserver{name: "two"}),
			},
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

func TestSessions_ReportsEndsTo(t *testing.T) {
	t.Parallel()

	o1, o2 := &pointerObserver{name: "one"}, &pointerObserver{name: "two"}
	noop := func(context.Context, session.EndReport) {}
	heldFunc := func() {}

	type testCase struct {
		name   string
		wired  []session.EndObserver
		asked  session.EndObserver
		assert func(t *testing.T, reports bool)
	}

	yes := func(t *testing.T, reports bool) {
		t.Helper()
		assert.True(t, reports, "a manager built with the observer says it does not report to it")
	}
	no := func(t *testing.T, reports bool) {
		t.Helper()
		assert.False(t, reports, "a manager says it reports to an observer it was not built with")
	}

	cases := []testCase{
		{name: "the first of two is reported to", wired: []session.EndObserver{o1, o2}, asked: o1, assert: yes},
		{name: "the second of two is reported to", wired: []session.EndObserver{o1, o2}, asked: o2, assert: yes},
		{
			name:   "another value of the same type is not",
			wired:  []session.EndObserver{o1, o2},
			asked:  &pointerObserver{name: "one"},
			assert: no,
		},
		{name: "a manager with none reports to no one", asked: o1, assert: no},
		{name: "asking about nil answers no", wired: []session.EndObserver{o1}, asked: nil, assert: no},
		{
			name:   "a func asked about another func answers no",
			wired:  []session.EndObserver{session.EndObserverFunc(noop)},
			asked:  session.EndObserverFunc(func(context.Context, session.EndReport) {}),
			assert: no,
		},
		{
			name:   "a func asked about itself answers no, since it cannot be compared",
			wired:  []session.EndObserver{session.EndObserverFunc(noop)},
			asked:  session.EndObserverFunc(noop),
			assert: no,
		},
		{
			name:   "a struct holding a func answers no",
			wired:  []session.EndObserver{funcObserver{fn: func() {}}},
			asked:  funcObserver{fn: func() {}},
			assert: no,
		},
		{
			// The type is comparable and this value of it is not, so a check
			// of the type alone lets == reach the held func, and panic.
			name:   "a value of a comparable type holding a func answers no",
			wired:  []session.EndObserver{holdingObserver{held: heldFunc}},
			asked:  holdingObserver{held: heldFunc},
			assert: no,
		},
		{
			name:   "a value holding something comparable is itself",
			wired:  []session.EndObserver{holdingObserver{held: 1}},
			asked:  holdingObserver{held: 1},
			assert: yes,
		},
		{
			name:   "a comparable value asked of a wired one holding a func answers no",
			wired:  []session.EndObserver{holdingObserver{held: heldFunc}},
			asked:  holdingObserver{held: 1},
			assert: no,
		},
		{
			name:   "an incomparable wired observer does not hide a later one",
			wired:  []session.EndObserver{session.EndObserverFunc(noop), o1},
			asked:  o1,
			assert: yes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := make([]session.Option, 0, len(tc.wired))
			for _, o := range tc.wired {
				opts = append(opts, session.WithEndObserver(o))
			}
			m := managerFor(t, opts...)

			assert.NotPanics(t, func() { tc.assert(t, m.ReportsEndsTo(tc.asked)) })
		})
	}
}

const (
	// endUser, endIssuer and endUpstream are long enough that finding one in
	// a log line cannot be a coincidence.
	endUser     = identity.UserID("user-of-the-ended-sign-in")
	endIssuer   = "https://idp.example.com"
	endUpstream = "upstream-session-x-9"
)

// writeHookStore runs afterWrite once each deleting store call has written,
// and before the manager sees it return, which is the moment a request can
// still hang up with the sign-in already gone.
type writeHookStore struct {
	*session.MemoryStore

	afterWrite func()
}

func (s *writeHookStore) wrote() {
	if s.afterWrite != nil {
		s.afterWrite()
	}
}

func (s *writeHookStore) Delete(ctx context.Context, sid string) error {
	defer s.wrote()

	return s.MemoryStore.Delete(ctx, sid)
}

func (s *writeHookStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	defer s.wrote()

	return s.MemoryStore.DeleteByUser(ctx, user)
}

func (s *writeHookStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	defer s.wrote()

	return s.MemoryStore.DeleteByUserExcept(ctx, user, keep)
}

func (s *writeHookStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	defer s.wrote()

	return s.MemoryStore.DeleteFamily(ctx, family)
}

func (s *writeHookStore) DeleteByExternalSession(ctx context.Context, issuer, sid string) (int, error) {
	defer s.wrote()

	return s.MemoryStore.DeleteByExternalSession(ctx, issuer, sid)
}

func (s *writeHookStore) DeleteByUserAndExternalIssuer(ctx context.Context, user identity.UserID, issuer string) (int, error) {
	defer s.wrote()

	return s.MemoryStore.DeleteByUserAndExternalIssuer(ctx, user, issuer)
}

// endCall is one call an observer received.
type endCall struct {
	observer string
	report   session.EndReport
	written  bool
	ctxErr   error
	ctxValue any
}

// endCtxKey is the key of a value a caller's context carries to an observer.
type endCtxKey struct{}

// endRecorder is an observer writing its calls to a list its siblings share,
// which is what shows their order. Observers run on the caller's goroutine, so
// the list needs no lock: a report sent from another goroutine fails -race.
type endRecorder struct {
	name    string
	calls   *[]endCall
	written *bool
}

func (r *endRecorder) SignInsEnded(ctx context.Context, report session.EndReport) {
	*r.calls = append(*r.calls, endCall{
		observer: r.name,
		report:   report,
		written:  *r.written,
		ctxErr:   ctx.Err(),
		ctxValue: ctx.Value(endCtxKey{}),
	})
}

// observedFixture is a manager on a fake clock, with sign-in a, from a provider,
// and sign-in b, both of endUser.
type observedFixture struct {
	clk     *clockwork.FakeClock
	m       *session.Sessions
	a, b    *session.Session
	created []string
	calls   []endCall
	written bool
	logs    *bytes.Buffer
}

// observers returns the two recording observers of f.
func (f *observedFixture) observers() (first, second *endRecorder) {
	return &endRecorder{name: "first", calls: &f.calls, written: &f.written},
		&endRecorder{name: "second", calls: &f.calls, written: &f.written}
}

// logger writes to f.logs at every level.
func (f *observedFixture) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// remember records identifiers no report or log line may hold.
func (f *observedFixture) remember(sessions ...*session.Session) {
	for _, s := range sessions {
		f.created = append(f.created, s.ID)
	}
}

// renew rotates s with a 30 s window, requires it to succeed and remembers the
// successor.
func (f *observedFixture) renew(ctx context.Context, t *testing.T, s *session.Session) *session.Session {
	t.Helper()

	next, _, err := f.m.RotateWithGrace(ctx, s, 30*time.Second)
	require.NoError(t, err)
	f.remember(next)

	return next
}

// newObservedFixture builds a fixture whose manager has the observers observe
// returns, over a store told when a write has happened.
func newObservedFixture(t *testing.T, observe func(f *observedFixture) []session.EndObserver, opts ...session.Option) (*observedFixture, *writeHookStore) {
	t.Helper()

	f := &observedFixture{clk: clockwork.NewFakeClockAt(createdAt), logs: &bytes.Buffer{}}
	store := &writeHookStore{MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk)))}

	all := []session.Option{session.WithStore(store), session.WithClock(f.clk), session.WithLogger(f.logger())}
	for _, o := range observe(f) {
		all = append(all, session.WithEndObserver(o))
	}
	f.m = managerFor(t, append(all, opts...)...)

	var err error
	f.a, err = f.m.Create(t.Context(), endUser, session.WithExternalSession("idp", endIssuer, endUpstream, "id-token"))
	require.NoError(t, err)
	f.b, err = f.m.Create(t.Context(), endUser)
	require.NoError(t, err)
	f.remember(f.a, f.b)

	return f, store
}

// recordingObservers is an observe function for newObservedFixture.
func recordingObservers(f *observedFixture) []session.EndObserver {
	first, second := f.observers()

	return []session.EndObserver{first, second}
}

// reusedStoredFor makes a failing-write fixture's Load find sid superseded and
// past its window, as supersededStored does, at the clock mockedObservedFixture
// sets.
func reusedStoredFor(store *MockStore, sid string) {
	store.EXPECT().Load(gomock.Any(), sid).Return(supersededStored(sid), nil).AnyTimes()
}

// mockedObservedFixture is an observedFixture over a mocked store, at 09:05, whose a is
// a stored session the mock is told about by failWrite.
func mockedObservedFixture(t *testing.T, failWrite func(store *MockStore, a *session.Session)) *observedFixture {
	t.Helper()

	f := &observedFixture{clk: clockwork.NewFakeClockAt(createdAt.Add(5 * time.Minute)), logs: &bytes.Buffer{}}
	f.a = familyOf("end-a", graceFamily)
	f.a.UserID = endUser

	store := NewMockStore(gomock.NewController(t))
	failWrite(store, f.a)

	first, second := f.observers()
	f.m = managerFor(t,
		session.WithStore(store),
		session.WithClock(f.clk),
		session.WithLogger(f.logger()),
		session.WithEndObserver(first),
		session.WithEndObserver(second),
	)

	return f
}

// endPanicValue opens the value of an observer's panic. It is logged nowhere,
// because a value may quote the report it was given, as this one does.
const endPanicValue = "observer-panic-value"

// assertPanicLoggedWithoutContents asserts logs hold one ERROR line for an
// observer's panic, with neither the panic's value nor any of the report.
func assertPanicLoggedWithoutContents(t *testing.T, logs string, r session.EndReport) {
	t.Helper()

	var errorLines []string
	for line := range strings.Lines(logs) {
		if strings.Contains(line, "level=ERROR") {
			errorLines = append(errorLines, line)
		}
	}
	require.Len(t, errorLines, 1, "logs: %s", logs)

	assert.NotContains(t, errorLines[0], endPanicValue)
	for _, content := range []string{string(r.User), r.ExternalIssuer, r.ExternalSessionID} {
		if content != "" {
			assert.NotContains(t, errorLines[0], content)
		}
	}
	for _, family := range []id.ID{r.Family, r.KeptFamily} {
		if !family.IsZero() {
			assert.NotContains(t, errorLines[0], family.String())
		}
	}
}

func TestSessions_EndObserver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []session.Option
		// arrange runs before the manager is watched, for what makes a reuse.
		arrange func(ctx context.Context, t *testing.T, f *observedFixture)
		act     func(ctx context.Context, f *observedFixture) error
		// assert gets the one report each observer received.
		assert func(t *testing.T, f *observedFixture, got session.EndReport, err error)
		// failWrite makes the store fail the path's write. A path whose failure
		// is the same store call as another row's has none.
		failWrite func(store *MockStore, a *session.Session)
	}

	reused := func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrReused)
		assert.Equal(t, session.EndReport{
			Cause: session.EndReuse, User: endUser, Family: f.a.FamilyID, At: f.clk.Now(),
		}, got)
	}
	revokeFails := func(store *MockStore, a *session.Session) {
		reusedStoredFor(store, a.ID)
		store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(0, errStoreQuotes)
	}
	renewedPastWindow := func(ctx context.Context, t *testing.T, f *observedFixture) {
		f.renew(ctx, t, f.a)
		f.clk.Advance(5 * time.Minute)
	}

	cases := []testCase{
		{
			name:    "reuse past the grace window, at a renewal",
			arrange: renewedPastWindow,
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.LoadForRenewal(ctx, f.a.ID)
				return err
			},
			assert:    reused,
			failWrite: revokeFails,
		},
		{
			name:    "reuse past the grace window, at an ordinary load",
			arrange: renewedPastWindow,
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.Load(ctx, f.a.ID)
				return err
			},
			assert:    reused,
			failWrite: revokeFails,
		},
		{
			name: "reuse found by a re-rotation whose successor moved on",
			arrange: func(ctx context.Context, t *testing.T, f *observedFixture) {
				s1 := f.renew(ctx, t, f.a)
				f.clk.Advance(5 * time.Second)
				f.renew(ctx, t, s1)
				f.clk.Advance(5 * time.Second)
			},
			act: func(ctx context.Context, f *observedFixture) error {
				_, _, err := f.m.RotateWithGrace(ctx, f.a, 30*time.Second)
				return err
			},
			assert: reused,
		},
		{
			name: "reuse found under recovery, of an ended session whose successor was used",
			opts: []session.Option{session.WithIdleTimeout(30 * time.Minute), session.WithUnusedSuccessorRecovery()},
			arrange: func(ctx context.Context, t *testing.T, f *observedFixture) {
				f.clk.Advance(10 * time.Minute)
				s1 := f.renew(ctx, t, f.a)
				f.clk.Advance(10 * time.Minute)
				_, err := f.m.Load(ctx, s1.ID)
				require.NoError(t, err)
				f.clk.Advance(11 * time.Minute)
			},
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.LoadForRenewal(ctx, f.a.ID)
				return err
			},
			assert: reused,
		},
		{
			name: "RevokeFamily names the family and no user",
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.RevokeFamily(ctx, f.a.FamilyID)
				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndFamilyRevoked, Family: f.a.FamilyID, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, a *session.Session) {
				store.EXPECT().DeleteFamily(gomock.Any(), a.FamilyID).Return(0, errStoreQuotes)
			},
		},
		{
			name: "Delete names the user and the family it read",
			act: func(ctx context.Context, f *observedFixture) error {
				return f.m.Delete(ctx, f.a.ID)
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndDeleted, User: endUser, Family: f.a.FamilyID, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, a *session.Session) {
				store.EXPECT().Load(gomock.Any(), a.ID).Return(a, nil)
				store.EXPECT().Delete(gomock.Any(), a.ID).Return(errStoreQuotes)
			},
		},
		{
			name: "DeleteByUser names the user and no family",
			act: func(ctx context.Context, f *observedFixture) error {
				return f.m.DeleteByUser(ctx, endUser)
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndUserSessions, User: endUser, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, _ *session.Session) {
				store.EXPECT().DeleteByUser(gomock.Any(), endUser).Return(errStoreQuotes)
			},
		},
		{
			name: "DeleteByUserExcept names the user and the kept family",
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.DeleteByUserExcept(ctx, endUser, f.a.ID)
				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndUserSessionsExcept, User: endUser, KeptFamily: f.a.FamilyID, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, a *session.Session) {
				store.EXPECT().Load(gomock.Any(), a.ID).Return(a, nil)
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, a.ID).Return(0, errStoreQuotes)
			},
		},
		{
			name: "DeleteByExternalSession names the issuer and session, and no user or family",
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.DeleteByExternalSession(ctx, endIssuer, endUpstream)
				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndExternalSession, ExternalIssuer: endIssuer, ExternalSessionID: endUpstream, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, _ *session.Session) {
				store.EXPECT().DeleteByExternalSession(gomock.Any(), endIssuer, endUpstream).Return(0, errStoreQuotes)
			},
		},
		{
			name: "DeleteByUserAndExternalIssuer names the user and the issuer",
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.DeleteByUserAndExternalIssuer(ctx, endUser, endIssuer)
				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndUserExternalIssuer, User: endUser, ExternalIssuer: endIssuer, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, _ *session.Session) {
				store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), endUser, endIssuer).Return(0, errStoreQuotes)
			},
		},
		{
			name: "EndSignIn names the user and the family",
			act: func(ctx context.Context, f *observedFixture) error {
				return f.m.EndSignIn(ctx, endUser, f.a.FamilyID.String())
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndByHandle, User: endUser, Family: f.a.FamilyID, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, a *session.Session) {
				store.EXPECT().ListByUser(gomock.Any(), endUser, gomock.Any()).Return([]*session.Session{a}, nil)
				store.EXPECT().DeleteFamily(gomock.Any(), a.FamilyID).Return(0, errStoreQuotes)
			},
		},
		{
			name: "EndOtherSignIns names the user and the family kept",
			act: func(ctx context.Context, f *observedFixture) error {
				_, err := f.m.EndOtherSignIns(ctx, endUser, f.a)
				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.EndReport{
					Cause: session.EndOtherSignIns, User: endUser, KeptFamily: f.a.FamilyID, At: f.clk.Now(),
				}, got)
			},
			failWrite: func(store *MockStore, a *session.Session) {
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, a.ID).Return(0, errStoreQuotes)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			t.Run("reported after the write, to each observer in order", func(t *testing.T) {
				t.Parallel()

				f, store := newObservedFixture(t, recordingObservers, tc.opts...)
				if tc.arrange != nil {
					tc.arrange(t.Context(), t, f)
				}
				f.calls = nil

				ctx, hangUp := context.WithCancel(context.WithValue(t.Context(), endCtxKey{}, "caller's value"))
				defer hangUp()
				// The clock moves during the write, so a time read before it
				// is told apart from one read after, and the client hangs up
				// with the sign-in already gone.
				store.afterWrite = func() {
					f.written = true
					f.clk.Advance(time.Second)
					hangUp()
				}

				err := tc.act(ctx, f)

				require.Len(t, f.calls, 2, "each of the two observers is told once")
				assert.Equal(t, "first", f.calls[0].observer)
				assert.Equal(t, "second", f.calls[1].observer)
				assert.Equal(t, f.calls[0].report, f.calls[1].report)
				assert.True(t, f.calls[0].written, "the observer ran before the store write")
				for _, call := range f.calls {
					assert.NoError(t, call.ctxErr, "a client hanging up reached the observer")
					assert.Equal(t, "caller's value", call.ctxValue, "the observer lost the caller's values")
				}
				tc.assert(t, f, f.calls[0].report, err)
				assertNoIdentifier(t, fmt.Sprintf("%+v", f.calls[0].report), f.created...)
				assertNoIdentifier(t, f.logs.String(), f.created...)
			})

			t.Run("an observer that panics does not stop the next or change the end", func(t *testing.T) {
				t.Parallel()

				f, _ := newObservedFixture(t, func(f *observedFixture) []session.EndObserver {
					_, second := f.observers()

					return []session.EndObserver{
						session.EndObserverFunc(func(_ context.Context, r session.EndReport) {
							panic(fmt.Sprintf("%s: %+v", endPanicValue, r))
						}),
						second,
					}
				}, tc.opts...)
				if tc.arrange != nil {
					tc.arrange(t.Context(), t, f)
				}
				f.calls = nil

				var err error
				require.NotPanics(t, func() { err = tc.act(t.Context(), f) })

				require.Len(t, f.calls, 1, "the observer after the panic was not called")
				tc.assert(t, f, f.calls[0].report, err)
				assertPanicLoggedWithoutContents(t, f.logs.String(), f.calls[0].report)
			})

			t.Run("a write that fails tells no one", func(t *testing.T) {
				t.Parallel()

				if tc.failWrite == nil {
					t.Skip("the same store call as another row's")
				}

				f := mockedObservedFixture(t, tc.failWrite)

				err := tc.act(t.Context(), f)

				require.ErrorIs(t, err, errStoreQuotes)
				assert.Empty(t, f.calls)
			})
		})
	}
}

func TestSessions_EndObserver_NotReported(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		act    func(ctx context.Context, t *testing.T, f *observedFixture) error
		assert func(t *testing.T, err error)
	}

	expired := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, session.ErrExpired)
		assert.NotErrorIs(t, err, session.ErrReused)
	}
	notFound := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, session.ErrNotFound)
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
	}
	fine := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}
	endedNothing := func(n int, err error) error {
		if n != 0 {
			return fmt.Errorf("the call ended %d sessions", n)
		}

		return err
	}

	cases := []testCase{
		{
			name: "the expiry sweep",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				f.clk.Advance(13 * time.Hour)
				n, err := f.m.DeleteExpired(ctx)
				assert.Equal(t, 2, n, "the sweep removed nothing, so it proves nothing")

				return err
			},
			assert: fine,
		},
		{
			name: "a session reaching its idle deadline",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				f.clk.Advance(31 * time.Minute)
				_, err := f.m.Load(ctx, f.a.ID)

				return err
			},
			assert: expired,
		},
		{
			name: "a session reaching its absolute deadline",
			opts: []session.Option{session.WithIdleTimeout(12 * time.Hour)},
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				f.clk.Advance(12 * time.Hour)
				_, err := f.m.Load(ctx, f.a.ID)

				return err
			},
			assert: expired,
		},
		{
			name: "a renewal under recovery of a session past its deadline, whose successor was not used",
			opts: []session.Option{session.WithIdleTimeout(30 * time.Minute), session.WithUnusedSuccessorRecovery()},
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				f.renew(ctx, t, f.a)
				f.clk.Advance(30 * time.Minute)
				_, err := f.m.LoadForRenewal(ctx, f.a.ID)

				return err
			},
			assert: expired,
		},
		{
			name: "RevokeFamily refusing the nil family",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				_, err := f.m.RevokeFamily(ctx, id.Nil)

				return err
			},
			assert: refused,
		},
		{
			name: "EndSignIn given a malformed handle",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return f.m.EndSignIn(ctx, endUser, "not-a-handle")
			},
			assert: notFound,
		},
		{
			name: "EndSignIn given another user's handle",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return f.m.EndSignIn(ctx, "someone-else", f.a.FamilyID.String())
			},
			assert: notFound,
		},
		{
			name: "EndOtherSignIns given no current session",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				_, err := f.m.EndOtherSignIns(ctx, endUser, nil)

				return err
			},
			assert: refused,
		},
		{
			name: "EndOtherSignIns given another user's current session",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				_, err := f.m.EndOtherSignIns(ctx, "someone-else", f.a)

				return err
			},
			assert: refused,
		},
		{
			name: "DeleteByExternalSession given an empty issuer, which ends nothing by contract",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return endedNothing(f.m.DeleteByExternalSession(ctx, "", endUpstream))
			},
			assert: fine,
		},
		{
			name: "DeleteByExternalSession given an empty session, which ends nothing by contract",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return endedNothing(f.m.DeleteByExternalSession(ctx, endIssuer, ""))
			},
			assert: fine,
		},
		{
			name: "DeleteByUserAndExternalIssuer given an empty issuer, which ends nothing by contract",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return endedNothing(f.m.DeleteByUserAndExternalIssuer(ctx, endUser, ""))
			},
			assert: fine,
		},
		{
			name: "a strict rotation, which ends no sign-in",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				_, err := f.m.Rotate(ctx, f.a)

				return err
			},
			assert: fine,
		},
		{
			name: "a renewal, and a load inside its window, which end no sign-in",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				f.renew(ctx, t, f.a)
				_, err := f.m.Load(ctx, f.a.ID)

				return err
			},
			assert: fine,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, _ := newObservedFixture(t, recordingObservers, tc.opts...)

			err := tc.act(t.Context(), t, f)

			tc.assert(t, err)
			assert.Empty(t, f.calls, "an observer was told")
		})
	}
}

// TestSessions_EndObserver_ZeroRows pins that a store write matching nothing,
// and returning no error, is still reported: the store's nil is what a report
// follows, as Delete and DeleteByUser have no count to judge by.
func TestSessions_EndObserver_ZeroRows(t *testing.T) {
	t.Parallel()

	unknownFamily := id.MustParse("0192d2a0-0000-7000-8000-00000000dead")

	type testCase struct {
		name   string
		act    func(ctx context.Context, t *testing.T, f *observedFixture) error
		assert func(t *testing.T, f *observedFixture, got session.EndReport)
	}

	cases := []testCase{
		{
			name: "RevokeFamily of an unknown family",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				n, err := f.m.RevokeFamily(ctx, unknownFamily)
				assert.Zero(t, n)

				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{Cause: session.EndFamilyRevoked, Family: unknownFamily, At: f.clk.Now()}, got)
			},
		},
		{
			name: "Delete of an identifier the store does not hold names no one",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return f.m.Delete(ctx, "no-such-session")
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{Cause: session.EndDeleted, At: f.clk.Now()}, got)
			},
		},
		{
			name: "DeleteByUser of a user with no sessions",
			act: func(ctx context.Context, _ *testing.T, f *observedFixture) error {
				return f.m.DeleteByUser(ctx, "no-sessions")
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{Cause: session.EndUserSessions, User: "no-sessions", At: f.clk.Now()}, got)
			},
		},
		{
			name: "DeleteByUserExcept of a user with no sessions",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				n, err := f.m.DeleteByUserExcept(ctx, "no-sessions", "")
				assert.Zero(t, n)

				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{Cause: session.EndUserSessionsExcept, User: "no-sessions", At: f.clk.Now()}, got)
			},
		},
		{
			name: "DeleteByExternalSession of an upstream session with none here",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				n, err := f.m.DeleteByExternalSession(ctx, endIssuer, "no-such-upstream")
				assert.Zero(t, n)

				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{
					Cause: session.EndExternalSession, ExternalIssuer: endIssuer, ExternalSessionID: "no-such-upstream", At: f.clk.Now(),
				}, got)
			},
		},
		{
			name: "DeleteByUserAndExternalIssuer of an issuer with none here",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				n, err := f.m.DeleteByUserAndExternalIssuer(ctx, endUser, "https://other.example.com")
				assert.Zero(t, n)

				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{
					Cause: session.EndUserExternalIssuer, User: endUser, ExternalIssuer: "https://other.example.com", At: f.clk.Now(),
				}, got)
			},
		},
		{
			name: "EndOtherSignIns of a user with no other sign-in",
			act: func(ctx context.Context, t *testing.T, f *observedFixture) error {
				require.NoError(t, f.m.Delete(ctx, f.b.ID))
				f.calls = nil
				n, err := f.m.EndOtherSignIns(ctx, endUser, f.a)
				assert.Zero(t, n)

				return err
			},
			assert: func(t *testing.T, f *observedFixture, got session.EndReport) {
				assert.Equal(t, session.EndReport{Cause: session.EndOtherSignIns, User: endUser, KeptFamily: f.a.FamilyID, At: f.clk.Now()}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, _ := newObservedFixture(t, recordingObservers)

			require.NoError(t, tc.act(t.Context(), t, f))

			require.Len(t, f.calls, 2, "each of the two observers is told once")
			tc.assert(t, f, f.calls[0].report)
		})
	}
}

// TestSessions_EndObserver_ReadBeforeWrite covers the read Delete and
// DeleteByUserExcept make to fill a report, and the store's answers a memory
// store cannot be made to give.
func TestSessions_EndObserver_ReadBeforeWrite(t *testing.T) {
	t.Parallel()

	const sid = "named-by-the-call"

	someone := func() *session.Session {
		s := familyOf(sid, graceFamily)
		s.UserID = endUser

		return s
	}

	type testCase struct {
		name string
		// unobserved builds the manager with no observer. A store read then
		// fails the case, since the mock expects none.
		unobserved bool
		at         time.Time
		expect     func(store *MockStore)
		act        func(ctx context.Context, m *session.Sessions) error
		assert     func(t *testing.T, calls []endCall, logs string, err error)
	}

	deleteIt := func(ctx context.Context, m *session.Sessions) error { return m.Delete(ctx, sid) }
	deleteOthers := func(ctx context.Context, m *session.Sessions) error {
		_, err := m.DeleteByUserExcept(ctx, endUser, sid)

		return err
	}

	cases := []testCase{
		{
			name:       "Delete reads nothing with no observer",
			unobserved: true,
			expect: func(store *MockStore) {
				store.EXPECT().Delete(gomock.Any(), sid).Return(nil)
			},
			act: deleteIt,
			assert: func(t *testing.T, _ []endCall, _ string, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:       "DeleteByUserExcept reads nothing with no observer",
			unobserved: true,
			expect: func(store *MockStore) {
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, sid).Return(1, nil)
			},
			act: deleteOthers,
			assert: func(t *testing.T, _ []endCall, _ string, err error) {
				require.NoError(t, err)
			},
		},
		{
			// Reading through Load would judge it, and revoke its family for a
			// logout. The mock expects no DeleteFamily.
			name: "the read judges nothing: a session past its window is only deleted",
			at:   createdAt.Add(5 * time.Minute),
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(supersededStored(sid), nil)
				store.EXPECT().Delete(gomock.Any(), sid).Return(nil)
			},
			act: deleteIt,
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndDeleted, calls[0].report.Cause)
				assert.Equal(t, graceFamily, calls[0].report.Family)
			},
		},
		{
			// Reading through Load would record a presentation. The mock
			// expects no MarkPresented.
			name: "the read marks nothing: a session never presented is only deleted",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(someone(), nil)
				store.EXPECT().Delete(gomock.Any(), sid).Return(nil)
			},
			act: deleteIt,
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, endUser, calls[0].report.User)
			},
		},
		{
			name: "a failed read stops Delete, naming neither the store's text nor the identifier",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, errStoreQuotes)
			},
			act: deleteIt,
			assert: func(t *testing.T, calls []endCall, logs string, err error) {
				hidesStoreText()(t, err)
				assert.EqualError(t, err, textEndReportRead)
				assert.NotContains(t, err.Error(), sid)
				assert.Empty(t, calls)
				assert.Empty(t, logs, "the caller has the failure, so it is not logged as well")
			},
		},
		{
			name: "a store answering neither a session nor an error holds no session, as every read takes it",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, nil)
				store.EXPECT().Delete(gomock.Any(), sid).Return(nil)
			},
			act: deleteIt,
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndDeleted, At: createdAt}, calls[0].report)
			},
		},
		{
			name: "a session the store holds as expired is deleted, unnamed and unlogged",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, session.ErrExpired)
				store.EXPECT().Delete(gomock.Any(), sid).Return(nil)
			},
			act: deleteIt,
			assert: func(t *testing.T, calls []endCall, logs string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndDeleted, At: createdAt}, calls[0].report)
				assert.Empty(t, logs)
			},
		},
		{
			name: "a failed read stops DeleteByUserExcept, naming neither the store's text nor the identifier",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, errStoreQuotes)
			},
			act: deleteOthers,
			assert: func(t *testing.T, calls []endCall, logs string, err error) {
				hidesStoreText()(t, err)
				assert.EqualError(t, err, textEndReportRead)
				assert.NotContains(t, err.Error(), sid)
				assert.Empty(t, calls)
				assert.Empty(t, logs, "the caller has the failure, so it is not logged as well")
			},
		},
		{
			name: "a keep that has expired names no kept family",
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, session.ErrExpired)
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, sid).Return(2, nil)
			},
			act: deleteOthers,
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndUserSessionsExcept, User: endUser, At: createdAt}, calls[0].report)
				assert.Equal(t, id.ID{}, calls[0].report.KeptFamily)
			},
		},
		{
			// The store leaves that session alone and ends every one of the
			// user's, so nothing of the user's was kept, and naming the other
			// user's family would tell an observer otherwise.
			name: "a keep naming another user's session names no kept family",
			expect: func(store *MockStore) {
				foreign := someone()
				foreign.UserID = "someone-else"
				store.EXPECT().Load(gomock.Any(), sid).Return(foreign, nil)
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, sid).Return(2, nil)
			},
			act: deleteOthers,
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndUserSessionsExcept, User: endUser, At: createdAt}, calls[0].report)
			},
		},
		{
			name: "an empty keep reads nothing and names no kept family",
			expect: func(store *MockStore) {
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, "").Return(2, nil)
			},
			act: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.DeleteByUserExcept(ctx, endUser, "")

				return err
			},
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndUserSessionsExcept, User: endUser, At: createdAt}, calls[0].report)
			},
		},
		{
			name: "EndOtherSignIns reads nothing, since it holds the current session",
			expect: func(store *MockStore) {
				store.EXPECT().DeleteByUserExcept(gomock.Any(), endUser, sid).Return(1, nil)
			},
			act: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.EndOtherSignIns(ctx, endUser, someone())

				return err
			},
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{
					Cause: session.EndOtherSignIns, User: endUser, KeptFamily: graceFamily, At: createdAt,
				}, calls[0].report)
			},
		},
		{
			name: "EndSignIn losing a race to the delete is still reported",
			expect: func(store *MockStore) {
				store.EXPECT().ListByUser(gomock.Any(), endUser, gomock.Any()).Return([]*session.Session{someone()}, nil)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(0, nil)
			},
			act: func(ctx context.Context, m *session.Sessions) error {
				return m.EndSignIn(ctx, endUser, graceFamily.String())
			},
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.NoError(t, err)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{
					Cause: session.EndByHandle, User: endUser, Family: graceFamily, At: createdAt,
				}, calls[0].report)
			},
		},
		{
			name: "reuse losing a race to the revocation is still reported",
			at:   createdAt.Add(5 * time.Minute),
			expect: func(store *MockStore) {
				store.EXPECT().Load(gomock.Any(), sid).Return(supersededStored(sid), nil)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(0, nil)
			},
			act: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.Load(ctx, sid)

				return err
			},
			assert: func(t *testing.T, calls []endCall, _ string, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				require.Len(t, calls, 1)
				assert.Equal(t, session.EndReport{
					Cause: session.EndReuse, User: testUser, Family: graceFamily, At: createdAt.Add(5 * time.Minute),
				}, calls[0].report)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			at := tc.at
			if at.IsZero() {
				at = createdAt
			}

			store := NewMockStore(gomock.NewController(t))
			tc.expect(store)

			f := &observedFixture{clk: clockwork.NewFakeClockAt(at), logs: &bytes.Buffer{}}
			opts := []session.Option{session.WithStore(store), session.WithClock(f.clk), session.WithLogger(f.logger())}
			if !tc.unobserved {
				first, _ := f.observers()
				opts = append(opts, session.WithEndObserver(first))
			}
			m := managerFor(t, opts...)

			err := tc.act(t.Context(), m)

			tc.assert(t, f.calls, f.logs.String(), err)
		})
	}
}

// textEndReportRead is what a read for an end's report fails with.
const textEndReportRead = "session: the session could not be read for its end report"

// loadFailingStore is a memory store whose Load fails with loadErr, or with the
// context's error as a store on a network would, while every write still works,
// so a row sees what a failed read left behind.
type loadFailingStore struct {
	*session.MemoryStore

	loadErr error
	loads   atomic.Int32
}

func (s *loadFailingStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	s.loads.Add(1)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.loadErr != nil {
		return nil, s.loadErr
	}

	return s.MemoryStore.Load(ctx, sid)
}

// TestSessions_EndReportRead pins that an end which cannot read what its report
// must say changes nothing, so its caller can ask again. Over a store really
// holding the sessions, a row sees what stands afterwards.
func TestSessions_EndReportRead(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// unobserved builds the manager with no observer.
		unobserved bool
		loadErr    error
		ctx        func(ctx context.Context) context.Context
		act        func(ctx context.Context, m *session.Sessions, f *observedFixture) (int, error)
		assert     func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error)
	}

	deleteA := func(ctx context.Context, m *session.Sessions, f *observedFixture) (int, error) {
		return 0, m.Delete(ctx, f.a.ID)
	}
	deleteAllButA := func(ctx context.Context, m *session.Sessions, f *observedFixture) (int, error) {
		return m.DeleteByUserExcept(ctx, endUser, f.a.ID)
	}

	stored := func(t *testing.T, store *loadFailingStore, s *session.Session) bool {
		t.Helper()

		_, err := store.MemoryStore.Load(t.Context(), s.ID)
		if err != nil {
			require.ErrorIs(t, err, session.ErrNotFound)
		}

		return err == nil
	}

	// changedNothing is every row whose read stops the end.
	changedNothing := func(t *testing.T, f *observedFixture, store *loadFailingStore, n int) {
		t.Helper()

		assert.Zero(t, n)
		assert.True(t, stored(t, store, f.a), "the session named is still stored")
		assert.True(t, stored(t, store, f.b), "the user's other session is still stored")
		assert.Empty(t, f.calls, "no observer is told of an end that did not happen")
		assert.EqualValues(t, 1, store.loads.Load())
	}

	cases := []testCase{
		{
			name:    "Delete with an observer fails and changes nothing",
			loadErr: errStoreQuotes,
			act:     deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				changedNothing(t, f, store, n)
				hidesStoreText()(t, err)
				assert.EqualError(t, err, textEndReportRead)
			},
		},
		{
			name:    "DeleteByUserExcept with an observer fails and changes nothing",
			loadErr: errStoreQuotes,
			act:     deleteAllButA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				changedNothing(t, f, store, n)
				hidesStoreText()(t, err)
				assert.EqualError(t, err, textEndReportRead)
			},
		},
		{
			// Asking again will not help here, but the family is still unknown, so
			// the report could not name it. DeleteByUser still reaches the session.
			name:    "a session that cannot be opened is not gone, so Delete fails with that answer",
			loadErr: session.ErrUnreadable,
			act:     deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				changedNothing(t, f, store, n)
				isBare(session.ErrUnreadable)(t, err)
			},
		},
		{
			name: "a request hung up before the read fails Delete and changes nothing",
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
			act: deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				changedNothing(t, f, store, n)
				require.ErrorIs(t, err, context.Canceled)
			},
		},
		{
			name:       "Delete with no observer proceeds without reading",
			unobserved: true,
			loadErr:    errStoreQuotes,
			act:        deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, _ int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, stored(t, store, f.a))
				assert.True(t, stored(t, store, f.b))
				assert.Zero(t, store.loads.Load(), "Load is not called")
			},
		},
		{
			name:       "DeleteByUserExcept with no observer proceeds without reading",
			unobserved: true,
			loadErr:    errStoreQuotes,
			act:        deleteAllButA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 1, n)
				assert.True(t, stored(t, store, f.a))
				assert.False(t, stored(t, store, f.b))
				assert.Zero(t, store.loads.Load(), "Load is not called")
			},
		},
		{
			name:    "Delete proceeds when the read finds the session gone",
			loadErr: session.ErrNotFound,
			act:     deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, _ int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, stored(t, store, f.a))
				require.Len(t, f.calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndDeleted, At: createdAt}, f.calls[0].report)
			},
		},
		{
			name:    "Delete proceeds when the store wraps its answer that the session is gone",
			loadErr: fmt.Errorf("the row: %w", session.ErrNotFound),
			act:     deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, _ int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, stored(t, store, f.a))
				require.Len(t, f.calls, 1)
			},
		},
		{
			name:    "Delete proceeds when the read finds the session expired",
			loadErr: session.ErrExpired,
			act:     deleteA,
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, _ int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, stored(t, store, f.a))
				require.Len(t, f.calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndDeleted, At: createdAt}, f.calls[0].report)
			},
		},
		{
			name:    "DeleteByUserExcept proceeds when the read finds the kept session gone",
			loadErr: session.ErrNotFound,
			act:     deleteAllButA,
			assert: func(t *testing.T, f *observedFixture, _ *loadFailingStore, n int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 1, n)
				require.Len(t, f.calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndUserSessionsExcept, User: endUser, At: createdAt}, f.calls[0].report)
			},
		},
		{
			name:    "DeleteByUserExcept with an empty keep proceeds with no read",
			loadErr: errStoreQuotes,
			act: func(ctx context.Context, m *session.Sessions, _ *observedFixture) (int, error) {
				return m.DeleteByUserExcept(ctx, endUser, "")
			},
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 2, n)
				assert.False(t, stored(t, store, f.a))
				assert.False(t, stored(t, store, f.b))
				assert.Zero(t, store.loads.Load(), "Load is not called")
				require.Len(t, f.calls, 1)
			},
		},
		{
			name:    "RevokeFamily while reads fail ends the family and tells the observer",
			loadErr: errStoreQuotes,
			act: func(ctx context.Context, m *session.Sessions, f *observedFixture) (int, error) {
				return m.RevokeFamily(ctx, f.a.FamilyID)
			},
			assert: func(t *testing.T, f *observedFixture, store *loadFailingStore, n int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 1, n)
				assert.False(t, stored(t, store, f.a))
				assert.True(t, stored(t, store, f.b))
				assert.Zero(t, store.loads.Load(), "a revocation reads nothing")
				require.Len(t, f.calls, 1)
				assert.Equal(t, session.EndReport{Cause: session.EndFamilyRevoked, Family: f.a.FamilyID, At: createdAt}, f.calls[0].report)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &observedFixture{clk: clockwork.NewFakeClockAt(createdAt), logs: &bytes.Buffer{}}
			store := &loadFailingStore{MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk)))}

			opts := []session.Option{session.WithStore(store), session.WithClock(f.clk), session.WithLogger(f.logger())}
			if !tc.unobserved {
				first, _ := f.observers()
				opts = append(opts, session.WithEndObserver(first))
			}
			f.m = managerFor(t, opts...)

			var err error
			f.a, err = f.m.Create(t.Context(), endUser)
			require.NoError(t, err)
			f.b, err = f.m.Create(t.Context(), endUser)
			require.NoError(t, err)

			store.loadErr = tc.loadErr
			store.loads.Store(0)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			n, err := tc.act(ctx, f.m, f)

			tc.assert(t, f, store, n, err)
		})
	}
}

// TestSessions_EndObserver_BesideReuseObserver pins that end observers and
// the reuse observer are both told of one reuse, whatever the reuse observer
// does: unlike an end observer's, its panic is not recovered.
func TestSessions_EndObserver_BesideReuseObserver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		reuse  session.ReuseObserver
		assert func(t *testing.T, load func())
	}

	var reuseTold atomic.Int32

	cases := []testCase{
		{
			name:  "both are told",
			reuse: func(context.Context, session.ReuseReport) { reuseTold.Add(1) },
			assert: func(t *testing.T, load func()) {
				assert.NotPanics(t, load)
				assert.EqualValues(t, 1, reuseTold.Load(), "the reuse observer was not told")
			},
		},
		{
			name:  "a reuse observer that panics does not take the end report with it",
			reuse: func(context.Context, session.ReuseReport) { panic("reuse observer") },
			assert: func(t *testing.T, load func()) {
				assert.Panics(t, load)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, _ := newObservedFixture(t, recordingObservers, session.WithReuseObserver(tc.reuse))
			f.renew(t.Context(), t, f.a)
			f.clk.Advance(5 * time.Minute)

			tc.assert(t, func() {
				_, err := f.m.Load(t.Context(), f.a.ID)
				assert.ErrorIs(t, err, session.ErrReused)
			})

			require.Len(t, f.calls, 2, "the end observers were not told")
			assert.Equal(t, session.EndReuse, f.calls[0].report.Cause)
		})
	}
}
