package httpsec_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// Most of these tests run in a synctest bubble: the chain's clock, the session manager's and
// the reload's context.WithTimeout all read the bubble's virtual time, so a day of a stream's
// life takes no real time, a store that hangs can be waited out, and synctest.Wait is the
// barrier that says the stream has done all it will until time next moves. A bubble has no
// sockets, so a stream's bytes land in streamWriter. A smaller set at the end drives a real
// connection through signalsFixture.

// streamSecret is what a consumer's panic quotes, and no log may hold.
const streamSecret = "tok-very-secret-value"

// streamClient is the client address of a stream's request, which a stream must never send.
const streamClient = "198.51.100.7"

// streamFrame is one thing a stream sent.
type streamFrame struct {
	At         time.Time
	Kind       string // retry, comment or event
	Name, Data string
}

// streamWriter is the http.ResponseWriter below a stream in a bubble. A frame counts as sent
// only once it has been flushed.
type streamWriter struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	chunks  []streamFrame
	flushed int

	failWrite, failFlush atomic.Bool

	// hold keeps a write waiting until the channel closes.
	hold atomic.Pointer[chan struct{}]
}

// holdWrites keeps every later write waiting until the returned channel closes.
func (w *streamWriter) holdWrites() chan struct{} {
	let := make(chan struct{})
	w.hold.Store(&let)

	return let
}

func (w *streamWriter) Header() http.Header { return w.header }

func (w *streamWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.status == 0 {
		w.status = status
	}
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.failWrite.Load() {
		return 0, errors.New("the client has gone")
	}

	if let := w.hold.Load(); let != nil {
		<-*let
	}

	w.WriteHeader(http.StatusOK)

	w.mu.Lock()
	defer w.mu.Unlock()

	w.chunks = append(w.chunks, parseStreamFrame(string(p)))

	return len(p), nil
}

func (w *streamWriter) FlushError() error {
	if w.failFlush.Load() {
		return errors.New("the client has gone")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.flushed = len(w.chunks)

	return nil
}

func (*streamWriter) SetWriteDeadline(time.Time) error { return nil }

// parseStreamFrame reads what one Write held, which is exactly one frame.
func parseStreamFrame(text string) streamFrame {
	frame := streamFrame{At: time.Now()}

	switch {
	case text == ":\n\n":
		frame.Kind = "comment"
	case strings.HasPrefix(text, "retry: "):
		frame.Kind, frame.Data = "retry", strings.TrimSuffix(strings.TrimPrefix(text, "retry: "), "\n\n")
	default:
		frame.Kind = "event"

		for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n\n"), "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				frame.Name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				frame.Data = strings.TrimPrefix(line, "data: ")
			default:
				frame.Kind = "malformed: " + text
			}
		}
	}

	return frame
}

// streamClock is a chain clock a test can step: time plus an offset, waiting in real (bubble)
// time, as a wall clock that an operator or NTP stepped does. Armed, it panics.
type streamClock struct {
	offset atomic.Int64
	armed  atomic.Bool

	// beats, when set, is what a wait as long as a heartbeat of beatsFor waits on instead of time,
	// so a row can name the moment a heartbeat falls, whatever its jitter drew.
	beats    atomic.Pointer[chan time.Time]
	beatsFor atomic.Int64
}

func (c *streamClock) Now() time.Time {
	if c.armed.Load() {
		panic(fmt.Errorf("clock read with %s", streamSecret))
	}

	return time.Now().Add(time.Duration(c.offset.Load()))
}

func (c *streamClock) After(d time.Duration) <-chan time.Time {
	if beats := c.beats.Load(); beats != nil {
		if heartbeat := time.Duration(c.beatsFor.Load()); d >= heartbeat*9/10 && d <= heartbeat*11/10 {
			return *beats
		}
	}

	return time.After(d)
}

var _ clock.Timed = (*streamClock)(nil)

// streamSetup is what a case varies.
type streamSetup struct {
	signals        httpsec.SessionSignals
	idle, absolute time.Duration
	assurance      bool
	opts           func(r *streamRig) []httpsec.Option
	requestCtx     func(context.Context) context.Context

	// withoutSessionBearer leaves the session bearer off, for a row with another authenticator.
	withoutSessionBearer bool

	// sameClock puts the session manager and its store on the chain's clock, as one machine's
	// clock is. By default they have one of their own, so the chain's can be stepped against it.
	sameClock bool
}

// streamRig is a chain with the stream enabled, in a bubble.
type streamRig struct {
	clock    *streamClock
	inner    session.Store
	counted  *countingLoadStore
	sessions *session.Sessions
	users    *MockUserLoader
	chain    *httpsec.Chain
	handler  http.Handler
	logs     *lockedBuffer
	setup    streamSetup

	// listHook sees a listing before it runs, and an error it returns fails the listing.
	// loadHook does the same for a load, which is what an authenticator's read is.
	// userHook replaces what the user loader answers.
	listHook atomic.Pointer[func(context.Context) error]
	loadHook atomic.Pointer[func(context.Context) error]
	userHook atomic.Pointer[func(context.Context) (*identity.Details, error)]

	// familyDeleted runs once a family's delete has reached the store and before its caller is
	// told, which is before the session manager makes its end report.
	familyDeleted atomic.Pointer[func()]

	// listsNothing makes a listing answer that the user holds no sign-in, as a store does once an
	// end has reached it, and setting it back as one does when that end is rolled back.
	listsNothing atomic.Bool

	// lists counts listings, ends the end reports, and reuses the reuse reports. The ByTest
	// counts are what the test's own calls caused, and each stream's opening: anything else is
	// the stream's doing, and when the test ends there must be none (see newStreamRig).
	lists        atomic.Int64
	ends         atomic.Int64
	reuses       atomic.Int64
	loadsByTest  atomic.Int64
	endsByTest   atomic.Int64
	reusesByTest atomic.Int64
}

func newStreamRig(t *testing.T, setup streamSetup) *streamRig {
	t.Helper()

	r := &streamRig{clock: &streamClock{}, logs: &lockedBuffer{}, setup: setup}

	var storeOpts []session.MemoryStoreOption

	if setup.sameClock {
		storeOpts = append(storeOpts, session.WithMemoryStoreClock(r.clock))
	}

	r.inner = must.Must(session.NewMemoryStore(storeOpts...))
	r.counted = &countingLoadStore{Store: r.inner}

	idle, absolute := setup.idle, setup.absolute
	if idle == 0 {
		idle = 30 * time.Minute
	}

	if absolute == 0 {
		absolute = 12 * time.Hour
	}

	sessionOpts := []session.Option{
		session.WithStore(&streamHookStore{Store: r.counted, rig: r}),
		session.WithIdleTimeout(idle),
		session.WithAbsoluteTimeout(absolute),
		session.WithTouchInterval(0),
		session.WithReuseObserver(func(context.Context, session.ReuseReport) { r.reuses.Add(1) }),
		session.WithEndObserver(session.EndObserverFunc(func(context.Context, session.EndReport) { r.ends.Add(1) })),
	}

	if setup.sameClock {
		sessionOpts = append(sessionOpts, session.WithClock(r.clock))
	}

	var err error

	r.sessions, err = session.New(sessionOpts...)
	require.NoError(t, err)

	r.users = NewMockUserLoader(gomock.NewController(t))
	r.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, user identity.UserID) (*identity.Details, error) {
			if hook := r.userHook.Load(); hook != nil {
				return (*hook)(ctx)
			}

			details := storedUser()
			details.ID = user

			return details, nil
		})

	opts := []httpsec.Option{
		httpsec.WithClock(r.clock),
		httpsec.WithLogger(slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		httpsec.EnableSessionSignals(setup.signals),
	}

	if !setup.withoutSessionBearer {
		opts = append(opts, httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: r.sessions, Users: r.users}))
	}

	if setup.assurance {
		opts = append(opts,
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: NewMockAuthenticator(gomock.NewController(t)),
				Sessions:      r.sessions,
				Attempts:      NewMockAttemptStore(gomock.NewController(t)),
			}),
			httpsec.EnableReauthentication(),
		)
	}

	if setup.opts != nil {
		opts = append(opts, setup.opts(r)...)
	}

	r.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	r.handler = r.chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(signalsDownstreamStatus)
	}))

	// Every row, whatever it is about, also shows the stream presented nothing, revoked nothing and
	// reported no reuse. It runs last, once every stream's cleanup has ended that stream.
	t.Cleanup(func() {
		assert.Equal(t, r.loadsByTest.Load(), r.counted.loads.Load(), "a stream presented a session through Load")
		assert.Equal(t, r.endsByTest.Load(), r.ends.Load(), "a stream ended a sign-in")
		assert.Equal(t, r.reusesByTest.Load(), r.reuses.Load(), "a stream's read reported reuse")
	})

	return r
}

// streamHookStore is the rig's session store, which sees and can fail each listing.
type streamHookStore struct {
	session.Store

	rig *streamRig
}

func (s *streamHookStore) ListByUser(ctx context.Context, user identity.UserID, at time.Time) ([]*session.Session, error) {
	s.rig.lists.Add(1)

	if hook := s.rig.listHook.Load(); hook != nil {
		if err := (*hook)(ctx); err != nil {
			return nil, err
		}
	}

	if s.rig.listsNothing.Load() {
		return nil, nil
	}

	return s.Store.ListByUser(ctx, user, at)
}

func (s *streamHookStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	if hook := s.rig.loadHook.Load(); hook != nil {
		if err := (*hook)(ctx); err != nil {
			return nil, err
		}
	}

	return s.Store.Load(ctx, sid)
}

func (s *streamHookStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	n, err := s.Store.DeleteFamily(ctx, family)

	if hook := s.rig.familyDeleted.Load(); hook != nil {
		(*hook)()
	}

	return n, err
}

// failListing makes every listing fail with a store's error until it is called with false.
func (r *streamRig) failListing(fail bool) {
	if !fail {
		r.listHook.Store(nil)

		return
	}

	hook := func(context.Context) error { return errors.New("the store is down") }
	r.listHook.Store(&hook)
}

// act runs what the test does to the session manager, whose Loads are the test's and not the
// stream's, and waits for the stream to have answered.
func (r *streamRig) act(fn func()) {
	loads, ends, reuses := r.counted.loads.Load(), r.ends.Load(), r.reuses.Load()

	fn()

	r.loadsByTest.Add(r.counted.loads.Load() - loads)
	r.endsByTest.Add(r.ends.Load() - ends)
	r.reusesByTest.Add(r.reuses.Load() - reuses)
	synctest.Wait()
}

// signIn stores a sign-in of u-1.
func (r *streamRig) signIn(t *testing.T, opts ...session.CreateOption) *session.Session {
	t.Helper()

	var s *session.Session

	r.act(func() {
		var err error

		s, err = r.sessions.Create(t.Context(), "u-1", append([]session.CreateOption{session.WithFirstFactor(factor.Password)}, opts...)...)
		require.NoError(t, err)
	})

	return s
}

// stored is the session as the store holds it, read by nothing the rig counts.
func (r *streamRig) stored(t *testing.T, sid string) *session.Session {
	t.Helper()

	s, err := r.inner.Load(t.Context(), sid)
	require.NoError(t, err)

	return s
}

// touch records activity on the session now.
func (r *streamRig) touch(t *testing.T, sid string) {
	t.Helper()

	r.act(func() { require.NoError(t, r.sessions.Touch(t.Context(), r.stored(t, sid))) })
}

// reauthenticate moves the sign-in's authentication time to now, as a step-up does, rotating
// strictly, and returns its new session.
func (r *streamRig) reauthenticate(t *testing.T, s *session.Session, at time.Time) *session.Session {
	t.Helper()

	var next *session.Session

	r.act(func() {
		current := r.stored(t, s.ID)
		current.AuthenticatedAt = at

		var err error

		next, err = r.sessions.Rotate(t.Context(), current)
		require.NoError(t, err)
	})

	return next
}

// userAnswers makes the user loader answer as fn says.
func (r *streamRig) userAnswers(fn func(context.Context) (*identity.Details, error)) {
	r.userHook.Store(&fn)
}

// inactiveUser is the user disabled, which revokes no session.
func inactiveUser() *identity.Details {
	u := storedUser()
	u.Active = false

	return u
}

// requireHarmless asserts the stream presented nothing, and that the only ends and reuse
// reports are the ones the test caused.
func (r *streamRig) requireHarmless(t *testing.T, ends, reuses int64) {
	t.Helper()

	assert.Equal(t, r.loadsByTest.Load(), r.counted.loads.Load(), "a stream presented a session through Load")
	assert.Equal(t, ends, r.ends.Load(), "end reports")
	assert.Equal(t, reuses, r.reuses.Load(), "reuse reports")
}

// openStreams is how many places are held.
func (r *streamRig) openStreams() int {
	open, _ := httpsec.SignalHubProbeOf(r.chain).Registry().Stats()

	return open
}

// wakeWith delivers a session_ended for the sign-in as a shared bus would. What the stream then
// does is its own, so it is not counted as the test's.
func (r *streamRig) wakeWith(s *session.Session, reason string) {
	httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{
		User: s.UserID, Family: s.FamilyID, Name: string(httpsec.SignalSessionEnded), Reason: reason,
	})
	synctest.Wait()
}

// riggedStream is one stream's request.
type riggedStream struct {
	w      *streamWriter
	cancel context.CancelFunc
	done   chan struct{}
}

// open sends the stream's request and waits until the stream has nothing more to do.
func (r *streamRig) open(t *testing.T, sid string, query ...string) *riggedStream {
	t.Helper()

	target := httpsec.DefaultSessionSignalsPath
	if len(query) > 0 {
		target += "?" + query[0]
	}

	ctx, cancel := context.WithCancel(t.Context())
	if r.setup.requestCtx != nil {
		ctx = r.setup.requestCtx(ctx)
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	req.RemoteAddr = streamClient + ":4242"
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+sid)

	s := &riggedStream{w: &streamWriter{header: http.Header{}}, cancel: cancel, done: make(chan struct{})}

	before, reusesBefore, endsBefore := r.counted.loads.Load(), r.reuses.Load(), r.ends.Load()

	go func() {
		defer close(s.done)

		r.handler.ServeHTTP(s.w, req)
	}()

	synctest.Wait()

	r.loadsByTest.Add(r.counted.loads.Load() - before)
	r.reusesByTest.Add(r.reuses.Load() - reusesBefore)
	r.endsByTest.Add(r.ends.Load() - endsBefore)

	t.Cleanup(func() {
		cancel()
		synctest.Wait()
	})

	return s
}

// frames is what the stream has sent, flushed.
func (s *riggedStream) frames() []streamFrame {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()

	return append([]streamFrame(nil), s.w.chunks[:s.w.flushed]...)
}

// unflushed is how many frames were written and never flushed.
func (s *riggedStream) unflushed() int {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()

	return len(s.w.chunks) - s.w.flushed
}

func (s *riggedStream) status() int {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()

	return s.w.status
}

// sent is every event's name, in order, with no retry and no comment.
func (s *riggedStream) sent() []string {
	names := []string{}

	for _, f := range s.frames() {
		if f.Kind == "event" {
			names = append(names, f.Name)
		}
	}

	return names
}

// events is the events named name.
func (s *riggedStream) events(name string) []streamFrame {
	var out []streamFrame

	for _, f := range s.frames() {
		if f.Kind == "event" && f.Name == name {
			out = append(out, f)
		}
	}

	return out
}

// comments is the heartbeats sent.
func (s *riggedStream) comments() []streamFrame {
	var out []streamFrame

	for _, f := range s.frames() {
		if f.Kind == "comment" {
			out = append(out, f)
		}
	}

	return out
}

// closed reports whether the stream's request has ended.
func (s *riggedStream) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// advance moves virtual time, and waits until every goroutine has done what that lets it.
func advance(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

// advanceUntil moves time in half-second steps until cond holds, failing past bound. It returns
// how long that took.
func advanceUntil(t *testing.T, bound time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()

	began := time.Now()

	for !cond() {
		require.Less(t, time.Since(began), bound, "%s did not happen", what)
		advance(500 * time.Millisecond)
	}

	return time.Since(began)
}

// requireEnded asserts the stream's last event is session_ended with the reason, that it is
// the only one, nothing follows it, the request has ended, and its place is free.
func (r *streamRig) requireEnded(t *testing.T, s *riggedStream, reason string) {
	t.Helper()

	frames := s.frames()
	require.NotEmpty(t, frames)

	last := frames[len(frames)-1]
	assert.Equal(t, string(httpsec.SignalSessionEnded), last.Name)
	assert.JSONEq(t, `{"reason":"`+reason+`"}`, last.Data)
	assert.Len(t, s.events(string(httpsec.SignalSessionEnded)), 1, "session_ended is said once")
	assert.Zero(t, s.unflushed(), "what was written was not flushed")
	assert.True(t, s.closed(), "the stream did not close")
	assert.Zero(t, r.openStreams(), "the place was not freed")
}

// requireLive asserts the stream goes on: open, holding its place, with no session_ended.
func (r *streamRig) requireLive(t *testing.T, s *riggedStream) {
	t.Helper()

	assert.False(t, s.closed(), "the stream closed")
	assert.Empty(t, s.events(string(httpsec.SignalSessionEnded)), "the stream said its sign-in ended")
	assert.Equal(t, 1, r.openStreams(), "the place was freed")
}

// streamCase is a row driven in a bubble.
type streamCase struct {
	name   string
	setup  streamSetup
	assert func(t *testing.T, r *streamRig)
}

func runStreamCases(t *testing.T, cases []streamCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) { tc.assert(t, newStreamRig(t, tc.setup)) })
		})
	}
}

// endedOnly is a set with nothing but what is always sent, for a row about the stream's end.
var endedOnly = []httpsec.Signal{httpsec.SignalSessionEnded}

// TestSessionSignals_Heartbeat_Jitter pins the spread each delay is drawn from.
func TestSessionSignals_Heartbeat_Jitter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		d        time.Duration
		fraction float64
		roll     float64
		assert   func(t *testing.T, got time.Duration)
	}

	equals := func(want time.Duration) func(t *testing.T, got time.Duration) {
		return func(t *testing.T, got time.Duration) {
			t.Helper()

			assert.InDelta(t, float64(want), float64(got), float64(time.Millisecond))
		}
	}

	cases := []testCase{
		{name: "the lowest roll is the bottom of the spread", d: 15 * time.Second, fraction: 0.10, roll: 0, assert: equals(13500 * time.Millisecond)},
		{name: "the middle is the interval itself", d: 15 * time.Second, fraction: 0.10, roll: 0.5, assert: equals(15 * time.Second)},
		{name: "the highest roll is the top of the spread", d: 15 * time.Second, fraction: 0.10, roll: 1, assert: equals(16500 * time.Millisecond)},
		{name: "a reconnection's spread is wider", d: 5 * time.Second, fraction: 0.30, roll: 0, assert: equals(3500 * time.Millisecond)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, httpsec.Jittered(tc.d, tc.fraction, tc.roll))
		})
	}
}

// TestSessionSignals_Heartbeat_Verdict is D4's reload table, as a pure function of what a reload
// found, what the stream holds, and the two kept reports.
func TestSessionSignals_Heartbeat_Verdict(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	rules := httpsec.StreamRules{ReasonWindow: 30 * time.Second}
	future := httpsec.HeldSignIn{State: session.SignInState{IdleDeadline: now.Add(time.Minute), AbsoluteDeadline: now.Add(time.Hour)}}
	idlePast := httpsec.HeldSignIn{State: session.SignInState{IdleDeadline: now.Add(-time.Second), AbsoluteDeadline: now.Add(time.Hour)}}
	absolutePast := httpsec.HeldSignIn{State: session.SignInState{IdleDeadline: now.Add(-time.Hour), AbsoluteDeadline: now}}
	down := errors.New("the store is down")

	fresh := func(reason string) *httpsec.EndNotice {
		return &httpsec.EndNotice{Reason: reason, At: now.Add(-10 * time.Second)}
	}
	stale := func(reason string) *httpsec.EndNotice {
		return &httpsec.EndNotice{Reason: reason, At: now.Add(-31 * time.Second)}
	}

	type testCase struct {
		name          string
		held          httpsec.HeldSignIn
		read          httpsec.StreamRead
		reuse, notice *httpsec.EndNotice
		assert        func(t *testing.T, v httpsec.StreamVerdict)
	}

	ends := func(reason string) func(t *testing.T, v httpsec.StreamVerdict) {
		return func(t *testing.T, v httpsec.StreamVerdict) {
			t.Helper()

			assert.Equal(t, reason, v.End)
			assert.False(t, v.Alive)
		}
	}

	alive := func(t *testing.T, v httpsec.StreamVerdict) {
		t.Helper()

		assert.Empty(t, v.End)
		assert.True(t, v.Alive)
		assert.False(t, v.Failed)
	}

	cases := []testCase{
		{name: "the sign-in is there", held: future, assert: alive},
		{name: "a kept report that the store does not agree with changes nothing", held: future, notice: fresh("logout"), assert: alive},
		{name: "a kept reuse the store does not agree with changes nothing", held: future, reuse: fresh("reuse"), assert: alive},
		{name: "gone with a kept report names it", held: future, read: httpsec.StreamRead{Gone: true}, notice: fresh("all_ended"), assert: ends("all_ended")},
		{name: "gone with a report at the edge of its window names it", held: future, read: httpsec.StreamRead{Gone: true}, notice: &httpsec.EndNotice{Reason: "logout", At: now.Add(-30 * time.Second)}, assert: ends("logout")},
		{name: "gone with a report past its window ignores it", held: future, read: httpsec.StreamRead{Gone: true}, notice: stale("logout"), assert: ends("ended")},
		{name: "gone with no report, no deadline passed", held: future, read: httpsec.StreamRead{Gone: true}, assert: ends("ended")},
		{name: "gone, the idle deadline passed", held: idlePast, read: httpsec.StreamRead{Gone: true}, assert: ends("expired")},
		{name: "gone, the absolute deadline passed", held: absolutePast, read: httpsec.StreamRead{Gone: true}, assert: ends("expired")},
		{name: "gone, a deadline passed and a stale report", held: idlePast, read: httpsec.StreamRead{Gone: true}, notice: stale("logout"), assert: ends("expired")},
		{name: "gone, a deadline passed and a fresh report names the report", held: idlePast, read: httpsec.StreamRead{Gone: true}, notice: fresh("logout"), assert: ends("logout")},
		{name: "reuse outranks a later report in its window", held: future, read: httpsec.StreamRead{Gone: true}, reuse: fresh("reuse"), notice: fresh("logout"), assert: ends("reuse")},
		{name: "a stale reuse does not name a later logout", held: future, read: httpsec.StreamRead{Gone: true}, reuse: stale("reuse"), notice: fresh("logout"), assert: ends("logout")},
		{name: "a stale reuse with nothing else names nothing", held: future, read: httpsec.StreamRead{Gone: true}, reuse: stale("reuse"), assert: ends("ended")},
		{name: "an inactive user is ended whatever the notice says", held: future, read: httpsec.StreamRead{UserGone: true}, notice: fresh("logout"), assert: ends("ended")},
		{name: "an inactive user is ended whatever reuse says", held: future, read: httpsec.StreamRead{UserGone: true}, reuse: fresh("reuse"), assert: ends("ended")},
		{name: "an inactive user of a gone sign-in is ended, past a deadline too", held: idlePast, read: httpsec.StreamRead{Gone: true, UserGone: true}, notice: fresh("logout"), assert: ends("ended")},
		{
			name: "a session store failure keeps going",
			held: future,
			read: httpsec.StreamRead{SessionErr: down},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Empty(t, v.End)
				assert.True(t, v.Failed)
				assert.False(t, v.Alive)
			},
		},
		{
			name:   "a session store failure past the idle deadline keeps going",
			held:   idlePast,
			read:   httpsec.StreamRead{SessionErr: down},
			notice: fresh("logout"),
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Empty(t, v.End)
				assert.True(t, v.Failed)
			},
		},
		{
			name: "a session store failure at the absolute deadline is expired",
			held: absolutePast,
			read: httpsec.StreamRead{SessionErr: down},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Equal(t, "expired", v.End)
				assert.True(t, v.Failed)
			},
		},
		{
			name: "a user store failure over a live sign-in counts, and the sign-in's answer stands",
			held: absolutePast,
			read: httpsec.StreamRead{UserErr: down},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Empty(t, v.End, "the session store said it is there")
				assert.True(t, v.Alive)
				assert.True(t, v.Failed)
			},
		},
		{
			name: "a user store failure over a gone sign-in ends it, because the store has said",
			held: future,
			read: httpsec.StreamRead{Gone: true, UserErr: down},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Equal(t, "ended", v.End)
			},
		},
	}

	cases = append(cases,
		testCase{
			name: "gone with nothing reported and no deadline passed is ended for want of a report",
			held: future,
			read: httpsec.StreamRead{Gone: true},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Equal(t, "ended", v.End)
				assert.True(t, v.Unreported)
			},
		},
		testCase{
			name:   "gone with a report is that report's, and waits for nothing",
			held:   future,
			read:   httpsec.StreamRead{Gone: true},
			notice: fresh("logout"),
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Equal(t, "logout", v.End)
				assert.False(t, v.Unreported)
			},
		},
		testCase{
			name: "gone past a deadline is expired, and waits for nothing",
			held: idlePast,
			read: httpsec.StreamRead{Gone: true},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Equal(t, "expired", v.End)
				assert.False(t, v.Unreported)
			},
		},
		testCase{
			name: "a user no longer active waits for nothing",
			held: future,
			read: httpsec.StreamRead{Gone: true, UserGone: true},
			assert: func(t *testing.T, v httpsec.StreamVerdict) {
				assert.Equal(t, "ended", v.End)
				assert.False(t, v.Unreported)
			},
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, rules.Judge(tc.held, tc.read, tc.reuse, tc.notice, now))
		})
	}
}

// TestSessionSignals_Heartbeat is the store deciding, one row per line of D4's reload table.
func TestSessionSignals_Heartbeat(t *testing.T) {
	t.Parallel()

	runStreamCases(t, []streamCase{
		{
			name: "a sign-in that stays is a comment each beat, within the jitter, and nothing else",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				before := r.stored(t, s.ID)

				advance(5 * time.Minute)

				comments := stream.comments()
				require.GreaterOrEqual(t, len(comments), 18)
				require.LessOrEqual(t, len(comments), 23)

				gaps := map[time.Duration]bool{}

				for i := 1; i < len(comments); i++ {
					gap := comments[i].At.Sub(comments[i-1].At)
					assert.GreaterOrEqual(t, gap, 13500*time.Millisecond)
					assert.LessOrEqual(t, gap, 16500*time.Millisecond)
					gaps[gap] = true
				}

				assert.Greater(t, len(gaps), 1, "each beat's jitter is drawn again")
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Equal(t, before, r.stored(t, s.ID), "a heartbeat changed the session")
				r.requireLive(t, stream)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a consumer's interval is used",
			setup: streamSetup{signals: httpsec.SessionSignals{Heartbeat: 30 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				advance(5 * time.Minute)

				comments := stream.comments()
				require.GreaterOrEqual(t, len(comments), 9)

				for i := 1; i < len(comments); i++ {
					gap := comments[i].At.Sub(comments[i-1].At)
					assert.GreaterOrEqual(t, gap, 27*time.Second)
					assert.LessOrEqual(t, gap, 33*time.Second)
				}
			},
		},
		{
			name: "each beat reads the sign-in and its user, and never Load",
			assert: func(t *testing.T, r *streamRig) {
				var users atomic.Int64

				r.userAnswers(func(context.Context) (*identity.Details, error) {
					users.Add(1)

					return storedUser(), nil
				})

				stream := r.open(t, r.signIn(t).ID)
				lists, loaded := r.lists.Load(), users.Load()

				advance(2 * time.Minute)

				beats := int64(len(stream.comments()))
				require.Positive(t, beats)
				assert.Equal(t, beats, r.lists.Load()-lists)
				assert.Equal(t, beats, users.Load()-loaded)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a user who is not found is ended at the next beat",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return nil, identity.ErrUserNotFound })
				advance(17 * time.Second)

				r.requireEnded(t, stream, "ended")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a user no longer active is ended at the next beat, whose sign-in stays",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return inactiveUser(), nil })
				advance(17 * time.Second)

				r.requireEnded(t, stream, "ended")
				r.stored(t, s.ID)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a user who is another user is ended, as the bearer refuses one",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				other := storedUser()
				other.ID = "u-2"

				r.userAnswers(func(context.Context) (*identity.Details, error) { return other, nil })
				advance(17 * time.Second)

				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name: "an inactive user is ended whatever the wake's report said",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return inactiveUser(), nil })
				r.wakeWith(s, "logout")

				r.requireEnded(t, stream, "ended")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "gone with no report is ended at the next beat",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				advance(17 * time.Second)

				r.requireEnded(t, stream, "ended")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a store failing for two reloads and then saying gone is a comment each beat and then session_ended",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				var left atomic.Int64
				left.Store(2)

				hook := func(context.Context) error {
					if left.Add(-1) >= 0 {
						return errors.New("the store is down")
					}

					return nil
				}
				r.listHook.Store(&hook)

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))

				advanceUntil(t, time.Minute, "the end", stream.closed)

				assert.Len(t, stream.comments(), 3, "the third beat's comment goes out before its read")
				assert.Equal(t, []string{"session", "session_ended"}, stream.sent())
				r.requireEnded(t, stream, "ended")

				total, inRow := httpsec.SignalReloadCounts(r.chain)
				assert.EqualValues(t, 2, total)
				assert.Zero(t, inRow, "a stream that closed no longer counts")
				assert.Contains(t, r.logs.String(), "reload failed")
				assert.NotContains(t, r.logs.String(), "the store is down", "a store's error text is not logged")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a user store failure is a comment, and the stream goes on until the user store answers",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return nil, errors.New("the user store is down") })
				advance(40 * time.Second)

				assert.GreaterOrEqual(t, len(stream.comments()), 2)
				r.requireLive(t, stream)

				total, inRow := httpsec.SignalReloadCounts(r.chain)
				assert.GreaterOrEqual(t, total, uint64(2))
				assert.Equal(t, total, inRow)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return inactiveUser(), nil })
				advance(17 * time.Second)

				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name: "a successful read clears the stream's failures in a row, and not the total",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.failListing(true)
				advance(40 * time.Second)

				total, inRow := httpsec.SignalReloadCounts(r.chain)
				require.Positive(t, inRow)
				assert.Equal(t, total, inRow)

				r.failListing(false)
				advance(17 * time.Second)

				after, inRow := httpsec.SignalReloadCounts(r.chain)
				assert.Equal(t, total, after)
				assert.Zero(t, inRow)
				r.requireLive(t, stream)
			},
		},
		{
			name: "a store that hangs times out on the default budget, and the heartbeat goes out on time",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				opened := time.Now()

				var began atomic.Int64

				hook := func(ctx context.Context) error {
					began.Store(time.Now().UnixNano())

					<-ctx.Done()

					return ctx.Err()
				}
				r.listHook.Store(&hook)

				advanceUntil(t, 20*time.Second, "a comment", func() bool { return len(stream.comments()) > 0 })

				first := stream.comments()[0].At.Sub(opened)
				assert.GreaterOrEqual(t, first, 13500*time.Millisecond)
				assert.LessOrEqual(t, first, 16500*time.Millisecond)

				total, _ := httpsec.SignalReloadCounts(r.chain)
				require.Zero(t, total, "the read has its budget")

				at := time.Unix(0, began.Load())
				time.Sleep(time.Until(at.Add(7500*time.Millisecond)) + time.Millisecond)
				synctest.Wait()

				r.requireLive(t, stream)

				total, _ = httpsec.SignalReloadCounts(r.chain)
				assert.EqualValues(t, 1, total, "a timeout counts as a failure, at the end of the 7.5 s budget")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a consumer's ReloadTimeout is used",
			setup: streamSetup{signals: httpsec.SessionSignals{ReloadTimeout: 2 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				r.open(t, r.signIn(t).ID)

				var began atomic.Int64

				hook := func(ctx context.Context) error {
					began.Store(time.Now().UnixNano())

					<-ctx.Done()

					return ctx.Err()
				}
				r.listHook.Store(&hook)

				advanceUntil(t, 20*time.Second, "the read", func() bool { return began.Load() != 0 })

				at := time.Unix(0, began.Load())

				time.Sleep(time.Until(at.Add(2*time.Second)) - time.Millisecond)
				synctest.Wait()

				total, _ := httpsec.SignalReloadCounts(r.chain)
				require.Zero(t, total, "before the consumer's 2 s")

				advance(2 * time.Millisecond)

				total, _ = httpsec.SignalReloadCounts(r.chain)
				assert.EqualValues(t, 1, total, "after the consumer's 2 s")
			},
		},
		{
			name: "the session read and the user read share one budget",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				hook := func(context.Context) error {
					time.Sleep(5 * time.Second)

					return nil
				}
				r.listHook.Store(&hook)

				left := make(chan time.Duration, 8)

				r.userAnswers(func(ctx context.Context) (*identity.Details, error) {
					deadline, ok := ctx.Deadline()
					if !ok {
						return nil, errors.New("the user read has no deadline")
					}

					select {
					case left <- time.Until(deadline):
					default:
					}

					return storedUser(), nil
				})

				advance(25 * time.Second)

				require.NotEmpty(t, left)
				assert.Equal(t, 2500*time.Millisecond, <-left, "the budget is 7.5 s, and the session read took 5")
				r.requireLive(t, stream)
			},
		},
		{
			name: "a user store that hangs times out too",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.userAnswers(func(ctx context.Context) (*identity.Details, error) {
					<-ctx.Done()

					return nil, ctx.Err()
				})

				advance(40 * time.Second)

				assert.NotEmpty(t, stream.comments())
				r.requireLive(t, stream)
				total, _ := httpsec.SignalReloadCounts(r.chain)
				assert.Positive(t, total)
			},
		},
		{
			name: "a renewal past its grace window leaves the stream open and the sign-in live",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				var next *session.Session

				advance(time.Minute)
				r.act(func() {
					var err error

					next, _, err = r.sessions.RotateWithGrace(t.Context(), r.stored(t, s.ID), 10*time.Second)
					require.NoError(t, err)
				})
				advance(time.Minute)

				r.requireLive(t, stream)
				assert.Equal(t, []string{"session", "session"}, stream.sent(), "the renewal moved the deadlines")

				var data struct {
					IdleDeadline string `json:"idle_deadline"`
				}

				require.Len(t, stream.events("session"), 2)
				require.NoError(t, json.Unmarshal([]byte(stream.events("session")[1].Data), &data))
				assert.Equal(t, next.IdleExpiresAt.UTC().Format(time.RFC3339Nano), data.IdleDeadline)

				r.requireHarmless(t, 0, 0)
				r.act(func() {
					_, err := r.sessions.Load(t.Context(), next.ID)
					require.NoError(t, err, "the sign-in is live")
				})
				assert.Zero(t, r.reuses.Load())
			},
		},
		{
			name: "a strict rotation leaves the stream open and the sign-in live",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				var next *session.Session

				advance(time.Minute)
				r.act(func() {
					var err error

					next, err = r.sessions.Rotate(t.Context(), r.stored(t, s.ID))
					require.NoError(t, err)
				})
				advance(5 * time.Minute)

				r.requireLive(t, stream)
				r.requireHarmless(t, 0, 0)
				r.act(func() {
					_, err := r.sessions.Load(t.Context(), next.ID)
					require.NoError(t, err)
				})
			},
		},
		{
			name: "a step-up leaves the stream open, moves authenticated_at, and the sign-in stays live",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(time.Minute)
				next := r.reauthenticate(t, s, time.Now())
				advance(20 * time.Second)

				r.requireLive(t, stream)
				require.Len(t, stream.events("session"), 2)
				assert.Contains(t, stream.events("session")[1].Data, next.AuthenticatedAt.UTC().Format(time.RFC3339Nano))
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a transaction on the opening request, committed since, does not reach a reload",
			setup: streamSetup{
				requestCtx: func(ctx context.Context) context.Context { return context.WithValue(ctx, signalsTenantKey{}, "tx") },
			},
			assert: func(t *testing.T, r *streamRig) {
				hook := func(ctx context.Context) error {
					if ctx.Value(signalsTenantKey{}) != nil {
						return errors.New("the transaction has been committed")
					}

					return nil
				}
				r.listHook.Store(&hook)

				s := r.signIn(t)
				stream := r.open(t, s.ID)
				require.Equal(t, http.StatusOK, stream.status())

				advance(40 * time.Second)
				r.requireLive(t, stream)

				total, _ := httpsec.SignalReloadCounts(r.chain)
				assert.Zero(t, total, "a reload read through the opening request's transaction")

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				advance(17 * time.Second)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name: "a tenant carried by ReloadContext reaches every read of both stores",
			setup: streamSetup{
				requestCtx: func(ctx context.Context) context.Context { return context.WithValue(ctx, signalsTenantKey{}, "t-1") },
				signals: httpsec.SessionSignals{ReloadContext: func(ctx context.Context) context.Context {
					return context.WithValue(context.Background(), signalsTenantKey{}, ctx.Value(signalsTenantKey{}))
				}},
			},
			assert: func(t *testing.T, r *streamRig) {
				var sessionReads, userReads, untenanted atomic.Int64

				see := func(ctx context.Context, n *atomic.Int64) {
					n.Add(1)

					if ctx.Value(signalsTenantKey{}) != "t-1" {
						untenanted.Add(1)
					}
				}

				listHook := func(ctx context.Context) error {
					see(ctx, &sessionReads)

					return nil
				}
				r.listHook.Store(&listHook)
				r.userAnswers(func(ctx context.Context) (*identity.Details, error) {
					see(ctx, &userReads)

					return storedUser(), nil
				})

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(40 * time.Second)

				assert.GreaterOrEqual(t, sessionReads.Load(), int64(3), "the first read and two beats")
				assert.GreaterOrEqual(t, userReads.Load(), int64(3))
				assert.Zero(t, untenanted.Load())
				r.requireLive(t, stream)
			},
		},
		{
			name: "a stream's open and close log at DEBUG, with no identifier or token",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t, session.WithExternalSession("provider", "https://idp.example", "upstream-sid", "raw-id-token"))
				stream := r.open(t, s.ID)

				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
					require.NoError(t, err)
				})

				r.requireEnded(t, stream, "logout")

				opened, closed := streamLogRecord(t, r.logs.String(), "stream opened"), streamLogRecord(t, r.logs.String(), "stream closed")

				for _, record := range []map[string]any{opened, closed} {
					assert.Equal(t, "DEBUG", record["level"])
					assert.Equal(t, "u-1", record["user"])
					assert.Equal(t, s.FamilyID.String(), record["family"])
					assert.Equal(t, streamClient, record["client_address"])
					assert.Equal(t, "http://example.com", record["origin"])
				}

				assert.Equal(t, "session_ended:logout", closed["reason"])

				for _, secret := range []string{s.ID, "upstream-sid", "raw-id-token"} {
					assert.NotContains(t, r.logs.String(), secret)
				}
			},
		},
		{
			name: "a stream sends no client address, and no session or upstream identifier",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t, session.WithExternalSession("provider", "https://idp.example", "upstream-sid", "raw-id-token"))
				stream := r.open(t, s.ID)

				advance(time.Minute)
				r.touch(t, s.ID)
				advance(20 * time.Second)
				require.GreaterOrEqual(t, len(stream.events("session")), 2)

				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
					require.NoError(t, err)
				})
				require.True(t, stream.closed())

				for _, f := range stream.frames() {
					for _, secret := range []string{s.ID, s.FamilyID.String(), "upstream-sid", "raw-id-token", "idp.example", streamClient} {
						assert.NotContains(t, f.Data+f.Name, secret)
					}
				}
			},
		},
		{
			name: "a client that leaves ends the stream with no event, and frees its place",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				stream.cancel()
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Zero(t, r.openStreams())
				assert.Contains(t, r.logs.String(), "client_left")
			},
		},
		{
			name: "a client that leaves during a read that hangs does not count as a failure",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				entered := make(chan struct{}, 1)
				hook := func(ctx context.Context) error {
					entered <- struct{}{}
					<-ctx.Done()

					return ctx.Err()
				}
				r.listHook.Store(&hook)

				advanceUntil(t, 20*time.Second, "the read", func() bool { return len(entered) > 0 })
				stream.cancel()
				synctest.Wait()

				assert.True(t, stream.closed(), "the read goes on past the client")

				total, _ := httpsec.SignalReloadCounts(r.chain)
				assert.Zero(t, total)
			},
		},
		{
			name: "closing ends the stream with no session_ended, and frees its place",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				require.NoError(t, httpsec.SignalHubProbeOf(r.chain).Registry().Close(t.Context()))
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name: "a failed write ends the stream, and frees its place",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				stream.w.failWrite.Store(true)
				advance(17 * time.Second)

				assert.True(t, stream.closed())
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name: "a failed flush ends the stream, and frees its place",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				stream.w.failFlush.Store(true)
				advance(17 * time.Second)

				assert.True(t, stream.closed())
				assert.Zero(t, r.openStreams())
			},
		},
	})
}

// streamLogRecord finds the JSON log record whose message holds msg.
func streamLogRecord(t *testing.T, logs, msg string) map[string]any {
	t.Helper()

	for line := range strings.SplitSeq(logs, "\n") {
		if line == "" {
			continue
		}

		var record map[string]any

		require.NoError(t, json.Unmarshal([]byte(line), &record))

		if text, _ := record["msg"].(string); strings.Contains(text, msg) {
			return record
		}
	}

	require.FailNow(t, "no record says "+msg, logs)

	return nil
}

// TestSessionSignals_Heartbeat_Ends is one row per way a sign-in ends. A report wakes the stream
// at once, so no time passes, and a reconnection with the same credential is refused.
func TestSessionSignals_Heartbeat_Ends(t *testing.T) {
	t.Parallel()

	federated := session.WithExternalSession("provider", "https://idp.example", "upstream-sid", "raw-id-token")

	type testCase struct {
		name   string
		create []session.CreateOption
		end    func(t *testing.T, r *streamRig, s *session.Session)
		assert func(t *testing.T, r *streamRig, stream *riggedStream)
	}

	reasonIs := func(reason string, ends, reuses int64) func(*testing.T, *streamRig, *riggedStream) {
		return func(t *testing.T, r *streamRig, stream *riggedStream) {
			t.Helper()

			r.requireEnded(t, stream, reason)
			r.requireHarmless(t, ends, reuses)
		}
	}

	cases := []testCase{
		{
			name: "a logout names logout",
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
				require.NoError(t, err)
			},
			assert: reasonIs("logout", 1, 0),
		},
		{
			name: "deleting the session names logout",
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				require.NoError(t, r.sessions.Delete(t.Context(), s.ID))
			},
			assert: reasonIs("logout", 1, 0),
		},
		{
			name: "an ended sign-in names ended",
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				require.NoError(t, r.sessions.EndSignIn(t.Context(), s.UserID, s.FamilyID.String()))
			},
			assert: reasonIs("ended", 1, 0),
		},
		{
			name: "a family a consumer revoked names ended",
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				_, err := r.sessions.RevokeFamily(t.Context(), s.FamilyID)
				require.NoError(t, err)
			},
			assert: reasonIs("ended", 1, 0),
		},
		{
			name: "every session of the user names all_ended",
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				require.NoError(t, r.sessions.DeleteByUser(t.Context(), s.UserID))
			},
			assert: reasonIs("all_ended", 1, 0),
		},
		{
			name:   "the user's sessions from a provider name provider_logout",
			create: []session.CreateOption{federated},
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				_, err := r.sessions.DeleteByUserAndExternalIssuer(t.Context(), s.UserID, "https://idp.example")
				require.NoError(t, err)
			},
			assert: reasonIs("provider_logout", 1, 0),
		},
		{
			name:   "a back-channel logout names provider_logout, without a heartbeat",
			create: []session.CreateOption{federated},
			end: func(t *testing.T, r *streamRig, _ *session.Session) {
				_, err := r.sessions.DeleteByExternalSession(t.Context(), "https://idp.example", "upstream-sid")
				require.NoError(t, err)
			},
			assert: reasonIs("provider_logout", 1, 0),
		},
		{
			name: "a family revoked on reuse names reuse",
			end: func(t *testing.T, r *streamRig, s *session.Session) {
				_, _, err := r.sessions.RotateWithGrace(t.Context(), r.stored(t, s.ID), time.Second)
				require.NoError(t, err)
				time.Sleep(2 * time.Second)

				_, err = r.sessions.Load(t.Context(), s.ID)
				require.ErrorIs(t, err, session.ErrReused)
			},
			assert: reasonIs("reuse", 1, 1),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{})
				s := r.signIn(t, tc.create...)
				stream := r.open(t, s.ID)

				r.act(func() { tc.end(t, r, s) })

				tc.assert(t, r, stream)
				assert.Empty(t, stream.comments(), "the stream waited for a heartbeat")

				again := r.open(t, s.ID)
				assert.Equal(t, http.StatusUnauthorized, again.status(), "a reconnection with the same credential")
				assert.Empty(t, again.frames())
				assert.Zero(t, r.openStreams())
			})
		})
	}
}

// TestSessionSignals_BusWakeUp pins that a message never ends a stream, and that a flood of
// them cannot flood the store.
func TestSessionSignals_BusWakeUp(t *testing.T) {
	t.Parallel()

	noBeat := streamSetup{
		idle:    3 * time.Hour,
		signals: httpsec.SessionSignals{Heartbeat: 60 * time.Second, MaxAge: httpsec.NoMaxAge, Signals: endedOnly},
	}

	runStreamCases(t, []streamCase{
		{
			name:  "a message whose session still exists sends nothing, and the first reloads at once",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				lists := r.lists.Load()

				r.wakeWith(s, "reuse")

				assert.EqualValues(t, 1, r.lists.Load()-lists, "the wake reloads with no time passing")
				assert.Equal(t, []string{"session"}, stream.sent())
				r.requireLive(t, stream)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a message whose session still exists is not forwarded, and the heartbeat ends it later",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				// A forged message, or one whose outer transaction rolled back.
				r.wakeWith(s, "logout")
				r.requireLive(t, stream)

				// The reason it named is past its window by the time the store agrees.
				advance(2*time.Minute + 30*time.Second)
				r.requireLive(t, stream)

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				advanceUntil(t, 70*time.Second, "the heartbeat", stream.closed)

				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "several wake-ups at once coalesce into one reload",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				lists := r.lists.Load()
				hub := httpsec.SignalHubProbeOf(r.chain)

				held := r.holdListings(t)

				// The first is taken, and is the read held here. The rest have one slot to fill.
				r.wakeWith(s, "")
				require.EqualValues(t, 1, held.entered.Load())

				for range 8 {
					hub.Deliver(httpsec.SignalEnvelope{User: s.UserID, Family: s.FamilyID, Name: string(httpsec.SignalSessionEnded)})
				}

				held.letGo()
				synctest.Wait()
				assert.EqualValues(t, 1, r.lists.Load()-lists, "a wake inside the gap reloaded")

				advance(2 * time.Second)
				assert.EqualValues(t, 2, r.lists.Load()-lists, "nine wake-ups are one, and one more pending")
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a flood costs at most one read a second, and the last wake is still honoured",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				lists := r.lists.Load()

				r.wakeWith(s, "")
				require.EqualValues(t, 1, r.lists.Load()-lists)

				for range 50 {
					advance(100 * time.Millisecond)
					r.wakeWith(s, "")
					assert.False(t, stream.closed())
				}

				got := r.lists.Load() - lists
				assert.GreaterOrEqual(t, got, int64(5), "a pending wake was dropped")
				assert.LessOrEqual(t, got, int64(6), "five seconds of wakes")
			},
		},
		{
			name:  "a wake inside the gap stays pending, and is honoured when the gap ends",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "")

				advance(100 * time.Millisecond)
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				r.wakeWith(s, "logout")

				assert.False(t, stream.closed(), "the second wake reloaded inside the gap")

				advance(900 * time.Millisecond)

				r.requireEnded(t, stream, "logout")
			},
		},
		{
			name:  "a wake after the gap reloads at once again",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "")
				advance(1100 * time.Millisecond)

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				r.wakeWith(s, "logout")

				r.requireEnded(t, stream, "logout")
			},
		},
		{
			name:  "a clock with no monotonic reading stepped back holds a pending wake for at most two gaps",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "")

				lists := r.lists.Load()

				r.clock.offset.Store(int64(-time.Hour))
				r.wakeWith(s, "")

				advance(2 * time.Second)

				assert.Greater(t, r.lists.Load(), lists, "the step back held a pending wake past two gaps")
				r.requireLive(t, stream)
			},
		},
		{
			name: "a kept reason within its window names the end",
			setup: streamSetup{
				idle:    3 * time.Hour,
				signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge},
			},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "all_ended")
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))

				advanceUntil(t, 20*time.Second, "the end", stream.closed)
				r.requireEnded(t, stream, "all_ended")
			},
		},
		{
			name: "a kept reason past its two heartbeats does not name a later end",
			setup: streamSetup{
				idle:    3 * time.Hour,
				signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge},
			},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "all_ended")
				advance(31 * time.Second)

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				advanceUntil(t, 20*time.Second, "the end", stream.closed)

				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name: "a forged reuse an hour before a logout does not name it",
			setup: streamSetup{
				idle:    3 * time.Hour,
				signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge},
			},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "reuse")
				r.requireLive(t, stream)
				advance(time.Hour)
				r.requireLive(t, stream)

				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
					require.NoError(t, err)
				})

				r.requireEnded(t, stream, "logout")
				r.requireHarmless(t, 1, 0)
			},
		},
		{
			name: "reuse is not relabelled by a later logout report",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "reuse")
				advance(2 * time.Second)

				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
					require.NoError(t, err)
				})

				r.requireEnded(t, stream, "reuse")
			},
		},
		{
			name: "a reason a bus made up says nothing",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "expired")
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				advanceUntil(t, 20*time.Second, "the end", stream.closed)

				r.requireEnded(t, stream, "ended")
			},
		},
	})
}

// raiseOnQueue delivers a consumer's signal as a bus would, onto every stream of u-1.
func (r *streamRig) raiseOnQueue(names ...string) {
	for _, name := range names {
		httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{User: "u-1", Name: name, Data: json.RawMessage(`{}`)})
	}

	synctest.Wait()
}

// logoutHeldBeforeItsReport starts a logout that has deleted the family and has not yet made its end
// report, which it makes when the returned function is called. That is the gap a read can answer in.
func (r *streamRig) logoutHeldBeforeItsReport(t *testing.T, s *session.Session) (report func()) {
	t.Helper()

	deleted, let, done := make(chan struct{}), make(chan struct{}), make(chan struct{})

	hook := func() {
		close(deleted)
		<-let
	}
	r.familyDeleted.Store(&hook)

	ends := r.ends.Load()

	go func() {
		defer close(done)

		_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
		assert.NoError(t, err)
	}()

	<-deleted
	synctest.Wait()

	var once sync.Once

	report = func() {
		once.Do(func() {
			close(let)
			<-done
			r.endsByTest.Add(r.ends.Load() - ends)
			synctest.Wait()
		})
	}
	t.Cleanup(report)

	return report
}

// untilRead moves time in small steps until a read has begun and answered, however long the
// heartbeat's jitter took to start one.
func (r *streamRig) untilRead(t *testing.T) {
	t.Helper()

	lists, began := r.lists.Load(), time.Now()

	for r.lists.Load() == lists {
		require.Less(t, time.Since(began), 2*time.Minute, "no read began")
		advance(10 * time.Millisecond)
	}
}

// manualBeats makes the stream's heartbeats the row's to fire, for a heartbeat of d. It must be called
// before the stream opens.
func (r *streamRig) manualBeats(d time.Duration) (fire func()) {
	beats := make(chan time.Time)

	r.clock.beatsFor.Store(int64(d))
	r.clock.beats.Store(&beats)

	return func() {
		beats <- time.Now()

		synctest.Wait()
	}
}

// TestSessionSignals_Heartbeat_ReportBehindTheRead is a read that answers gone before the end's report
// has reached the stream, which a session manager makes only after the store's write has returned. So a
// stream that holds no report waits a short while for one, and only then says ended.
func TestSessionSignals_Heartbeat_ReportBehindTheRead(t *testing.T) {
	t.Parallel()

	quick := streamSetup{signals: httpsec.SessionSignals{Heartbeat: 5 * time.Second, Signals: endedOnly}}

	// goneUnreported opens a stream whose read has just said gone, with nothing reported.
	goneUnreported := func(t *testing.T, r *streamRig) (*session.Session, *riggedStream) {
		t.Helper()

		s := r.signIn(t)
		stream := r.open(t, s.ID)

		r.listsNothing.Store(true)
		r.untilRead(t)

		return s, stream
	}

	runStreamCases(t, []streamCase{
		{
			name:  "a logout's report arriving just after the read names logout, at once",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				report := r.logoutHeldBeforeItsReport(t, s)
				r.untilRead(t)
				r.requireLive(t, stream)

				report()

				r.requireEnded(t, stream, "logout")
			},
		},
		{
			name:  "any report during the wait names its reason",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				s, stream := goneUnreported(t, r)

				advance(httpsec.StreamReportGrace / 2)
				r.wakeWith(s, "all_ended")

				r.requireEnded(t, stream, "all_ended")
			},
		},
		{
			name:  "a report during the wait ends it at once, when a wake began the read and its gap is running",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				r.wakeWith(s, "")
				r.requireLive(t, stream)

				advance(httpsec.StreamReportGrace / 2)
				r.wakeWith(s, "all_ended")

				r.requireEnded(t, stream, "all_ended")
			},
		},
		{
			name:  "a wake during the wait, with a read in flight that answers alive, is asked again",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				fire := r.manualBeats(5 * time.Second)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				fire()
				r.requireLive(t, stream)

				held := r.holdListings(t)
				fire()
				require.EqualValues(t, 1, held.entered.Load(), "no read is in flight during the wait")

				r.wakeWith(s, "")
				r.listsNothing.Store(false)

				lists := r.lists.Load()

				held.letGo()
				synctest.Wait()

				assert.Equal(t, lists+1, r.lists.Load(), "what the wake asked was never asked")

				advance(httpsec.StreamReportGrace)
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a deadline passing during the wait says expired, on the read that deadline starts",
			setup: streamSetup{idle: time.Minute, signals: quick.signals},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				fire := r.manualBeats(5 * time.Second)
				stream := r.open(t, s.ID)

				advance(time.Minute - httpsec.StreamReportGrace/2)

				r.listsNothing.Store(true)
				fire()
				r.requireLive(t, stream)

				advance(httpsec.StreamReportGrace)
				r.requireEnded(t, stream, "expired")
			},
		},
		{
			name:  "a deadline passing during the wait says expired at its end, with that read still out",
			setup: streamSetup{idle: time.Minute, signals: quick.signals},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				fire := r.manualBeats(5 * time.Second)
				stream := r.open(t, s.ID)

				advance(time.Minute - httpsec.StreamReportGrace/2)

				r.listsNothing.Store(true)
				fire()
				r.requireLive(t, stream)

				held := r.holdListings(t)

				advance(httpsec.StreamReportGrace)
				require.EqualValues(t, 1, held.entered.Load(), "the deadline's read is not out")
				r.requireEnded(t, stream, "expired")
			},
		},
		{
			name:  "a wake that names no reason does not cut the wait short",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				s, stream := goneUnreported(t, r)

				r.wakeWith(s, "")
				r.requireLive(t, stream)

				advance(httpsec.StreamReportGrace)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "no report says ended once the wait is over, and not before",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				_, stream := goneUnreported(t, r)

				r.requireLive(t, stream)

				advance(httpsec.StreamReportGrace - 50*time.Millisecond)
				r.requireLive(t, stream)

				advance(100 * time.Millisecond)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "closing during the wait closes with no event",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				_, stream := goneUnreported(t, r)

				require.NoError(t, <-r.closing(t.Context()))

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent(), "closing sent an event")
				lastRetry(t, stream)
			},
		},
		{
			name:  "a client leaving during the wait ends the stream at once",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				_, stream := goneUnreported(t, r)

				stream.cancel()
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name: "a deadline passed says expired with no wait",
			setup: streamSetup{
				idle:    3 * time.Minute,
				signals: httpsec.SessionSignals{Heartbeat: time.Minute, Signals: endedOnly},
			},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(3*time.Minute - 100*time.Millisecond)
				r.listsNothing.Store(true)
				r.untilRead(t)
				advance(100 * time.Millisecond)

				r.requireEnded(t, stream, "expired")
			},
		},
		{
			name:  "a user no longer active says ended with no wait",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return inactiveUser(), nil })
				r.listsNothing.Store(true)
				r.untilRead(t)

				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "a heartbeat during the wait still goes out, and its read's answer is not lost",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				fire := r.manualBeats(5 * time.Second)

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				fire()
				r.requireLive(t, stream)

				comments := len(stream.comments())
				r.listsNothing.Store(false)
				fire()
				assert.Len(t, stream.comments(), comments+1, "the heartbeat waited")

				advance(2 * httpsec.StreamReportGrace)
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a read that says gone again does not start the wait over",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				fire := r.manualBeats(5 * time.Second)

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				fire()

				advance(httpsec.StreamReportGrace - 50*time.Millisecond)
				fire()
				r.requireLive(t, stream)

				advance(100 * time.Millisecond)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "a store that fails during the wait does not take back what it said",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				fire := r.manualBeats(5 * time.Second)

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				fire()

				r.failListing(true)
				fire()

				advance(httpsec.StreamReportGrace)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "a signal raised during the wait says nothing ahead of the end",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				_, stream := goneUnreported(t, r)

				r.raiseOnQueue("app.note")
				assert.Empty(t, stream.events("app.note"))

				advance(httpsec.StreamReportGrace)
				r.requireEnded(t, stream, "ended")
				assert.Empty(t, stream.events("app.note"))
			},
		},
		{
			name:  "a signal raised during the wait goes out when the store takes the end back",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				fire := r.manualBeats(5 * time.Second)

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				fire()

				r.raiseOnQueue("app.note")
				assert.Empty(t, stream.events("app.note"))

				r.listsNothing.Store(false)
				fire()

				assert.Len(t, stream.events("app.note"), 1)
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a clock stepped back during the wait holds it for at most two",
			setup: quick,
			assert: func(t *testing.T, r *streamRig) {
				_, stream := goneUnreported(t, r)

				r.clock.offset.Add(int64(-time.Hour))

				advance(2*httpsec.StreamReportGrace + 50*time.Millisecond)
				r.requireEnded(t, stream, "ended")
			},
		},
	})
}

// TestSessionSignals_BusWakeUp_QueueHold pins that a stream holding an end notice whose reload has
// not answered sends nothing from its queue, so that a signal raised just after an end does not
// overtake the session_ended it may have become moot by, and that a hold always ends.
func TestSessionSignals_BusWakeUp_QueueHold(t *testing.T) {
	t.Parallel()

	const firstHeard, secondHeard = "app.first", "app.second"

	heardBoth := []string{"session", firstHeard, secondHeard}

	noBeat := streamSetup{
		idle:    3 * time.Hour,
		signals: httpsec.SessionSignals{Heartbeat: 60 * time.Second, MaxAge: httpsec.NoMaxAge, Signals: endedOnly},
	}

	// The default ReloadTimeout at that heartbeat.
	const reloadTimeout = 10 * time.Second

	runStreamCases(t, []streamCase{
		{
			name:  "a forged end holds the queue until the store says alive, and nothing held is lost",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "logout")
				require.EqualValues(t, 1, held.entered.Load())

				r.raiseOnQueue(firstHeard, secondHeard)
				assert.Equal(t, []string{"session"}, stream.sent(), "a signal overtook the reload")

				held.letGo()
				synctest.Wait()

				assert.Equal(t, heardBoth, stream.sent())
				r.requireLive(t, stream)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "the store saying gone sends session_ended, and what was queued goes with the close",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard, secondHeard)
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))

				held.letGo()
				synctest.Wait()

				assert.Equal(t, []string{"session", "session_ended"}, stream.sent())
				r.requireEnded(t, stream, "logout")
			},
		},
		{
			name:  "a wake within the gap holds the queue until its reload answers, in the order raised",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "")
				advance(100 * time.Millisecond)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard, secondHeard)
				advance(800 * time.Millisecond)
				assert.Equal(t, []string{"session"}, stream.sent(), "the gap let a signal through")

				advance(100 * time.Millisecond)
				assert.Equal(t, heardBoth, stream.sent())
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a read that began before the end does not answer for it",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "")
				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				held.letGo()
				synctest.Wait()
				assert.Equal(t, []string{"session"}, stream.sent(), "a read older than the end released the queue")

				advance(time.Second)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent())
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a failing read releases the queue",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.wakeWith(s, "")
				advance(100 * time.Millisecond)

				r.failListing(true)
				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)
				assert.Equal(t, []string{"session"}, stream.sent())

				advance(900 * time.Millisecond)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "a failed read left the queue held")
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a timed-out read releases the queue",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.honouringStore()
				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				advance(reloadTimeout - time.Millisecond)
				assert.Equal(t, []string{"session"}, stream.sent())

				advance(time.Millisecond)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "a timed-out read left the queue held")
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a store ignoring its context does not hold the queue past the read's timeout",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				advance(reloadTimeout - time.Millisecond)
				assert.Equal(t, []string{"session"}, stream.sent())

				advance(time.Millisecond)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "a hung read left the queue held")
				assert.EqualValues(t, 1, held.entered.Load())

				// Its timeout answered the notice, so its return in the end does not hold again.
				held.letGo()
				synctest.Wait()

				r.raiseOnQueue(secondHeard)
				assert.Equal(t, heardBoth, stream.sent(), "a late return held the queue again")
				r.requireLive(t, stream)
			},
		},
		{
			name:  "an end noted while a read hangs past its timeout holds nothing, for no read can answer it",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "")
				advance(reloadTimeout)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "a hung read held the queue with no end in sight")
				assert.EqualValues(t, 1, held.entered.Load())
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a flood of forged ends does not hold the queue for ever",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				// Every read is overtaken by another notice, so that no read answers the latest.
				hub := httpsec.SignalHubProbeOf(r.chain)
				flood := func(context.Context) error {
					hub.Deliver(httpsec.SignalEnvelope{User: s.UserID, Family: s.FamilyID, Name: string(httpsec.SignalSessionEnded), Reason: "logout"}) //nolint:contextcheck // the hub logs a panic on its own context, detached from any request

					return nil
				}
				r.listHook.Store(&flood)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				advanceUntil(t, 5*time.Second, "the signal behind the flood", func() bool { return len(stream.events(firstHeard)) == 1 })
				r.requireLive(t, stream)

				r.raiseOnQueue(secondHeard)
				assert.Equal(t, heardBoth, stream.sent(), "the flood held the queue again")
			},
		},
		{
			name:  "the store saying alive with no end left unanswered lets the next end hold again",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				// Past the bound on a hold, as a flood takes it.
				hub := httpsec.SignalHubProbeOf(r.chain)
				flood := func(context.Context) error {
					hub.Deliver(httpsec.SignalEnvelope{User: s.UserID, Family: s.FamilyID, Name: string(httpsec.SignalSessionEnded), Reason: "logout"}) //nolint:contextcheck // the hub logs a panic on its own context, detached from any request

					return nil
				}
				r.listHook.Store(&flood)
				r.wakeWith(s, "logout")
				advance(5 * time.Second)

				// The flood stops, and one more read answers everything noted.
				r.listHook.Store(nil)
				advance(2 * time.Second)

				held := r.holdListings(t)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)
				assert.Equal(t, []string{"session"}, stream.sent(), "the end of a flood left the stream unable to hold")

				held.letGo()
				synctest.Wait()
				assert.Equal(t, []string{"session", firstHeard}, stream.sent())
			},
		},
		{
			name:  "a wake with no end notice holds nothing",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "a reason this replica does not know")
				require.EqualValues(t, 1, held.entered.Load())

				r.raiseOnQueue(firstHeard)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "a wake with no end notice held the queue")
				r.requireLive(t, stream)
			},
		},
		{
			name:  "closing during a hold closes with no event",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				r.holdListings(t)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				require.NoError(t, httpsec.SignalHubProbeOf(r.chain).Registry().Close(t.Context()))
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent())
			},
		},
		{
			name:  "a client leaving during a hold closes with no event",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				r.holdListings(t)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				stream.cancel()
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name: "a heartbeat goes out during a hold",
			setup: streamSetup{
				idle:    3 * time.Hour,
				signals: httpsec.SessionSignals{Heartbeat: 10 * time.Second, MaxAge: httpsec.NoMaxAge, Signals: endedOnly},
			},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advanceUntil(t, 12*time.Second, "the first beat", func() bool { return len(stream.comments()) == 1 })

				// The next beat is 9 to 11 seconds after the first, and a read here has 5.
				advance(6 * time.Second)

				held := r.holdListings(t)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)
				advance(5*time.Second - time.Millisecond)

				assert.Len(t, stream.comments(), 2, "the hold stopped the heartbeat")
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.EqualValues(t, 1, held.entered.Load())
			},
		},
		{
			name:  "a reuse notice holds the queue too",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				r.wakeWith(s, "reuse")
				r.raiseOnQueue(firstHeard)
				assert.Equal(t, []string{"session"}, stream.sent(), "a signal overtook the reload a reuse notice asked for")

				held.letGo()
				synctest.Wait()
				assert.Equal(t, []string{"session", firstHeard}, stream.sent())
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a notice noted while a read is overdue holds again once that read returns late",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				overdue := r.holdListings(t)

				r.wakeWith(s, "")
				advance(reloadTimeout)

				// Nothing can answer it while that read hangs, so it holds nothing.
				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent())

				// The late return answers nothing, so the notice holds again, for the read it then starts.
				next := r.holdListings(t)

				overdue.letGo()
				synctest.Wait()
				require.EqualValues(t, 1, next.entered.Load())

				r.raiseOnQueue(secondHeard)
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "a late return answered a notice it never read")

				next.letGo()
				synctest.Wait()
				assert.Equal(t, heardBoth, stream.sent())
				r.requireLive(t, stream)
			},
		},
		{
			name: "MaxAge closes with no event during a hold",
			setup: streamSetup{
				idle:    3 * time.Hour,
				signals: httpsec.SessionSignals{Heartbeat: 60 * time.Second, MaxAge: 2 * time.Minute, Signals: endedOnly},
			},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				// MaxAge lands between 108 and 132 seconds after the open, jittered. A hold is kept
				// up over all of it: each round raises a notice, so that one is always unanswered, and
				// lets the read go only after a second has passed with it held.
				advance(107 * time.Second)

				closedHeld := false

				for range 30 {
					held := r.holdListings(t)

					r.wakeWith(s, "logout")
					r.raiseOnQueue(firstHeard)
					advance(time.Second)

					if stream.closed() {
						closedHeld = true

						break
					}

					held.letGo()
					synctest.Wait()
				}

				assert.True(t, closedHeld, "MaxAge did not close the stream while a notice was unanswered")
				assert.NotContains(t, stream.sent(), "session_ended", "MaxAge said the sign-in ended")
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name:  "a hold ends within two ReloadTimeouts and a wake gap, though each read hangs to its own timeout",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				// A read older than the notice, slow but within its timeout.
				older := r.holdListings(t)

				r.wakeWith(s, "")
				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)

				began := time.Now()

				// It answers just inside its timeout, and the read the notice then gets hangs to its own.
				advance(reloadTimeout - time.Second)

				newer := r.holdListings(t)

				older.letGo()
				synctest.Wait()
				advance(time.Second)
				require.EqualValues(t, 1, newer.entered.Load())

				const bound = 2*reloadTimeout + time.Second

				advance(bound - time.Since(began))
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "held past two ReloadTimeouts and a wake gap, at %s", time.Since(began))
				r.requireLive(t, stream)
			},
		},
		{
			name:  "a flood of forged ends delays the queue across two answered reads, and no more",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				// Every read is overtaken by another notice, so that none answers the latest.
				var reads atomic.Int64

				hub := httpsec.SignalHubProbeOf(r.chain)
				flood := func(context.Context) error {
					reads.Add(1)
					hub.Deliver(httpsec.SignalEnvelope{User: s.UserID, Family: s.FamilyID, Name: string(httpsec.SignalSessionEnded), Reason: "logout"}) //nolint:contextcheck // the hub logs a panic on its own context, detached from any request

					return nil
				}
				r.listHook.Store(&flood)

				r.wakeWith(s, "logout")
				r.raiseOnQueue(firstHeard)
				assert.EqualValues(t, 1, reads.Load())
				assert.Equal(t, []string{"session"}, stream.sent(), "the flood let a signal through after one answered read")

				// The second read opens when the gap after the first does.
				advance(httpsec.StreamWakeGap)
				assert.EqualValues(t, 2, reads.Load())
				assert.Equal(t, []string{"session", firstHeard}, stream.sent(), "the flood held a signal across more than two answered reads")

				r.raiseOnQueue(secondHeard)
				assert.Equal(t, heardBoth, stream.sent())
				r.requireLive(t, stream)
			},
		},
	})
}

// heldRead makes a store's read wait until it is let go, whatever its context says: a store that
// ignores its context, as a consumer's loader is likely to. The test's end lets it go, since a
// bubble cannot end around a goroutine that never returns.
type heldRead struct {
	entered atomic.Int64
	let     chan struct{}
	once    sync.Once
}

// holdListings holds every listing, and what the listing then does is the store's.
func (r *streamRig) holdListings(t *testing.T) *heldRead {
	t.Helper()

	h := &heldRead{let: make(chan struct{})}
	t.Cleanup(h.letGo)

	hook := func(context.Context) error {
		h.entered.Add(1)
		<-h.let

		return nil
	}
	r.listHook.Store(&hook)

	return h
}

// holdUserReads holds every read of the user, which comes after the session store has answered.
func (r *streamRig) holdUserReads(t *testing.T) *heldRead {
	t.Helper()

	h := &heldRead{let: make(chan struct{})}
	t.Cleanup(h.letGo)

	r.userAnswers(func(context.Context) (*identity.Details, error) {
		h.entered.Add(1)
		<-h.let

		return storedUser(), nil
	})

	return h
}

func (h *heldRead) letGo() { h.once.Do(func() { close(h.let) }) }

// waitForRead moves time until the read has begun, which the next heartbeat starts.
func (h *heldRead) waitForRead(t *testing.T) {
	t.Helper()

	advanceUntil(t, 20*time.Second, "the read", func() bool { return h.entered.Load() > 0 })
}

// honouringStore makes every listing wait for its context.
func (r *streamRig) honouringStore() {
	hook := func(ctx context.Context) error {
		<-ctx.Done()

		return ctx.Err()
	}
	r.listHook.Store(&hook)
}

// requireGapsWithin asserts nothing went longer than bound without a byte, from began.
func requireGapsWithin(t *testing.T, s *riggedStream, began time.Time, bound time.Duration) {
	t.Helper()

	last := began

	for _, f := range s.frames() {
		assert.LessOrEqual(t, f.At.Sub(last), bound, "the gap between two bytes")
		last = f.At
	}

	assert.LessOrEqual(t, time.Since(last), bound, "the gap since the last byte")
}

// TestSessionSignals_Heartbeat_ReadInFlight pins that a read runs beside a stream's body and not
// in it: what it holds up is itself, and the store's answer is judged only by the body.
func TestSessionSignals_Heartbeat_ReadInFlight(t *testing.T) {
	t.Parallel()

	noBeat := streamSetup{
		idle:    3 * time.Hour,
		signals: httpsec.SessionSignals{Heartbeat: 60 * time.Second, MaxAge: httpsec.NoMaxAge, Signals: endedOnly},
	}

	runStreamCases(t, []streamCase{
		{
			name: "a store ignoring its context stops neither the heartbeat nor the queue, and no second read starts",
			setup: streamSetup{signals: httpsec.SessionSignals{
				Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
			}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				held := r.holdListings(t)

				held.waitForRead(t)

				beats := len(stream.comments())
				s := httpsec.SignalHubProbeOf(r.chain)

				advance(5 * time.Minute)
				s.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: json.RawMessage(`{"kind":"passkey"}`)})
				synctest.Wait()

				assert.GreaterOrEqual(t, len(stream.comments())-beats, 18, "five minutes of heartbeats")
				assert.Equal(t, []string{"session", "credential_changed"}, stream.sent(), "the queue did not drain")
				assert.EqualValues(t, 1, held.entered.Load(), "a second read started beside the first")
				r.requireLive(t, stream)

				total, inRow := httpsec.SignalReloadCounts(r.chain)
				assert.EqualValues(t, 1, total, "one attempt is one failure")
				assert.EqualValues(t, 1, inRow)
			},
		},
		{
			name:  "a store ignoring its context does not stop MaxAge, and the place is free before the read ends",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxAge: 30 * time.Second, Heartbeat: 5 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				advance(time.Minute)

				assert.True(t, stream.closed(), "MaxAge did not close it")
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Zero(t, r.openStreams(), "the read holds the stream's place")
			},
		},
		{
			name: "a store ignoring its context does not stop a client leaving",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				stream.cancel()
				synctest.Wait()

				assert.True(t, stream.closed(), "a client leaving did not end it")
				assert.Zero(t, r.openStreams())

				total, inRow := httpsec.SignalReloadCounts(r.chain)
				assert.Zero(t, total, "a client that left is not a failure of the store")
				assert.Zero(t, inRow)
			},
		},
		{
			name: "a store ignoring its context does not stop closing, which sends nothing",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				held := r.holdListings(t)

				held.waitForRead(t)

				closed := make(chan error, 1)

				go func() {
					closed <- httpsec.SignalHubProbeOf(r.chain).Registry().Close(context.WithoutCancel(t.Context()))
				}()

				synctest.Wait()

				require.True(t, stream.closed(), "closing waited for the read")
				assert.NoError(t, <-closed)
				assert.Equal(t, []string{"session"}, stream.sent())
			},
		},
		{
			name: "closing pre-empts a read that would honour its context, with no wait for its timeout",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				entered := make(chan struct{}, 1)
				ended := make(chan error, 1)

				hook := func(ctx context.Context) error {
					entered <- struct{}{}
					<-ctx.Done()
					ended <- ctx.Err()

					return ctx.Err()
				}
				r.listHook.Store(&hook)

				advanceUntil(t, 20*time.Second, "the read", func() bool { return len(entered) > 0 })

				closed := make(chan error, 1)

				go func() {
					closed <- httpsec.SignalHubProbeOf(r.chain).Registry().Close(context.WithoutCancel(t.Context()))
				}()

				synctest.Wait()

				require.True(t, stream.closed(), "closing waited for the read")
				assert.NoError(t, <-closed)
				require.Len(t, ended, 1, "the read goes on past its stream")
				assert.ErrorIs(t, <-ended, context.Canceled, "the stream's end did not cancel the read")
			},
		},
		{
			name: "a sign-in found gone by a read that ends after closing sends no session_ended",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				held.waitForRead(t)

				closed := make(chan error, 1)

				go func() {
					closed <- httpsec.SignalHubProbeOf(r.chain).Registry().Close(context.WithoutCancel(t.Context()))
				}()

				synctest.Wait()

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				held.letGo()
				synctest.Wait()

				assert.NoError(t, <-closed)
				assert.Equal(t, []string{"session"}, stream.sent(), "an event after closing")
			},
		},
		{
			name: "an answer waiting when a slow write ends does not outrun closing",
			setup: streamSetup{signals: httpsec.SessionSignals{
				Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
			}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				held.waitForRead(t)

				// A queued signal holds the body in a write, with the read still inside its budget.
				writing := stream.w.holdWrites()

				httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: json.RawMessage(`{"kind":"passkey"}`)})
				synctest.Wait()

				closed := make(chan error, 1)

				go func() {
					closed <- httpsec.SignalHubProbeOf(r.chain).Registry().Close(context.WithoutCancel(t.Context()))
				}()

				synctest.Wait()

				// So the answer, saying gone, and closing are both ready when the write ends.
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				held.letGo()
				synctest.Wait()

				close(writing)
				synctest.Wait()

				assert.NoError(t, <-closed)
				assert.Empty(t, stream.events("session_ended"), "an event after closing")
			},
		},
		{
			name:  "a hang that honours its context does not stretch the gap between bytes",
			setup: streamSetup{signals: httpsec.SessionSignals{Heartbeat: 20 * time.Second, ReloadTimeout: 10 * time.Second, MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				began := time.Now()

				r.honouringStore()
				advance(3 * time.Minute)

				requireGapsWithin(t, stream, began, 22*time.Second)
				assert.GreaterOrEqual(t, len(stream.comments()), 8)
			},
		},
		{
			name:  "a hang that ignores its context does not stretch the gap between bytes",
			setup: streamSetup{signals: httpsec.SessionSignals{Heartbeat: 20 * time.Second, ReloadTimeout: 10 * time.Second, MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				began := time.Now()

				r.holdListings(t)
				advance(3 * time.Minute)

				requireGapsWithin(t, stream, began, 22*time.Second)
				assert.GreaterOrEqual(t, len(stream.comments()), 8)
			},
		},
		{
			name: "a read past its timeout counts at once, logged, while it has yet to return",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				held := r.holdListings(t)

				// The read began within the half-second step that found it.
				advanceUntil(t, 20*time.Second, "the read", func() bool { return held.entered.Load() > 0 })
				advance(6900 * time.Millisecond)

				total, inRow := httpsec.SignalReloadCounts(r.chain)
				require.Zero(t, total, "before the budget of 7.5 s")
				require.Zero(t, inRow)

				advance(600 * time.Millisecond)

				total, inRow = httpsec.SignalReloadCounts(r.chain)
				assert.EqualValues(t, 1, total, "the timeout did not count")
				assert.EqualValues(t, 1, inRow)

				record := streamLogRecord(t, r.logs.String(), "a reload failed")
				assert.Equal(t, true, record["timed_out"])
				r.requireLive(t, stream)
			},
		},
		{
			name: "a late answer is discarded, and the next heartbeat asks again",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				advance(8 * time.Second)

				// The read is past its budget, and this answers "gone" for it.
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				held.letGo()
				synctest.Wait()

				r.requireLive(t, stream)
				assert.Equal(t, []string{"session"}, stream.sent(), "a late answer was acted on")

				advanceUntil(t, 20*time.Second, "the next read's end", stream.closed)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name: "a late answer says nothing of a deadline that moved",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				advance(8 * time.Second)

				r.touch(t, s.ID)
				held.letGo()
				synctest.Wait()

				assert.Len(t, stream.events("session"), 1, "a late answer replaced what the stream holds")

				advanceUntil(t, 20*time.Second, "the next read", func() bool { return len(stream.events("session")) == 2 })
			},
		},
		{
			name: "a beat that wanted a read while one was in flight is served when it returns",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				advance(20 * time.Second)

				require.False(t, stream.closed())

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				held.letGo()
				synctest.Wait()

				advance(httpsec.StreamReportGrace)
				r.requireEnded(t, stream, "ended")
			},
		},
		{
			name:  "a wake during a read is not lost, and is served when the read ends",
			setup: noBeat,
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdUserReads(t)

				r.wakeWith(s, "")
				require.EqualValues(t, 1, held.entered.Load(), "the wake reads at once")

				// The session store has answered "alive" for this read, so only a second read can
				// hear of this.
				advance(2 * time.Second)
				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				r.wakeWith(s, "logout")

				require.EqualValues(t, 1, held.entered.Load(), "a second read started beside the first")
				require.False(t, stream.closed())

				held.letGo()
				synctest.Wait()

				r.requireEnded(t, stream, "logout")
			},
		},
		{
			name:  "a wake during a read a heartbeat started is served when the read ends, and starts no read beside it",
			setup: streamSetup{idle: 3 * time.Hour, signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge, Signals: endedOnly}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)
				held := r.holdUserReads(t)

				held.waitForRead(t)

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))
				r.wakeWith(s, "logout")

				require.EqualValues(t, 1, held.entered.Load(), "a wake started a read beside the first")
				require.False(t, stream.closed())

				held.letGo()
				synctest.Wait()

				r.requireEnded(t, stream, "logout")
			},
		},
		{
			name:  "a hang past the idle deadline stays open, and past the absolute one ends with expired",
			setup: streamSetup{idle: 10 * time.Minute, absolute: time.Hour, signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				opened := time.Now()
				stream := r.open(t, s.ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				advance(30 * time.Minute)
				r.requireLive(t, stream)

				advance(30 * time.Minute)

				r.requireEnded(t, stream, "expired")
				require.NotEmpty(t, stream.events("session_ended"))
				assert.Equal(t, time.Hour, stream.events("session_ended")[0].At.Sub(opened), "it waited for a heartbeat")
				assert.EqualValues(t, 1, held.entered.Load())
			},
		},
		{
			name: "a panic in a read past its timeout is logged, closes the stream and reaches nothing else",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				let := make(chan struct{})

				hook := func(context.Context) error {
					<-let
					panic(fmt.Errorf("store holding %s", streamSecret))
				}
				r.listHook.Store(&hook)

				advance(25 * time.Second)
				close(let)
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Zero(t, r.openStreams())

				record := streamLogRecord(t, r.logs.String(), "panic")
				assert.Equal(t, "reload", record["phase"])
				assert.Contains(t, record["frames"], "httpsec_test")
				assert.NotContains(t, r.logs.String(), streamSecret)
				assert.Contains(t, r.logs.String(), `"reason":"panicked"`)
			},
		},
		{
			name: "a panic in a read after its body has gone is logged, and nothing else happens",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				let := make(chan struct{})
				entered := make(chan struct{}, 1)

				hook := func(context.Context) error {
					entered <- struct{}{}
					<-let
					panic(fmt.Errorf("store holding %s", streamSecret))
				}
				r.listHook.Store(&hook)

				advanceUntil(t, 20*time.Second, "the read", func() bool { return len(entered) > 0 })
				stream.cancel()
				synctest.Wait()
				require.True(t, stream.closed())

				close(let)
				synctest.Wait()

				assert.Equal(t, "reload", streamLogRecord(t, r.logs.String(), "panic")["phase"])
				assert.NotContains(t, r.logs.String(), streamSecret)
			},
		},
		{
			name: "a late answer to a body that has gone blocks nothing",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				held := r.holdListings(t)

				held.waitForRead(t)
				stream.cancel()
				synctest.Wait()
				require.True(t, stream.closed())

				// The read now delivers to no one. A bubble fails on a goroutine that never ends.
				held.letGo()
				synctest.Wait()
			},
		},
		{
			name: "the first read of a store ignoring its context holds the request, and no place",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				held := r.holdListings(t)
				stream := r.open(t, s.ID)

				assert.EqualValues(t, 1, held.entered.Load())
				assert.Zero(t, stream.status(), "the request's answer did not wait")
				assert.Zero(t, r.openStreams(), "a place is held from after the first read")

				advance(time.Minute)
				stream.cancel()
				synctest.Wait()

				assert.False(t, stream.closed(), "a read on the request's path cannot be left behind")

				held.letGo()
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name: "a stream that leaves during failures gives back its share of the failures in a row",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.failListing(true)
				advance(20 * time.Second)

				_, inRow := httpsec.SignalReloadCounts(r.chain)
				require.NotZero(t, inRow)

				stream.cancel()
				synctest.Wait()

				_, inRow = httpsec.SignalReloadCounts(r.chain)
				assert.Zero(t, inRow)
			},
		},
	})
}

// TestSessionSignals_Heartbeat_NothingAfterClosing pins that what is ready when a stream has been
// told to close stays unsent, when a slow write held the body as the close came. The body's select
// would pick among what is ready at random, so a stream that did not look first shows it only some
// of the time, and the rounds make that near certain. A stream that looks is right on every round.
func TestSessionSignals_Heartbeat_NothingAfterClosing(t *testing.T) {
	t.Parallel()

	setup := streamSetup{signals: httpsec.SessionSignals{
		Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
	}}

	for round := range 16 {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, setup)
				stream := r.open(t, r.signIn(t).ID)
				hub := httpsec.SignalHubProbeOf(r.chain)
				signal := httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: json.RawMessage(`{"kind":"passkey"}`)}

				writing := stream.w.holdWrites()

				hub.Deliver(signal)
				synctest.Wait()

				hub.Deliver(signal)
				synctest.Wait()

				closed := make(chan error, 1)

				go func() { closed <- hub.Registry().Close(context.WithoutCancel(t.Context())) }()

				synctest.Wait()
				close(writing)
				synctest.Wait()

				require.True(t, stream.closed())
				assert.NoError(t, <-closed)
				assert.Equal(t, []string{"session", "credential_changed"}, stream.sent(), "a signal after closing")
			})
		})
	}
}

// TestSessionSignals_Heartbeat_AnswerAfterEnding pins that a read's answer a body has already
// taken says nothing, when the stream was told to end before the body got to act on it. A body
// blocked in its select wakes for the first thing that happened, so only a direct call can land
// the second thing between the two.
func TestSessionSignals_Heartbeat_AnswerAfterEnding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		closing bool
		left    bool
		assert  func(t *testing.T, reason string, written string, failures uint64)
	}

	cases := []testCase{
		{
			name:    "after closing it closes, with no event",
			closing: true,
			assert: func(t *testing.T, reason string, written string, _ uint64) {
				assert.Equal(t, "closing", reason)
				assert.Empty(t, written)
			},
		},
		{
			name: "after the client left it closes, with no event and no failure",
			left: true,
			assert: func(t *testing.T, reason string, written string, failures uint64) {
				assert.Equal(t, "client_left", reason)
				assert.Empty(t, written)
				assert.Zero(t, failures)
			},
		},
		{
			name: "with neither it sends what the read found",
			assert: func(t *testing.T, reason string, written string, _ uint64) {
				assert.Equal(t, "session_ended:ended", reason)
				assert.Contains(t, written, "session_ended")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, signalsSetup{})

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tc.left {
				cancel()
			}

			var written bytes.Buffer

			reason := httpsec.StreamAnswer(ctx, f.chain, &bufferEventWriter{&written}, tc.closing)
			failures, _ := httpsec.SignalReloadCounts(f.chain)

			tc.assert(t, reason, written.String(), failures)
		})
	}
}

// bufferEventWriter is an EventWriter that only keeps what it was given.
type bufferEventWriter struct{ io.Writer }

func (*bufferEventWriter) Flush() error { return nil }

// labelledStreamGoroutines counts the goroutines carrying label whose stacks hold what. They
// inherit it from what started them, so that tests running beside this one are not counted.
func labelledStreamGoroutines(t *testing.T, label, what string) int {
	t.Helper()

	var profile bytes.Buffer

	require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))

	count := 0

	for block := range strings.SplitSeq(profile.String(), "\n\n") {
		if !strings.Contains(block, label) || !strings.Contains(block, what) {
			continue
		}

		n, _, _ := strings.Cut(block, " @")

		// The profile's header shares the first block.
		n = n[strings.LastIndexByte(n, '\n')+1:]

		parsed, err := strconv.Atoi(n)
		require.NoError(t, err)

		count += parsed
	}

	return count
}

// realStreams is a chain and a real server on the real clock, for the rows a bubble cannot show.
type realStreams struct {
	sessions *session.Sessions
	chain    *httpsec.Chain
	srv      *httptest.Server
}

func newRealStreams(t *testing.T) *realStreams {
	t.Helper()

	sessions := must.Must(session.New(
		session.WithStore(must.Must(session.NewMemoryStore())),
		session.WithIdleTimeout(30*time.Minute),
		session.WithAbsoluteTimeout(12*time.Hour),
	))

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(storedUser(), nil)

	chain := must.Must(httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionSignals(httpsec.SessionSignals{Heartbeat: 5 * time.Second}),
	))

	srv := httptest.NewServer(chain.Middleware()(http.NotFoundHandler()))
	t.Cleanup(srv.Close)

	return &realStreams{sessions: sessions, chain: chain, srv: srv}
}

// open opens a stream of a new sign-in, whose response's lines arrive on the channel, and returns
// what ends it.
func (r *realStreams) open(t *testing.T) (*session.Session, <-chan string, context.CancelFunc) {
	t.Helper()

	s := must.Must(r.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password)))

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	req := must.Must(http.NewRequestWithContext(ctx, http.MethodGet, r.srv.URL+httpsec.DefaultSessionSignalsPath, nil))
	req.Header.Set("Authorization", "Bearer "+s.ID)

	resp, err := r.srv.Client().Do(req) //nolint:bodyclose // the reading goroutine below closes the body when the stream ends
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	lines := make(chan string, 64)

	go func() {
		defer close(lines)
		defer func() { _ = resp.Body.Close() }()

		body := bufio.NewReader(resp.Body)

		for {
			line, err := body.ReadString('\n')
			if err != nil {
				return
			}

			lines <- strings.TrimSuffix(line, "\n")
		}
	}()

	return s, lines, cancel
}

// nextStreamLine is the next line of a stream, and false once the response ended.
func nextStreamLine(t *testing.T, lines <-chan string) (string, bool) {
	t.Helper()

	select {
	case line, ok := <-lines:
		return line, ok
	case <-time.After(3 * signalsTestBound):
		require.FailNow(t, "the stream sent nothing")

		return "", false
	}
}

// TestSessionSignals_Heartbeat_RealTime runs a stream's life on the real clock over a real
// connection, at the shortest heartbeat: a heartbeat arrives inside its jitter, a client that
// leaves frees its place, and a logout arrives without waiting for the next beat.
func TestSessionSignals_Heartbeat_RealTime(t *testing.T) {
	t.Parallel()

	r := newRealStreams(t)

	s1, lines, _ := r.open(t)
	_, leaving, leave := r.open(t)

	// A stream's first lines are its retry and its session event.
	began := time.Now()

	for {
		line, ok := nextStreamLine(t, lines)
		require.True(t, ok, "the stream closed before its heartbeat")

		if line == ":" {
			break
		}
	}

	beat := time.Since(began)
	t.Logf("a heartbeat after %s", beat)
	assert.GreaterOrEqual(t, beat, 4*time.Second, "the heartbeat came early")

	leave()

	for {
		if _, ok := nextStreamLine(t, leaving); !ok {
			break
		}
	}

	assert.Eventually(t, func() bool {
		open, _ := httpsec.SignalHubProbeOf(r.chain).Registry().Stats()

		return open == 1
	}, signalsTestBound, 10*time.Millisecond, "a client that left still holds its place")

	began = time.Now()

	_, err := r.sessions.Logout(t.Context(), s1.UserID, s1.FamilyID)
	require.NoError(t, err)

	var tail []string

	for {
		line, ok := nextStreamLine(t, lines)
		if !ok {
			break
		}

		tail = append(tail, line)
	}

	t.Logf("the logout's end after %s", time.Since(began))
	assert.Contains(t, tail, "event: session_ended")
	assert.Contains(t, tail, `data: {"reason":"logout"}`)
}

// TestSessionSignals_Heartbeat_GoroutinesPerStream pins what an open stream costs beyond its
// body: no goroutine watching the request's context, which is what a context that hides its
// parent's cancellation costs where a parent offers no AfterFunc.
func TestSessionSignals_Heartbeat_GoroutinesPerStream(t *testing.T) {
	t.Parallel()

	label := "stream-goroutines-" + t.Name()
	pprof.SetGoroutineLabels(pprof.WithLabels(t.Context(), pprof.Labels("stream-test", label)))

	defer pprof.SetGoroutineLabels(t.Context())

	r := newRealStreams(t)

	const streams = 4

	var drained sync.WaitGroup

	for range streams {
		_, lines, _ := r.open(t)

		// The first event has arrived, so that the body is running.
		for {
			line, ok := nextStreamLine(t, lines)
			require.True(t, ok)

			if line == "event: session" {
				break
			}
		}

		drained.Go(func() {
			for range lines { //nolint:revive // the response's lines are of no interest here
			}
		})
	}

	assert.Equal(t, streams, labelledStreamGoroutines(t, label, "runStream"), "a body per stream")
	assert.Zero(t, labelledStreamGoroutines(t, label, "propagateCancel"), "a goroutine watching each request's context")
	t.Logf("server goroutines per stream: %d", labelledStreamGoroutines(t, label, "net/http.(*conn).serve")/streams)
}

// TestSessionSignals_Heartbeat_Queue pins what goes through a stream's queue.
func TestSessionSignals_Heartbeat_Queue(t *testing.T) {
	t.Parallel()

	withCredentials := httpsec.SessionSignals{Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged}}

	runStreamCases(t, []streamCase{
		{
			name:  "credential_changed and a consumer's signal go out unchanged, and flushed",
			setup: streamSetup{signals: withCredentials},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				hub := httpsec.SignalHubProbeOf(r.chain)

				r.act(func() {
					hub.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: json.RawMessage(`{"kind":"passkey"}`)})
				})
				r.act(func() {
					hub.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "app.roles_changed", Data: json.RawMessage(`{"roles":["editor"]}`)})
				})

				assert.Equal(t, []string{"session", "credential_changed", "app.roles_changed"}, stream.sent())
				require.NotEmpty(t, stream.events("credential_changed"))
				require.NotEmpty(t, stream.events("app.roles_changed"))
				assert.JSONEq(t, `{"kind":"passkey"}`, stream.events("credential_changed")[0].Data)
				assert.Equal(t, `{"roles":["editor"]}`, stream.events("app.roles_changed")[0].Data)
				assert.Zero(t, stream.unflushed())
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "an event the writer refuses is logged with sampling and skipped, and the stream goes on",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				registry := httpsec.SignalHubProbeOf(r.chain).Registry()

				r.act(func() { registry.DeliverSignal("u-1", "app.bad", "{\n}") })
				r.act(func() { registry.DeliverSignal("u-1", "app.good", "{}") })

				assert.Equal(t, []string{"session", "app.good"}, stream.sent())
				assert.Contains(t, r.logs.String(), "event was refused")
				r.requireLive(t, stream)
			},
		},
		{
			name: "a failed write of a queued signal ends the stream",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				stream.w.failWrite.Store(true)
				r.act(func() {
					httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "app.x", Data: json.RawMessage(`{}`)})
				})

				assert.True(t, stream.closed())
				assert.Zero(t, r.openStreams())
			},
		},
	})
}

// TestSessionSignals_DeadlineMoved pins the session event a later check sends.
func TestSessionSignals_DeadlineMoved(t *testing.T) {
	t.Parallel()

	sessionData := func(t *testing.T, f streamFrame) map[string]any {
		t.Helper()

		var data map[string]any

		require.NoError(t, json.Unmarshal([]byte(f.Data), &data))

		return data
	}

	runStreamCases(t, []streamCase{
		{
			name: "activity elsewhere sends a session event with the new idle deadline within a heartbeat",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(time.Minute)
				r.touch(t, s.ID)
				moved := r.stored(t, s.ID).IdleExpiresAt

				advanceUntil(t, 17*time.Second, "a session event", func() bool { return len(stream.events("session")) == 2 })

				require.Len(t, stream.events("session"), 2)

				data := sessionData(t, stream.events("session")[1])
				assert.Equal(t, moved.UTC().Format(time.RFC3339Nano), data["idle_deadline"])
				r.requireLive(t, stream)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a beat that finds the sign-in moved sends its comment and then the session event",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(time.Second)
				r.touch(t, s.ID)

				before := len(stream.comments())

				advanceUntil(t, 17*time.Second, "a session event", func() bool { return len(stream.events("session")) == 2 })
				require.Len(t, stream.comments(), before+1, "a beat's comment does not wait for what its read finds")
				assert.True(t, stream.comments()[before].At.Equal(stream.events("session")[1].At), "the read came at the beat")
			},
		},
		{
			name: "a re-authentication sends a session event with the new time",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(time.Minute)
				next := r.reauthenticate(t, s, time.Now())

				advanceUntil(t, 17*time.Second, "a session event", func() bool { return len(stream.events("session")) == 2 })

				data := sessionData(t, stream.events("session")[1])
				assert.Equal(t, next.AuthenticatedAt.UTC().Format(time.RFC3339Nano), data["authenticated_at"])
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "nothing moved sends none",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				advance(2 * time.Minute)

				assert.Len(t, stream.events("session"), 1)
			},
		},
		{
			name: "a wake that finds a moved deadline says so without waiting for a beat",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(time.Second)
				r.touch(t, s.ID)
				r.wakeWith(s, "logout")

				assert.Len(t, stream.events("session"), 2)
				r.requireLive(t, stream)
			},
		},
		{
			name: "a session event carries the three values and nothing upstream, at open and later",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t, session.WithExternalSession("provider", "https://idp.example", "upstream-sid", "raw-id-token"))
				stream := r.open(t, s.ID)

				advance(time.Second)
				r.touch(t, s.ID)
				advance(17 * time.Second)

				require.Len(t, stream.events("session"), 2)

				for _, f := range stream.events("session") {
					data := sessionData(t, f)
					assert.Len(t, data, 3, f.Data)
					assert.Contains(t, data, "idle_deadline")
					assert.Contains(t, data, "absolute_deadline")
					assert.Contains(t, data, "authenticated_at")
					assert.NotContains(t, f.Data, "upstream-sid")
					assert.NotContains(t, f.Data, "idp.example")
				}
			},
		},
	})
}

// TestSessionSignals_Expiring_Speak pins what a stream's held state says is due.
func TestSessionSignals_Expiring_Speak(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	rules := httpsec.StreamRules{Warning: 2 * time.Minute}
	held := func(idle, absolute time.Duration) httpsec.HeldSignIn {
		return httpsec.HeldSignIn{State: session.SignInState{IdleDeadline: now.Add(idle), AbsoluteDeadline: now.Add(absolute)}}
	}

	warning := func(deadline string, at time.Time) string {
		return `{"deadline":"` + deadline + `","at":"` + at.UTC().Format(time.RFC3339Nano) + `"}`
	}

	type testCase struct {
		name   string
		rules  httpsec.StreamRules
		held   httpsec.HeldSignIn
		assert func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn)
	}

	nothing := func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn) {
		t.Helper()

		assert.Empty(t, events)
		assert.Empty(t, left.Warned)
	}

	cases := []testCase{
		{name: "outside the window nothing is due", rules: rules, held: held(3*time.Minute, time.Hour), assert: nothing},
		{
			name:  "inside the window warns, naming the idle deadline",
			rules: rules,
			held:  held(90*time.Second, time.Hour),
			assert: func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn) {
				require.Len(t, events, 1)
				assert.Equal(t, "session_expiring", events[0].Name)
				assert.JSONEq(t, warning("idle", now.Add(90*time.Second)), events[0].Data)
				assert.Equal(t, "idle", left.Warned)
			},
		},
		{
			name:  "the window's first instant warns",
			rules: rules,
			held:  held(2*time.Minute, time.Hour),
			assert: func(t *testing.T, events []httpsec.StreamEvent, _ httpsec.HeldSignIn) {
				assert.Len(t, events, 1)
			},
		},
		{
			name:  "a consumer's window names the absolute deadline",
			rules: httpsec.StreamRules{Warning: 5 * time.Minute},
			held:  held(time.Hour, 4*time.Minute),
			assert: func(t *testing.T, events []httpsec.StreamEvent, _ httpsec.HeldSignIn) {
				require.Len(t, events, 1)
				assert.JSONEq(t, warning("absolute", now.Add(4*time.Minute)), events[0].Data)
			},
		},
		{
			name:  "equal deadlines name absolute",
			rules: rules,
			held:  held(time.Minute, time.Minute),
			assert: func(t *testing.T, events []httpsec.StreamEvent, _ httpsec.HeldSignIn) {
				require.Len(t, events, 1)
				assert.JSONEq(t, warning("absolute", now.Add(time.Minute)), events[0].Data)
			},
		},
		{
			name:  "already warned is not warned again in the same window",
			rules: rules,
			held: func() httpsec.HeldSignIn {
				h := held(time.Minute, time.Hour)
				h.Warned = "idle"

				return h
			}(),
			assert: func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn) {
				assert.Empty(t, events)
				assert.Equal(t, "idle", left.Warned)
			},
		},
		{
			name:  "moved out of the window forgets the warning",
			rules: rules,
			held: func() httpsec.HeldSignIn {
				h := held(10*time.Minute, time.Hour)
				h.Warned = "idle"

				return h
			}(),
			assert: nothing,
		},
		{
			name:  "activity capping the idle deadline at the absolute warns again, naming the one that cannot move",
			rules: rules,
			held: func() httpsec.HeldSignIn {
				h := held(time.Minute, time.Minute)
				h.Warned = "idle"

				return h
			}(),
			assert: func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn) {
				require.Len(t, events, 1)
				assert.Contains(t, events[0].Data, `"absolute"`)
				assert.Equal(t, "absolute", left.Warned)
			},
		},
		{name: "with no window, that is, not in the stream's set, nothing warns", held: held(time.Second, time.Hour), assert: nothing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			events, left := tc.rules.Speak(tc.held, now)
			tc.assert(t, events, left)
		})
	}
}

// TestSessionSignals_Expiring_NextSpeech pins what the one timer is armed for: the earliest of
// what has not been sent, strictly after now, so that nothing already past can spin it. What is
// past is the next heartbeat's to look at.
func TestSessionSignals_Expiring_NextSpeech(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	window := 2 * time.Minute
	auth := now.Add(-10 * time.Minute)

	type testCase struct {
		name   string
		rules  httpsec.StreamRules
		held   httpsec.HeldSignIn
		assert func(t *testing.T, at time.Time)
	}

	armedAt := func(want time.Time) func(t *testing.T, at time.Time) {
		return func(t *testing.T, at time.Time) {
			t.Helper()

			assert.True(t, want.Equal(at), "armed for %s, want %s", at, want)
		}
	}

	state := func(idle, absolute time.Duration) session.SignInState {
		return session.SignInState{IdleDeadline: now.Add(idle), AbsoluteDeadline: now.Add(absolute), AuthenticatedAt: auth}
	}

	cases := []testCase{
		{
			name:   "the warning comes first",
			rules:  httpsec.StreamRules{Warning: window},
			held:   httpsec.HeldSignIn{State: state(30*time.Minute, time.Hour)},
			assert: armedAt(now.Add(28 * time.Minute)),
		},
		{
			name:   "with the warning sent, the deadline",
			rules:  httpsec.StreamRules{Warning: window},
			held:   httpsec.HeldSignIn{State: state(time.Minute, time.Hour), Warned: "idle"},
			assert: armedAt(now.Add(time.Minute)),
		},
		{
			name:   "with no warning wanted, the deadline",
			held:   httpsec.HeldSignIn{State: state(30*time.Minute, time.Hour)},
			assert: armedAt(now.Add(30 * time.Minute)),
		},
		{
			name:   "the lapse when it is earliest",
			rules:  httpsec.StreamRules{Warning: window, Assurance: 15 * time.Minute},
			held:   httpsec.HeldSignIn{State: state(30*time.Minute, time.Hour)},
			assert: armedAt(auth.Add(15 * time.Minute)),
		},
		{
			name:   "a lapse already sent for this authentication is not armed",
			rules:  httpsec.StreamRules{Assurance: 15 * time.Minute},
			held:   httpsec.HeldSignIn{State: state(30*time.Minute, time.Hour), LapsedFor: auth},
			assert: armedAt(now.Add(30 * time.Minute)),
		},
		{
			name:  "a zero authentication time is not armed",
			rules: httpsec.StreamRules{Assurance: 15 * time.Minute},
			held: httpsec.HeldSignIn{State: session.SignInState{
				IdleDeadline: now.Add(30 * time.Minute), AbsoluteDeadline: now.Add(time.Hour),
			}},
			assert: armedAt(now.Add(30 * time.Minute)),
		},
		{
			name:   "a warning already past is not armed, and the deadline is",
			rules:  httpsec.StreamRules{Warning: window},
			held:   httpsec.HeldSignIn{State: state(time.Minute, time.Hour)},
			assert: armedAt(now.Add(time.Minute)),
		},
		{
			name:   "the idle deadline already past leaves the absolute deadline armed, which an outage still needs",
			held:   httpsec.HeldSignIn{State: state(-time.Minute, time.Hour)},
			assert: armedAt(now.Add(time.Hour)),
		},
		{
			name:   "the idle deadline exactly now is past",
			held:   httpsec.HeldSignIn{State: state(0, time.Hour)},
			assert: armedAt(now.Add(time.Hour)),
		},
		{
			name: "every deadline past arms nothing, so it cannot spin",
			held: httpsec.HeldSignIn{State: state(-time.Hour, -time.Minute)},
			assert: func(t *testing.T, at time.Time) {
				assert.True(t, at.IsZero(), "armed for %s", at)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.rules.NextSpeech(tc.held, now))
		})
	}
}

// TestSessionSignals_Expiring pins the timer on a running stream.
func TestSessionSignals_Expiring(t *testing.T) {
	t.Parallel()

	runStreamCases(t, []streamCase{
		{
			name: "the idle deadline warns once, at its window, and the timer reloaded first",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				opened := time.Now()
				stream := r.open(t, s.ID)

				advance(27*time.Minute + 59*time.Second)
				require.Empty(t, stream.events("session_expiring"))

				lists := r.lists.Load()
				beats := len(stream.comments())

				advance(2 * time.Second)

				warned := stream.events("session_expiring")
				require.Len(t, warned, 1)
				assert.Equal(t, 28*time.Minute, warned[0].At.Sub(opened))
				assert.JSONEq(t, `{"deadline":"idle","at":"`+s.IdleExpiresAt.UTC().Format(time.RFC3339Nano)+`"}`, warned[0].Data)
				assert.Greater(t, r.lists.Load()-lists, int64(len(stream.comments())-beats), "the timer did not reload before it spoke")

				advance(90 * time.Second)
				assert.Len(t, stream.events("session_expiring"), 1)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a consumer's window is used, and names the absolute deadline",
			setup: streamSetup{idle: 2 * time.Hour, absolute: 30 * time.Minute, signals: httpsec.SessionSignals{ExpiryWarning: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				opened := time.Now()
				stream := r.open(t, s.ID)

				advance(26 * time.Minute)

				warned := stream.events("session_expiring")
				require.Len(t, warned, 1)
				assert.Equal(t, 25*time.Minute, warned[0].At.Sub(opened))
				assert.Contains(t, warned[0].Data, `"deadline":"absolute"`)
			},
		},
		{
			name:  "equal deadlines name absolute",
			setup: streamSetup{idle: 30 * time.Minute, absolute: 30 * time.Minute},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				advance(29 * time.Minute)

				warned := stream.events("session_expiring")
				require.Len(t, warned, 1)
				assert.Contains(t, warned[0].Data, `"deadline":"absolute"`)
			},
		},
		{
			name: "a deadline already inside the window at open warns at once, after the first event",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				advance(29 * time.Minute)

				stream := r.open(t, s.ID)

				assert.Equal(t, []string{"session", "session_expiring"}, stream.sent())
			},
		},
		{
			name:  "activity after a warning moves the deadline, sends a session event, and does not end at the old one",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(28*time.Minute + time.Second)
				require.Len(t, stream.events("session_expiring"), 1)

				r.touch(t, s.ID)
				advance(3 * time.Minute)

				r.requireLive(t, stream)
				assert.Len(t, stream.events("session"), 2)
				assert.Len(t, stream.events("session_expiring"), 1, "still outside the window")

				// It comes back into the window, and warns again.
				advance(26 * time.Minute)
				assert.Len(t, stream.events("session_expiring"), 2)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a warning timer that finds the deadline moved does not warn",
			setup: streamSetup{signals: httpsec.SessionSignals{Heartbeat: time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(27*time.Minute + 59*time.Second)
				r.touch(t, s.ID)
				advance(2 * time.Second)

				assert.Empty(t, stream.events("session_expiring"), "the timer spoke from a stale deadline")
			},
		},
		{
			name:  "activity one second before the deadline leaves the stream open, with a session event",
			setup: streamSetup{signals: httpsec.SessionSignals{Signals: endedOnly, Heartbeat: time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(30*time.Minute - time.Second)
				r.touch(t, s.ID)
				advance(2 * time.Second)

				r.requireLive(t, stream)
				assert.Len(t, stream.events("session"), 2, "the timer reloaded and found it moved")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a chain's clock ahead of a manager on its own clock stays open, and reloads only at heartbeats",
			setup: streamSetup{signals: httpsec.SessionSignals{Signals: endedOnly}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.clock.offset.Store(int64(31 * time.Minute))
				advance(17 * time.Second)

				lists, beats := r.lists.Load(), len(stream.comments())

				advance(5 * time.Minute)

				r.requireLive(t, stream)
				assert.Equal(t, int64(len(stream.comments())-beats), r.lists.Load()-lists, "a read between heartbeats")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a clock ahead, shared with the manager, says expired, as that manager refuses the session too",
			setup: streamSetup{sameClock: true, signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(20 * time.Minute)
				r.clock.offset.Store(int64(11 * time.Minute))
				advance(20 * time.Second)

				r.requireEnded(t, stream, "expired")

				r.act(func() {
					_, err := r.sessions.Load(t.Context(), s.ID)
					require.ErrorIs(t, err, session.ErrExpired, "that replica refuses the session as well")
				})
			},
		},
		{
			name: "a clock stepped forward is corrected at the next reload",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.clock.offset.Store(int64(28*time.Minute + 30*time.Second))
				advance(17 * time.Second)

				assert.Len(t, stream.events("session_expiring"), 1)
				r.requireLive(t, stream)
			},
		},
		{
			name: "a clock stepped back is corrected at the next reload",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.clock.offset.Store(int64(-10 * time.Minute))
				advance(17 * time.Second)

				lists, beats := r.lists.Load(), len(stream.comments())

				// The timer was armed for 28 minutes on, and by this clock that is now 38. A timer
				// the step did not re-arm would read the store at 28, between two heartbeats.
				advance(29 * time.Minute)

				assert.Equal(t, int64(len(stream.comments())-beats), r.lists.Load()-lists, "the timer was not re-armed by the step")
				assert.Empty(t, stream.events("session_expiring"))
			},
		},
		{
			name:  "the idle deadline during an outage leaves the stream open, with no warning",
			setup: streamSetup{absolute: 2 * time.Hour, signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.failListing(true)
				advance(45 * time.Minute)

				r.requireLive(t, stream)
				assert.Empty(t, stream.events("session_expiring"), "a warning from a store it cannot read")
				assert.Greater(t, len(stream.comments()), 100)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "an outage that lasts until the absolute deadline ends the stream with expired",
			setup: streamSetup{absolute: time.Hour, signals: httpsec.SessionSignals{MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				opened := time.Now()
				stream := r.open(t, s.ID)

				r.failListing(true)
				advance(59*time.Minute + 59*time.Second)
				r.requireLive(t, stream)

				advance(2 * time.Second)

				r.requireEnded(t, stream, "expired")
				require.NotEmpty(t, stream.events("session_ended"))
				assert.Equal(t, time.Hour, stream.events("session_ended")[0].At.Sub(opened), "it waited for a heartbeat")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "an outage of the user store alone does not end the stream at a deadline the session store moved",
			setup: streamSetup{signals: httpsec.SessionSignals{Signals: endedOnly, Heartbeat: time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { return nil, errors.New("down") })

				advance(10 * time.Minute)
				r.touch(t, s.ID)
				advance(25 * time.Minute)

				r.requireLive(t, stream)
				assert.GreaterOrEqual(t, len(stream.events("session")), 2, "the session store's answer stands")
			},
		},
		{
			name:  "narrowed away, no warning is sent",
			setup: streamSetup{},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID, "signals=session_ended")

				advance(29 * time.Minute)

				assert.Empty(t, stream.events("session_expiring"))
			},
		},
		{
			name:  "with session_expiring not in the set, no warning is sent",
			setup: streamSetup{signals: httpsec.SessionSignals{Signals: endedOnly}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				advance(29 * time.Minute)

				assert.Equal(t, []string{"session"}, stream.sent())
			},
		},
	})
}

// TestSessionSignals_AssuranceLapsed_Speak pins when the lapse is due.
func TestSessionSignals_AssuranceLapsed_Speak(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	rules := httpsec.StreamRules{Assurance: 15 * time.Minute}
	authenticated := now.Add(-15 * time.Minute)
	state := func(auth time.Time) session.SignInState {
		return session.SignInState{IdleDeadline: now.Add(time.Hour), AbsoluteDeadline: now.Add(2 * time.Hour), AuthenticatedAt: auth}
	}

	type testCase struct {
		name   string
		rules  httpsec.StreamRules
		held   httpsec.HeldSignIn
		assert func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn)
	}

	nothing := func(t *testing.T, events []httpsec.StreamEvent, _ httpsec.HeldSignIn) {
		t.Helper()

		assert.Empty(t, events)
	}

	cases := []testCase{
		{name: "inside the window nothing is due", rules: rules, held: httpsec.HeldSignIn{State: state(now.Add(-14 * time.Minute))}, assert: nothing},
		{
			name:  "the window passing lapses, naming the time",
			rules: rules,
			held:  httpsec.HeldSignIn{State: state(authenticated)},
			assert: func(t *testing.T, events []httpsec.StreamEvent, left httpsec.HeldSignIn) {
				require.Len(t, events, 1)
				assert.Equal(t, "assurance_lapsed", events[0].Name)
				assert.JSONEq(t, `{"authenticated_at":"`+authenticated.UTC().Format(time.RFC3339Nano)+`"}`, events[0].Data)
				assert.True(t, authenticated.Equal(left.LapsedFor))
			},
		},
		{name: "once per authentication", rules: rules, held: httpsec.HeldSignIn{State: state(authenticated), LapsedFor: authenticated}, assert: nothing},
		{
			name:  "a new authentication may lapse again",
			rules: rules,
			held:  httpsec.HeldSignIn{State: state(authenticated), LapsedFor: authenticated.Add(-time.Hour)},
			assert: func(t *testing.T, events []httpsec.StreamEvent, _ httpsec.HeldSignIn) {
				assert.Len(t, events, 1)
			},
		},
		{name: "a zero time never lapses", rules: rules, held: httpsec.HeldSignIn{State: state(time.Time{})}, assert: nothing},
		{name: "with no window, that is, not in the stream's set, nothing lapses", held: httpsec.HeldSignIn{State: state(authenticated)}, assert: nothing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			events, left := tc.rules.Speak(tc.held, now)
			tc.assert(t, events, left)
		})
	}
}

// TestSessionSignals_AssuranceLapsed pins the lapse on a running stream.
func TestSessionSignals_AssuranceLapsed(t *testing.T) {
	t.Parallel()

	lapsing := []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalAssuranceLapsed}

	runStreamCases(t, []streamCase{
		{
			name:  "the default fifteen minutes, once",
			setup: streamSetup{assurance: true, signals: httpsec.SessionSignals{Signals: lapsing}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				opened := time.Now()
				stream := r.open(t, s.ID)

				advance(14*time.Minute + 59*time.Second)
				require.Empty(t, stream.events("assurance_lapsed"))

				advance(10 * time.Minute)

				lapsed := stream.events("assurance_lapsed")
				require.Len(t, lapsed, 1)
				assert.Equal(t, 15*time.Minute, lapsed[0].At.Sub(opened))
				assert.JSONEq(t, `{"authenticated_at":"`+s.AuthenticatedAt.UTC().Format(time.RFC3339Nano)+`"}`, lapsed[0].Data)
				r.requireLive(t, stream)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a consumer's five minutes",
			setup: streamSetup{assurance: true, signals: httpsec.SessionSignals{Signals: lapsing, AssuranceWindow: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				opened := time.Now()

				advance(6 * time.Minute)

				lapsed := stream.events("assurance_lapsed")
				require.Len(t, lapsed, 1)
				assert.Equal(t, 5*time.Minute, lapsed[0].At.Sub(opened))
			},
		},
		{
			name:  "re-proved, a session event, and later one more",
			setup: streamSetup{assurance: true, idle: 3 * time.Hour, signals: httpsec.SessionSignals{Signals: lapsing, AssuranceWindow: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(6 * time.Minute)
				require.Len(t, stream.events("assurance_lapsed"), 1)

				r.reauthenticate(t, s, time.Now())
				advance(20 * time.Second)
				assert.Len(t, stream.events("session"), 2)
				assert.Len(t, stream.events("assurance_lapsed"), 1, "a re-authentication is not a lapse")

				advance(5 * time.Minute)
				assert.Len(t, stream.events("assurance_lapsed"), 2)

				advance(10 * time.Minute)
				assert.Len(t, stream.events("assurance_lapsed"), 2)
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "a zero AuthenticatedAt states null and never lapses",
			setup: streamSetup{assurance: true, idle: 3 * time.Hour, signals: httpsec.SessionSignals{Signals: lapsing, AssuranceWindow: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				next := r.reauthenticate(t, r.signIn(t), time.Time{})
				stream := r.open(t, next.ID)

				advance(30 * time.Minute)

				require.NotEmpty(t, stream.events("session"))
				assert.Contains(t, stream.events("session")[0].Data, `"authenticated_at":null`)
				assert.Empty(t, stream.events("assurance_lapsed"))
			},
		},
		{
			name:  "a window already passed at open is sent at once, after the first event",
			setup: streamSetup{assurance: true, signals: httpsec.SessionSignals{Signals: lapsing, AssuranceWindow: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				advance(6 * time.Minute)

				stream := r.open(t, s.ID)

				assert.Equal(t, []string{"session", "assurance_lapsed"}, stream.sent())
			},
		},
		{
			name:  "during an outage the lapse waits for the store, since a re-proof may have moved it",
			setup: streamSetup{assurance: true, signals: httpsec.SessionSignals{Signals: lapsing, AssuranceWindow: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.failListing(true)
				advance(6 * time.Minute)
				require.Empty(t, stream.events("assurance_lapsed"))

				r.failListing(false)
				advance(17 * time.Second)
				assert.Len(t, stream.events("assurance_lapsed"), 1)
			},
		},
		{
			name:  "not in the stream's narrowing",
			setup: streamSetup{assurance: true, signals: httpsec.SessionSignals{Signals: lapsing, AssuranceWindow: 5 * time.Minute}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID, "signals=session_ended")

				advance(10 * time.Minute)

				assert.Empty(t, stream.events("assurance_lapsed"))
			},
		},
		{
			name: "not in the chain's set",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				advance(20 * time.Minute)

				assert.Empty(t, stream.events("assurance_lapsed"))
			},
		},
	})
}

// TestSessionSignals_IdleTab is a tab left open: nothing but the stream reaches the sign-in.
func TestSessionSignals_IdleTab(t *testing.T) {
	t.Parallel()

	runStreamCases(t, []streamCase{
		{
			name: "the sign-in reaches its idle deadline, warned first, and ends with expired",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				opened := time.Now()
				stream := r.open(t, s.ID)
				before := r.stored(t, s.ID)

				advance(29 * time.Minute)
				assert.Equal(t, before, r.stored(t, s.ID), "the stream recorded activity, or moved a deadline")

				advanceUntil(t, 2*time.Minute, "the end", stream.closed)

				assert.Equal(t, []string{"session", "session_expiring", "session_ended"}, stream.sent())
				r.requireEnded(t, stream, "expired")
				require.NotEmpty(t, stream.events("session_ended"))
				assert.LessOrEqual(t, stream.events("session_ended")[0].At.Sub(opened), 30*time.Minute+17*time.Second)

				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name: "a reconnection after that is refused",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advanceUntil(t, 31*time.Minute, "the end", stream.closed)

				assert.Equal(t, http.StatusUnauthorized, r.open(t, s.ID).status())
			},
		},
	})
}

// TestSessionSignals_EndedAlwaysSent pins session_ended whatever the set and the narrowing say.
func TestSessionSignals_EndedAlwaysSent(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		signals httpsec.SessionSignals
		query   string
		assert  func(t *testing.T, r *streamRig, stream *riggedStream)
	}

	ended := func(t *testing.T, r *streamRig, stream *riggedStream) {
		t.Helper()

		r.requireEnded(t, stream, "all_ended")
	}

	cases := []testCase{
		{name: "narrowed away", query: "signals=session_expiring", assert: ended},
		{name: "an empty parameter keeps only what is always sent", query: "signals=", assert: ended},
		{name: "not in the chain's set", signals: httpsec.SessionSignals{Signals: []httpsec.Signal{httpsec.SignalSessionExpiring}}, assert: ended},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{signals: tc.signals})
				s := r.signIn(t)
				stream := r.open(t, s.ID, tc.query)

				r.act(func() { require.NoError(t, r.sessions.DeleteByUser(t.Context(), s.UserID)) })

				tc.assert(t, r, stream)
			})
		})
	}
}

// TestSessionSignals_MaxAge pins a stream closing so that it is judged again.
func TestSessionSignals_MaxAge(t *testing.T) {
	t.Parallel()

	long := func(s httpsec.SessionSignals) streamSetup {
		s.Signals = endedOnly

		return streamSetup{idle: 3 * time.Hour, signals: s}
	}

	runStreamCases(t, []streamCase{
		{
			name:  "the default hour, with its jitter, closes with no event and frees its place",
			setup: long(httpsec.SessionSignals{}),
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				lived := advanceUntil(t, 67*time.Minute, "the close", stream.closed)

				assert.GreaterOrEqual(t, lived, 54*time.Minute)
				assert.LessOrEqual(t, lived, 66*time.Minute+time.Second)
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.Zero(t, r.openStreams())
				assert.Contains(t, r.logs.String(), "max_age")
				r.requireHarmless(t, 0, 0)
			},
		},
		{
			name:  "each stream draws its own jitter",
			setup: long(httpsec.SessionSignals{}),
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				streams := make([]*riggedStream, 4)
				for i := range streams {
					streams[i] = r.open(t, s.ID)
				}

				lived := map[time.Duration]bool{}
				began := time.Now()
				closedSeen := map[int]bool{}

				advanceUntil(t, 67*time.Minute, "every close", func() bool {
					for i, stream := range streams {
						if stream.closed() && !closedSeen[i] {
							closedSeen[i] = true
							lived[time.Since(began)] = true
						}
					}

					return len(closedSeen) == len(streams)
				})

				assert.Greater(t, len(lived), 1)
			},
		},
		{
			name:  "a consumer's value",
			setup: long(httpsec.SessionSignals{MaxAge: 10 * time.Minute}),
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				lived := advanceUntil(t, 12*time.Minute, "the close", stream.closed)

				assert.GreaterOrEqual(t, lived, 9*time.Minute)
				assert.LessOrEqual(t, lived, 11*time.Minute+time.Second)
				assert.Equal(t, []string{"session"}, stream.sent())
			},
		},
		{
			name:  "NoMaxAge stays open until the sign-in ends",
			setup: streamSetup{idle: 12 * time.Hour, signals: httpsec.SessionSignals{Signals: endedOnly, MaxAge: httpsec.NoMaxAge}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				advance(11*time.Hour + 59*time.Minute)
				r.requireLive(t, stream)

				advanceUntil(t, 2*time.Minute, "the end", stream.closed)
				r.requireEnded(t, stream, "expired")
			},
		},
		{
			name:  "it also bounds an outage",
			setup: long(httpsec.SessionSignals{MaxAge: 10 * time.Minute}),
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.failListing(true)
				advanceUntil(t, 12*time.Minute, "the close", stream.closed)

				assert.Equal(t, []string{"session"}, stream.sent())
			},
		},
		{
			name:  "a place freed at MaxAge can be taken again",
			setup: long(httpsec.SessionSignals{MaxAge: 10 * time.Minute, MaxPerSignIn: 1}),
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advanceUntil(t, 12*time.Minute, "the close", stream.closed)

				again := r.open(t, s.ID)
				assert.Equal(t, http.StatusOK, again.status())
				assert.Equal(t, 1, r.openStreams())
			},
		},
	})
}

// TestSessionSignals_WireFormat_Endpoint pins the bytes of a real stream.
func TestSessionSignals_WireFormat_Endpoint(t *testing.T) {
	t.Parallel()

	runStreamCases(t, []streamCase{
		{
			name: "the first bytes are retry and then the session event, flushed together",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				frames := stream.frames()
				require.Len(t, frames, 2)
				assert.Zero(t, stream.unflushed())

				assert.Equal(t, "retry", frames[0].Kind)

				ms, err := strconv.Atoi(frames[0].Data)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, ms, 3500)
				assert.LessOrEqual(t, ms, 6500)

				assert.Equal(t, "session", frames[1].Name)
				assert.JSONEq(t, fmt.Sprintf(`{"idle_deadline":%q,"absolute_deadline":%q,"authenticated_at":%q}`,
					s.IdleExpiresAt.UTC().Format(time.RFC3339Nano),
					s.AbsoluteExpiresAt.UTC().Format(time.RFC3339Nano),
					s.AuthenticatedAt.UTC().Format(time.RFC3339Nano)), frames[1].Data)
			},
		},
		{
			name:  "a consumer's ReconnectDelay is used, differing across streams within the spread",
			setup: streamSetup{signals: httpsec.SessionSignals{ReconnectDelay: 10 * time.Second, MaxPerSignIn: 16}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				seen := map[string]bool{}

				for range 16 {
					stream := r.open(t, s.ID)
					require.NotEmpty(t, stream.frames())

					retry := stream.frames()[0]
					require.Equal(t, "retry", retry.Kind)

					ms, err := strconv.Atoi(retry.Data)
					require.NoError(t, err)
					assert.GreaterOrEqual(t, ms, 7000)
					assert.LessOrEqual(t, ms, 13000)

					seen[retry.Data] = true
				}

				assert.Greater(t, len(seen), 1, "every stream said the same delay")
			},
		},
		{
			name: "heartbeats are comments, and nothing is an id",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				advance(time.Minute)
				r.touch(t, s.ID)
				advance(20 * time.Second)

				require.NotEmpty(t, stream.comments())

				for _, f := range stream.frames() {
					assert.NotContains(t, f.Kind, "malformed")
				}
			},
		},
		{
			name: "a stream's response carries the stream's headers",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				assert.Equal(t, http.StatusOK, stream.status())
				assert.Equal(t, "text/event-stream", stream.w.Header().Get("Content-Type"))
				assert.Equal(t, "no-store, no-transform", stream.w.Header().Get("Cache-Control"))
				assert.Equal(t, "no", stream.w.Header().Get("X-Accel-Buffering"))
			},
		},
	})
}

// TestSessionSignals_Narrowing_Endpoint pins what a client's narrowing does to a real stream.
func TestSessionSignals_Narrowing_Endpoint(t *testing.T) {
	t.Parallel()

	many := "signals=" + strings.Repeat("a,", 16) + "a"

	type testCase struct {
		name    string
		signals httpsec.SessionSignals
		query   string
		assert  func(t *testing.T, stream *riggedStream)
	}

	wantsNoExpiring := func(t *testing.T, stream *riggedStream) {
		t.Helper()

		assert.Empty(t, stream.events("session_expiring"))
		assert.Empty(t, stream.events("credential_changed"))
		assert.Empty(t, stream.events("app.roles"))
		assert.Equal(t, http.StatusOK, stream.status())
	}

	cases := []testCase{
		{name: "narrowed to session_ended", query: "signals=session_ended", assert: wantsNoExpiring},
		{name: "an empty parameter sends only what is always sent", query: "signals=", assert: wantsNoExpiring},
		{name: "a widening name is ignored", query: "signals=credential_changed", assert: wantsNoExpiring},
		{name: "a malformed name is dropped", query: "signals=app.BAD%0Aevent:x", assert: wantsNoExpiring},
		{
			name: "no parameter is the chain's set",
			assert: func(t *testing.T, stream *riggedStream) {
				assert.Len(t, stream.events("session_expiring"), 1)
				assert.Len(t, stream.events("app.roles"), 1)
				assert.Empty(t, stream.events("credential_changed"), "not in the chain's set")
			},
		},
		{
			name:  "a client names its own consumer signal",
			query: "signals=app.roles",
			assert: func(t *testing.T, stream *riggedStream) {
				assert.Len(t, stream.events("app.roles"), 1)
				assert.Empty(t, stream.events("session_expiring"))
			},
		},
		{
			name:  "17 names is 400",
			query: many,
			assert: func(t *testing.T, stream *riggedStream) {
				assert.Equal(t, http.StatusBadRequest, stream.status())
				assert.Empty(t, stream.frames())
			},
		},
		{
			name:  "more than 256 bytes across repeated parameters is 400",
			query: "signals=" + strings.Repeat("a", 200) + "&signals=" + strings.Repeat("b", 100),
			assert: func(t *testing.T, stream *riggedStream) {
				assert.Equal(t, http.StatusBadRequest, stream.status())
				assert.Empty(t, stream.frames())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{signals: tc.signals})
				stream := r.open(t, r.signIn(t).ID, tc.query)

				if stream.status() == http.StatusOK {
					hub := httpsec.SignalHubProbeOf(r.chain)
					r.act(func() {
						hub.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: json.RawMessage(`{"kind":"password"}`)})
						hub.Deliver(httpsec.SignalEnvelope{User: "u-1", Name: "app.roles", Data: json.RawMessage(`{}`)})
					})
					advance(29 * time.Minute)
				}

				tc.assert(t, stream)
			})
		})
	}
}

// TestSessionSignals_Heartbeat_Admission pins the first read reading the user too, one budget for
// the two, on a real connection.
func TestSessionSignals_Heartbeat_Admission(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) signalsSetup
		open   func(t *testing.T, f *signalsFixture) *http.Response
		assert func(t *testing.T, f *signalsFixture, resp *http.Response)
	}

	loader := func(t *testing.T, fn func(ctx context.Context) (*identity.Details, error)) *MockUserLoader {
		t.Helper()

		users := NewMockUserLoader(gomock.NewController(t))
		users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(ctx context.Context, _ identity.UserID) (*identity.Details, error) { return fn(ctx) })

		return users
	}

	openFor := func(t *testing.T, f *signalsFixture) *http.Response {
		t.Helper()

		resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

		return resp
	}

	// answerCheck is a row's assertion on the response it opened. It is a named type so that a
	// call returning one is not mistaken for a call returning a response.
	type answerCheck func(t *testing.T, f *signalsFixture, resp *http.Response)

	refused := func(status int) answerCheck {
		return func(t *testing.T, f *signalsFixture, resp *http.Response) {
			t.Helper()

			requireNoStream(t, resp, status)

			open, _ := httpsec.SignalHubProbeOf(f.chain).Registry().Stats()
			assert.Zero(t, open)
		}
	}

	answeredRetry := func(t *testing.T, f *signalsFixture, resp *http.Response) {
		t.Helper()

		requireOnlyRetryResponse(t, resp, busyLeast, busyMost)

		open, _ := httpsec.SignalHubProbeOf(f.chain).Registry().Stats()
		assert.Zero(t, open)
	}

	cases := []testCase{
		{
			name: "a disabled user is 401, on a consumer's Users",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{signals: httpsec.SessionSignals{Users: loader(t, func(context.Context) (*identity.Details, error) {
					return inactiveUser(), nil
				})}}
			},
			open:   openFor,
			assert: refused(http.StatusUnauthorized),
		},
		{
			name: "a disabled user on a consumer's cookie authenticator is 401",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{
					withoutBearer: true,
					signals: httpsec.SessionSignals{Users: loader(t, func(context.Context) (*identity.Details, error) {
						return inactiveUser(), nil
					})},
					opts: func(f *signalsFixture) []httpsec.Option {
						return []httpsec.Option{
							httpsec.WithSessions(f.sessions),
							httpsec.WithoutCSRFProtection(),
							httpsec.RegisterInterceptor(consumerSessionCookie{sessions: f.sessions}, httpsec.OrderBearerToken),
						}
					},
				}
			},
			open: func(t *testing.T, f *signalsFixture) *http.Response {
				t.Helper()

				resp, _ := f.openStream(t, "", withSignalsCookie(f.signIn(t, "u-1").ID))

				return resp
			},
			assert: refused(http.StatusUnauthorized),
		},
		{
			name: "a user who is not found is 401",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{signals: httpsec.SessionSignals{Users: loader(t, func(context.Context) (*identity.Details, error) {
					return nil, identity.ErrUserNotFound
				})}}
			},
			open:   openFor,
			assert: refused(http.StatusUnauthorized),
		},
		{
			name: "a tenant-scoped user store with no hook opens no stream, and is a dependency failure",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{signals: httpsec.SessionSignals{Users: loader(t, func(ctx context.Context) (*identity.Details, error) {
					if ctx.Value(signalsTenantKey{}) == nil {
						return nil, errors.New("no tenant on the read")
					}

					return storedUser(), nil
				})}, wrapHandler: withSignalsTenant}
			},
			open:   openFor,
			assert: answeredRetry,
		},
		{
			name: "a tenant-scoped session store with no hook opens no stream, and is a dependency failure",
			setup: func(*testing.T) signalsSetup {
				return signalsSetup{
					wrap: func(s session.Store) session.Store {
						return &listSpyStore{Store: s, fail: func() error { return errors.New("no tenant on the read") }}
					},
					wrapHandler: withSignalsTenant,
				}
			},
			open:   openFor,
			assert: answeredRetry,
		},
		{
			name: "the first read of the user is bounded by the same budget, on a context with none of the request's values",
			setup: func(t *testing.T) signalsSetup {
				t.Helper()

				return signalsSetup{signals: httpsec.SessionSignals{
					ReloadTimeout: 3 * time.Second,
					Users: loader(t, func(ctx context.Context) (*identity.Details, error) {
						deadline, ok := ctx.Deadline()
						if !ok || time.Until(deadline) > 3*time.Second {
							return nil, errors.New("the user read is outside the budget")
						}

						if ctx.Value(signalsTenantKey{}) != nil {
							return nil, errors.New("the user read holds the request's values")
						}

						return storedUser(), nil
					}),
				}, wrapHandler: withSignalsTenant}
			},
			open: openFor,
			assert: func(t *testing.T, _ *signalsFixture, resp *http.Response) {
				t.Helper()

				requireStreamHead(t, resp)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, tc.setup(t))

			tc.assert(t, f, tc.open(t, f)) //nolint:bodyclose // open is f.openStream, which closes the body when the test ends
		})
	}
}

// endedContextWriter runs a stream's body on a context that has already ended, as fiber does when
// the chain refused after Stream, and records what it wrote.
type endedContextWriter struct {
	*stubWriter

	wrote strings.Builder
}

func (w *endedContextWriter) Write(p []byte) (int, error) { return w.wrote.Write(p) }

func (*endedContextWriter) Flush() error { return nil }

func (w *endedContextWriter) Stream(ctx context.Context, body func(context.Context, httpsec.EventWriter) error) error {
	ended, cancel := context.WithCancel(ctx)
	cancel()

	return body(ended, w)
}

// TestSessionSignals_Heartbeat_EndedBody pins a body on a context that has ended: it writes
// nothing, and what it holds is freed.
func TestSessionSignals_Heartbeat_EndedBody(t *testing.T) {
	t.Parallel()

	f := newSignalsFixture(t, signalsSetup{})
	s := f.signIn(t, "u-1")
	w := &endedContextWriter{stubWriter: &stubWriter{}}

	require.NoError(t, f.chain.Assemble(func(*httpsec.Exchange) error { return nil })(httpsec.NewExchange(t.Context(), stubRequest{
		method:   http.MethodGet,
		path:     httpsec.DefaultSessionSignalsPath,
		clientIP: streamClient,
		headers:  map[string]string{"Authorization": "Bearer " + s.ID},
	}, w)))

	assert.Empty(t, w.wrote.String())

	open, _ := httpsec.SignalHubProbeOf(f.chain).Registry().Stats()
	assert.Zero(t, open)
}

// TestSessionSignals_Heartbeat_HubStarts pins that a consumer's bus starts with the first stream.
func TestSessionSignals_Heartbeat_HubStarts(t *testing.T) {
	t.Parallel()

	subscribed := make(chan struct{})

	bus := NewMockSignalBus(gomock.NewController(t))
	bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ func(httpsec.SignalEnvelope)) error {
			close(subscribed)
			<-ctx.Done()

			return ctx.Err()
		})

	f := newSignalsFixture(t, signalsSetup{signals: httpsec.SessionSignals{Bus: bus}})

	t.Cleanup(httpsec.SignalHubProbeOf(f.chain).Close)

	select {
	case <-subscribed:
		require.FailNow(t, "the bus started before anyone used it")
	default:
	}

	resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
	requireStreamHead(t, resp)

	select {
	case <-subscribed:
	case <-time.After(signalsTestBound):
		require.FailNow(t, "the first stream did not start the bus")
	}
}

// TestSessionSignals_Heartbeat_Panic drives a real connection, since what a panic must never
// reach is the server's own log of it.
func TestSessionSignals_Heartbeat_Panic(t *testing.T) {
	t.Parallel()

	panicking := func() { panic(fmt.Errorf("loader holding %s", streamSecret)) }

	type rig struct {
		logs       *lockedBuffer
		reachedTop atomic.Pointer[any]
		clock      *streamClock
		arm        atomic.Bool
		disarm     func()
	}

	type testCase struct {
		name   string
		setup  func(t *testing.T, g *rig) signalsSetup
		trip   func(t *testing.T, f *signalsFixture, g *rig, sid string)
		assert func(t *testing.T, f *signalsFixture, g *rig, sid string)
	}

	listens := func(g *rig, s signalsSetup) signalsSetup {
		inner := s.opts
		s.opts = func(f *signalsFixture) []httpsec.Option {
			opts := []httpsec.Option{httpsec.WithLogger(slog.New(slog.NewJSONHandler(g.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))}
			if inner != nil {
				opts = append(opts, inner(f)...)
			}

			return opts
		}
		s.wrapHandler = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if v := recover(); v != nil {
						g.reachedTop.Store(&v)
					}
				}()

				next.ServeHTTP(w, r)
			})
		}

		return s
	}

	wake := func(t *testing.T, f *signalsFixture, g *rig, _ string) {
		t.Helper()

		g.arm.Store(true)
		httpsec.SignalHubProbeOf(f.chain).Deliver(httpsec.SignalEnvelope{
			User: "u-1", Name: string(httpsec.SignalSessionEnded),
		})
	}

	phaseIs := func(phase string) func(t *testing.T, f *signalsFixture, g *rig, sid string) {
		return func(t *testing.T, f *signalsFixture, g *rig, _ string) {
			t.Helper()

			f.waitDone(t)

			record := streamLogRecord(t, g.logs.String(), "panic")
			assert.Equal(t, phase, record["phase"])
			assert.Equal(t, "*errors.errorString", panicTypeOf(record), "the value's type")
			assert.NotEmpty(t, record["family"])
			assert.Contains(t, record["frames"], "httpsec_test")

			assert.NotContains(t, g.logs.String(), streamSecret, "a log holds the panic's value")
			assert.Nil(t, g.reachedTop.Load(), "the panic reached what is above the chain")

			open, _ := httpsec.SignalHubProbeOf(f.chain).Registry().Stats()
			assert.Zero(t, open, "the place was not freed")

			// The process runs on, and so does the chain.
			g.disarm()

			resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
			requireStreamHead(t, resp)
		}
	}

	cases := []testCase{
		{
			name: "a consumer's user loader, on a reload",
			setup: func(t *testing.T, g *rig) signalsSetup {
				t.Helper()

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
					func(context.Context, identity.UserID) (*identity.Details, error) {
						if g.arm.Load() {
							panicking()
						}

						return storedUser(), nil
					})

				return listens(g, signalsSetup{signals: httpsec.SessionSignals{Users: users}})
			},
			trip:   wake,
			assert: phaseIs("reload"),
		},
		{
			name: "a consumer's session store, on a reload",
			setup: func(_ *testing.T, g *rig) signalsSetup {
				return listens(g, signalsSetup{wrap: func(s session.Store) session.Store {
					return &listSpyStore{Store: s, see: func(context.Context) {
						if g.arm.Load() {
							panicking()
						}
					}}
				}})
			},
			trip:   wake,
			assert: phaseIs("reload"),
		},
		{
			name: "the stream's own code",
			setup: func(_ *testing.T, g *rig) signalsSetup {
				return listens(g, signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.WithClock(g.clock)}
				}})
			},
			trip: func(t *testing.T, f *signalsFixture, g *rig, _ string) {
				t.Helper()

				g.clock.armed.Store(true)

				// Queued, so the panic is the stream's own and on no reload: the loop reads the
				// clock when it next re-arms, and the wake does that.
				httpsec.SignalHubProbeOf(f.chain).Registry().DeliverEndToUser("u-1", [16]byte{}, "", time.Time{})
			},
			assert: phaseIs("stream"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := &rig{logs: &lockedBuffer{}, clock: &streamClock{}}
			g.disarm = func() {
				g.arm.Store(false)
				g.clock.armed.Store(false)
			}

			f := newSignalsFixture(t, tc.setup(t, g))
			s := f.signIn(t, "u-1")

			resp, _ := f.openStream(t, s.ID)
			requireStreamHead(t, resp)
			readStreamLines(t, resp.Body, 4)

			tc.trip(t, f, g, s.ID)
			tc.assert(t, f, g, s.ID)
		})
	}

	t.Run("a consumer's loader at the first read", func(t *testing.T) {
		t.Parallel()

		g := &rig{logs: &lockedBuffer{}, clock: &streamClock{}}
		g.arm.Store(true)

		users := NewMockUserLoader(gomock.NewController(t))
		users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(context.Context, identity.UserID) (*identity.Details, error) {
				if g.arm.Load() {
					panicking()
				}

				return storedUser(), nil
			})

		f := newSignalsFixture(t, listens(g, signalsSetup{signals: httpsec.SessionSignals{Users: users}}))

		resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

		requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
		assert.Nil(t, g.reachedTop.Load(), "the panic reached what is above the chain")
		assert.NotContains(t, g.logs.String(), streamSecret)
		assert.Equal(t, "reload", streamLogRecord(t, g.logs.String(), "panic")["phase"])

		open, _ := httpsec.SignalHubProbeOf(f.chain).Registry().Stats()
		assert.Zero(t, open)
	})
}

// panicTypeOf is a panic record's type attribute.
func panicTypeOf(record map[string]any) string {
	got, _ := record["panic_type"].(string)

	return got
}

// readStreamLines reads n lines from a stream's body, bounded, and returns them.
func readStreamLines(t *testing.T, body io.Reader, n int) []string {
	t.Helper()

	type answer struct {
		lines []string
		err   error
	}

	got := make(chan answer, 1)

	go func() {
		r := bufio.NewReader(body)

		var lines []string

		for range n {
			line, err := r.ReadString('\n')
			if err != nil {
				got <- answer{lines, err}

				return
			}

			lines = append(lines, strings.TrimSuffix(line, "\n"))
		}

		got <- answer{lines, nil}
	}()

	select {
	case a := <-got:
		require.NoError(t, a.err)

		return a.lines
	case <-time.After(signalsTestBound):
		require.FailNow(t, "the stream sent nothing")

		return nil
	}
}

// TestSessionSignals_Heartbeat_OverARealConnection drives one stream's whole life through a real
// server on the fixture's fake clock: the first bytes, a heartbeat, a logout on another request,
// the end, and the reconnection.
func TestSessionSignals_Heartbeat_OverARealConnection(t *testing.T) {
	t.Parallel()

	f := newSignalsFixture(t, signalsSetup{})
	s := f.signIn(t, "u-1")

	resp, _ := f.openStream(t, s.ID)
	requireStreamHead(t, resp)

	lines := make(chan string, 64)

	go func() {
		defer close(lines)

		r := bufio.NewReader(resp.Body)

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}

			lines <- strings.TrimSuffix(line, "\n")
		}
	}()

	next := func() (string, bool) {
		select {
		case line, ok := <-lines:
			return line, ok
		case <-time.After(signalsTestBound):
			require.FailNow(t, "the stream sent nothing")

			return "", false
		}
	}

	line, _ := next()
	assert.True(t, strings.HasPrefix(line, "retry: "), line)

	line, _ = next()
	assert.Empty(t, line)

	line, _ = next()
	assert.Equal(t, "event: session", line)

	line, _ = next()
	assert.True(t, strings.HasPrefix(line, `data: {"idle_deadline":`), line)

	line, _ = next()
	assert.Empty(t, line)

	require.NoError(t, f.clk.BlockUntilContext(t.Context(), 2))
	f.clk.Advance(17 * time.Second)

	line, _ = next()
	assert.Equal(t, ":", line, "the heartbeat")

	line, _ = next()
	assert.Empty(t, line)

	_, err := f.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
	require.NoError(t, err)

	line, _ = next()
	assert.Equal(t, "event: session_ended", line)

	line, _ = next()
	assert.Equal(t, `data: {"reason":"logout"}`, line)

	line, _ = next()
	assert.Empty(t, line)

	_, open := next()
	assert.False(t, open, "the response did not end")

	f.waitDone(t)

	stats, _ := httpsec.SignalHubProbeOf(f.chain).Registry().Stats()
	assert.Zero(t, stats)

	again, _ := f.openStream(t, s.ID)
	requireNoStream(t, again, http.StatusUnauthorized)
}

// TestSessionSignals_MaxAge_SignedBearer is the expired token itself: a verifier that stops
// accepting it, with the sign-in still live.
func TestSessionSignals_MaxAge_SignedBearer(t *testing.T) {
	t.Parallel()

	var expired atomic.Bool

	verifier := NewMockVerifier(gomock.NewController(t))
	verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, presented string) (*token.Claims, error) {
			if expired.Load() {
				return nil, token.ErrInvalid
			}

			return token.NewClaims("u-1", presented), nil
		})

	synctest.Test(t, func(t *testing.T) {
		r := newStreamRig(t, streamSetup{
			idle:                 3 * time.Hour,
			withoutSessionBearer: true,
			signals:              httpsec.SessionSignals{Signals: endedOnly, MaxAge: 10 * time.Minute},
			opts: func(r *streamRig) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: verifier, Sessions: r.sessions, Users: r.users,
				})}
			},
		})

		s := r.signIn(t)
		stream := r.open(t, s.ID)
		require.Equal(t, http.StatusOK, stream.status())

		expired.Store(true)

		lived := advanceUntil(t, 12*time.Minute, "the close", stream.closed)
		assert.GreaterOrEqual(t, lived, 9*time.Minute, "the stream outlived its token, until its age")
		assert.Equal(t, []string{"session"}, stream.sent())

		again := r.open(t, s.ID)
		assert.Equal(t, http.StatusUnauthorized, again.status())
		assert.Empty(t, again.frames())
	})
}
