package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// signalsFixture is a chain with the signal stream enabled, on a fake clock and a memory
// session store, behind a real server, because a recorder has no client to lose and no
// response that stays open.
type signalsFixture struct {
	clk      *clockwork.FakeClock
	store    session.Store
	sessions *session.Sessions
	users    *MockUserLoader
	chain    *httpsec.Chain
	server   *httptest.Server

	// done receives once each time the server's handler for a request returns, which is
	// how a test sees a stream has ended on the server, with no sleep.
	done chan struct{}
}

// signalsSetup is what a test may vary about the fixture.
type signalsSetup struct {
	// signals is the stream's configuration. Default: the zero value, every default.
	signals httpsec.SessionSignals

	// withoutSignals leaves the stream off.
	withoutSignals bool

	// withoutBearer leaves the session bearer off.
	withoutBearer bool

	// wrap decorates the session store.
	wrap func(session.Store) session.Store

	// sessionOpts are added to the session manager's options.
	sessionOpts []session.Option

	// opts are added to the chain's options.
	opts func(f *signalsFixture) []httpsec.Option

	// wrapHandler wraps the chain's handler, as a consumer's middleware does.
	wrapHandler func(http.Handler) http.Handler
}

// newSignalsFixture builds the fixture. Its session bearer reads users through a mock that
// answers storedUser for "u-1" any number of times, until a test sets another expectation
// on f.users before calling it through wrap or opts.
func newSignalsFixture(t *testing.T, setup signalsSetup) *signalsFixture {
	t.Helper()

	f := &signalsFixture{
		clk:  clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)),
		done: make(chan struct{}, 64),
	}

	f.store = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk)))
	if setup.wrap != nil {
		f.store = setup.wrap(f.store)
	}

	var err error

	f.sessions, err = session.New(append([]session.Option{
		session.WithClock(f.clk),
		session.WithStore(f.store),
		session.WithIdleTimeout(30 * time.Minute),
		session.WithAbsoluteTimeout(12 * time.Hour),
	}, setup.sessionOpts...)...)
	require.NoError(t, err)

	f.users = NewMockUserLoader(gomock.NewController(t))
	f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	opts := []httpsec.Option{httpsec.WithClock(f.clk)}
	if !setup.withoutBearer {
		opts = append(opts, httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: f.users}))
	}

	if !setup.withoutSignals {
		if setup.withoutBearer && setup.signals.Users == nil {
			setup.signals.Users = f.users
		}

		opts = append(opts, httpsec.EnableSessionSignals(setup.signals))
	}

	if setup.opts != nil {
		opts = append(opts, setup.opts(f)...)
	}

	f.chain, err = httpsec.New(opts...)
	require.NoError(t, err)

	var handler http.Handler = f.chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(signalsDownstreamStatus)
	}))
	if setup.wrapHandler != nil {
		handler = setup.wrapHandler(handler)
	}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { f.done <- struct{}{} }()

		handler.ServeHTTP(w, r)
	}))

	// A stream's response stays open, so the bound can only be on its head, and a stream
	// that never sends one fails its test rather than hanging it.
	transport, ok := f.server.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport.ResponseHeaderTimeout = signalsTestBound

	// Close waits for every handler, so a stream that does not hear its client leave would
	// otherwise hang the test binary. The test's context has ended by now.
	t.Cleanup(func() { requireReturns(t, f.server.Close) })

	return f
}

// signalsTestBound is how long a test waits for what must happen promptly, so a stream that
// fails to end fails its test instead of hanging the binary.
const signalsTestBound = 10 * time.Second

// requireReturns fails the test if fn has not returned within signalsTestBound.
func requireReturns(t *testing.T, fn func()) {
	t.Helper()

	returned := make(chan struct{})

	go func() {
		defer close(returned)

		fn()
	}()

	select {
	case <-returned:
	case <-time.After(signalsTestBound):
		require.FailNow(t, "what should have returned promptly did not")
	}
}

// signalsDownstreamStatus is what the application's own route answers, so a test can tell
// a request that passed through the chain from one an endpoint answered.
const signalsDownstreamStatus = http.StatusTeapot

// signIn stores a new sign-in of user, with a first factor and a recent authentication.
func (f *signalsFixture) signIn(t *testing.T, user identity.UserID) *session.Session {
	t.Helper()

	s, err := f.sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s
}

// send sends method on target to the server, presenting credential as a session reference
// when it is not empty. change, when given, adjusts the request first. The response's body
// is closed when the test ends, which is how a stream it opened is left.
func (f *signalsFixture) send(
	t *testing.T, ctx context.Context, method, target, credential string, change ...func(*http.Request),
) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, method, f.server.URL+target, nil)
	require.NoError(t, err)

	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}

	for _, c := range change {
		c(req)
	}

	resp, err := f.server.Client().Do(req)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

// openStream asks for the stream at its default path on a context the test can end, and
// returns the response and that context's cancel.
func (f *signalsFixture) openStream(
	t *testing.T, credential string, change ...func(*http.Request),
) (*http.Response, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	return f.send(t, ctx, http.MethodGet, httpsec.DefaultSessionSignalsPath, credential, change...), cancel
}

// waitDone waits for one request's handler to have returned on the server.
func (f *signalsFixture) waitDone(t *testing.T) {
	t.Helper()

	select {
	case <-f.done:
	case <-time.After(signalsTestBound):
		require.FailNow(t, "the server's handler did not return")
	}
}

// requireOpen asserts no request's handler returns while it watches, for a stream that
// must stay open. It can only pass wrongly, never fail wrongly: a stream that ends at once
// has returned by the time its head is read.
func (f *signalsFixture) requireOpen(t *testing.T) {
	t.Helper()

	select {
	case <-f.done:
		require.FailNow(t, "the stream's handler returned while the stream should be open")
	case <-time.After(50 * time.Millisecond):
	}
}

// storedSession reads a session straight from the store, which judges nothing.
func (f *signalsFixture) storedSession(t *testing.T, id string) *session.Session {
	t.Helper()

	s, err := f.store.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}
