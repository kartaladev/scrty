package httpsec_test

// The tests below are separate functions where their setup differs in shape:
// TestSwitchActiveRole_RunEndWaitsForSwitch and
// TestSwitchActiveRole_QueuedSwitchGivesUp each hold a switch inside its
// rotation behind a barrier, with goroutines of their own, while
// TestSwitchActiveRole_AfterHandlerReturned is a table of switches made once
// the handler has returned, on one request each.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// runEndGrace is how long TestSwitchActiveRole_RunEndWaitsForSwitch gives the
// run to end on its own while the switch is held inside its rotation. A run
// that ends inside it ended before the switch, which fails the test; a run
// that waits for the switch reaches it and is then released. It decides
// nothing on correct code, which passes whatever its length.
const runEndGrace = 250 * time.Millisecond

// queuedGiveUpBound is how long TestSwitchActiveRole_QueuedSwitchGivesUp
// waits for a queued switch whose context is cancelled to return while the
// switch ahead of it is held. A switch that honours its context returns at
// once; one that waits for the lock regardless returns only once the test
// releases the first switch, after this bound, and fails.
const queuedGiveUpBound = 2 * time.Second

// eventLog records, in order, what happened on the goroutines of a test.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.events = append(l.events, e)
}

func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.events...)
}

// heldRotation is a barrier around a store's superseding write: the first
// write signals entered and waits for release (bounded by raceTimeout, so a
// failing run never hangs), and every write is counted. A second write does
// not wait, and closes nothing twice.
type heldRotation struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	writes  atomic.Int32
	log     *eventLog
}

func holdRotation(w *switchCookieWorld, log *eventLog) *heldRotation {
	h := &heldRotation{entered: make(chan struct{}), release: make(chan struct{}), log: log}

	w.store.onSupersede = func(_ context.Context, write func() error) error {
		h.writes.Add(1)

		first := false
		h.once.Do(func() {
			first = true

			close(h.entered)
		})

		if first {
			select {
			case <-h.release:
			case <-time.After(raceTimeout):
				// Never reached on a passing run; it keeps a failing one
				// from hanging the suite.
			}
		}

		err := write()

		if h.log != nil {
			h.log.add("rotated")
		}

		return err
	}

	return h
}

// afterNext is what an interceptor registered after the session's resolution
// saw once the handler had returned to it.
type afterNext struct {
	mu        sync.Mutex
	sessionID string
	hasCtx    bool
}

// TestSwitchActiveRole_RunEndWaitsForSwitch pins that a role switch on a
// cookie chain started before its request's handler returns completes before
// that return does: the handler starts the switch on a goroutine of its own
// and returns while the switch is held inside the store's rotating write. An
// interceptor after the handler then reads the request's session and context
// and sets a response header; it runs only once the switch has stored its
// rotation and set the cookie, so it sees the successor, races nothing, and
// the response carries the successor's identifier. That holds whether the
// interceptor is on the switching chain or on another chain whose run is the
// switching chain's handler, on the same exchange.
func TestSwitchActiveRole_RunEndWaitsForSwitch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// mount places after, the interceptor that runs after the handler:
		// it returns the options the switching chain is built with and wraps
		// the consumer's handler into the switching chain's terminal.
		mount func(t *testing.T, after httpsec.Interceptor) ([]httpsec.Option, func(httpsec.Next) httpsec.Next)
		// ownExchange is set when after runs on an exchange of its own,
		// which resolved no session, so it has no session to see.
		ownExchange bool
	}{
		{
			name: "interceptor on the switching chain",
			mount: func(_ *testing.T, after httpsec.Interceptor) ([]httpsec.Option, func(httpsec.Next) httpsec.Next) {
				return []httpsec.Option{httpsec.RegisterInterceptor(after, httpsec.OrderSessionTouch)},
					func(h httpsec.Next) httpsec.Next { return h }
			},
		},
		{
			name: "interceptor on a chain nested inside it",
			mount: func(t *testing.T, after httpsec.Interceptor) ([]httpsec.Option, func(httpsec.Next) httpsec.Next) {
				inner, err := httpsec.New(httpsec.RegisterInterceptor(after, httpsec.Order(100)))
				require.NoError(t, err)

				return nil, inner.Assemble
			},
		},
		{
			// Two stacked adapter mounts (Middleware, ginsec, fibersec) each
			// build an exchange of their own over the same request and
			// writer: the inner chain, which cannot switch roles itself, runs
			// on a new exchange whose context is the switching run's.
			name: "interceptor on a chain nested inside it, on an exchange of its own",
			mount: func(t *testing.T, after httpsec.Interceptor) ([]httpsec.Option, func(httpsec.Next) httpsec.Next) {
				inner, err := httpsec.New(httpsec.RegisterInterceptor(after, httpsec.Order(100)))
				require.NoError(t, err)

				return nil, func(h httpsec.Next) httpsec.Next {
					run := inner.Assemble(h)

					return func(ex *httpsec.Exchange) error {
						return run(httpsec.NewExchange(ex.Context(), ex.Request, ex.Writer))
					}
				}
			},
			ownExchange: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var log eventLog

			var seen afterNext

			after := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				err := next(ex)

				log.add("after next")

				seen.mu.Lock()
				if ex.Session != nil {
					seen.sessionID = ex.Session.ID
				}
				seen.hasCtx = ex.Context() != nil
				seen.mu.Unlock()

				ex.Writer.SetHeader("X-After", "1")

				return err
			})

			opts, wrap := tc.mount(t, after)
			w := newSwitchCookieWorld(t, opts...)

			held := holdRotation(w, &log)

			switchDone := make(chan struct{})

			var switched error

			req := sessionCookieRequest(t.Context(), http.MethodPost, named(w.signIn.ID),
				map[string]string{"X-CSRF-Token": w.signIn.CSRFToken})
			out := served{rec: httptest.NewRecorder()}

			run := w.chain.Assemble(wrap(func(ex *httpsec.Exchange) error {
				out.handlerRan = true
				ctx := ex.Context()

				go func() {
					defer close(switchDone)

					switched = w.chain.SwitchActiveRole(ctx, "audit")
				}()

				// The handler returns once the switch is inside its rotation,
				// before the rotation is stored.
				select {
				case <-held.entered:
				case <-time.After(raceTimeout):
				}

				return nil
			}))

			runDone := make(chan struct{})

			// setCookies is the response's Set-Cookie lines as the run left
			// them, read on the run's goroutine as it returns, so a switch
			// still writing after the run cannot put its cookie there in time
			// for the assertion.
			var setCookies []string

			go func() {
				defer close(runDone)

				out.err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))
				setCookies = slices.Clone(out.rec.Header().Values("Set-Cookie"))

				log.add("run ended")
			}()

			await(t, held.entered, "the switch to enter its rotation")

			// The run is given the chance to end on its own; one that waits
			// for the switch does not, and is released at the end of the
			// grace.
			select {
			case <-runDone:
			case <-time.After(runEndGrace):
			}

			close(held.release)

			await(t, runDone, "the run to end")
			await(t, switchDone, "the switch to return")

			// Every row: the code after the handler ran after the switch, saw
			// its successor, and the response names it.
			require.NoError(t, out.err)
			require.True(t, out.handlerRan)
			require.NoError(t, switched, "the switch completed")

			assert.Equal(t, []string{"rotated", "after next", "run ended"}, log.all(),
				"the code after the handler ran only after the switch's rotation was stored")

			set := sessionCookiesFrom(t, setCookies)
			require.Len(t, set, 1, "the response re-sets the session cookie")
			assert.NotEqual(t, w.signIn.ID, set[0].Value, "the cookie names the successor")

			seen.mu.Lock()
			if !tc.ownExchange {
				assert.Equal(t, set[0].Value, seen.sessionID, "the interceptor after the handler saw the successor")
			}
			assert.True(t, seen.hasCtx)
			seen.mu.Unlock()

			successor, err := w.sessions.Load(t.Context(), set[0].Value)
			require.NoError(t, err, "the successor the cookie names is stored")
			assert.Equal(t, w.signIn.FamilyID, successor.FamilyID, "the successor is in the same sign-in")
			assert.Equal(t, "audit", successor.SelectedRole, "the successor carries the switched role")
		})
	}
}

// TestSwitchActiveRole_QueuedSwitchGivesUp pins that a role switch waiting
// behind another on the same request gives up when its own context ends:
// with the first switch held inside its rotation, a second one made on a
// cancelled context returns that context's error at once and stores nothing,
// and the first then completes.
func TestSwitchActiveRole_QueuedSwitchGivesUp(t *testing.T) {
	t.Parallel()

	w := newSwitchCookieWorld(t)

	held := holdRotation(w, nil)

	firstDone := make(chan struct{})
	queuedDone := make(chan struct{})

	var first, queued error

	req := sessionCookieRequest(t.Context(), http.MethodPost, named(w.signIn.ID),
		map[string]string{"X-CSRF-Token": w.signIn.CSRFToken})
	out := served{rec: httptest.NewRecorder()}

	run := w.chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		ctx := ex.Context()

		go func() {
			defer close(firstDone)

			first = w.chain.SwitchActiveRole(ctx, "audit")
		}()

		select {
		case <-held.entered:
		case <-time.After(raceTimeout):
		}

		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		go func() {
			defer close(queuedDone)

			queued = w.chain.SwitchActiveRole(cancelled, "")
		}()

		return nil
	})

	runDone := make(chan struct{})

	var setCookies []string

	go func() {
		defer close(runDone)

		out.err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))
		setCookies = slices.Clone(out.rec.Header().Values("Set-Cookie"))
	}()

	await(t, held.entered, "the first switch to enter its rotation")

	gaveUp := false

	select {
	case <-queuedDone:
		gaveUp = true
	case <-time.After(queuedGiveUpBound):
	}

	close(held.release)

	await(t, queuedDone, "the queued switch to return")
	await(t, firstDone, "the first switch to return")
	await(t, runDone, "the run to end")

	require.True(t, gaveUp, "the queued switch gave up while the first was still held")
	require.ErrorIs(t, queued, context.Canceled, "the queued switch failed with its context's error")
	require.NoError(t, first, "the first switch completed")
	require.NoError(t, out.err)

	assert.Equal(t, int32(1), held.writes.Load(), "only the first switch wrote a rotation")

	set := sessionCookiesFrom(t, setCookies)
	require.Len(t, set, 1, "the response re-sets the session cookie once")

	successor, err := w.store.Load(t.Context(), set[0].Value)
	require.NoError(t, err)
	assert.True(t, successor.SupersededAt.IsZero(), "the queued switch rotated nothing")
	assert.Equal(t, "audit", successor.SelectedRole, "the first switch's role stands")
}

// chainRunningDelivery is a session delivery that runs a chain of the
// consumer's own on the exchange copy it is handed, as a delivery that
// reuses an application's middleware might, before setting the cookie.
type chainRunningDelivery struct {
	run   httpsec.Next
	calls atomic.Int32
}

func (d *chainRunningDelivery) Deliver(ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
	d.calls.Add(1)

	if err := d.run(ex); err != nil {
		return "", err
	}

	ex.Writer.SetCookie(sessionCookieFor(credential))

	return "", nil
}

// TestSwitchActiveRole_DeliveryRunsChainOnItsCopy pins that a consumer's
// session delivery that runs a chain on the exchange copy it is handed shares
// nothing with the request's role-switch ordering: called inside a switch's
// rotation, it neither waits for the switch it is part of, which would never
// end, nor marks the request's handler as returned, so a second switch on the
// request is still made.
func TestSwitchActiveRole_DeliveryRunsChainOnItsCopy(t *testing.T) {
	t.Parallel()

	inner, err := httpsec.New()
	require.NoError(t, err)

	delivery := &chainRunningDelivery{run: inner.Assemble(func(*httpsec.Exchange) error { return nil })}

	w := newSwitchCookieWorldWith(t, nil, nil,
		[]httpsec.SessionCookieOption{httpsec.WithSessionDelivery(delivery)},
		func(*session.Sessions) []httpsec.Option { return nil })

	var first, second error

	done := make(chan struct{})

	var out served

	go func() {
		defer close(done)

		out = w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
			first = w.chain.SwitchActiveRole(ex.Context(), "audit")
			second = w.chain.SwitchActiveRole(ex.Context(), "")

			return nil
		})
	}()

	select {
	case <-done:
	case <-time.After(queuedGiveUpBound):
		// The request is left blocked; the test fails rather than hangs.
		t.Fatal("the request deadlocked: the delivery's chain waited for the switch that called it")
	}

	require.NoError(t, out.err)
	require.True(t, out.handlerRan)
	require.NoError(t, first, "the first switch completed")
	require.NoError(t, second, "the delivery's chain did not mark the request's handler as returned")
	assert.Equal(t, int32(2), delivery.calls.Load(), "each switch delivered its successor")
}

// TestSwitchActiveRole_AfterHandlerReturned pins that a role switch on a
// cookie chain is refused as a configuration error, rotating nothing and
// leaving the cookie the browser holds working, once the request's handler
// has returned: from an interceptor's code after the handler, or on a context
// kept past the run, the handler's or that of a run whose interceptor
// answered before the handler. A second pass through the handler, made by an
// interceptor that calls the rest of the chain again, may still switch.
func TestSwitchActiveRole_AfterHandlerReturned(t *testing.T) {
	t.Parallel()

	refused := func(t *testing.T, w *switchCookieWorld, out served, switched error) {
		t.Helper()

		require.ErrorIs(t, switched, httpsec.ErrConfig)
		assert.Empty(t, sessionCookiesSet(t, out), "no cookie was set")

		raw, err := w.store.Load(t.Context(), w.signIn.ID)
		require.NoError(t, err)
		assert.True(t, raw.SupersededAt.IsZero(), "nothing was rotated")
		assert.Empty(t, raw.SelectedRole, "no role was selected")

		n, err := w.sessions.CountActiveByUser(t.Context(), testUserID)
		require.NoError(t, err)
		assert.Equal(t, 1, n, "no successor was stored")
	}

	tests := []struct {
		name string
		// act builds the world, sends one request and makes the switch,
		// returning what the chain answered and what the switch returned.
		act    func(t *testing.T) (*switchCookieWorld, served, error)
		assert func(t *testing.T, w *switchCookieWorld, out served, switched error)
	}{
		{
			name: "context kept past the run",
			act: func(t *testing.T) (*switchCookieWorld, served, error) {
				w := newSwitchCookieWorld(t)

				var kept context.Context

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					kept = ex.Context()

					return nil
				})
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
				require.NotNil(t, kept)

				return w, out, w.chain.SwitchActiveRole(kept, "audit")
			},
			assert: func(t *testing.T, w *switchCookieWorld, out served, switched error) {
				t.Helper()

				refused(t, w, out, switched)
				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "the old cookie still authenticates, unswitched")
			},
		},
		{
			name: "interceptor after the handler",
			act: func(t *testing.T) (*switchCookieWorld, served, error) {
				var (
					w        *switchCookieWorld
					switched error
					once     sync.Once
				)

				w = newSwitchCookieWorld(t, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						err := next(ex)

						once.Do(func() { switched = w.chain.SwitchActiveRole(ex.Context(), "audit") })

						return err
					}), httpsec.OrderSessionTouch))

				out := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)

				return w, out, switched
			},
			assert: refused,
		},
		{
			name: "interceptor after the handler, on a chain nested inside it",
			act: func(t *testing.T) (*switchCookieWorld, served, error) {
				w := newSwitchCookieWorld(t)

				var switched error

				inner, err := httpsec.New(httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						err := next(ex)

						switched = w.chain.SwitchActiveRole(ex.Context(), "audit")

						return err
					}), httpsec.Order(100)))
				require.NoError(t, err)

				var handlerRan bool

				out := w.post(t, w.signIn.ID, inner.Assemble(func(*httpsec.Exchange) error {
					handlerRan = true

					return nil
				}))
				require.NoError(t, out.err)
				require.True(t, handlerRan)

				return w, out, switched
			},
			assert: refused,
		},
		{
			// The consumer's handler is the innermost terminal, so the
			// return of a chain's handler counts as the request's: a handler
			// that runs another chain on its own exchange cannot switch
			// once that chain's handler has returned.
			name: "handler that ran another chain on its exchange first",
			act: func(t *testing.T) (*switchCookieWorld, served, error) {
				w := newSwitchCookieWorld(t)

				other, err := httpsec.New()
				require.NoError(t, err)

				var switched error

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					if err := other.Assemble(func(*httpsec.Exchange) error { return nil })(ex); err != nil {
						return err
					}

					switched = w.chain.SwitchActiveRole(ex.Context(), "audit")

					return nil
				})
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)

				return w, out, switched
			},
			assert: refused,
		},
		{
			name: "context kept past a run answered before the handler",
			act: func(t *testing.T) (*switchCookieWorld, served, error) {
				var kept context.Context

				w := newSwitchCookieWorld(t, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, _ httpsec.Next) error {
						kept = ex.Context()

						return nil
					}), httpsec.OrderSessionTouch))

				out := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.NoError(t, out.err)
				require.False(t, out.handlerRan, "the interceptor answered first")
				require.NotNil(t, kept)

				return w, out, w.chain.SwitchActiveRole(kept, "audit")
			},
			assert: refused,
		},
		{
			name: "second pass through the handler",
			act: func(t *testing.T) (*switchCookieWorld, served, error) {
				w := newSwitchCookieWorld(t, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						if err := next(ex); err != nil {
							return err
						}

						return next(ex)
					}), httpsec.OrderSessionTouch))

				var (
					passes   int
					switched error
				)

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					passes++
					if passes == 2 {
						switched = w.chain.SwitchActiveRole(ex.Context(), "audit")
					}

					return nil
				})
				require.NoError(t, out.err)
				require.Equal(t, 2, passes, "the handler ran twice")

				return w, out, switched
			},
			assert: func(t *testing.T, w *switchCookieWorld, out served, switched error) {
				t.Helper()

				require.NoError(t, switched, "a switch inside the handler's second pass is made")

				set := sessionCookiesSet(t, out)
				require.Len(t, set, 1, "the response re-sets the session cookie")
				assert.NotEqual(t, w.signIn.ID, set[0].Value, "the cookie names the successor")

				successor, err := w.sessions.Load(t.Context(), set[0].Value)
				require.NoError(t, err)
				assert.Equal(t, "audit", successor.SelectedRole)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, out, switched := tc.act(t)
			tc.assert(t, w, out, switched)
		})
	}
}

// sessionCookiesFrom parses lines, Set-Cookie header values, and returns the
// session cookies among them.
func sessionCookiesFrom(t *testing.T, lines []string) []*http.Cookie {
	t.Helper()

	var set []*http.Cookie

	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)

		if c.Name == httpsec.DefaultSessionCookieName {
			set = append(set, c)
		}
	}

	return set
}
