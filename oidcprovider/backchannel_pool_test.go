package oidcprovider_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
)

// oneClient is a registry holding billing-web, listening.
func oneClient() []oidcprovider.Client {
	return []oidcprovider.Client{listeningClient("billing-web", billingBackChannel)}
}

// gate is a consumer's delivery that holds every call until it is opened, counting them.
type gate struct {
	open chan struct{}
	// honour says a call also leaves when its context ends.
	honour bool

	entered, left, peak, running atomic.Int64
}

func newGate(honour bool) *gate { return &gate{open: make(chan struct{}), honour: honour} }

// Deliver implements oidcprovider.LogoutDelivery.
func (g *gate) Deliver(ctx context.Context, _, _ string) error {
	g.entered.Add(1)
	now := g.running.Add(1)
	for {
		peak := g.peak.Load()
		if now <= peak || g.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	defer func() {
		g.running.Add(-1)
		g.left.Add(1)
	}()

	if g.honour {
		select {
		case <-g.open:
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	}
	<-g.open

	return nil
}

// TestProvider_BackChannelDelivery_Hung pins that nothing hanging delays an end, and that a hang holds a
// worker no longer than the bound on one delivery, a consumer's call ignoring its context included.
func TestProvider_BackChannelDelivery_Hung(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// wire returns what makes a delivery hang, and what lets the hang go at the end of the row.
		wire    func(t *testing.T) (clients []oidcprovider.Client, registry oidcprovider.ClientRegistry, opts []oidcprovider.Option, release func())
		arrange func(x *ending)
		// bound is what a row expects a delivery to be held to.
		bound time.Duration
	}

	cases := []testCase{
		{
			name: "a relying party that never answers",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option, func()) {
				hung := roundTripFunc(func(r *http.Request) (*http.Response, error) {
					<-r.Context().Done()

					return nil, r.Context().Err()
				})

				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(&http.Client{Transport: hung}))}, func() {}
			},
			bound: 5 * time.Second,
		},
		{
			name: "a consumer's delivery honouring its context",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option, func()) {
				g := newGate(true)

				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutDelivery(g)}, func() {}
			},
			bound: 5 * time.Second,
		},
		{
			name: "a consumer's delivery ignoring its context",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option, func()) {
				g := newGate(false)

				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutDelivery(g)}, func() { close(g.open) }
			},
			bound: 5 * time.Second,
		},
		{
			name: "a registry that does not answer",
			wire: func(t *testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option, func()) {
				t.Helper()
				registry := NewMockClientRegistry(gomock.NewController(t))
				registry.EXPECT().Client(gomock.Any(), "billing-web").DoAndReturn(
					func(ctx context.Context, _ string) (*oidcprovider.RegisteredClient, error) {
						<-ctx.Done()

						return nil, ctx.Err()
					}).AnyTimes()

				return nil, registry, nil, func() {}
			},
			bound: 5 * time.Second,
		},
		{
			name: "keys that do not answer",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option, func()) {
				return oneClient(), nil, nil, func() {}
			},
			arrange: func(x *ending) {
				x.keys.failSigning(func(ctx context.Context) error {
					<-ctx.Done()

					return ctx.Err()
				})
			},
			bound: 5 * time.Second,
		},
		{
			name: "a bound the consumer chose",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option, func()) {
				g := newGate(true)

				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryTimeout(time.Second)}, func() {}
			},
			bound: time.Second,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				clients, registry, opts, release := tc.wire(t)
				x := newEnding(t, clients, registry, opts...)
				if tc.arrange != nil {
					tc.arrange(x)
				}

				started := time.Now()
				x.end(t.Context(), t, "billing-web")
				assert.Zero(t, time.Since(started), "the end did not wait for its delivery")

				time.Sleep(tc.bound - time.Nanosecond)
				synctest.Wait()
				assert.Empty(t, x.reasons(), "the delivery has until its bound")

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, []string{"timeout"}, x.reasons(), "and is reported as failed at it")

				release()
				require.NoError(t, x.p.Shutdown(t.Context()))
			})
		})
	}
}

// TestProvider_BackChannelDelivery_HungHoldsOneWorker pins that a lone worker held by a hang takes up
// the next delivery the moment the bound ends, whether or not the hung call ever returned.
func TestProvider_BackChannelDelivery_HungHoldsOneWorker(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		honour bool
	}

	cases := []testCase{
		{name: "a call that honours its context", honour: true},
		{name: "a call that ignores it"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				g := newGate(tc.honour)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 4))

				x.end(t.Context(), t, "billing-web")
				x.end(t.Context(), t, "billing-web")
				synctest.Wait()
				assert.Equal(t, int64(1), g.entered.Load(), "one worker, held")

				time.Sleep(5*time.Second - time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, int64(1), g.entered.Load(), "held until the bound")

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				assert.Equal(t, int64(2), g.entered.Load(), "and free at it")

				close(g.open)
				require.NoError(t, x.p.Shutdown(t.Context()))
			})
		})
	}
}

// TestProvider_BackChannelDelivery_IgnoringItsContext states what a consumer's call that never returns
// costs: a goroutine, of at most as many again as there are workers, and past those a delivery fails at
// once rather than start another. Shutdown says so by not returning nil until the calls have gone.
func TestProvider_BackChannelDelivery_IgnoringItsContext(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		g := newGate(false)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 16))

		for range 4 {
			x.end(t.Context(), t, "billing-web")
		}
		synctest.Wait()
		assert.Equal(t, int64(1), g.entered.Load())

		time.Sleep(5 * time.Second)
		synctest.Wait()
		assert.Equal(t, int64(2), g.entered.Load(), "the first was left behind, and the second holds the worker")
		assert.Equal(t, []string{"timeout"}, x.reasons())

		time.Sleep(5 * time.Second)
		synctest.Wait()
		assert.Equal(t, int64(2), g.entered.Load(), "no more than one call is left behind per worker")
		assert.Equal(t, []string{"timeout", "timeout", "busy", "busy"}, x.reasons(), "and what finds no room fails at once")

		shutdown, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		require.ErrorIs(t, x.p.Shutdown(shutdown), context.DeadlineExceeded, "the calls still hold their goroutines")

		close(g.open)
		synctest.Wait()
		require.NoError(t, x.p.Shutdown(t.Context()), "and nil means they have gone")
	})
}

// TestProvider_BackChannelDelivery_LeftBehindLeavesRoom pins that a call left behind costs only its own
// place: with one left, the next place is given back as each delivery ends, so none finds it taken.
func TestProvider_BackChannelDelivery_LeftBehindLeavesRoom(t *testing.T) {
	t.Parallel()

	const quick = 500
	synctest.Test(t, func(t *testing.T) {
		stuck := make(chan struct{})
		var calls, delivered atomic.Int64
		delivery := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
			if calls.Add(1) == 1 {
				<-stuck
			}
			delivered.Add(1)

			return nil
		})
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(delivery), oidcprovider.WithLogoutDeliveryPool(1, quick))

		x.end(t.Context(), t, "billing-web")
		time.Sleep(5 * time.Second)
		synctest.Wait()
		require.Equal(t, []string{"timeout"}, x.reasons())

		for range quick {
			x.end(t.Context(), t, "billing-web")
		}
		synctest.Wait()
		assert.Equal(t, int64(quick), delivered.Load())
		assert.Equal(t, []string{"timeout"}, x.reasons(), "none of them found its place taken")

		close(stuck)
		require.NoError(t, x.p.Shutdown(t.Context()))
	})
}

// lateHandler is a consumer's log handler that panics at the record of a call ending after its bound,
// and takes every other.
type lateHandler struct{ slog.Handler }

// Enabled implements slog.Handler.
func (lateHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements slog.Handler.
func (lateHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "after its bound") {
		panic("in the log handler")
	}

	return nil
}

// TestProvider_BackChannelDelivery_EndsAfterItsBound pins what a call left behind does when it finally
// ends: its failure was already reported, and how it ended is logged, and takes nothing with it, even
// when logging it panics too.
func TestProvider_BackChannelDelivery_EndsAfterItsBound(t *testing.T) {
	t.Parallel()

	const panicText = "a panic quoting something private"

	type testCase struct {
		name   string
		end    func()
		opts   []oidcprovider.Option
		assert func(t *testing.T, x *ending)
	}

	cases := []testCase{
		{
			name: "a panic is logged by its type",
			end:  func() { panic(errors.New(panicText)) },
			assert: func(t *testing.T, x *ending) {
				logged := x.logs.String()
				assert.Contains(t, logged, "reason=panic")
				assert.Contains(t, logged, "value_type=*errors.errorString")
				assert.NotContains(t, logged, panicText)
			},
		},
		{
			name: "a goroutine ended outright is logged",
			end:  runtime.Goexit,
			assert: func(t *testing.T, x *ending) {
				assert.Contains(t, x.logs.String(), "reason=goexit")
			},
		},
		{
			name: "a log handler panicking at it brings nothing down",
			end:  func() { panic(errors.New(panicText)) },
			opts: []oidcprovider.Option{oidcprovider.WithLogger(slog.New(lateHandler{slog.DiscardHandler}))},
			assert: func(*testing.T, *ending) {
			},
		},
		{
			name: "a return is not logged, being no ending of its goroutine",
			end:  func() {},
			assert: func(t *testing.T, x *ending) {
				assert.NotContains(t, x.logs.String(), "after its bound")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				delivery := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
					<-release
					tc.end()

					return nil
				})
				x := newEnding(t, oneClient(), nil, append([]oidcprovider.Option{oidcprovider.WithLogoutDelivery(delivery)}, tc.opts...)...)

				x.end(t.Context(), t, "billing-web")
				time.Sleep(5 * time.Second)
				synctest.Wait()
				close(release)
				require.NoError(t, x.p.Shutdown(t.Context()))

				assert.Equal(t, []string{"timeout"}, x.reasons(), "reported once, as what it was at its bound")
				tc.assert(t, x)
			})
		})
	}
}

// TestProvider_BackChannelDelivery_Bounded pins the pool and the queue, and that a full queue drops and
// reports without the end waiting.
func TestProvider_BackChannelDelivery_Bounded(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name           string
		opts           []oidcprovider.Option
		workers, queue int
	}

	cases := []testCase{
		{name: "by default, 8 workers and a queue of 1024", workers: 8, queue: 1024},
		{name: "as the consumer chose", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryPool(2, 3)}, workers: 2, queue: 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				g := newGate(true)
				x := newEnding(t, oneClient(), nil, append([]oidcprovider.Option{oidcprovider.WithLogoutDelivery(g)}, tc.opts...)...)

				for range tc.workers {
					x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()
				assert.Equal(t, int64(tc.workers), g.entered.Load(), "every worker is at work")

				for range tc.queue {
					x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()
				assert.Equal(t, int64(tc.workers), g.entered.Load(), "and no more than that")
				assert.Empty(t, x.reasons(), "the queue holds what they cannot take")

				started := time.Now()
				x.end(t.Context(), t, "billing-web")
				assert.Zero(t, time.Since(started), "a full queue does not hold up the end")
				assert.Equal(t, []string{"queue_full"}, x.reasons())
				assert.Contains(t, x.logs.String(), "reason=queue_full", "and is logged")

				close(g.open)
				require.NoError(t, x.p.Shutdown(t.Context()))
				assert.Equal(t, int64(tc.workers+tc.queue), g.left.Load(), "all that was accepted is delivered")
				assert.Equal(t, int64(tc.workers), g.peak.Load())
				assert.Equal(t, []string{"queue_full"}, x.reasons())
			})
		})
	}
}

// TestProvider_BackChannelDelivery_EndedGoroutine pins that a delivery ending its goroutine is reported,
// takes nothing with it, and leaves the pool the size it was.
func TestProvider_BackChannelDelivery_EndedGoroutine(t *testing.T) {
	t.Parallel()

	const panicText = "a panic quoting something private"

	type testCase struct {
		name   string
		end    func()
		reason string
		// valueType is what the log says of what it panicked with.
		valueType string
	}

	cases := []testCase{
		{name: "a panic", end: func() { panic(errors.New(panicText)) }, reason: "panic", valueType: "value_type=*errors.errorString"},
		{name: "a panic with a string", end: func() { panic(panicText) }, reason: "panic", valueType: "value_type=string"},
		{name: "a goroutine ended outright", end: runtime.Goexit, reason: "goexit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				const workers = 2
				g := newGate(true)
				var failing atomic.Int32
				failing.Store(workers)
				delivery := oidcprovider.LogoutDeliveryFunc(func(ctx context.Context, uri, raw string) error {
					if failing.Add(-1) >= 0 {
						tc.end()
					}

					return g.Deliver(ctx, uri, raw)
				})
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(delivery), oidcprovider.WithLogoutDeliveryPool(workers, 8))

				for range workers {
					x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()
				assert.Equal(t, []string{tc.reason, tc.reason}, x.reasons(), "each is reported")
				logged := x.logs.String()
				assert.Contains(t, logged, "reason="+tc.reason)
				assert.Contains(t, logged, tc.valueType)
				assert.NotContains(t, logged, panicText, "without what it said")
				assert.NotContains(t, logged, "after its bound", "and it ended within it")

				for range workers + 1 {
					x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()
				assert.Equal(t, int64(workers), g.entered.Load(), "the pool is the size it was, at work")

				close(g.open)
				require.NoError(t, x.p.Shutdown(t.Context()))
				assert.Equal(t, int64(workers+1), g.left.Load(), "and takes up what was queued")
			})
		})
	}
}

// TestProvider_BackChannelDelivery_ReportingEndsItsGoroutine pins that the report itself, which runs a
// consumer's log handler and will run its sink, costs the pool nothing either.
func TestProvider_BackChannelDelivery_ReportingEndsItsGoroutine(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		end  func()
	}

	cases := []testCase{
		{name: "a panic", end: func() { panic("in the report") }},
		{name: "a goroutine ended outright", end: runtime.Goexit},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var reports atomic.Int32
				failing := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error { return errOutage })
				x := newEnding(t, oneClient(), nil,
					oidcprovider.WithLogoutDelivery(failing),
					oidcprovider.WithLogoutDeliveryPool(1, 8),
					oidcprovider.WithLogoutFailuresForTest(func(context.Context, oidcprovider.LogoutFailure) {
						if reports.Add(1) == 1 {
							tc.end()
						}
					}))

				x.end(t.Context(), t, "billing-web")
				x.end(t.Context(), t, "billing-web")
				synctest.Wait()
				assert.Equal(t, int32(2), reports.Load(), "the next delivery still ran")

				require.NoError(t, x.p.Shutdown(t.Context()))
			})
		})
	}
}

// TestProvider_BackChannelDelivery_Shutdown pins how delivery stops.
func TestProvider_BackChannelDelivery_Shutdown(t *testing.T) {
	t.Parallel()

	type scene struct {
		x *ending
		g *gate
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, s scene)
	}

	cases := []testCase{
		{
			name: "it waits for what is queued, and reports nothing",
			assert: func(t *testing.T, s scene) {
				for range 3 {
					s.x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()
				assert.Equal(t, int64(1), s.g.entered.Load())
				go func() {
					time.Sleep(3 * time.Second)
					close(s.g.open)
				}()

				started := time.Now()
				require.NoError(t, s.x.p.Shutdown(t.Context()))
				assert.Equal(t, 3*time.Second, time.Since(started))
				assert.Equal(t, int64(3), s.g.left.Load())
				assert.Empty(t, s.x.reasons())
			},
		},
		{
			name: "past its context it stops: what is queued is reported, what it cut off is not",
			assert: func(t *testing.T, s scene) {
				for range 3 {
					s.x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()

				shutdown, stop := context.WithTimeout(t.Context(), time.Second)
				defer stop()
				started := time.Now()
				require.ErrorIs(t, s.x.p.Shutdown(shutdown), context.DeadlineExceeded)
				assert.Equal(t, time.Second, time.Since(started))
				assert.Equal(t, []string{"shutdown", "shutdown"}, s.x.reasons())

				synctest.Wait()
				assert.Equal(t, int64(1), s.g.entered.Load(), "nothing queued ran after")
				assert.Equal(t, int64(1), s.g.left.Load(), "and what it cut off was told so")
				assert.Equal(t, []string{"shutdown", "shutdown"}, s.x.reasons(), "and did not fail")
				assert.Contains(t, s.x.logs.String(), "level=INFO", "though it is logged")

				require.NoError(t, s.x.p.Shutdown(t.Context()), "and asking again finds nothing left")
			},
		},
		{
			name: "a delivery after it is dropped and reported, and the end still succeeds",
			assert: func(t *testing.T, s scene) {
				require.NoError(t, s.x.p.Shutdown(t.Context()))
				s.x.end(t.Context(), t, "billing-web")
				assert.Equal(t, []string{"shutdown"}, s.x.reasons())
				synctest.Wait()
				assert.Zero(t, s.g.entered.Load())
			},
		},
		{
			name: "twice is safe",
			assert: func(t *testing.T, s scene) {
				s.x.end(t.Context(), t, "billing-web")
				close(s.g.open)
				require.NoError(t, s.x.p.Shutdown(t.Context()))
				require.NoError(t, s.x.p.Shutdown(t.Context()))
				assert.Empty(t, s.x.reasons())
			},
		},
		{
			name: "with work done, an ended context is no failure",
			assert: func(t *testing.T, s scene) {
				cancelled, cancel := context.WithCancel(t.Context())
				cancel()
				assert.NoError(t, s.x.p.Shutdown(cancelled))
			},
		},
		{
			name: "a nil context is refused, and changes nothing",
			assert: func(t *testing.T, s scene) {
				var none context.Context
				require.ErrorIs(t, s.x.p.Shutdown(none), oidcprovider.ErrConfig)

				s.x.end(t.Context(), t, "billing-web")
				synctest.Wait()
				assert.Equal(t, int64(1), s.g.entered.Load(), "delivery goes on")
				close(s.g.open)
				require.NoError(t, s.x.p.Shutdown(t.Context()))
			},
		},
		{
			name: "several at once all wait, and all end",
			assert: func(t *testing.T, s scene) {
				s.x.end(t.Context(), t, "billing-web")
				synctest.Wait()

				var wg sync.WaitGroup
				var returned atomic.Int32
				for range 4 {
					wg.Go(func() {
						assert.NoError(t, s.x.p.Shutdown(t.Context()))
						returned.Add(1)
					})
				}
				synctest.Wait()
				assert.Zero(t, returned.Load(), "with the delivery still running")

				close(s.g.open)
				wg.Wait()
				assert.Equal(t, int32(4), returned.Load())
			},
		},
		{
			name: "a report holds nothing another call needs",
			assert: func(t *testing.T, s scene) {
				require.NoError(t, s.x.p.Shutdown(t.Context()))
				run := func() { assert.NoError(t, s.x.p.Shutdown(t.Context())) }
				s.x.reentrant.Store(&run)
				s.x.end(t.Context(), t, "billing-web")
				assert.Equal(t, []string{"shutdown"}, s.x.reasons())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				g := newGate(true)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 8))
				tc.assert(t, scene{x: x, g: g})
			})
		})
	}
}

// TestProvider_BackChannelDelivery_ShutdownCutsOffNoFailure pins that what Shutdown cut off, however deep
// it had got, raises no failure.
func TestProvider_BackChannelDelivery_ShutdownCutsOffNoFailure(t *testing.T) {
	t.Parallel()

	hung := func(ctx context.Context) error {
		<-ctx.Done()

		return ctx.Err()
	}

	type testCase struct {
		name string
		wire func(t *testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option)
		hang func(x *ending)
	}

	cases := []testCase{
		{
			name: "a post",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option) {
				transport := roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, hung(r.Context()) })

				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(&http.Client{Transport: transport}))}
			},
		},
		{
			name: "a registry read",
			wire: func(t *testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option) {
				t.Helper()
				registry := NewMockClientRegistry(gomock.NewController(t))
				registry.EXPECT().Client(gomock.Any(), "billing-web").DoAndReturn(
					func(ctx context.Context, _ string) (*oidcprovider.RegisteredClient, error) { return nil, hung(ctx) }).AnyTimes()

				return nil, registry, nil
			},
		},
		{
			name: "a signature",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option) {
				return oneClient(), nil, nil
			},
			hang: func(x *ending) { x.keys.failSigning(hung) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				clients, registry, opts := tc.wire(t)
				x := newEnding(t, clients, registry, opts...)
				if tc.hang != nil {
					tc.hang(x)
				}
				x.end(t.Context(), t, "billing-web")
				synctest.Wait()

				shutdown, stop := context.WithTimeout(t.Context(), time.Second)
				defer stop()
				require.ErrorIs(t, x.p.Shutdown(shutdown), context.DeadlineExceeded)
				synctest.Wait()

				assert.Empty(t, x.reasons())
				require.NoError(t, x.p.Shutdown(t.Context()))
			})
		})
	}
}

// TestProvider_BackChannelDelivery_ShutdownRaces runs ends against Shutdown, under -race: every delivery
// is either delivered or reported, none of them panics, and none is lost.
func TestProvider_BackChannelDelivery_ShutdownRaces(t *testing.T) {
	t.Parallel()

	const enders, ends = 8, 50

	var delivered atomic.Int64
	x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(
		func(context.Context, string, string) error {
			delivered.Add(1)

			return nil
		})), oidcprovider.WithLogoutDeliveryPool(4, enders*ends))

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range enders {
		wg.Go(func() {
			<-start
			for range ends {
				x.p.SignInsEnded(t.Context(), x.report(t, "billing-web"))
			}
		})
	}
	for range 2 {
		wg.Go(func() {
			<-start
			bounded, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
			defer stop()
			assert.NoError(t, x.p.Shutdown(bounded))
		})
	}
	close(start)
	wg.Wait()
	drained(t, x.p)

	reasons := x.reasons()
	for _, reason := range reasons {
		assert.Equal(t, "shutdown", reason)
	}
	assert.Equal(t, x.handed.Load(), delivered.Load()+int64(len(reasons)), "each went one way or the other")
}

// TestProvider_BackChannelDelivery_Lifecycle pins Start, and what a provider never started does.
func TestProvider_BackChannelDelivery_Lifecycle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(ctx context.Context, t *testing.T, x *ending, delivered *atomic.Int32)
	}

	tell := func(ctx context.Context, t *testing.T, x *ending) {
		t.Helper()
		x.end(ctx, t, "billing-web")
	}

	cases := []testCase{
		{
			name: "a provider never started delivers, and asks nothing of its consumer",
			assert: func(ctx context.Context, t *testing.T, x *ending, delivered *atomic.Int32) {
				tell(ctx, t, x)
				synctest.Wait()
				assert.Equal(t, int32(1), delivered.Load())
			},
		},
		{
			name: "a provider started delivers",
			assert: func(ctx context.Context, t *testing.T, x *ending, delivered *atomic.Int32) {
				require.NoError(t, x.p.Start(ctx))
				tell(ctx, t, x)
				synctest.Wait()
				assert.Equal(t, int32(1), delivered.Load())
			},
		},
		{
			name: "starting after a first delivery is no mistake, as traffic may come first",
			assert: func(ctx context.Context, t *testing.T, x *ending, _ *atomic.Int32) {
				tell(ctx, t, x)
				assert.NoError(t, x.p.Start(ctx))
			},
		},
		{
			name: "starting twice is",
			assert: func(ctx context.Context, t *testing.T, x *ending, _ *atomic.Int32) {
				require.NoError(t, x.p.Start(ctx))
				assert.ErrorIs(t, x.p.Start(ctx), oidcprovider.ErrAlreadyStarted)
			},
		},
		{
			name: "starting after a shutdown is",
			assert: func(ctx context.Context, t *testing.T, x *ending, _ *atomic.Int32) {
				require.NoError(t, x.p.Shutdown(ctx))
				assert.ErrorIs(t, x.p.Start(ctx), oidcprovider.ErrAlreadyShutdown)
			},
		},
		{
			name: "a nil context is refused, and a later start still works",
			assert: func(ctx context.Context, t *testing.T, x *ending, _ *atomic.Int32) {
				var none context.Context
				require.ErrorIs(t, x.p.Start(none), oidcprovider.ErrConfig) //nolint:contextcheck // the nil context is the point
				assert.NoError(t, x.p.Start(ctx))
			},
		},
		{
			name: "the context it is given ends nothing",
			assert: func(ctx context.Context, t *testing.T, x *ending, delivered *atomic.Int32) {
				started, cancel := context.WithCancel(ctx)
				require.NoError(t, x.p.Start(started))
				cancel()
				tell(ctx, t, x)
				synctest.Wait()
				assert.Equal(t, int32(1), delivered.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// In a bubble, a goroutine a row leaves behind fails it: nothing here calls Shutdown after
			// the row's delivery, so these rows also pin that nothing stays behind without one.
			synctest.Test(t, func(t *testing.T) {
				var delivered atomic.Int32
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(
					func(context.Context, string, string) error {
						delivered.Add(1)

						return nil
					})))

				tc.assert(t.Context(), t, x, &delivered)
			})
		})
	}
}

// TestProvider_BackChannelDelivery_Construction pins that a wiring mistake fails at New, naming the
// setting.
func TestProvider_BackChannelDelivery_Construction(t *testing.T) {
	t.Parallel()

	var typedNil oidcprovider.LogoutDeliveryFunc
	refused := func(setting string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, setting)
		}
	}
	delivery := oidcprovider.WithLogoutDelivery(&logoutRecorder{})

	type testCase struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{name: "no options", assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "options for delivery, none of them", opts: []oidcprovider.Option{oidcprovider.WithLogoutOutbound()}, assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "a nil delivery", opts: []oidcprovider.Option{oidcprovider.WithLogoutDelivery(nil)}, assert: refused("WithLogoutDelivery")},
		{name: "a typed nil delivery", opts: []oidcprovider.Option{oidcprovider.WithLogoutDelivery(typedNil)}, assert: refused("WithLogoutDelivery")},
		{name: "no workers", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryPool(0, 1)}, assert: refused("WithLogoutDeliveryPool")},
		{name: "negative workers", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryPool(-1, 1)}, assert: refused("WithLogoutDeliveryPool")},
		{name: "no queue", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryPool(1, 0)}, assert: refused("WithLogoutDeliveryPool")},
		{name: "a negative queue", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryPool(1, -1)}, assert: refused("WithLogoutDeliveryPool")},
		{name: "one worker and one place is enough", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryPool(1, 1)}, assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "no bound", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryTimeout(0)}, assert: refused("WithLogoutDeliveryTimeout")},
		{name: "a negative bound", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryTimeout(-time.Second)}, assert: refused("WithLogoutDeliveryTimeout")},
		{name: "options an outbound client refuses", opts: []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithTimeout(-time.Second))}, assert: refused("WithLogoutOutbound")},
		{name: "options for a post that a consumer's delivery replaces", opts: []oidcprovider.Option{delivery, oidcprovider.WithLogoutOutbound()}, assert: refused("WithLogoutOutbound")},
		{name: "the same, the other way round", opts: []oidcprovider.Option{oidcprovider.WithLogoutOutbound(), delivery}, assert: refused("WithLogoutOutbound")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcprovider.New(validDeps(t), tc.opts...)
			tc.assert(t, err)
		})
	}
}

// TestProvider_BackChannelDelivery_TransportKeepsNoConnection pins that the default delivery leaves
// nothing behind it, as a kept connection is a goroutine outliving Shutdown.
func TestProvider_BackChannelDelivery_TransportKeepsNoConnection(t *testing.T) {
	t.Parallel()

	assert.True(t, oidcprovider.LogoutTransportForTest().DisableKeepAlives)
}

// TestProvider_BackChannelDelivery_NoGoroutineOutlivesShutdown is not parallel, because goleak counts
// goroutines process-wide. Parallel tests are paused while it runs, and the snapshot ignores them.
func TestProvider_BackChannelDelivery_NoGoroutineOutlivesShutdown(t *testing.T) {
	type testCase struct {
		name string
		run  func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "New starts nothing",
			run: func(t *testing.T) {
				t.Helper()
				newEnding(t, oneClient(), nil)
			},
		},
		{
			name: "Start starts nothing that stays",
			run: func(t *testing.T) {
				t.Helper()
				x := newEnding(t, oneClient(), nil)
				require.NoError(t, x.p.Start(t.Context()))
			},
		},
		{
			name: "deliveries over TLS, then Shutdown",
			run: func(t *testing.T) {
				t.Helper()
				rp := newRelyingParty(t, func(http.ResponseWriter, *http.Request) {})
				x := newEnding(t, []oidcprovider.Client{listeningClient("billing-web", rp.srv.URL+"/logout")}, nil,
					oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(rp.srv.Client())))
				for range 20 {
					x.end(t.Context(), t, "billing-web")
				}
				drained(t, x.p)
				require.Len(t, rp.received(), 20)
				rp.srv.Close()
			},
		},
		{
			name: "deliveries with no Shutdown at all, once they have finished",
			run: func(t *testing.T) {
				t.Helper()
				finished := make(chan struct{}, 5)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(
					func(context.Context, string, string) error {
						finished <- struct{}{}

						return nil
					})))
				for range 5 {
					x.end(t.Context(), t, "billing-web")
				}
				for range 5 {
					select {
					case <-finished:
					case <-time.After(30 * time.Second):
						require.Fail(t, "a delivery never ran")
					}
				}
			},
		},
		{
			name: "a Shutdown past its context, then another",
			run: func(t *testing.T) {
				t.Helper()
				g := newGate(true)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g))
				for range 20 {
					x.end(t.Context(), t, "billing-web")
				}
				shutdown, stop := context.WithCancel(t.Context())
				stop()
				require.ErrorIs(t, x.p.Shutdown(shutdown), context.Canceled)
				drained(t, x.p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()
			tc.run(t)
			goleak.VerifyNone(t, ignore)
		})
	}
}
