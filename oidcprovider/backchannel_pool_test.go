package oidcprovider_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
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

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/eventsink"
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
// costs: a goroutine, with at most twice the workers' calls left behind, and past those a delivery fails at
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
		assert.Equal(t, int64(2), g.entered.Load(), "with the worker's own call, no more than twice the workers")
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
				synctest.Wait()
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
			name: "past its context it stops: what is queued is reported, and so is the post it cut off",
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

				synctest.Wait()
				assert.Equal(t, int64(1), s.g.entered.Load(), "nothing queued ran after")
				assert.Equal(t, int64(1), s.g.left.Load(), "and what it cut off was told so")
				assert.Equal(t, []string{"shutdown", "shutdown", "shutdown"}, s.x.reasons(), "and no client went unreported")
				assert.NotContains(t, s.x.logs.String(), "cut off", "as a failure, and not a note")

				require.NoError(t, s.x.p.Shutdown(t.Context()), "and asking again finds nothing left")
			},
		},
		{
			name: "a delivery after it is dropped and reported, and the end still succeeds",
			assert: func(t *testing.T, s scene) {
				require.NoError(t, s.x.p.Shutdown(t.Context()))
				s.x.end(t.Context(), t, "billing-web")
				synctest.Wait()
				assert.Equal(t, []string{"shutdown"}, s.x.reasons())
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
				run := func() { assert.ErrorIs(t, s.x.p.Start(t.Context()), oidcprovider.ErrAlreadyShutdown) }
				s.x.reentrant.Store(&run)
				s.x.end(t.Context(), t, "billing-web")
				synctest.Wait()
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

// TestProvider_BackChannelDelivery_ShutdownCutsOffNoFailure pins what Shutdown cutting off a delivery says,
// by how deep it had got: a post is a client not told, and reported as that, and a read of the client or a
// signature it stopped is no failure, and only logged.
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
		// reasons is what is reported.
		reasons []string
	}

	cases := []testCase{
		{
			name: "a post",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option) {
				transport := roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, hung(r.Context()) })

				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(&http.Client{Transport: transport}))}
			},
			reasons: []string{"shutdown"},
		},
		{
			name: "a consumer's delivery",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option) {
				return oneClient(), nil, []oidcprovider.Option{oidcprovider.WithLogoutDelivery(newGate(true))}
			},
			reasons: []string{"shutdown"},
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
			reasons: []string{},
		},
		{
			name: "a signature",
			wire: func(*testing.T) ([]oidcprovider.Client, oidcprovider.ClientRegistry, []oidcprovider.Option) {
				return oneClient(), nil, nil
			},
			hang:    func(x *ending) { x.keys.failSigning(hung) },
			reasons: []string{},
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

				assert.Equal(t, tc.reasons, x.reasons())
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
		{name: "the longest bound there is", opts: []oidcprovider.Option{oidcprovider.WithLogoutDeliveryTimeout(math.MaxInt64)}, assert: func(t *testing.T, err error) { require.NoError(t, err) }},
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

	transport := oidcprovider.LogoutTransportForTest()
	assert.True(t, transport.DisableKeepAlives)
	require.NotNil(t, transport.Proxy, "an operator's proxy settings apply to it, as they do to any other client")
	assert.Equal(t, reflect.ValueOf(http.ProxyFromEnvironment).Pointer(), reflect.ValueOf(transport.Proxy).Pointer())
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

// onRecord is a consumer's log handler that runs act at each record holding text.
type onRecord struct {
	text string
	act  func()
}

// Enabled implements slog.Handler.
func (onRecord) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements slog.Handler.
func (h onRecord) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.text) {
		h.act()
	}

	return nil
}

// WithAttrs implements slog.Handler.
func (h onRecord) WithAttrs([]slog.Attr) slog.Handler { return h }

// WithGroup implements slog.Handler.
func (h onRecord) WithGroup(string) slog.Handler { return h }

// aFailedDelivery is what the record of a failed delivery says.
const aFailedDelivery = "was not delivered"

// onFailureRecord is a logger running act at each failed delivery's record.
func onFailureRecord(act func()) oidcprovider.Option {
	return oidcprovider.WithLogger(slog.New(onRecord{text: aFailedDelivery, act: act}))
}

// atFailedDelivery is a sink running act at each failed delivery's event, and taking every other.
func atFailedDelivery(act func()) oidcprovider.Option {
	return oidcprovider.WithSecurityEvents(func(_ context.Context, e event.Event) {
		if e.Name == event.LogoutDeliveryFailed {
			act()
		}
	})
}

// TestProvider_BackChannelDelivery_ReportCannotHoldTheEnd pins that what a drop's report runs, a consumer's
// log handler or sink, neither delays the logout that dropped it nor stops it finishing.
func TestProvider_BackChannelDelivery_ReportCannotHoldTheEnd(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opt  func() oidcprovider.Option
	}

	cases := []testCase{
		{
			name: "a slow log handler",
			opt:  func() oidcprovider.Option { return onFailureRecord(func() { time.Sleep(time.Second) }) },
		},
		{
			name: "a log handler that panics",
			opt:  func() oidcprovider.Option { return onFailureRecord(func() { panic("in the log handler") }) },
		},
		{
			name: "a slow sink",
			opt: func() oidcprovider.Option {
				return atFailedDelivery(func() { time.Sleep(time.Second) })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				memory, err := oidcprovider.NewMemoryBrowserSessionStore()
				require.NoError(t, err)
				var deletes atomic.Int32
				browsers := &hookedBrowsers{BrowserSessionStore: memory, sawDelete: func(context.Context) { deletes.Add(1) }}
				g := newGate(true)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
					oidcprovider.WithBrowserSessionStore(browsers), tc.opt())

				x.end(t.Context(), t, "billing-web")
				synctest.Wait()
				x.end(t.Context(), t, "billing-web")
				before := deletes.Load()

				started := time.Now()
				require.NotPanics(t, func() { x.end(t.Context(), t, "billing-web", "billing-web", "billing-web") })
				assert.Zero(t, time.Since(started), "the logout waited on the reports of its drops")
				assert.Equal(t, before+1, deletes.Load(), "and its browser sessions were deleted")

				close(g.open)
				require.NoError(t, x.p.Shutdown(t.Context()))
			})
		})
	}
}

// TestProvider_BackChannelDelivery_EndOrder pins that the browser sessions go before anything that reports,
// so that nothing a report does can leave the sessions of an ended sign-in valid.
func TestProvider_BackChannelDelivery_EndOrder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts watches what an end reaches, by the time the browser sessions have gone.
		opts func(deleted func() bool, saw func(bool)) []oidcprovider.Option
		// end runs the end, which a row may expect to panic.
		end func(t *testing.T, x *ending)
	}

	ends := func(t *testing.T, x *ending) {
		t.Helper()
		x.end(t.Context(), t, "billing-web")
	}

	cases := []testCase{
		{
			name: "before a client is handed on",
			opts: func(deleted func() bool, saw func(bool)) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithLogoutNoticesForTest(func(context.Context, []oidcprovider.ClientToNotify) { saw(deleted()) })}
			},
			end: ends,
		},
		{
			name: "before a revoked grant is reported",
			opts: func(deleted func() bool, saw func(bool)) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithSecurityEvents(func(context.Context, event.Event) { saw(deleted()) })}
			},
			end: ends,
		},
		{
			name: "before a sink and a log handler that both panic can end the call",
			opts: func(deleted func() bool, saw func(bool)) []oidcprovider.Option {
				return []oidcprovider.Option{
					oidcprovider.WithSecurityEvents(func(context.Context, event.Event) {
						saw(deleted())
						panic("in the sink")
					}),
					oidcprovider.WithLogger(slog.New(onRecord{text: "panicked", act: func() { panic("in the log handler") }})),
				}
			},
			end: func(t *testing.T, x *ending) {
				t.Helper()
				assert.Panics(t, func() { x.end(t.Context(), t, "billing-web") })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			memory, err := oidcprovider.NewMemoryBrowserSessionStore()
			require.NoError(t, err)
			var deletes atomic.Int32
			browsers := &hookedBrowsers{BrowserSessionStore: memory, sawDelete: func(context.Context) { deletes.Add(1) }}
			var seen, deletedFirst atomic.Int32
			opts := tc.opts(func() bool { return deletes.Load() > 0 }, func(was bool) {
				seen.Add(1)
				if was {
					deletedFirst.Add(1)
				}
			})
			delivered := &logoutRecorder{}
			x := newEnding(t, oneClient(), nil, append(opts, oidcprovider.WithBrowserSessionStore(browsers), oidcprovider.WithLogoutDelivery(delivered))...)

			tc.end(t, x)
			drained(t, x.p)

			require.NotZero(t, seen.Load())
			assert.Equal(t, seen.Load(), deletedFirst.Load(), "the sessions had gone by then")
			assert.Len(t, delivered.handed(), 1, "and the client was still told")
		})
	}
}

// TestProvider_BackChannelDelivery_ReportCannotHoldShutdown pins Shutdown's promise to its context against
// what its reports run: it returns at that context's end, non-nil, and a later one sees them finish.
func TestProvider_BackChannelDelivery_ReportCannotHoldShutdown(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opt  func(release <-chan struct{}) oidcprovider.Option
	}

	cases := []testCase{
		{
			name: "a slow log handler",
			opt: func(<-chan struct{}) oidcprovider.Option {
				return onFailureRecord(func() { time.Sleep(time.Second) })
			},
		},
		{
			name: "a log handler that does not return",
			opt:  func(release <-chan struct{}) oidcprovider.Option { return onFailureRecord(func() { <-release }) },
		},
		{
			name: "a sink that does not return",
			opt: func(release <-chan struct{}) oidcprovider.Option {
				return atFailedDelivery(func() { <-release })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				g := newGate(true)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 8), tc.opt(release))
				for range 4 {
					x.end(t.Context(), t, "billing-web")
				}
				synctest.Wait()

				bounded, stop := context.WithTimeout(t.Context(), time.Second)
				defer stop()
				started := time.Now()
				require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded)
				assert.Equal(t, time.Second, time.Since(started), "Shutdown kept to its context")

				close(release)
				require.NoError(t, x.p.Shutdown(t.Context()), "and nil means the reports have finished")
				assert.Equal(t, []string{"shutdown", "shutdown", "shutdown", "shutdown"}, x.reasons(), "none of them lost")
			})
		})
	}
}

// TestProvider_BackChannelDelivery_ReportCannotKeepAWorker pins that a report that never returns leaves the
// pool at work, as its godoc promises of anything a consumer's code does.
func TestProvider_BackChannelDelivery_ReportCannotKeepAWorker(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opt  func(release <-chan struct{}) oidcprovider.Option
	}

	cases := []testCase{
		{
			name: "a log handler",
			opt:  func(release <-chan struct{}) oidcprovider.Option { return onFailureRecord(func() { <-release }) },
		},
		{
			name: "a sink",
			opt: func(release <-chan struct{}) oidcprovider.Option {
				return atFailedDelivery(func() { <-release })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var calls atomic.Int32
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDeliveryPool(1, 8), tc.opt(release),
					oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
						calls.Add(1)

						return errOutage
					})))

				x.end(t.Context(), t, "billing-web")
				x.end(t.Context(), t, "billing-web")
				time.Sleep(time.Minute)
				synctest.Wait()
				assert.Equal(t, int32(2), calls.Load(), "the report kept the only worker")

				close(release)
				require.NoError(t, x.p.Shutdown(t.Context()))
			})
		})
	}
}

// fillQueue takes a lone worker and the one place of its queue, so that each end after it is a drop.
func fillQueue(t *testing.T, x *ending, g *gate) {
	t.Helper()

	x.end(t.Context(), t, "billing-web")
	synctest.Wait()
	require.Equal(t, int64(1), g.entered.Load())
	x.end(t.Context(), t, "billing-web")
}

// countsOf adds up the records that say how many failures lost their log line, and how many their event.
func countsOf(t *testing.T, logged string) (records, events int) {
	t.Helper()

	return lostCount(t, logged, "lost_records="), lostCount(t, logged, "lost_events=")
}

// lostCount adds up one field of the records that say how much found no room.
func lostCount(t *testing.T, logged, prefix string) int {
	t.Helper()

	total := 0
	for line := range strings.Lines(logged) {
		if !strings.Contains(line, "found no room") {
			continue
		}
		for field := range strings.FieldsSeq(line) {
			if rest, ok := strings.CutPrefix(field, prefix); ok {
				n, err := strconv.Atoi(rest)
				require.NoError(t, err)
				total += n
			}
		}
	}

	return total
}

// The bound on reports, as the godoc states it: 64 goroutines at a sink and 1024 reports waiting for one.
const (
	reportsAtASink = 64
	reportsWaiting = 1024
)

// TestProvider_BackChannelDelivery_LogLinesOutliveAHungSink pins the stated limit of a sink that does not
// return: it holds at most its bound, what finds no room loses its event and keeps its log line, and how
// many is logged.
func TestProvider_BackChannelDelivery_LogLinesOutliveAHungSink(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const over = 5
		release := make(chan struct{})
		var entered, running, peak atomic.Int64
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
			atFailedDelivery(func() {
				entered.Add(1)
				now := running.Add(1)
				for {
					was := peak.Load()
					if now <= was || peak.CompareAndSwap(was, now) {
						break
					}
				}
				<-release
				running.Add(-1)
			}))
		fillQueue(t, x, g)

		// One at a time, so that this is about the sink: a burst outrunning the log handler has its own limit.
		for range reportsAtASink + reportsWaiting + over {
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
		}

		assert.Equal(t, int64(reportsAtASink), peak.Load(), "no more than its bound at the sink")
		assert.Equal(t, reportsAtASink+reportsWaiting+over, strings.Count(x.logs.String(), aFailedDelivery), "every failure is logged")
		records, events := countsOf(t, x.logs.String())
		assert.Zero(t, records)
		assert.Equal(t, over, events, "and those with no event are counted")

		close(release)
		close(g.open)
		require.NoError(t, x.p.Shutdown(t.Context()))
		assert.Equal(t, int64(reportsAtASink+reportsWaiting), entered.Load(), "and what waited was reported")
	})
}

// TestProvider_BackChannelDelivery_HungLogHandlerLosesTheNewest pins the other half of the limit: a log
// handler that does not return holds the log lines, the newest past the bound are lost, and how many is
// the first thing it is told once it returns.
func TestProvider_BackChannelDelivery_HungLogHandlerLosesTheNewest(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const over = 5
		release := make(chan struct{})
		logs := &lockedBuffer{}
		handler := slog.NewTextHandler(logs, nil)
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
			oidcprovider.WithLogger(slog.New(heldHandler{Handler: handler, release: release})))
		fillQueue(t, x, g)

		started := time.Now()
		x.end(t.Context(), t, "billing-web") // What the handler holds, once its goroutine has taken it.
		synctest.Wait()
		for range reportsWaiting + over {
			x.end(t.Context(), t, "billing-web")
		}
		assert.Zero(t, time.Since(started), "no end waited")
		synctest.Wait()
		assert.Empty(t, x.reasons(), "the handler holds the first")

		close(release)
		close(g.open)
		require.NoError(t, x.p.Shutdown(t.Context()))

		assert.Len(t, x.reasons(), 1+reportsWaiting, "the oldest are kept")
		assert.Equal(t, 1+reportsWaiting, strings.Count(logs.String(), aFailedDelivery))
		records, events := countsOf(t, logs.String())
		assert.Equal(t, over, records, "and the newest are counted")
		assert.Zero(t, events)
	})
}

// heldHandler holds every record until it is released.
type heldHandler struct {
	slog.Handler
	release <-chan struct{}
}

// Handle implements slog.Handler.
func (h heldHandler) Handle(ctx context.Context, r slog.Record) error {
	<-h.release

	return h.Handler.Handle(ctx, r)
}

// TestProvider_BackChannelDelivery_FullQueueAtShutdown pins that none of a full queue is lost to the bound on
// reports, however long the sink and the log handler take: Shutdown has nothing else to do with it, and
// the queue's bound already holds it.
func TestProvider_BackChannelDelivery_FullQueueAtShutdown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const queue = reportsWaiting + 300 // More than the bound on reports could hold.
		release := make(chan struct{})
		var log eventLog
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, queue),
			oidcprovider.WithSecurityEvents(func(ctx context.Context, e event.Event) {
				if e.Name == event.LogoutDeliveryFailed {
					<-release
				}
				log.sink(ctx, e)
			}))
		x.end(t.Context(), t, "billing-web")
		synctest.Wait()
		for range queue {
			x.end(t.Context(), t, "billing-web")
		}

		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded)
		synctest.Wait()

		close(release)
		require.NoError(t, x.p.Shutdown(t.Context()))
		assert.Len(t, x.reasons(), 1+queue)
		assert.Len(t, named(log.all(), event.LogoutDeliveryFailed), 1+queue, "every one has its event")
		records, events := countsOf(t, x.logs.String())
		assert.Zero(t, records+events, "and nothing is counted as lost")
	})
}

// TestProvider_BackChannelDelivery_NilMeansNoReportIsLeft pins what Shutdown's nil says when an end comes
// after it: the drop's report is one more goroutine, and the next Shutdown waits for it.
func TestProvider_BackChannelDelivery_NilMeansNoReportIsLeft(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(&logoutRecorder{}), onFailureRecord(func() { <-release }))
		require.NoError(t, x.p.Shutdown(t.Context()))

		x.end(t.Context(), t, "billing-web")
		synctest.Wait()

		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded, "a report is still running")

		close(release)
		require.NoError(t, x.p.Shutdown(t.Context()))
		assert.Equal(t, []string{"shutdown"}, x.reasons())
	})
}

// TestProvider_BackChannelDelivery_LongerBound pins that a bound longer than the outbound client's own default
// is the one a delivery is held to, and ends as the bound's.
func TestProvider_BackChannelDelivery_LongerBound(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		hung := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()

			return nil, r.Context().Err()
		})
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDeliveryTimeout(30*time.Second),
			oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(&http.Client{Transport: hung})))
		x.end(t.Context(), t, "billing-web")

		time.Sleep(30*time.Second - time.Nanosecond)
		synctest.Wait()
		assert.Empty(t, x.reasons(), "the post ended before the bound the consumer chose")

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		assert.Equal(t, []string{"timeout"}, x.reasons())
		require.NoError(t, x.p.Shutdown(t.Context()))
	})
}

// TestProvider_BackChannelDelivery_Verdict pins what a worker comes to in the ties a delivery's goroutine and
// its context can arrive in. Each row runs often, as a select chooses at random among what is ready.
func TestProvider_BackChannelDelivery_Verdict(t *testing.T) {
	t.Parallel()

	live := func(ctx context.Context) (context.Context, context.CancelFunc) { return context.WithCancel(ctx) }
	stopped := func(ctx context.Context) (context.Context, context.CancelFunc) {
		ended, cancel := context.WithCancel(ctx)
		cancel()

		return ended, cancel
	}
	expired := func(ctx context.Context) (context.Context, context.CancelFunc) {
		return context.WithDeadline(ctx, time.Now().Add(-time.Hour))
	}
	failure := func(reason string) *oidcprovider.LogoutFailure { return &oidcprovider.LogoutFailure{Reason: reason} }

	type testCase struct {
		name     string
		ctx      func(context.Context) (context.Context, context.CancelFunc)
		posting  bool
		answer   *oidcprovider.LogoutFailure
		answered bool
		reason   string
		cutOff   bool
	}

	cases := []testCase{
		{name: "a success before the end of anything", ctx: live, posting: true, answered: true},
		{name: "a failure before the end of anything", ctx: live, posting: true, answer: failure("post"), answered: true, reason: "post"},
		{name: "a success arriving together with the bound is no timeout", ctx: expired, posting: true, answered: true},
		{name: "a success arriving together with Shutdown is no failure", ctx: stopped, posting: true, answered: true},
		{name: "no answer at the bound", ctx: expired, posting: true, reason: "timeout"},
		{name: "no answer at the bound, before the token left", ctx: expired, reason: "timeout"},
		{name: "a post's error at the bound", ctx: expired, posting: true, answer: failure("post"), answered: true, reason: "timeout"},
		{name: "a 500 arriving together with the bound", ctx: expired, posting: true, answer: failure("status"), answered: true, reason: "status"},
		{name: "no answer at Shutdown, with the token on its way", ctx: stopped, posting: true, reason: "shutdown"},
		{name: "no answer at Shutdown, before the token left", ctx: stopped, cutOff: true},
		{name: "a post's error at Shutdown", ctx: stopped, posting: true, answer: failure("post"), answered: true, reason: "shutdown"},
		{name: "a consumer's delivery's error at Shutdown", ctx: stopped, posting: true, answer: failure("delivery"), answered: true, reason: "shutdown"},
		{name: "a registry's error at Shutdown", ctx: stopped, answer: failure("client"), answered: true, cutOff: true},
		{name: "a signature's error at Shutdown", ctx: stopped, answer: failure("sign"), answered: true, cutOff: true},
		{name: "a 500 arriving together with Shutdown", ctx: stopped, posting: true, answer: failure("status"), answered: true, reason: "status"},
		{name: "a panic arriving together with Shutdown", ctx: stopped, posting: true, answer: failure("panic"), answered: true, reason: "panic"},
		{name: "a goroutine ending together with Shutdown", ctx: stopped, answer: failure("goexit"), answered: true, reason: "goexit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := tc.ctx(t.Context())
			defer cancel()
			for range 200 {
				reason, cutOff := oidcprovider.JudgeLogoutAttemptForTest(ctx, tc.posting, tc.answer, tc.answered)
				require.Equal(t, tc.reason, reason)
				require.Equal(t, tc.cutOff, cutOff)
			}
		})
	}
}

// TestProvider_BackChannelDelivery_TakenAsShutdownStops pins that a job a worker took just as Shutdown cut
// everything off is not started, and is reported as what it is: a client not told.
func TestProvider_BackChannelDelivery_TakenAsShutdownStops(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g))
		x.end(t.Context(), t, "billing-web")
		synctest.Wait()

		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded)
		synctest.Wait()
		require.Equal(t, []string{"shutdown"}, x.reasons())

		x.p.AttemptLogoutForTest(t.Context(), oidcprovider.ClientToNotify{ClientID: "billing-web", User: "u-1"})
		synctest.Wait()

		assert.Equal(t, []string{"shutdown", "shutdown"}, x.reasons())
		assert.Equal(t, int64(1), g.entered.Load(), "and it was not started")
		require.NoError(t, x.p.Shutdown(t.Context()))
	})
}

// TestProvider_BackChannelDelivery_ReportsAreIsolated pins that a report ending its goroutine costs the reports
// after it nothing, on either of the goroutines reports run on.
func TestProvider_BackChannelDelivery_ReportsAreIsolated(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		end  func()
		// opt runs act in what a row is about.
		opt func(act func()) oidcprovider.Option
	}

	cases := []testCase{
		{name: "a log handler panicking", end: func() { panic("in the handler") }, opt: onFailureRecord},
		{name: "a log handler ending its goroutine", end: runtime.Goexit, opt: onFailureRecord},
		{name: "a sink ending its goroutine", end: runtime.Goexit, opt: atFailedDelivery},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				const failures = 3
				var acts atomic.Int32
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDeliveryPool(1, 8), tc.opt(func() {
					acts.Add(1)
					tc.end()
				}), oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error { return errOutage })))

				for range failures {
					x.end(t.Context(), t, "billing-web")
				}
				require.NoError(t, x.p.Shutdown(t.Context()))

				assert.Equal(t, int32(failures), acts.Load(), "each came to it, and nothing was lost")
				assert.Len(t, x.reasons(), failures)
			})
		})
	}
}

// TestProvider_BackChannelDelivery_NoSinkReadsNoClient pins that with no sink a failure costs no read of
// the client, as what reads it serves only the event.
func TestProvider_BackChannelDelivery_NoSinkReadsNoClient(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var reads atomic.Int32
		registry := NewMockClientRegistry(gomock.NewController(t))
		registry.EXPECT().Client(gomock.Any(), "billing-web").DoAndReturn(
			func(context.Context, string) (*oidcprovider.RegisteredClient, error) {
				reads.Add(1)

				return nil, oidcprovider.ErrClientNotFound
			}).AnyTimes()
		x := newEnding(t, nil, registry)
		require.NoError(t, x.p.Shutdown(t.Context()))
		reads.Store(0)

		x.end(t.Context(), t, "billing-web")
		synctest.Wait()

		assert.Equal(t, []string{"shutdown"}, x.reasons())
		assert.Zero(t, reads.Load())
	})
}

// heldAtSinkLookup is a caller's context that, once armed, holds the next look for a chain's sink until it is
// released. A failed delivery's report looks for one between handing on its log line and its event, so this
// stops a report at that point, and whatever is meant to race it can be run there on purpose.
type heldAtSinkLookup struct {
	context.Context //nolint:containedctx // what it holds is a lookup on this context

	armed   atomic.Bool
	release chan struct{}
}

func newHeldAtSinkLookup(ctx context.Context) *heldAtSinkLookup {
	return &heldAtSinkLookup{Context: ctx, release: make(chan struct{})}
}

// Value implements context.Context.
func (c *heldAtSinkLookup) Value(key any) any {
	if strings.Contains(fmt.Sprintf("%T", key), "eventsink") && c.armed.CompareAndSwap(true, false) {
		<-c.release
	}

	return c.Context.Value(key)
}

// failuresOnChain is ctx with a chain's sink that keeps each failed delivery's event in log, once release says.
// A nil release holds nothing.
func failuresOnChain(ctx context.Context, log *eventLog, release <-chan struct{}) context.Context {
	return eventsink.With(ctx, func(ctx context.Context, e event.Event) {
		if e.Name != event.LogoutDeliveryFailed {
			return
		}
		if release != nil {
			<-release
		}
		log.sink(ctx, e)
	})
}

// TestProvider_BackChannelDelivery_NilCoversEveryReport pins that Shutdown's nil means every report has been
// made, on two paths where no worker, call or report goroutine is left to say one is still to come.
func TestProvider_BackChannelDelivery_NilCoversEveryReport(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// reach runs the provider up to where a report is held, on held. What held wraps holds nothing.
		reach      func(t *testing.T, x *ending, held *heldAtSinkLookup)
		wantEvents int
	}

	cases := []testCase{
		{
			name: "a drop whose log line is out and whose event is not",
			reach: func(t *testing.T, x *ending, held *heldAtSinkLookup) {
				t.Helper()
				require.NoError(t, x.p.Shutdown(t.Context()))
				held.armed.Store(true)
				go x.end(held, t, "billing-web")
				synctest.Wait()
				assert.Equal(t, []string{"shutdown"}, x.reasons(), "its log line is out")
			},
			wantEvents: 1,
		},
		{
			name: "a queue another Shutdown has taken and is still reporting",
			reach: func(t *testing.T, x *ending, held *heldAtSinkLookup) {
				t.Helper()
				x.end(held.Context, t, "billing-web")
				synctest.Wait()
				x.end(held, t, "billing-web")
				held.armed.Store(true)

				bounded, stop := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(stop)
				go func() { _ = x.p.Shutdown(bounded) }()
				time.Sleep(time.Second)
				synctest.Wait()
				assert.Equal(t, []string{"shutdown", "shutdown"}, x.reasons(), "what it cut off and took are logged")
			},
			wantEvents: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var log eventLog
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(newGate(true)), oidcprovider.WithLogoutDeliveryPool(1, 1))
				held := newHeldAtSinkLookup(failuresOnChain(t.Context(), &log, nil))
				tc.reach(t, x, held)

				bounded, stop := context.WithTimeout(t.Context(), time.Second)
				defer stop()
				err := x.p.Shutdown(bounded)
				close(held.release)
				require.ErrorIs(t, err, context.DeadlineExceeded, "a report is still to be made")

				require.NoError(t, x.p.Shutdown(t.Context()))
				assert.Len(t, named(log.all(), event.LogoutDeliveryFailed), tc.wantEvents, "and nil is said once it has been")
			})
		})
	}
}

// TestProvider_BackChannelDelivery_CutOffPostHasRoomAtShutdown pins that what Shutdown finds queued and a post
// it cuts off lose nothing to lanes already full: each of those two has room of its own.
func TestProvider_BackChannelDelivery_CutOffPostHasRoomAtShutdown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var made atomic.Int32
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
			atFailedDelivery(func() {
				<-release
				made.Add(1)
			}))
		fillQueue(t, x, g)
		for range reportsAtASink + reportsWaiting {
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
		}

		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded)
		synctest.Wait()
		close(release)
		require.NoError(t, x.p.Shutdown(t.Context()))

		_, events := countsOf(t, x.logs.String())
		assert.Zero(t, events, "nothing is counted as lost")
		assert.Equal(t, int32(reportsAtASink+reportsWaiting+2), made.Load(), "the queued one and the cut-off post have their events")
	})
}

// TestProvider_BackChannelDelivery_ShutdownRoomIsNotADropsRoom pins that "room of its own" holds against an end
// arriving during the flush: the drop is the newest and finds none, and what Shutdown found queued keeps its
// log line and its event.
func TestProvider_BackChannelDelivery_ShutdownRoomIsNotADropsRoom(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const later = 8
		release := make(chan struct{})
		logs := &lockedBuffer{}
		var log eventLog
		g := newGate(true)
		clients := append(oneClient(), listeningClient("audit-web", billingBackChannel))
		x := newEnding(t, clients, nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 2),
			oidcprovider.WithLogger(slog.New(heldHandler{Handler: slog.NewTextHandler(logs, nil), release: release})))
		base := failuresOnChain(t.Context(), &log, release)
		held := newHeldAtSinkLookup(base)

		x.end(base, t, "billing-web")
		synctest.Wait()
		x.end(held, t, "billing-web")
		x.end(base, t, "audit-web") // Queued behind the one the flush will be held at.
		held.armed.Store(true)
		for range reportsAtASink + reportsWaiting {
			x.end(base, t, "billing-web")
			synctest.Wait()
		}

		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		first := make(chan error, 1)
		go func() { first <- x.p.Shutdown(bounded) }()
		time.Sleep(time.Second)
		synctest.Wait()

		for range later {
			x.end(base, t, "billing-web")
		}
		close(held.release)
		require.ErrorIs(t, <-first, context.DeadlineExceeded)
		close(release)
		require.NoError(t, x.p.Shutdown(t.Context()))

		told := []string{}
		for _, f := range x.failed() {
			told = append(told, f.ClientID)
		}
		assert.Contains(t, told, "audit-web", "its log line had room")
		clientsReported := []string{}
		for _, e := range named(log.all(), event.LogoutDeliveryFailed) {
			clientsReported = append(clientsReported, e.Client)
		}
		assert.Contains(t, clientsReported, "audit-web", "and so did its event")
	})
}

// onLostCount is a log handler running act at each saying of how much found no room, and keeping every record
// it returns from.
type onLostCount struct {
	slog.Handler
	said *atomic.Int32
	act  func(n int32)
}

// Handle implements slog.Handler.
func (h onLostCount) Handle(ctx context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "found no room") {
		h.act(h.said.Add(1))
	}

	return h.Handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h onLostCount) WithAttrs([]slog.Attr) slog.Handler { return h }

// WithGroup implements slog.Handler.
func (h onLostCount) WithGroup(string) slog.Handler { return h }

// TestProvider_BackChannelDelivery_LostCountIsSaidOnce pins that how many found no room is said once, however
// the log handler takes it: one that fails to take it has it offered again, a limited number of times, so
// that a handler that always fails cannot keep a goroutine turning.
func TestProvider_BackChannelDelivery_LostCountIsSaidOnce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(n int32)
		assert func(t *testing.T, offered int32, events int)
	}

	const over = 1

	cases := []testCase{
		{
			name: "by a handler that takes it",
			act:  func(int32) {},
			assert: func(t *testing.T, offered int32, events int) {
				t.Helper()
				assert.Equal(t, int32(1), offered)
				assert.Equal(t, over, events)
			},
		},
		{
			name: "after a handler panicked on it once",
			act: func(n int32) {
				if n == 1 {
					panic("in the handler")
				}
			},
			assert: func(t *testing.T, offered int32, events int) {
				t.Helper()
				assert.Equal(t, int32(2), offered)
				assert.Equal(t, over, events)
			},
		},
		{
			name: "after a handler ended its goroutine on it once",
			act: func(n int32) {
				if n == 1 {
					runtime.Goexit()
				}
			},
			assert: func(t *testing.T, offered int32, events int) {
				t.Helper()
				assert.Equal(t, int32(2), offered)
				assert.Equal(t, over, events)
			},
		},
		{
			name: "or not at all, by a handler that always panics, after a few tries",
			act:  func(int32) { panic("in the handler") },
			assert: func(t *testing.T, offered int32, events int) {
				t.Helper()
				assert.Equal(t, int32(3), offered)
				assert.Zero(t, events)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				stuck := make(chan struct{})
				defer close(stuck)
				logs := &lockedBuffer{}
				var said atomic.Int32
				g := newGate(true)
				x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
					atFailedDelivery(func() { <-release }),
					oidcprovider.WithLogger(slog.New(onLostCount{Handler: slog.NewTextHandler(logs, nil), said: &said, act: func(n int32) {
						if n > 8 { // Said over and over: stop here, so that this fails rather than spins.
							<-stuck
						}
						tc.act(n)
					}})))
				fillQueue(t, x, g)
				for range reportsAtASink + reportsWaiting + over {
					x.end(t.Context(), t, "billing-web")
					synctest.Wait()
				}
				close(release)
				close(g.open)

				bounded, stop := context.WithTimeout(t.Context(), time.Minute)
				defer stop()
				require.NoError(t, x.p.Shutdown(bounded))
				_, events := countsOf(t, logs.String())
				tc.assert(t, said.Load(), events)
			})
		})
	}
}

// TestProvider_BackChannelDelivery_LostCountWaitsForTheNextBurst pins that a count the handler would not take
// is kept and said with the next, rather than dropped when the tries run out.
func TestProvider_BackChannelDelivery_LostCountWaitsForTheNextBurst(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const over = 1
		release := make(chan struct{})
		logs := &lockedBuffer{}
		var said atomic.Int32
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
			atFailedDelivery(func() { <-release }),
			oidcprovider.WithLogger(slog.New(onLostCount{Handler: slog.NewTextHandler(logs, nil), said: &said, act: func(n int32) {
				if n <= 3 {
					panic("in the handler")
				}
			}})))
		fillQueue(t, x, g)
		for range reportsAtASink + reportsWaiting + over {
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
		}
		assert.Equal(t, int32(3), said.Load(), "it has run out of tries")
		_, events := countsOf(t, logs.String())
		assert.Zero(t, events)

		x.end(t.Context(), t, "billing-web")
		synctest.Wait()

		_, events = countsOf(t, logs.String())
		assert.Equal(t, over+1, events, "the next burst says them all")
		close(release)
		close(g.open)
		require.NoError(t, x.p.Shutdown(t.Context()))
	})
}

// TestProvider_BackChannelDelivery_LostCountGoesOnBeingSaid pins that the tries are for a handler that fails: one
// that takes each count goes on being told, however many come before its goroutine next has nothing to do.
func TestProvider_BackChannelDelivery_LostCountGoesOnBeingSaid(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const rounds = 3 // With the first, one count past the tries, and nothing after it to say it instead.
		release := make(chan struct{})
		next := make(chan struct{}, 1+rounds)
		logs := &lockedBuffer{}
		var said atomic.Int32
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1),
			atFailedDelivery(func() { <-release }),
			oidcprovider.WithLogger(slog.New(onLostCount{Handler: slog.NewTextHandler(logs, nil), said: &said, act: func(int32) { <-next }})))
		fillQueue(t, x, g)
		for range reportsAtASink + reportsWaiting {
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
		}

		x.end(t.Context(), t, "billing-web") // Lost, and the handler is held at saying so.
		synctest.Wait()
		for range rounds {
			x.end(t.Context(), t, "billing-web") // Lost too, so the goroutine has more to say once it is let go.
			synctest.Wait()
			next <- struct{}{}
			synctest.Wait()
		}
		next <- struct{}{}
		close(release)
		close(g.open)
		require.NoError(t, x.p.Shutdown(t.Context()))

		_, events := countsOf(t, logs.String())
		assert.Equal(t, 1+rounds, events)
	})
}

// TestProvider_BackChannelDelivery_LostEventIsSaidWithTheLogIdle pins that a lost event gets said when nothing
// else is logging: its own log line has already gone, and the goroutine that logged it has left.
func TestProvider_BackChannelDelivery_LostEventIsSaidWithTheLogIdle(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var log eventLog
		g := newGate(true)
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1))
		base := failuresOnChain(t.Context(), &log, release)
		held := newHeldAtSinkLookup(base)
		fillQueue(t, x, g)
		for range reportsAtASink + reportsWaiting {
			x.end(base, t, "billing-web")
			synctest.Wait()
		}

		held.armed.Store(true)
		ended := make(chan struct{})
		go func() {
			defer close(ended)
			x.end(held, t, "billing-web")
		}()
		synctest.Wait()
		_, events := countsOf(t, x.logs.String())
		assert.Zero(t, events, "the log line went, and the goroutine that logged it has left")

		close(held.release)
		<-ended
		synctest.Wait()
		_, events = countsOf(t, x.logs.String())
		assert.Equal(t, 1, events)

		close(release)
		close(g.open)
		require.NoError(t, x.p.Shutdown(t.Context()))
	})
}

// TestProvider_BackChannelDelivery_LostRecordsCountsFailures pins what lost_records counts: failures that lost
// their log line. A note of how a delivery ended is no failure's report, and is counted apart if it is lost.
func TestProvider_BackChannelDelivery_LostRecordsCountsFailures(t *testing.T) {
	t.Parallel()

	t.Run("a late line lost is a note, and its count survives a panic", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			late := make(chan struct{})
			var calls, said atomic.Int32
			logs := &lockedBuffer{}
			handler := onLostCount{Handler: slog.NewTextHandler(logs, nil), said: &said, act: func(n int32) {
				if n == 1 {
					panic("in the handler")
				}
			}}
			x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDeliveryPool(1, 1), oidcprovider.WithLogoutDeliveryTimeout(time.Second),
				oidcprovider.WithLogger(slog.New(heldHandler{Handler: handler, release: release})),
				oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
					if calls.Add(1) == 1 {
						<-late
						panic("after its bound")
					}

					return nil
				})))
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
			x.end(t.Context(), t, "billing-web") // Queued, and delivered once the bound frees the worker.
			x.end(t.Context(), t, "billing-web") // Dropped, and its record is what the handler holds.
			synctest.Wait()
			for range reportsWaiting - 1 {
				x.end(t.Context(), t, "billing-web")
			}

			time.Sleep(time.Second) // The bound ends the call, and that failure's record takes the last place.
			synctest.Wait()
			close(late) // The call ends after its bound, which is noted, and that finds no room.
			synctest.Wait()
			close(release)
			require.NoError(t, x.p.Shutdown(t.Context()))

			records, _ := countsOf(t, logs.String())
			assert.Zero(t, records, "no failure lost its record")
			assert.Equal(t, 1, lostCount(t, logs.String(), "lost_notes="), "and the note is counted apart")
		})
	})

	t.Run("a late line after Shutdown has room, however many Shutdowns came", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			late := make(chan struct{})
			logs := &lockedBuffer{}
			x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDeliveryPool(1, 1),
				oidcprovider.WithLogger(slog.New(heldHandler{Handler: slog.NewTextHandler(logs, nil), release: release})),
				oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
					<-late
					panic("after Shutdown cut it off")
				})))
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
			x.end(t.Context(), t, "billing-web") // Queued.
			x.end(t.Context(), t, "billing-web") // Dropped, and its record is what the handler holds.
			synctest.Wait()
			for range reportsWaiting {
				x.end(t.Context(), t, "billing-web")
			}

			for range 2 {
				bounded, stop := context.WithTimeout(t.Context(), time.Second)
				require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded)
				stop()
				synctest.Wait()
			}
			close(late)
			synctest.Wait()
			close(release)
			require.NoError(t, x.p.Shutdown(t.Context()))

			assert.Contains(t, logs.String(), "after its bound")
			records, _ := countsOf(t, logs.String())
			assert.Zero(t, records+lostCount(t, logs.String(), "lost_notes="), "and nothing is counted as lost")
		})
	})

	t.Run("a cut-off read's note has room at Shutdown", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			logs := &lockedBuffer{}
			memory, err := oidcprovider.NewMemoryRegistry(oneClient())
			require.NoError(t, err)
			registry := &registryAnswering{ClientRegistry: memory, answer: func(ctx context.Context) error {
				<-ctx.Done()

				return ctx.Err()
			}}
			x := newEnding(t, nil, registry, oidcprovider.WithLogoutDeliveryPool(1, 1), oidcprovider.WithLogoutDelivery(&logoutRecorder{}),
				oidcprovider.WithLogoutDeliveryTimeout(time.Hour),
				oidcprovider.WithLogger(slog.New(heldHandler{Handler: slog.NewTextHandler(logs, nil), release: release})))
			registry.armed.Store(true)
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
			x.end(t.Context(), t, "billing-web") // Queued.
			x.end(t.Context(), t, "billing-web") // Dropped, and its record is what the handler holds.
			synctest.Wait()
			for range reportsWaiting {
				x.end(t.Context(), t, "billing-web")
			}

			bounded, stop := context.WithTimeout(t.Context(), time.Second)
			defer stop()
			require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded)
			synctest.Wait()
			close(release)
			require.NoError(t, x.p.Shutdown(t.Context()))

			assert.Contains(t, logs.String(), "shutdown cut off")
			records, _ := countsOf(t, logs.String())
			assert.Zero(t, records+lostCount(t, logs.String(), "lost_notes="), "and nothing is counted as lost")
		})
	})
}
