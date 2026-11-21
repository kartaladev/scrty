package fibersec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
)

// abortMessage is the constant message of the record an aborted
// classification writes.
const abortMessage = "httpsec: error classification aborted"

// selfCycleError unwraps to itself through Unwrap() error.
type selfCycleError struct{}

func (e *selfCycleError) Error() string { return "self cycle" }
func (e *selfCycleError) Unwrap() error { return e }

// listCycleError unwraps to itself through Unwrap() []error.
type listCycleError struct{}

func (e *listCycleError) Error() string   { return "list cycle" }
func (e *listCycleError) Unwrap() []error { return []error{e} }

// panickingAsError panics when asked to match a target.
type panickingAsError struct{}

func (e *panickingAsError) Error() string { return "panicking as" }
func (e *panickingAsError) As(any) bool   { panic("hostile As") }

// panickingUnwrapError panics when asked for what it wraps.
type panickingUnwrapError struct{}

func (e *panickingUnwrapError) Error() string { return "panicking unwrap" }
func (e *panickingUnwrapError) Unwrap() error { panic("hostile Unwrap") }

// panickingIsError wraps an error and panics when compared with a target.
type panickingIsError struct{ inner error }

func (e *panickingIsError) Error() string { return "panicking is" }
func (e *panickingIsError) Unwrap() error { return e.inner }
func (e *panickingIsError) Is(error) bool { panic("hostile Is") }

// consumerError is an application's own error type wrapping what it was given.
type consumerError struct{ inner error }

func (e *consumerError) Error() string { return "consumer: " + e.inner.Error() }
func (e *consumerError) Unwrap() error { return e.inner }

// wrappingNextInIs is an interceptor that wraps whatever the rest of the
// request returned in a panickingIsError, so the middleware's comparison with
// the route's own error meets a panicking Is.
func wrappingNextInIs() httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if err := next(ex); err != nil {
			return &panickingIsError{inner: err}
		}

		return nil
	})
}

// recordingHandler keeps the records slog.Default() was handed.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, r)

	return nil
}

func (h *recordingHandler) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = nil
}

func (h *recordingHandler) errorRecords() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []slog.Record

	for _, r := range h.records {
		if r.Level >= slog.LevelError {
			out = append(out, r)
		}
	}

	return out
}

// recordDefault swaps slog.Default() for a recording handler for the rest of
// the test. Tests that call it do not run in parallel.
func recordDefault(t *testing.T) *recordingHandler {
	t.Helper()

	rec := &recordingHandler{}
	prev := slog.Default()

	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

// panicStatus is what the fixture answers when the adapter panicked.
const panicStatus = 599

// serveThrough sends one request through an app with the chain built from
// opts mounted and ErrorHandler installed, whose route returns route. It fails
// the test when the request hangs, and reports whether the middleware or the
// error handler panicked.
//
// A handler and the error handler run on fasthttp's own goroutine, so a panic
// there is recovered there: by a fiber middleware around the chain, and by a
// wrapper around ErrorHandler.
func serveThrough(t *testing.T, opts []httpsec.Option, route error) (status int, panicked bool) {
	t.Helper()

	var sawPanic atomic.Bool

	app := fiber.New(fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) (out error) {
		defer func() {
			if r := recover(); r != nil {
				sawPanic.Store(true)
				fc.Status(panicStatus)

				out = nil
			}
		}()

		return fibersec.ErrorHandler(fc, err)
	}})
	app.Use(func(fc fiber.Ctx) (out error) {
		defer func() {
			if r := recover(); r != nil {
				sawPanic.Store(true)
				fc.Status(panicStatus)

				out = nil
			}
		}()

		return fc.Next()
	})
	app.Use(fibersec.Middleware(newChain(t, opts...)))
	app.Get("/orders", func(fiber.Ctx) error { return route })

	type result struct {
		status int
		err    error
	}

	done := make(chan result, 1)

	go func() {
		res, err := app.Test(
			httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil),
			fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
		if err != nil {
			done <- result{err: err}

			return
		}

		_ = res.Body.Close()
		done <- result{status: res.StatusCode}
	}()

	select {
	case r := <-done:
		require.NoError(t, r.err, "the request failed")

		return r.status, sawPanic.Load()
	case <-time.After(2 * time.Second):
		t.Fatal("the request hung")

		return 0, false
	}
}

// refusingWith is the chain option for an interceptor that refuses every
// request with err.
func refusingWith(err error) []httpsec.Option {
	return []httpsec.Option{httpsec.RegisterInterceptor(refusing(err, nil), httpsec.OrderBearerToken)}
}

// TestErrorHandler_HostileChains pins that an error, however hostile its
// chain, reaches ErrorHandler's status without hanging, panicking or writing
// more than one Error record for the request, whether a route returned it or
// the chain refused with it.
//
// It swaps slog.Default(), so it does not run in parallel.
func TestErrorHandler_HostileChains(t *testing.T) {
	rec := recordDefault(t)

	// A real refusal, as the adapter hands it to fiber, to put behind a typed nil.
	realRefusal := refusedBy(t, authorize.ErrAccessDenied)

	type testCase struct {
		name   string
		opts   []httpsec.Option
		route  error
		assert func(t *testing.T, status int, records []slog.Record)
	}

	// failsClosed is an aborted classification: 500, and one record for the
	// request, whether fibersec's walk or the core's aborted.
	failsClosed := func(t *testing.T, status int, records []slog.Record) {
		t.Helper()
		assert.Equal(t, http.StatusInternalServerError, status)
		require.Len(t, records, 1, "one request, one record")
		assert.Equal(t, abortMessage, records[0].Message)
	}

	// failsClosedInCore is a classification that passed fibersec's walk and
	// aborted in the core's: 500, and the one record the core writes.
	failsClosedInCore := failsClosed

	cases := []testCase{
		{name: "a route's cycle through Unwrap() error fails closed", route: &selfCycleError{}, assert: failsClosed},
		{name: "a route's cycle through Unwrap() []error fails closed", route: &listCycleError{}, assert: failsClosed},
		{name: "a route's panicking As fails closed", route: &panickingAsError{}, assert: failsClosed},
		{name: "a route's panicking Unwrap fails closed", route: &panickingUnwrapError{}, assert: failsClosed},
		{
			// fibersec's own walk aborts here, so its own record must carry
			// the panic's redacted attributes, as the core's does, with the
			// frames captured where the As method panicked.
			name:  "a route's panicking As is reported with the panic's type and frames",
			route: &panickingAsError{},
			assert: func(t *testing.T, status int, records []slog.Record) {
				t.Helper()
				failsClosed(t, status, records)

				attrs := map[string]string{}
				records[0].Attrs(func(a slog.Attr) bool {
					attrs[a.Key] = a.Value.String()

					return true
				})

				assert.Equal(t, "panic", attrs["reason"])
				assert.Equal(t, "string", attrs["panic_type"], "the panic's type, never its value")
				assert.Contains(t, attrs["frames"], "fibersec_test.(*panickingAsError).As", "the frames name where it panicked")

				for key, value := range attrs {
					assert.NotContains(t, value, "hostile As", "attribute %q quotes the panic's value", key)
				}
			},
		},
		{
			name:  "a chain refusal through a cycle fails closed",
			opts:  refusingWith(&selfCycleError{}),
			route: errors.New("never reached"), assert: failsClosed,
		},
		{
			name:  "a chain refusal through a list cycle fails closed",
			opts:  refusingWith(&listCycleError{}),
			route: errors.New("never reached"), assert: failsClosed,
		},
		{
			name:  "a chain refusal with a panicking Unwrap fails closed",
			opts:  refusingWith(&panickingUnwrapError{}),
			route: errors.New("never reached"), assert: failsClosed,
		},
		{
			name:  "a chain refusal with a panicking As fails closed in the core",
			opts:  refusingWith(&panickingAsError{}),
			route: errors.New("never reached"), assert: failsClosedInCore,
		},
		{
			name: "a panicking Is met while matching the route's error fails closed",
			opts: []httpsec.Option{httpsec.RegisterInterceptor(wrappingNextInIs(), httpsec.OrderBearerToken)},
			// Unrecognised by the core, so without the abort it would still be 500;
			// the record is what shows the abort was taken.
			route:  errors.New("route failed"),
			assert: failsClosed,
		},
		{
			name:  "a nil RefusalError joined ahead of a real one gives the real one's status",
			route: errors.Join((*fibersec.RefusalError)(nil), realRefusal),
			assert: func(t *testing.T, status int, records []slog.Record) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, status)
				assert.Empty(t, records)
			},
		},
		{
			name:  "a zero RefusalError a route built is answered 500",
			route: &fibersec.RefusalError{},
			assert: func(t *testing.T, status int, records []slog.Record) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, status)
				assert.Empty(t, records)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec.reset()

			status, panicked := serveThrough(t, tc.opts, tc.route)

			require.False(t, panicked, "the adapter panicked")
			tc.assert(t, status, rec.errorRecords())
		})
	}
}

// TestErrorHandler_RefusalPrecedence pins that a refusal found anywhere in an
// error is answered with the core's classification of the whole error, as it
// was before the bounded walk: a dependency outage joined with a refusal still
// reads as a failed authentication, and a refusal outranks a fiber status it
// travels with.
//
// It swaps slog.Default(), so it does not run in parallel.
func TestErrorHandler_RefusalPrecedence(t *testing.T) {
	rec := recordDefault(t)

	refusal := refusedBy(t, authorize.ErrAccessDenied)

	type testCase struct {
		name   string
		route  error
		assert func(t *testing.T, status int)
	}

	answers := func(want int) func(t *testing.T, status int) {
		return func(t *testing.T, status int) {
			t.Helper()
			assert.Equal(t, want, status)
		}
	}

	cases := []testCase{
		{name: "a refusal as the chain made it", route: refusal, assert: answers(http.StatusForbidden)},
		{name: "a wrapped refusal", route: fmt.Errorf("x: %w", refusal), assert: answers(http.StatusForbidden)},
		{
			name:   "an outage joined ahead of a refusal reads as a failed authentication",
			route:  errors.Join(authenticate.ErrUnavailable, refusal),
			assert: answers(http.StatusUnauthorized),
		},
		{
			name:   "an outage joined behind a refusal reads as a failed authentication",
			route:  errors.Join(refusal, authenticate.ErrUnavailable),
			assert: answers(http.StatusUnauthorized),
		},
		{
			name:   "a fiber status alone keeps its status",
			route:  fiber.NewError(http.StatusUnprocessableEntity),
			assert: answers(http.StatusUnprocessableEntity),
		},
		{
			name:   "a fiber status with an outage and no refusal keeps its status",
			route:  errors.Join(fiber.NewError(http.StatusUnprocessableEntity), authenticate.ErrUnavailable),
			assert: answers(http.StatusUnprocessableEntity),
		},
		{
			name:   "a refusal outranks a fiber status it is joined with",
			route:  errors.Join(fiber.NewError(http.StatusUnprocessableEntity), refusal),
			assert: answers(http.StatusForbidden),
		},
		{
			name:   "a consumer error wrapping a fiber status and a refusal gives the refusal's status",
			route:  &consumerError{inner: errors.Join(fiber.NewError(http.StatusUnprocessableEntity), refusal)},
			assert: answers(http.StatusForbidden),
		},
		{
			name: "a consumer error wrapping a fiber status, an outage and a refusal reads as a failed authentication",
			route: &consumerError{inner: errors.Join(
				fiber.NewError(http.StatusUnprocessableEntity), authenticate.ErrUnavailable, refusal)},
			assert: answers(http.StatusUnauthorized),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec.reset()

			status, panicked := serveThrough(t, nil, tc.route)

			require.False(t, panicked, "the adapter panicked")
			tc.assert(t, status)
			assert.Empty(t, rec.errorRecords())
		})
	}
}

// TestMapError_RefusalKeepsItsClassification pins that MapError answers a
// refusal the chain made with the status the chain classified it with, without
// classifying it again: a refusal whose own chain sits just under the walk's
// budget is not re-walked with the adapter's two extra links and lost to it.
func TestMapError_RefusalKeepsItsClassification(t *testing.T) {
	t.Parallel()

	// 999 links: the sentinel and 998 wrappers, inside the walk's budget of
	// 1,000. The adapter's RefusalError adds itself and its fiber status.
	deep := authorize.ErrAccessDenied
	for range 998 {
		deep = fmt.Errorf("w: %w", deep)
	}

	refusal := refusedBy(t, deep)

	status, _ := fibersec.MapError(refusal)

	assert.Equal(t, http.StatusForbidden, status)
}

// TestRefusalError_ZeroValueText pins that a RefusalError a consumer built
// without the adapter has a text, the 500 status text, instead of panicking
// in the fiber handler that reads it.
func TestRefusalError_ZeroValueText(t *testing.T) {
	t.Parallel()

	var text string

	require.NotPanics(t, func() { text = (&fibersec.RefusalError{}).Error() })
	assert.Equal(t, http.StatusText(http.StatusInternalServerError), text)
}
