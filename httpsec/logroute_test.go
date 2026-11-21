package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/pkg/clock"
)

// TestLogRoute_Guards pins where a guard writes the record of a refusal whose
// classification aborted. A guard holds no logger of its own: the record goes
// to the logger of the chain handling the request, read from the request's
// context, else to slog.Default() as it is when the record is written.
func TestLogRoute_Guards(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name    string
		chain   bool
		handler bool
		assert  func(t *testing.T, chainRecords, defaultRecords []slog.Record)
	}

	onChain := func(t *testing.T, chainRecords, defaultRecords []slog.Record) {
		t.Helper()
		assert.Len(t, abortRecords(chainRecords), 1, "the record did not land on the chain's logger")
		assert.Empty(t, abortRecords(defaultRecords), "the record landed on the default")
	}
	onDefault := func(t *testing.T, chainRecords, defaultRecords []slog.Record) {
		t.Helper()
		assert.Empty(t, abortRecords(chainRecords))
		assert.Len(t, abortRecords(defaultRecords), 1, "the record did not land on the default")
	}

	cases := []testCase{
		{name: "no option, inside a configured chain, the default answer", chain: true, assert: onChain},
		{name: "no option, inside a configured chain, WithGuardErrorHandler", chain: true, handler: true, assert: onChain},
		{name: "no chain, the default answer", assert: onDefault},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			w := &refusalWorld{chainLogs: &capturingHandler{}}

			var guardOpts []httpsec.GuardOption
			if tc.handler {
				guardOpts = append(guardOpts, httpsec.WithGuardErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
					w.WriteHeader(http.StatusTeapot)
				}))
			}

			h := guardRefusing(t, &cycleOne{}, guardOpts...)
			if tc.chain {
				h = behindChain(t, h, w.logger(), w.securityEvents())
			}

			serveRefusalWithin(t, h, principalRequest(t.Context()))

			tc.assert(t, w.chainLogs.records(), defaultLogs.records())
		})
	}
}

// TestLogRoute_RefusalSummary pins where a sampler's suppressed-count summary
// goes. It has no request context of its own, so it goes to the logger the
// chain last resolved a record to, else to slog.Default() at that moment.
func TestLogRoute_RefusalSummary(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const summary = "httpsec: refusal logs suppressed"

	count := func(recs []slog.Record) (n int) {
		for _, r := range recs {
			if r.Message == summary {
				n++
			}
		}

		return n
	}

	cases := []struct {
		name  string
		outer bool
	}{
		{name: "no option, inside a configured chain", outer: true},
		{name: "no chain"},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			outerLogs := &capturingHandler{}

			// A refusal whose classification aborts, so the chain writes a
			// sampled record: the first is written, the second counted.
			inner, err := httpsec.New(
				httpsec.WithRefusalLogInterval(time.Hour),
				httpsec.WithClock(clock.System()),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
					return &cycleOne{}
				}), httpsec.OrderBearerToken),
			)
			require.NoError(t, err)

			h := inner.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

			if tc.outer {
				outer, err := httpsec.New(httpsec.WithLogger(slog.New(outerLogs)))
				require.NoError(t, err)

				h = outer.Middleware()(h)
			}

			for range 2 {
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/x", nil))
			}

			require.NoError(t, inner.FlushRefusalLogs())

			if tc.outer {
				assert.Equal(t, 1, count(outerLogs.records()), "the summary did not reach the chain's logger")
				assert.Zero(t, count(defaultLogs.records()), "the summary landed on the default")

				return
			}

			assert.Equal(t, 1, count(defaultLogs.records()), "the summary did not reach the default")
		})
	}
}

// TestLogRoute_SignalHub pins where the hub writes a record raised on a
// request's goroutine: the logger the request's context carries, else the
// default as it is at that moment.
func TestLogRoute_SignalHub(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	cases := []struct {
		name  string
		chain bool
	}{
		{name: "no option, inside a configured chain", chain: true},
		{name: "no chain"},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			chainLogs := &capturingHandler{}

			hub := httpsec.NewSignalHubProbe(httpsec.SignalHubSetup{Clock: clock.System(), Log: ctxlog.Routing()})

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(chainLogs))
			}

			// A name that is no signal is dropped and logged.
			require.NoError(t, hub.RaiseContext(ctx, httpsec.SignalEnvelope{User: "u-1", Name: "unknown"}))

			if tc.chain {
				assert.Len(t, chainLogs.records(), 1, "the record did not land on the chain's logger")
				assert.Empty(t, defaultLogs.records(), "the record landed on the default")

				return
			}

			assert.Len(t, defaultLogs.records(), 1, "the record did not land on the default")
		})
	}
}
