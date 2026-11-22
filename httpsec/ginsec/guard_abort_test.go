package ginsec_test

// Every row of the test in this file replaces slog.Default() for its duration,
// so none of them runs in parallel, and each restores the logger it found.

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

// msgClassificationAborted is the record an aborted classification writes.
const msgClassificationAborted = "httpsec: error classification aborted"

// abortCounter counts the aborted-classification records written to it.
type abortCounter struct {
	mu sync.Mutex
	n  int
}

func (h *abortCounter) Enabled(context.Context, slog.Level) bool { return true }
func (h *abortCounter) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *abortCounter) WithGroup(string) slog.Handler            { return h }

func (h *abortCounter) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if r.Message == msgClassificationAborted {
		h.n++
	}

	return nil
}

func (h *abortCounter) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.n
}

// alwaysPanicsIs is a link whose own Is method panics for every target.
type alwaysPanicsIs struct{}

func (alwaysPanicsIs) Error() string { return "always panics" }
func (alwaysPanicsIs) Is(error) bool { panic("the link's Is panicked") }

// selectiveIs matches matches through its own Is method, and panics when
// asked about panicsOn and nothing else.
type selectiveIs struct{ matches, panicsOn error }

func (selectiveIs) Error() string { return "selective" }

func (e selectiveIs) Is(target error) bool {
	if target == e.panicsOn { //nolint:errorlint // the identity of the target asked about
		panic("the link's Is panicked")
	}

	return target == e.matches //nolint:errorlint // the identity of the target asked about
}

// TestGuard_AbortReporting pins the gin guard's reporting rule for an aborted
// classification of its refusal. The guard's own walks, the refusal's
// security event and the DPoP challenge, return their abort to the guard,
// which reports by its own configuration:
//
//   - with WithGuardErrorHandler, the guard classifies nothing, so any abort
//     writes one record to slog.Default();
//   - without it, the guard's status lookup reports its own abort, and the
//     guard writes one only when that lookup does not abort.
//
// Each row's request writes exactly one record. A cyclic chain is left out:
// gin's own Context.Error, which every gin refusal is registered with, walks
// the chain with the standard library and never returns on a cycle. That is
// gin's limit, stated in the design, and nothing the guard can stop.
func TestGuard_AbortReporting(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name    string
		err     error
		chain   []httpsec.Option
		handler bool
		written bool
		assert  func(t *testing.T, status, records int)
	}

	sink := httpsec.EnableSecurityEvents(func(context.Context, event.Event) {})
	dpop := httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "http://example.com"})

	kinds := []struct {
		name      string
		chain     []httpsec.Option
		selective error
	}{
		{
			name:      "a chain with events",
			chain:     []httpsec.Option{sink},
			selective: selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: authorize.ErrAccessDenied},
		},
		{
			name:      "a DPoP chain",
			chain:     []httpsec.Option{dpop},
			selective: selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: httpsec.ErrDPoPNonceRequired},
		},
		{
			name:      "a DPoP chain with events",
			chain:     []httpsec.Option{sink, dpop},
			selective: selectiveIs{matches: httpsec.ErrAuthenticationRequired, panicsOn: authorize.ErrAccessDenied},
		},
	}

	oneRecord := func(want int) func(t *testing.T, status, records int) {
		return func(t *testing.T, status, records int) {
			t.Helper()

			assert.Equal(t, want, status)
			assert.Equal(t, 1, records, "one record per request whose classification aborted")
		}
	}

	var cases []testCase

	for _, k := range kinds {
		errs := []struct {
			name   string
			err    error
			status int
		}{
			{name: "an Is that always panics", err: alwaysPanicsIs{}, status: http.StatusInternalServerError},
			{name: "a selective Is the lookup never meets", err: k.selective, status: http.StatusUnauthorized},
		}

		for _, e := range errs {
			cases = append(cases,
				testCase{
					name: k.name + ", " + e.name + ", the default answer", err: e.err, chain: k.chain,
					assert: oneRecord(e.status),
				},
				testCase{
					name: k.name + ", " + e.name + ", WithGuardErrorHandler", err: e.err, chain: k.chain,
					handler: true, assert: oneRecord(http.StatusTeapot),
				},
			)
		}

		// A response already written before the guard refused is not
		// classified by the default answer, so its lookup reports nothing,
		// and the guard reports the abort its own walk met in its place.
		cases = append(cases, testCase{
			name:    k.name + ", an Is that always panics, the default answer after the response was written",
			err:     alwaysPanicsIs{},
			chain:   k.chain,
			written: true,
			assert:  oneRecord(http.StatusAccepted),
		})
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaults := &abortCounter{}
			prev := slog.Default()
			slog.SetDefault(slog.New(defaults))
			t.Cleanup(func() { slog.SetDefault(prev) })

			chainLogs := &abortCounter{}

			opts, _ := authenticated(t)
			opts = append(append(opts, httpsec.WithLogger(slog.New(chainLogs))), tc.chain...)

			var guardOpts []ginsec.GuardOption
			if tc.handler {
				guardOpts = append(guardOpts, ginsec.WithGuardErrorHandler(func(gc *gin.Context, _ error) {
					gc.Status(http.StatusTeapot)
				}))
			}

			g := mustGuards(t, deciding(t, tc.err), guardOpts...)

			eng := gin.New()
			eng.Use(ginsec.Middleware(newChain(t, opts...)))

			if tc.written {
				eng.Use(func(gc *gin.Context) {
					gc.Status(http.StatusAccepted)
					gc.Writer.WriteHeaderNow()
					gc.Next()
				})
			}

			eng.GET("/invoices", g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
				func(*gin.Context) { t.Error("the route ran behind a guard's refusal") })

			status := serveWithin(t, eng, bearerRequest(t.Context(), http.MethodGet, "http://example.com/invoices"))

			tc.assert(t, status, defaults.count()+chainLogs.count())
		})
	}
}

// serveWithin serves req on eng and fails the row when it does not return
// within two seconds or lets a panic escape.
func serveWithin(t *testing.T, eng *gin.Engine, req *http.Request) int {
	t.Helper()

	type outcome struct {
		status   int
		panicked any
	}

	done := make(chan outcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- outcome{panicked: recover()}
			}
		}()

		rec := serve(eng, req)
		returned = true
		done <- outcome{status: rec.Code}
	}()

	select {
	case o := <-done:
		require.Nil(t, o.panicked, "a panic escaped the guard")

		return o.status
	case <-time.After(2 * time.Second):
		t.Fatal("the guard's refusal did not return within 2s")

		return 0
	}
}
