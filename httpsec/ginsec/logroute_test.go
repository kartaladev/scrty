package ginsec_test

// The test in this file replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

// TestLogRoute_AbortReport pins where the adapter writes the record of a
// refusal whose classification aborted: the logger of the chain handling the
// request, else slog.Default() as it is when the record is written. That holds
// for a guard's refusal behind the middleware, read from the request's
// context, and for an interceptor's refusal made before the route runs, which
// the adapter answers after the chain's run has ended. The adapter has no
// logger option of its own. Without a chain nothing walks the refusal, so
// there is no record to place.
func TestLogRoute_AbortReport(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		// interceptor has an interceptor of the chain refuse with the aborting
		// error before the route runs; otherwise a guard refuses with it.
		interceptor bool
	}

	cases := []testCase{
		{name: "no option, inside a configured chain, a guard's refusal"},
		{name: "no option, inside a configured chain, an interceptor's refusal before the route", interceptor: true},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaults, chainLogs := &abortCounter{}, &abortCounter{}
			prev := slog.Default()
			slog.SetDefault(slog.New(defaults))
			t.Cleanup(func() { slog.SetDefault(prev) })

			opts, _ := authenticated(t)
			opts = append(opts, httpsec.WithLogger(slog.New(chainLogs)),
				httpsec.EnableSecurityEvents(func(context.Context, event.Event) {}))

			eng := gin.New()

			if tc.interceptor {
				opts = append(opts, httpsec.RegisterInterceptor(refusing(alwaysPanicsIs{}, nil), httpsec.OrderAuthorizer))
				eng.Use(ginsec.Middleware(newChain(t, opts...)))
				eng.GET("/invoices", func(*gin.Context) { t.Error("the route ran behind an interceptor's refusal") })
			} else {
				g := mustGuards(t, deciding(t, alwaysPanicsIs{}))
				eng.Use(ginsec.Middleware(newChain(t, opts...)))
				eng.GET("/invoices", g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					func(*gin.Context) { t.Error("the route ran behind a guard's refusal") })
			}

			serveWithin(t, eng, bearerRequest(t.Context(), http.MethodGet, "http://example.com/invoices"))

			assert.Equal(t, 1, chainLogs.count(), "the record did not land on the chain's logger")
			assert.Zero(t, defaults.count(), "the record landed on the default")
		})
	}
}
