package fibersec_test

// Every row of the test in this file replaces slog.Default() for its duration,
// so none of them runs in parallel, and each restores the logger it found.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
)

// TestLogRoute_AbortReport pins where the adapter writes the record of a
// classification that aborted: the logger of the chain handling the request,
// read from the request's context, else slog.Default() as it is when the
// record is written. The adapter has no logger option of its own.
func TestLogRoute_AbortReport(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name  string
		chain bool
		// route returns the aborting error from the route, otherwise a guard
		// refuses with it.
		route bool
		// interceptor has an interceptor of the chain refuse with the
		// aborting error before the route runs.
		interceptor bool
	}

	cases := []testCase{
		{name: "no option, inside a configured chain, a route's error", chain: true, route: true},
		{name: "no option, inside a configured chain, a guard's refusal", chain: true},
		{name: "no option, inside a configured chain, an interceptor's refusal before the route", chain: true, interceptor: true},
		{name: "no chain, an error reaching ErrorHandler", route: true},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaults := recordDefault(t)
			chainLogs := &recordingHandler{}

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})

			var req = bearerRequest(t.Context(), "GET", "http://example.com/invoices")

			if tc.chain {
				opts, _ := authenticated(t)
				opts = append(opts, httpsec.WithLogger(slog.New(chainLogs)),
					httpsec.EnableSecurityEvents(func(context.Context, event.Event) {}))
				if tc.interceptor {
					opts = append(opts, httpsec.RegisterInterceptor(refusing(&selfCycleError{}, nil), httpsec.OrderAuthorizer))
				}
				app.Use(fibersec.Middleware(newChain(t, opts...)))
			}

			switch {
			case tc.interceptor:
				app.Get("/invoices", func(fiber.Ctx) error {
					t.Error("the route ran behind an interceptor's refusal")

					return nil
				})
			case tc.route:
				app.Get("/invoices", func(fiber.Ctx) error { return &selfCycleError{} })
			default:
				g := mustGuards(t, refusingAuthorizer(t, alwaysPanicsIs{}))
				app.Get("/invoices", g.ResourcePrivileges("billing", "invoice").RequireOne("read"), func(fiber.Ctx) error {
					return nil
				})
			}

			serveGuardWithin(t, app, req)

			if tc.chain {
				assert.Equal(t, 1, countAborts(chainLogs.errorRecords()), "the record did not land on the chain's logger")
				assert.Zero(t, countAborts(defaults.errorRecords()), "the record landed on the default")

				return
			}

			assert.Equal(t, 1, countAborts(defaults.errorRecords()), "the record did not land on the default")
		})
	}
}
