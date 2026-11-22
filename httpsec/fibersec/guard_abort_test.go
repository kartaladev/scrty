package fibersec_test

// Every row of the test in this file replaces slog.Default() for its duration,
// so none of them runs in parallel, and each restores the logger it found.

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
)

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

// TestGuard_AbortReporting pins the fiber guard's reporting rule for an
// aborted classification of its refusal. A fiber guard has no error handler of
// its own: it returns its refusal, classified once by the adapter, which
// reports an abort it meets. The refusal's security event returns its abort
// to the guard, which writes one record only when that classification does not
// abort. The DPoP challenge of a fiber guard's refusal is the chain's own, met
// on the refusal's way back out, and reported by the chain's rule.
//
// Each row's request writes exactly one record, with fibersec.ErrorHandler and
// with fiber's own. A cyclic chain is left out under fiber's own handler:
// fiber's DefaultErrorHandler reads the refusal with the standard library's
// errors.As, which never returns on a cycle. That is fiber's limit, as gin's
// Context.Error is gin's, and nothing the guard can stop.
func TestGuard_AbortReporting(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		chain  []httpsec.Option
		config fiber.Config
		assert func(t *testing.T, status, records int)
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

	handlers := []struct {
		name   string
		config fiber.Config
		cycles bool
	}{
		{name: "fibersec.ErrorHandler", config: fiber.Config{ErrorHandler: fibersec.ErrorHandler}, cycles: true},
		{name: "fiber's own error handler"},
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
		for _, h := range handlers {
			errs := []struct {
				name   string
				err    error
				status int
			}{
				{name: "an Is that always panics", err: alwaysPanicsIs{}, status: http.StatusInternalServerError},
				{name: "a selective Is the lookup never meets", err: k.selective, status: http.StatusUnauthorized},
			}

			for _, e := range errs {
				cases = append(cases, testCase{
					name: k.name + ", " + e.name + ", " + h.name, err: e.err, chain: k.chain, config: h.config,
					assert: oneRecord(e.status),
				})
			}

			if h.cycles {
				cases = append(cases, testCase{
					name: k.name + ", a cycle, " + h.name, err: &selfCycleError{}, chain: k.chain, config: h.config,
					assert: oneRecord(http.StatusInternalServerError),
				})
			}
		}
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaults := recordDefault(t)
			chainLogs := &recordingHandler{}

			opts, _ := authenticated(t)
			opts = append(append(opts, httpsec.WithLogger(slog.New(chainLogs))), tc.chain...)

			g := mustGuards(t, refusingAuthorizer(t, tc.err))

			app := fiber.New(tc.config)
			app.Use(fibersec.Middleware(newChain(t, opts...)))
			app.Get("/invoices", g.ResourcePrivileges("billing", "invoice").RequireOne("read"), func(fiber.Ctx) error {
				t.Error("the route ran behind a guard's refusal")

				return nil
			})

			status := serveGuardWithin(t, app, bearerRequest(t.Context(), http.MethodGet, "http://example.com/invoices"))

			tc.assert(t, status, countAborts(defaults.errorRecords())+countAborts(chainLogs.errorRecords()))
		})
	}
}

// countAborts counts the aborted-classification records among recs.
func countAborts(recs []slog.Record) int {
	n := 0

	for _, r := range recs {
		if r.Message == abortMessage {
			n++
		}
	}

	return n
}

// serveGuardWithin serves req on app and fails the row when it does not
// return within two seconds.
func serveGuardWithin(t *testing.T, app *fiber.App, req *http.Request) int {
	t.Helper()

	type result struct {
		status int
		err    error
	}

	done := make(chan result, 1)

	go func() {
		res, err := app.Test(req, fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
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

		return r.status
	case <-time.After(2 * time.Second):
		t.Fatal("the guard's refusal did not return within 2s")

		return 0
	}
}
