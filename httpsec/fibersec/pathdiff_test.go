package fibersec_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// rawTargetResult is what one raw request line produced: the status, the body,
// and whether the protected handler ran.
type rawTargetResult struct {
	status  int
	body    string
	reached bool
}

// sendRawTarget starts app on a real listener and sends target exactly as
// written in the request line, so neither net/http's client nor fiber's
// App.Test cleans it first.
func sendRawTarget(t *testing.T, app *fiber.App, reached *atomic.Bool, method, target, header string) rawTargetResult {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: example.test\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n",
		method, target, header)
	require.NoError(t, err)

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	return rawTargetResult{status: res.StatusCode, body: string(body), reached: reached.Load()}
}

// badRequest asserts the chain answered 400, with no body, and the handler did
// not run.
func badRequest(t *testing.T, r rawTargetResult) {
	t.Helper()
	assert.False(t, r.reached, "the protected handler ran (status %d)", r.status)
	assert.Equal(t, http.StatusBadRequest, r.status)
	assert.Empty(t, r.body)
}

// TestFiber_AuthorizationRuleSeesRoutedPath pins that a request fiber would
// route to /admin/users through a dot segment never reaches it under a rule
// set that permits /public: the chain refuses the path before any rule reads
// it. Letter case is left out on purpose: it stays the consumer's to match.
func TestFiber_AuthorizationRuleSeesRoutedPath(t *testing.T) {
	t.Parallel()

	publicThenAdmin := []authorize.Rule[httpsec.Request]{
		{Match: httpsec.PathPrefix("/public"), Require: authorize.PermitAll()},
		{Match: httpsec.PathPrefix("/admin"), Require: authorize.DenyAll()},
		{Match: func(httpsec.Request) bool { return true }, Require: authorize.DenyAll()},
	}

	notReached := func(t *testing.T, r rawTargetResult) {
		t.Helper()
		assert.False(t, r.reached, "the /admin/users handler ran (status %d)", r.status)
		assert.NotEqual(t, http.StatusOK, r.status)
	}

	type testCase struct {
		name   string
		config fiber.Config
		target string
		assert func(t *testing.T, r rawTargetResult)
	}

	cases := []testCase{
		{
			name: "control: canonical admin path is refused by its rule", target: "/admin/users",
			assert: func(t *testing.T, r rawTargetResult) {
				t.Helper()
				notReached(t, r)
				assert.Equal(t, http.StatusForbidden, r.status)
			},
		},
		{name: "dot-dot segment", target: "/public/../admin/users", assert: badRequest},
		{name: "encoded dot-dot segment", target: "/public/%2e%2e/admin/users", assert: badRequest},
		{name: "upper-case encoded dot-dot segment", target: "/public/%2E%2E/admin/users", assert: badRequest},
		{name: "dot segment then dot-dot", target: "/public/./../admin/users", assert: badRequest},
		{name: "double slash then dot-dot", target: "/public//../admin/users", assert: badRequest},
		{name: "encoded slash, default config", target: "/public%2F..%2Fadmin/users", assert: badRequest},
		{
			name: "encoded slash under UnescapePath", config: fiber.Config{UnescapePath: true},
			target: "/public%2F..%2Fadmin/users", assert: badRequest,
		},
		{name: "undecodable escape", target: "/public/%zz", assert: badRequest},
		// Not dot segments: fiber does not resolve them either, so they reach
		// no handler and are judged by the rules as written.
		{name: "semicolon after dot-dot", target: "/public/..;/admin/users", assert: notReached},
		{name: "backslash after dot-dot", target: `/public/..\admin/users`, assert: notReached},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := NewMockAuthorizer(gomock.NewController(t))
			chain := newChain(t,
				httpsec.RegisterInterceptor(publishing(testPrincipal()), httpsec.OrderBearerToken),
				httpsec.EnableAuthorization(az, publicThenAdmin...),
			)

			var reached atomic.Bool

			cfg := tc.config
			cfg.ErrorHandler = fibersec.ErrorHandler
			app := fiber.New(cfg)
			app.Use(fibersec.Middleware(chain))
			app.Get("/admin/users", func(c fiber.Ctx) error {
				reached.Store(true)
				return c.SendString("admin")
			})

			tc.assert(t, sendRawTarget(t, app, &reached, http.MethodGet, tc.target, ""))
		})
	}
}

// TestFiber_RecoveryCooldownSeesRoutedPath pins the cool-down's promise that
// fiber's lenient routing reaches no marked route by a path the guard does not
// match: a dot-segment spelling is refused before the guard runs.
func TestFiber_RecoveryCooldownSeesRoutedPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		target string
		assert func(t *testing.T, r rawTargetResult)
	}

	cooledDown := func(t *testing.T, r rawTargetResult) {
		t.Helper()
		assert.False(t, r.reached, "the marked handler ran (status %d)", r.status)
		assert.Equal(t, http.StatusForbidden, r.status)
	}

	cases := []testCase{
		{name: "control: canonical path", target: "/account/delete", assert: cooledDown},
		{name: "control: upper case", target: "/ACCOUNT/Delete/", assert: cooledDown},
		{name: "dot-dot segment", target: "/x/../account/delete", assert: badRequest},
		{name: "dot segment", target: "/account/./delete", assert: badRequest},
		{name: "encoded dot segment", target: "/account/%2e/delete", assert: badRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rid, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			at := time.Now().Add(-time.Minute)
			records := recovery.NewMemoryRecordStore()
			require.NoError(t, records.Insert(t.Context(), recovery.Record{
				ID: rid, User: identity.UserID("u-1"), StartedAt: at, NotBefore: at, CompletedAt: at,
			}))

			opts, _ := authenticated(t)
			opts = append(opts, httpsec.EnableRecoveryCooldown(records, time.Hour,
				httpsec.Route{Method: http.MethodPost, Path: "/account/delete"}))
			chain := newChain(t, opts...)

			var reached atomic.Bool

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(chain))
			app.Post("/account/delete", func(c fiber.Ctx) error {
				reached.Store(true)
				return c.SendString("deleted")
			})

			tc.assert(t, sendRawTarget(t, app, &reached, http.MethodPost, tc.target,
				"Authorization: Bearer "+presentedToken+"\r\n"))
		})
	}
}
