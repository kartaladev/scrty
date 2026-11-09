package ginsec_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

// TestGin_NonCanonicalTargetsNeverReachTheHandler pins that no raw spelling of
// /admin/users reaches its handler under a rule set that permits /public and
// denies /admin, on gin and on net/http's ServeMux, each behind the chain.
// Every target is sent as written over a real connection, so no client cleans
// it first.
func TestGin_NonCanonicalTargetsNeverReachTheHandler(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		handler func(t *testing.T, chain *httpsec.Chain, reached *atomic.Bool) http.Handler
		target  string
		assert  func(t *testing.T, status int, body string, reached bool)
	}

	notReached := func(t *testing.T, status int, _ string, reached bool) {
		t.Helper()
		assert.False(t, reached, "the /admin/users handler ran (status %d)", status)
		assert.NotEqual(t, http.StatusOK, status)
	}
	badRequest := func(t *testing.T, status int, body string, reached bool) {
		t.Helper()
		notReached(t, status, body, reached)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Empty(t, body, "a refusal carries no error text")
	}

	ginEngine := func(_ *testing.T, chain *httpsec.Chain, reached *atomic.Bool) http.Handler {
		e := gin.New()
		e.Use(ginsec.Middleware(chain))
		e.GET("/admin/users", func(c *gin.Context) { reached.Store(true); c.String(http.StatusOK, "admin") })

		return e
	}
	serveMux := func(_ *testing.T, chain *httpsec.Chain, reached *atomic.Bool) http.Handler {
		m := http.NewServeMux()
		m.HandleFunc("GET /admin/users", func(w http.ResponseWriter, _ *http.Request) {
			reached.Store(true)
			w.WriteHeader(http.StatusOK)
		})

		return chain.Middleware()(m)
	}

	frameworks := []struct {
		name    string
		handler func(t *testing.T, chain *httpsec.Chain, reached *atomic.Bool) http.Handler
	}{
		{"gin default", ginEngine},
		{"net/http ServeMux", serveMux},
	}

	targets := []struct {
		target string
		assert func(t *testing.T, status int, body string, reached bool)
	}{
		{"/public/../admin/users", badRequest},
		{"/public/%2e%2e/admin/users", badRequest},
		{"/admin/./users", badRequest},
		{"/public%2F..%2Fadmin/users", badRequest},
		{"/ADMIN/users", notReached},
		{"/admin/users/", notReached},
		{"/admin//users", notReached},
	}

	var cases []testCase
	for _, f := range frameworks {
		for _, tg := range targets {
			cases = append(cases, testCase{
				name: f.name + " " + tg.target, handler: f.handler, target: tg.target, assert: tg.assert,
			})
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain := newChain(t, httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)),
				authorize.Rule[httpsec.Request]{Match: httpsec.PathPrefix("/public"), Require: authorize.PermitAll()},
				authorize.Rule[httpsec.Request]{Match: httpsec.PathPrefix("/admin"), Require: authorize.DenyAll()},
			))

			var reached atomic.Bool

			srv := httptest.NewServer(tc.handler(t, chain, &reached))
			t.Cleanup(srv.Close)

			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

			_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", tc.target)
			require.NoError(t, err)

			res, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			defer func() { _ = res.Body.Close() }()
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)

			t.Logf("%-32s -> %d", tc.target, res.StatusCode)
			tc.assert(t, res.StatusCode, string(body), reached.Load())
		})
	}
}
