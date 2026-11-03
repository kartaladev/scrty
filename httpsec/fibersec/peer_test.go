package fibersec_test

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// serveFrom runs req through app as if it arrived over TCP from peer, an
// address and port such as "198.51.100.7:51000".
//
// fiber's in-memory transport (app.Test) always reports the unspecified
// address as the peer, so a test that needs a real transport peer hands the
// request to fiber's fasthttp handler on a request context initialised with
// that peer instead.
func serveFrom(t *testing.T, app *fiber.App, req *http.Request, peer string) response {
	t.Helper()

	addr, err := netip.ParseAddrPort(peer)
	require.NoError(t, err)

	if req.Host == "" {
		req.Host = "example.com"
	}

	req.RequestURI = ""

	dump, err := httputil.DumpRequest(req, true)
	require.NoError(t, err)

	// The body is read without pre-parsing a multipart form, which would
	// consume it into a form the request context's copy does not carry.
	var freq fasthttp.Request

	br := bufio.NewReader(bytes.NewReader(dump))
	require.NoError(t, freq.Header.Read(br))
	require.NoError(t, freq.ContinueReadBody(br, 0, false))

	var ctx fasthttp.RequestCtx
	ctx.Init(&freq, net.TCPAddrFromAddrPort(addr), nil)

	app.Handler()(&ctx)

	header := http.Header{}
	for k, v := range ctx.Response.Header.All() {
		header.Add(string(k), string(v))
	}

	return response{status: ctx.Response.StatusCode(), header: header, body: string(ctx.Response.Body())}
}
