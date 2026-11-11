package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/kartaladev/scrty/httpsec"
)

// benchChain builds a chain holding n consumer interceptors that only pass the
// request on, so what a benchmark measures is the chain's own cost.
func benchChain(b *testing.B, n int) *httpsec.Chain {
	b.Helper()

	opts := make([]httpsec.Option, 0, n)
	for i := range n {
		pass := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) })
		opts = append(opts, httpsec.RegisterInterceptor(pass, httpsec.Order(100+i)))
	}

	c, err := httpsec.New(opts...)
	if err != nil {
		b.Fatal(err)
	}

	return c
}

// BenchmarkAssemble measures what an adapter pays per request to put the
// chain in front of its handler: Assemble alone, and Assemble plus a run.
func BenchmarkAssemble(b *testing.B) {
	c := benchChain(b, 8)
	terminal := func(*httpsec.Exchange) error { return nil }

	b.Run("only/8", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			_ = c.Assemble(terminal)
		}
	})

	b.Run("run/8", func(b *testing.B) {
		r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
		ex := httpsec.NewExchange(b.Context(), httpsec.NewHTTPRequest(r),
			httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))

		b.ReportAllocs()

		for b.Loop() {
			if err := c.Assemble(terminal)(ex); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkChainRequest measures a whole net/http request through the chain,
// with no consumer interceptor and with eight.
func BenchmarkChainRequest(b *testing.B) {
	for _, n := range []int{0, 8} {
		c := benchChain(b, n)
		h := c.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				h.ServeHTTP(httptest.NewRecorder(),
					httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil))
			}
		})
	}
}
