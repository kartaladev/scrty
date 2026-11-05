package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// The origins these tests name. crossSiteTrusted is the one a test's CORS policy allows.
const (
	crossSiteTrusted = "https://app.example.com"
	crossSiteForeign = "https://evil.example"
)

// crossSiteRefusedMsg is the record a refused stream logs.
const crossSiteRefusedMsg = "httpsec: cross-site signal stream refused"

// fetchHeaders sets a request's Sec-Fetch-Site and Origin, leaving out what is empty.
func fetchHeaders(site, origin string) func(*http.Request) {
	return func(req *http.Request) {
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}

		if origin != "" {
			req.Header.Set("Origin", origin)
		}
	}
}

// crossSiteChain says what a test's chain authenticates with and what it trusts. The zero
// value is the session bearer with no CORS and no CSRF protection.
type crossSiteChain struct {
	// cookie uses a consumer's cookie authenticator in place of the bearer, and record has
	// it call RecordPresentedToken.
	cookie, record bool

	// csrf enables CSRF protection. A cookie chain without it opts out.
	csrf bool

	// cors is the chain's CORS policy, and nil for none.
	cors *httpsec.CORSPolicy

	// corsOpts adjust the CORS layer.
	corsOpts []httpsec.CORSOption

	// extra are added to the chain's options.
	extra []httpsec.Option

	// wrap decorates the session store.
	wrap func(session.Store) session.Store
}

// setup is the fixture's configuration for the chain.
func (c crossSiteChain) setup() signalsSetup {
	return signalsSetup{withoutBearer: c.cookie, wrap: c.wrap, opts: func(f *signalsFixture) []httpsec.Option {
		opts := append([]httpsec.Option(nil), c.extra...)

		if c.cors != nil {
			opts = append(opts, httpsec.EnableCORS(*c.cors, c.corsOpts...))
		}

		if c.csrf {
			opts = append(opts, httpsec.EnableCSRFProtection())
		}

		if c.cookie {
			opts = append(opts,
				httpsec.WithSessions(f.sessions),
				httpsec.RegisterInterceptor(
					consumerSessionCookie{sessions: f.sessions, record: c.record}, httpsec.OrderBearerToken,
				),
			)

			if !c.csrf {
				opts = append(opts, httpsec.WithoutCSRFProtection())
			}
		}

		return opts
	}}
}

// present opens the stream for a sign-in of u-1, by whichever credential the chain reads.
//
// The body is closed when the test ends, which the bodyclose linter cannot see, so the
// directive below marks the response as handled.
// bodyclose:handled
func (c crossSiteChain) present(
	t *testing.T, f *signalsFixture, change ...func(*http.Request),
) *http.Response {
	t.Helper()

	sid := f.signIn(t, "u-1").ID

	if c.cookie {
		resp, _ := f.openStream(t, "", append([]func(*http.Request){withSignalsCookie(sid)}, change...)...)

		return resp
	}

	resp, _ := f.openStream(t, sid, change...)

	return resp
}

// The CORS policies these tests name.
var (
	corsNamedWithCredentials    = &httpsec.CORSPolicy{AllowedOrigins: []string{crossSiteTrusted}, AllowCredentials: true}
	corsNamedWithoutCredentials = &httpsec.CORSPolicy{AllowedOrigins: []string{crossSiteTrusted}}
	corsEveryOrigin             = &httpsec.CORSPolicy{AllowedOrigins: []string{"*"}}
)

func TestSessionSignals_CrossSite(t *testing.T) {
	t.Parallel()

	var (
		cookieCSRF     = crossSiteChain{cookie: true, csrf: true, cors: corsNamedWithCredentials}
		cookieNoCSRF   = crossSiteChain{cookie: true, cors: corsNamedWithCredentials}
		bearerNoCORS   = crossSiteChain{}
		cookieNoCORS   = crossSiteChain{cookie: true}
		bearerNamed    = crossSiteChain{cors: corsNamedWithCredentials}
		cookieNoCreds  = crossSiteChain{cookie: true, cors: corsNamedWithoutCredentials}
		bearerNoCreds  = crossSiteChain{cors: corsNamedWithoutCredentials}
		cookieWildcard = crossSiteChain{cookie: true, cors: corsEveryOrigin}
		bearerWildcard = crossSiteChain{cors: corsEveryOrigin}
		patterned      = &httpsec.CORSPolicy{AllowedOrigins: []string{crossSiteTrusted}, AllowCredentials: true}
		patternOpt     = []httpsec.CORSOption{httpsec.WithOriginPattern("https://*.preview.example.com")}
	)

	refused := func(t *testing.T, resp *http.Response) {
		t.Helper()

		requireNoStream(t, resp, http.StatusForbidden)
	}

	opens := func(t *testing.T, resp *http.Response) {
		t.Helper()

		requireStreamHead(t, resp)
	}

	type testCase struct {
		name   string
		chain  crossSiteChain
		site   string
		origin string

		// ownOrigin sends the server's own address as the Origin, which is known only once the
		// fixture has been built.
		ownOrigin bool

		// change adjusts the request further.
		change func(*http.Request)

		assert func(t *testing.T, resp *http.Response)
	}

	cases := []testCase{
		{
			name:   "cross-site from an origin CORS does not allow is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "the same with CSRF protection off",
			chain:  cookieNoCSRF,
			site:   "cross-site",
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "the same for a bearer, with neither CORS nor CSRF protection",
			chain:  bearerNoCORS,
			site:   "cross-site",
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "same-site from an untrusted origin is 403",
			chain:  cookieCSRF,
			site:   "same-site",
			origin: "https://other.example.com",
			assert: refused,
		},
		{
			name:   "same-site from a trusted origin opens",
			chain:  cookieCSRF,
			site:   "same-site",
			origin: crossSiteTrusted,
			assert: opens,
		},
		{
			name:   "a Sec-Fetch-Site value the rule does not know is judged by the origin",
			chain:  cookieCSRF,
			site:   "SAME-ORIGIN",
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "same-origin opens, whatever CORS says",
			chain:  cookieNoCORS,
			site:   "same-origin",
			assert: opens,
		},
		{
			name:   "none, a page the user navigated to, opens",
			chain:  cookieNoCORS,
			site:   "none",
			assert: opens,
		},
		{
			name:   "cross-site with no Origin, an image tag, is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			assert: refused,
		},
		{
			name:   "cross-site with no Origin is 403 for a bearer under a wildcard too",
			chain:  bearerWildcard,
			site:   "cross-site",
			assert: refused,
		},
		{
			name:   "Origin: null is 403",
			chain:  cookieCSRF,
			origin: "null",
			assert: refused,
		},
		{
			name:   "Origin: null is 403 under same-origin fetch metadata",
			chain:  cookieCSRF,
			site:   "same-origin",
			origin: "null",
			assert: refused,
		},
		{
			name:   "Origin: null with a bearer under a wildcard is 403",
			chain:  bearerWildcard,
			origin: "null",
			assert: refused,
		},
		{
			name:   "Origin: null spelled otherwise with a bearer under a wildcard is 403",
			chain:  bearerWildcard,
			site:   "cross-site",
			origin: "NULL",
			assert: refused,
		},
		{
			name:   "no fetch metadata and no origin opens for a bearer",
			chain:  bearerNoCORS,
			assert: opens,
		},
		{
			name:   "no fetch metadata and no origin opens for a cookie",
			chain:  cookieNoCORS,
			assert: opens,
		},
		{
			name:   "no fetch metadata and a foreign origin is 403",
			chain:  cookieCSRF,
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "no fetch metadata and a trusted origin opens",
			chain:  cookieCSRF,
			origin: crossSiteTrusted,
			assert: opens,
		},
		{
			name:      "no fetch metadata and the request's own origin opens for a cookie, with no CORS",
			chain:     cookieNoCORS,
			ownOrigin: true,
			assert:    opens,
		},
		{
			name:      "no fetch metadata and the request's own origin opens for a bearer, with no CORS",
			chain:     bearerNoCORS,
			ownOrigin: true,
			assert:    opens,
		},
		{
			name:   "no CORS at all, a cross-origin Origin and no fetch metadata is 403",
			chain:  bearerNoCORS,
			origin: crossSiteTrusted,
			assert: refused,
		},
		{
			name:   "no CORS at all, cross-site is 403 for a cookie",
			chain:  cookieNoCORS,
			site:   "cross-site",
			origin: crossSiteTrusted,
			assert: refused,
		},
		{
			name:   "an allowed origin with credentials opens with its CORS headers",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: crossSiteTrusted,
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				requireStreamHead(t, resp)
				assert.Equal(t, crossSiteTrusted, resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
				assert.Contains(t, resp.Header.Values("Vary"), "Origin")
			},
		},
		{
			name:   "a bearer from an origin CORS names with credentials opens",
			chain:  bearerNamed,
			site:   "cross-site",
			origin: crossSiteTrusted,
			assert: opens,
		},
		{
			name:   "a cookie from an origin named without credentials is 403",
			chain:  cookieNoCreds,
			site:   "cross-site",
			origin: crossSiteTrusted,
			assert: refused,
		},
		{
			name:   "a bearer from an origin named without credentials opens",
			chain:  bearerNoCreds,
			site:   "cross-site",
			origin: crossSiteTrusted,
			assert: opens,
		},
		{
			name:   "a bearer from an origin CORS does not name is 403",
			chain:  bearerNoCreds,
			site:   "cross-site",
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "a wildcard with a cookie cross-site is 403",
			chain:  cookieWildcard,
			site:   "cross-site",
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "a wildcard with a cookie and no fetch metadata is 403",
			chain:  cookieWildcard,
			origin: crossSiteForeign,
			assert: refused,
		},
		{
			name:   "a wildcard with a bearer opens",
			chain:  bearerWildcard,
			site:   "cross-site",
			origin: crossSiteForeign,
			assert: opens,
		},
		{
			name:   "a wildcard with a bearer opens for an origin that is not http or https",
			chain:  bearerWildcard,
			site:   "cross-site",
			origin: "capacitor://localhost",
			assert: opens,
		},
		{
			name:   "a pattern with credentials opens for a cookie",
			chain:  crossSiteChain{cookie: true, cors: patterned, corsOpts: patternOpt},
			site:   "cross-site",
			origin: "https://pr-1.preview.example.com",
			assert: opens,
		},
		{
			name: "a pattern without credentials is 403 for a cookie",
			chain: crossSiteChain{
				cookie: true, cors: corsNamedWithoutCredentials, corsOpts: patternOpt,
			},
			site:   "cross-site",
			origin: "https://pr-1.preview.example.com",
			assert: refused,
		},
		{
			name:   "a pattern without credentials opens for a bearer",
			chain:  crossSiteChain{cors: corsNamedWithoutCredentials, corsOpts: patternOpt},
			site:   "cross-site",
			origin: "https://pr-1.preview.example.com",
			assert: opens,
		},
		{
			name:   "a pattern's wildcard matches one label, no more",
			chain:  crossSiteChain{cookie: true, cors: patterned, corsOpts: patternOpt},
			site:   "cross-site",
			origin: "https://a.b.preview.example.com",
			assert: refused,
		},
		{
			name:   "a trusted origin spelled with upper case and its default port opens",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: "HTTPS://APP.Example.COM:443",
			assert: opens,
		},
		{
			name:   "a trusted name as a foreign origin's subdomain is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: "https://app.example.com.evil.example",
			assert: refused,
		},
		{
			name:   "a trusted name as a foreign origin's userinfo is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: "https://app.example.com@evil.example",
			assert: refused,
		},
		{
			name:   "a trusted name on the other scheme is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: "http://app.example.com",
			assert: refused,
		},
		{
			name:   "a trusted name on another port is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: "https://app.example.com:8443",
			assert: refused,
		},
		{
			name:   "a trusted name followed by a path is 403",
			chain:  cookieCSRF,
			site:   "cross-site",
			origin: "https://evil.example/https://app.example.com",
			assert: refused,
		},
		{
			name:   "a consumer's cookie authenticator that records its token is judged as a cookie",
			chain:  crossSiteChain{cookie: true, record: true, cors: corsNamedWithoutCredentials},
			site:   "cross-site",
			origin: crossSiteTrusted,
			assert: refused,
		},
		{
			name:   "a cookie with an unclaimed Authorization header stays a cookie",
			chain:  cookieNoCreds,
			site:   "cross-site",
			origin: crossSiteTrusted,
			change: func(req *http.Request) { req.Header.Set("Authorization", "Bearer not-claimed") },
			assert: refused,
		},
		{
			name:   "a recording cookie with an unclaimed Authorization header stays a cookie",
			chain:  crossSiteChain{cookie: true, record: true, cors: corsNamedWithoutCredentials},
			site:   "cross-site",
			origin: crossSiteTrusted,
			change: func(req *http.Request) { req.Header.Set("Authorization", "Bearer not-claimed") },
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, tc.chain.setup())

			origin := tc.origin
			if tc.ownOrigin {
				origin = f.server.URL
			}

			change := []func(*http.Request){fetchHeaders(tc.site, origin)}
			if tc.change != nil {
				change = append(change, tc.change)
			}

			tc.assert(t, tc.chain.present(t, f, change...))
		})
	}
}

// crossSiteObserved is what a refusal left behind, for the rows that look past the status.
type crossSiteObserved struct {
	logs   capturingHandler
	events eventRecorder

	// credential is what a row presented, to look for in the logs.
	credential string

	mu     sync.Mutex
	errors []error
}

func (o *crossSiteObserved) handle(w http.ResponseWriter, _ *http.Request, err error) {
	o.mu.Lock()
	o.errors = append(o.errors, err)
	o.mu.Unlock()

	w.WriteHeader(http.StatusForbidden)
}

func (o *crossSiteObserved) seen() []error {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]error(nil), o.errors...)
}

// refusalRecords are the refused-stream records among what was logged.
func (o *crossSiteObserved) refusalRecords() []slog.Record {
	var out []slog.Record

	for _, r := range o.logs.records() {
		if r.Message == crossSiteRefusedMsg {
			out = append(out, r)
		}
	}

	return out
}

// everythingLogged prints every record, so a test can look for a value in all of them.
func (o *crossSiteObserved) everythingLogged() string {
	var b strings.Builder

	for _, r := range o.logs.records() {
		fmt.Fprintln(&b, r.Message)
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintln(&b, a.Key, a.Value.String())

			return true
		})
	}

	return b.String()
}

func TestSessionSignals_CrossSite_Refusal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(t *testing.T, f *signalsFixture, chain crossSiteChain, o *crossSiteObserved)
		assert func(t *testing.T, f *signalsFixture, o *crossSiteObserved)
	}

	foreign := fetchHeaders("cross-site", crossSiteForeign)

	cases := []testCase{
		{
			name: "the refusal is ErrCrossSiteStream, and not ErrCrossSiteRequest",
			act: func(t *testing.T, f *signalsFixture, chain crossSiteChain, _ *crossSiteObserved) {
				t.Helper()

				requireNoStream(t, chain.present(t, f, foreign), http.StatusForbidden)
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				require.Len(t, o.seen(), 1)
				require.ErrorIs(t, o.seen()[0], httpsec.ErrCrossSiteStream)
				assert.False(t, errors.Is(o.seen()[0], httpsec.ErrCrossSiteRequest))
			},
		},
		{
			name: "the refusal emits no MaliciousCSRF event",
			act: func(t *testing.T, f *signalsFixture, chain crossSiteChain, _ *crossSiteObserved) {
				t.Helper()

				requireNoStream(t, chain.present(t, f, foreign), http.StatusForbidden)
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				assert.NotContains(t, o.events.names(), event.MaliciousCSRF)
			},
		},
		{
			name: "a flood logs one record, carrying the origin",
			act: func(t *testing.T, f *signalsFixture, chain crossSiteChain, _ *crossSiteObserved) {
				t.Helper()

				for range 5 {
					requireNoStream(t, chain.present(t, f, foreign), http.StatusForbidden)
				}
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				records := o.refusalRecords()
				require.Len(t, records, 1, "an unsampled refusal is a flood the refused party chooses the size of")
				assert.Equal(t, slog.LevelWarn, records[0].Level)

				origin, ok := attrValue(records[0], "origin")
				require.True(t, ok)
				assert.Equal(t, crossSiteForeign, origin.String())
			},
		},
		{
			name: "a flood of different origins still logs one record",
			act: func(t *testing.T, f *signalsFixture, chain crossSiteChain, _ *crossSiteObserved) {
				t.Helper()

				for i := range 5 {
					resp := chain.present(t, f, fetchHeaders("cross-site", fmt.Sprintf("https://evil-%d.example", i)))
					requireNoStream(t, resp, http.StatusForbidden)
				}
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				assert.Len(t, o.refusalRecords(), 1, "the origin is the refused party's to choose, so it cannot key the sampling")
			},
		},
		{
			name: "what the sampling held back is counted when the logs are flushed",
			act: func(t *testing.T, f *signalsFixture, chain crossSiteChain, _ *crossSiteObserved) {
				t.Helper()

				for range 5 {
					requireNoStream(t, chain.present(t, f, foreign), http.StatusForbidden)
				}

				require.NoError(t, f.chain.FlushRefusalLogs())
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				var suppressed []slog.Record

				for _, r := range o.logs.records() {
					if r.Message == "httpsec: refusal logs suppressed" {
						suppressed = append(suppressed, r)
					}
				}

				require.Len(t, suppressed, 1)

				count, ok := attrValue(suppressed[0], "suppressed")
				require.True(t, ok)
				assert.Equal(t, int64(4), count.Int64())
			},
		},
		{
			name: "the record carries no credential",
			act: func(t *testing.T, f *signalsFixture, _ crossSiteChain, o *crossSiteObserved) {
				t.Helper()

				o.credential = f.signIn(t, "u-1").ID

				resp, _ := f.openStream(t, o.credential, foreign, withSignalsCookie("cookie-secret"))
				requireNoStream(t, resp, http.StatusForbidden)
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				require.Len(t, o.refusalRecords(), 1)
				assert.NotContains(t, o.everythingLogged(), o.credential)
				assert.NotContains(t, o.everythingLogged(), "cookie-secret")
			},
		},
		{
			name: "an oversized origin is logged cut short",
			act: func(t *testing.T, f *signalsFixture, chain crossSiteChain, _ *crossSiteObserved) {
				t.Helper()

				resp := chain.present(t, f, fetchHeaders("cross-site", "https://"+strings.Repeat("a", 4096)+".example"))
				requireNoStream(t, resp, http.StatusForbidden)
			},
			assert: func(t *testing.T, _ *signalsFixture, o *crossSiteObserved) {
				t.Helper()

				records := o.refusalRecords()
				require.Len(t, records, 1)

				origin, ok := attrValue(records[0], "origin")
				require.True(t, ok)
				assert.LessOrEqual(t, len(origin.String()), 256)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := &crossSiteObserved{}
			chain := crossSiteChain{
				cors: corsNamedWithCredentials,
				extra: []httpsec.Option{
					httpsec.WithLogger(slog.New(&o.logs)),
					httpsec.EnableSecurityEvents(o.events.sink),
					httpsec.WithErrorHandler(o.handle),
				},
			}
			f := newSignalsFixture(t, chain.setup())

			tc.act(t, f, chain, o)
			tc.assert(t, f, o)
		})
	}
}

// consumerRateLimit is a consumer's interceptor below the stream's slot, refusing every
// request as an over-limit source.
func consumerRateLimit() httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
		ex.Writer.WriteHeader(http.StatusTooManyRequests)

		return nil
	})
}

// TestSessionSignals_EarlySlots shows what the slots below the stream do to a request for it:
// each still applies, and the stream answers only what they let through.
func TestSessionSignals_EarlySlots(t *testing.T) {
	t.Parallel()

	preflightPolicy := &httpsec.CORSPolicy{
		AllowedOrigins: []string{crossSiteTrusted},
		AllowedHeaders: []string{"Authorization"},
	}

	type testCase struct {
		name   string
		chain  crossSiteChain
		assert func(t *testing.T, f *signalsFixture, chain crossSiteChain)
	}

	// signInReads counts the listings of the one row that reads it, which reads the store
	// for its sign-in.
	var signInReads atomic.Int64

	cases := []testCase{
		{
			name: "a refused cross-site request makes no read of the store",
			chain: crossSiteChain{
				cors: corsNamedWithCredentials,
				wrap: func(s session.Store) session.Store {
					return &listSpyStore{Store: s, see: func(context.Context) { signInReads.Add(1) }}
				},
			},
			assert: func(t *testing.T, f *signalsFixture, chain crossSiteChain) {
				t.Helper()

				requireNoStream(t, chain.present(t, f, fetchHeaders("cross-site", crossSiteForeign)), http.StatusForbidden)
				assert.Zero(t, signInReads.Load(), "the check has to run before anything is read")

				// The spy sees the reads of an admitted stream, so the zero above is not vacuous.
				requireStreamHead(t, chain.present(t, f, fetchHeaders("same-origin", f.server.URL)))
				assert.Positive(t, signInReads.Load())
			},
		},
		{
			name:  "an allowed origin opens with its CORS headers, varying by origin",
			chain: crossSiteChain{cookie: true, csrf: true, cors: corsNamedWithCredentials},
			assert: func(t *testing.T, f *signalsFixture, chain crossSiteChain) {
				t.Helper()

				resp := chain.present(t, f, fetchHeaders("cross-site", crossSiteTrusted))
				requireStreamHead(t, resp)
				assert.Equal(t, crossSiteTrusted, resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Contains(t, resp.Header.Values("Vary"), "Origin")
			},
		},
		{
			name:  "a CORS preflight for Authorization is answered, with no stream",
			chain: crossSiteChain{cors: preflightPolicy},
			assert: func(t *testing.T, f *signalsFixture, _ crossSiteChain) {
				t.Helper()

				resp := f.send(t.Context(), t, http.MethodOptions, httpsec.DefaultSessionSignalsPath, "",
					func(req *http.Request) {
						req.Header.Set("Origin", crossSiteTrusted)
						req.Header.Set("Sec-Fetch-Site", "cross-site")
						req.Header.Set("Access-Control-Request-Method", http.MethodGet)
						req.Header.Set("Access-Control-Request-Headers", "authorization")
					})

				requireNoStream(t, resp, http.StatusNoContent)
				assert.Equal(t, crossSiteTrusted, resp.Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Authorization", resp.Header.Get("Access-Control-Allow-Headers"))
				assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), http.MethodGet)
			},
		},
		{
			name:  "a same-origin cookie stream opens without a CSRF token",
			chain: crossSiteChain{cookie: true, csrf: true},
			assert: func(t *testing.T, f *signalsFixture, chain crossSiteChain) {
				t.Helper()

				requireStreamHead(t, chain.present(t, f, fetchHeaders("same-origin", f.server.URL)))
			},
		},
		{
			name:  "a POST under CSRF protection reaches 405 once CSRF passes",
			chain: crossSiteChain{csrf: true},
			assert: func(t *testing.T, f *signalsFixture, _ crossSiteChain) {
				t.Helper()

				resp := f.send(t.Context(), t, http.MethodPost, httpsec.DefaultSessionSignalsPath,
					f.signIn(t, "u-1").ID, fetchHeaders("same-origin", f.server.URL))

				requireNoStream(t, resp, http.StatusMethodNotAllowed)
				assert.Equal(t, http.MethodGet, resp.Header.Get("Allow"))
			},
		},
		{
			name:  "a POST CSRF refuses never reaches 405",
			chain: crossSiteChain{csrf: true},
			assert: func(t *testing.T, f *signalsFixture, _ crossSiteChain) {
				t.Helper()

				resp := f.send(t.Context(), t, http.MethodPost, httpsec.DefaultSessionSignalsPath,
					f.signIn(t, "u-1").ID, fetchHeaders("cross-site", crossSiteForeign))

				requireNoStream(t, resp, http.StatusForbidden)
				assert.Empty(t, resp.Header.Get("Allow"))
			},
		},
		{
			name: "a source a consumer's rate limit refuses below the slot gets no stream",
			chain: crossSiteChain{extra: []httpsec.Option{
				httpsec.RegisterInterceptor(consumerRateLimit(), httpsec.Before(httpsec.OrderSessionSignals)),
			}},
			assert: func(t *testing.T, f *signalsFixture, chain crossSiteChain) {
				t.Helper()

				requireNoStream(t, chain.present(t, f), http.StatusTooManyRequests)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newSignalsFixture(t, tc.chain.setup()), tc.chain)
		})
	}
}
