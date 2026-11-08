package httpsec_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// csrfTarget is the application route the CSRF tests post to.
const csrfTarget = "https://app.example.com/settings"

// csrfRequest is a request for target carrying headers, with a URL-encoded
// body when body is not "".
func csrfRequest(ctx context.Context, method, target string, headers map[string]string, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}

	req := httptest.NewRequestWithContext(ctx, method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	return req
}

// refusedCrossSite asserts the request was refused as cross-site and never
// reached the handler.
func refusedCrossSite(t *testing.T, s served) {
	t.Helper()

	require.ErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
	assert.False(t, s.handlerRan, "a refused request never reaches the handler")
}

// passedCSRF asserts the request reached the handler.
func passedCSRF(t *testing.T, s served) {
	t.Helper()

	require.NoError(t, s.err)
	assert.True(t, s.handlerRan)
}

func TestCSRF_FetchMetadata(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T) []httpsec.Option
		request func(ctx context.Context) *http.Request

		// oracle runs the request through net/http.CrossOriginProtection too
		// and requires the same verdict. It is false only where scrty departs
		// from it on purpose: the request's scheme and default port count, and
		// the request's own origin is the one the chain resolved.
		oracle bool
		assert func(t *testing.T, s served)
	}

	post := func(headers map[string]string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return csrfRequest(ctx, http.MethodPost, csrfTarget, headers, "")
		}
	}

	with := func(method string, headers map[string]string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return csrfRequest(ctx, method, csrfTarget, headers, "")
		}
	}

	site := func(v string) map[string]string { return map[string]string{"Sec-Fetch-Site": v} }
	origin := func(v string) map[string]string { return map[string]string{"Origin": v} }

	cases := []testCase{
		{name: "cross-site form post", request: post(site("cross-site")), oracle: true, assert: refusedCrossSite},
		{name: "same-origin passes", request: post(site("same-origin")), oracle: true, assert: passedCSRF},
		{name: "none (user-initiated) passes", request: post(site("none")), oracle: true, assert: passedCSRF},
		{
			name:    "same-site from an untrusted origin",
			request: post(map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://blog.example.com"}),
			oracle:  true, assert: refusedCrossSite,
		},
		{name: "an unknown Sec-Fetch-Site value", request: post(site("other")), oracle: true, assert: refusedCrossSite},
		{
			name:    "cross-site even with the request's own Origin",
			request: post(map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://app.example.com"}),
			oracle:  true, assert: refusedCrossSite,
		},
		{name: "older browser from another origin", request: post(origin("https://evil.example")), oracle: true, assert: refusedCrossSite},
		{name: "older browser from the request's own origin", request: post(origin("https://app.example.com")), oracle: true, assert: passedCSRF},
		{name: "Origin null", request: post(origin("null")), oracle: true, assert: refusedCrossSite},
		{name: "a port that differs", request: post(origin("https://app.example.com:8443")), oracle: true, assert: refusedCrossSite},
		{
			name: "a non-default port that matches",
			request: func(ctx context.Context) *http.Request {
				return csrfRequest(ctx, http.MethodPost, "https://app.example.com:8443/settings",
					origin("https://app.example.com:8443"), "")
			},
			oracle: true, assert: passedCSRF,
		},
		{name: "a non-browser client with neither header", request: post(nil), oracle: true, assert: passedCSRF},
		{name: "a cross-site GET", request: with(http.MethodGet, site("cross-site")), oracle: true, assert: passedCSRF},
		{name: "a cross-site HEAD", request: with(http.MethodHead, site("cross-site")), oracle: true, assert: passedCSRF},
		{name: "a cross-site OPTIONS", request: with(http.MethodOptions, site("cross-site")), oracle: true, assert: passedCSRF},
		{name: "a lower-case get is unsafe", request: with("get", site("cross-site")), oracle: true, assert: refusedCrossSite},
		{name: "PROPFIND is unsafe", request: with("PROPFIND", site("cross-site")), oracle: true, assert: refusedCrossSite},
		{name: "a cross-site PUT", request: with(http.MethodPut, site("cross-site")), oracle: true, assert: refusedCrossSite},
		{name: "a cross-site PATCH", request: with(http.MethodPatch, site("cross-site")), oracle: true, assert: refusedCrossSite},
		{name: "a cross-site DELETE", request: with(http.MethodDelete, site("cross-site")), oracle: true, assert: refusedCrossSite},
		{
			// net/http compares the Origin's host and port with Host as they
			// are written, so it refuses this; scrty normalises the default
			// port away as CORS does.
			name:    "an Origin naming the default port matches the host without it",
			request: post(origin("https://app.example.com:443")),
			assert:  passedCSRF,
		},
		{
			// net/http ignores the scheme and fails open here; scrty compares
			// it with the scheme the chain resolved.
			name:    "an http Origin against an https request",
			request: post(origin("http://app.example.com")),
			assert:  refusedCrossSite,
		},
		{
			name: "behind a trusted proxy, the Origin is compared with the forwarded scheme and host",
			options: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
					Prefixes: proxyNet,
					Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
						httpsec.ForwardedHost("app.example.com")),
				})}
			},
			request: proxiedPost,
			assert:  passedCSRF,
		},
		{
			name:    "the same request without trusted proxies is compared with the request as received",
			request: proxiedPost,
			assert:  refusedCrossSite,
		},
		{
			name: "login CSRF: no credential is checked and no session is created",
			options: func(t *testing.T) []httpsec.Option {
				// No expectation is set on the harness's mocks, so checking a
				// credential or storing a session fails the test.
				h := newAuthHarness(t)

				return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps())}
			},
			request: func(ctx context.Context) *http.Request {
				return csrfRequest(ctx, http.MethodPost, "https://app.example.com"+httpsec.DefaultLoginPath,
					site("cross-site"), "username=ada&password=attacker")
			},
			oracle: true, assert: refusedCrossSite,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []httpsec.Option{httpsec.EnableCSRFProtection()}
			if tc.options != nil {
				opts = append(opts, tc.options(t)...)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			req := tc.request(t.Context())

			if tc.oracle {
				oracleErr := http.NewCrossOriginProtection().Check(req)
				ours := serve(t, chain, req)
				assert.Equal(t, oracleErr == nil, ours.err == nil,
					"net/http.CrossOriginProtection and the chain disagree (oracle: %v, chain: %v)", oracleErr, ours.err)
				tc.assert(t, ours)

				return
			}

			tc.assert(t, serve(t, chain, req))
		})
	}
}

// proxiedPost is a POST that reached the application over plain HTTP for
// 10.20.1.5:8080 from a proxy in proxyNet, which forwarded https and
// app.example.com, from a browser page on https://app.example.com without
// Fetch Metadata.
func proxiedPost(ctx context.Context) *http.Request {
	req := csrfRequest(ctx, http.MethodPost, "http://10.20.1.5:8080/settings", map[string]string{
		"Origin":            "https://app.example.com",
		"X-Forwarded-For":   "203.0.113.7",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "app.example.com",
	}, "")
	req.RemoteAddr = "10.20.0.2:41000"

	return req
}

func TestCSRF_TrustedOrigins(t *testing.T) {
	t.Parallel()

	const api = "https://api.example.com/orders"

	type testCase struct {
		name    string
		opts    []httpsec.Option
		headers map[string]string

		// assert receives New's error, and the request's outcome when New
		// built the chain.
		assert func(t *testing.T, s served, err error)
	}

	cors := func(origins ...string) httpsec.Option {
		return httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: origins})
	}

	sameSite := func(origin string) map[string]string {
		return map[string]string{"Sec-Fetch-Site": "same-site", "Origin": origin}
	}

	passes := func(t *testing.T, s served, err error) {
		require.NoError(t, err)
		passedCSRF(t, s)
	}

	refused := func(t *testing.T, s served, err error) {
		require.NoError(t, err)
		refusedCrossSite(t, s)
	}

	misconfigured := func(names ...string) func(t *testing.T, _ served, err error) {
		return func(t *testing.T, _ served, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)

			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	cases := []testCase{
		{
			name:    "a sibling frontend CORS allows passes on same-site",
			opts:    []httpsec.Option{cors("https://app.example.com"), httpsec.EnableCSRFProtection()},
			headers: sameSite("https://app.example.com"),
			assert:  passes,
		},
		{
			name:    "CORS origins are trusted whatever the order of the options",
			opts:    []httpsec.Option{httpsec.EnableCSRFProtection(), cors("https://app.example.com")},
			headers: sameSite("https://app.example.com"),
			assert:  passes,
		},
		{
			name: "the consumer stops CORS origins being trusted",
			opts: []httpsec.Option{
				cors("https://app.example.com"),
				httpsec.EnableCSRFProtection(httpsec.WithoutCORSOriginsTrustedForCSRF()),
			},
			headers: sameSite("https://app.example.com"),
			assert:  refused,
		},
		{
			name:    "an unlisted same-site sibling is refused",
			opts:    []httpsec.Option{cors("https://app.example.com"), httpsec.EnableCSRFProtection()},
			headers: sameSite("https://blog.example.com"),
			assert:  refused,
		},
		{
			name:    "CORS * trusts nothing",
			opts:    []httpsec.Option{cors("*"), httpsec.EnableCSRFProtection()},
			headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
			assert:  refused,
		},
		{
			name: "an origin a CORS pattern matches is trusted",
			opts: []httpsec.Option{
				httpsec.EnableCORS(httpsec.CORSPolicy{}, httpsec.WithOriginPattern("https://*.example.com")),
				httpsec.EnableCSRFProtection(),
			},
			headers: sameSite("https://shop.example.com"),
			assert:  passes,
		},
		{
			name: "a pattern still matches one label only",
			opts: []httpsec.Option{
				httpsec.EnableCORS(httpsec.CORSPolicy{}, httpsec.WithOriginPattern("https://*.example.com")),
				httpsec.EnableCSRFProtection(),
			},
			headers: sameSite("https://a.shop.example.com"),
			assert:  refused,
		},
		{
			name:    "an added origin is trusted, normalised",
			opts:    []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins("HTTPS://Partner.Example:443"))},
			headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://partner.example"},
			assert:  passes,
		},
		{
			name:    "an added origin is trusted without Fetch Metadata",
			opts:    []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins("https://partner.example"))},
			headers: map[string]string{"Origin": "https://partner.example"},
			assert:  passes,
		},
		{
			name: "an added origin stays trusted when CORS origins are not",
			opts: []httpsec.Option{
				cors("https://app.example.com"),
				httpsec.EnableCSRFProtection(
					httpsec.WithoutCORSOriginsTrustedForCSRF(),
					httpsec.WithCSRFTrustedOrigins("https://partner.example"),
				),
			},
			headers: sameSite("https://partner.example"),
			assert:  passes,
		},
		{
			name:    "an untrusted origin without Fetch Metadata is refused",
			opts:    []httpsec.Option{cors("https://app.example.com"), httpsec.EnableCSRFProtection()},
			headers: map[string]string{"Origin": "https://evil.example"},
			assert:  refused,
		},
		{
			name:   "the null origin cannot be trusted",
			opts:   []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins("null"))},
			assert: misconfigured("WithCSRFTrustedOrigins", `"null"`),
		},
		{
			name:   "* cannot be trusted",
			opts:   []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins("*"))},
			assert: misconfigured("WithCSRFTrustedOrigins", `"*"`),
		},
		{
			name:   "a pattern cannot be trusted",
			opts:   []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins("https://*.example.com"))},
			assert: misconfigured("WithCSRFTrustedOrigins", `"https://*.example.com"`),
		},
		{
			name:   "an origin with a path cannot be trusted",
			opts:   []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins("https://partner.example/"))},
			assert: misconfigured("WithCSRFTrustedOrigins", `"https://partner.example/"`),
		},
		{
			name:   "no origin at all",
			opts:   []httpsec.Option{httpsec.EnableCSRFProtection(httpsec.WithCSRFTrustedOrigins())},
			assert: misconfigured("WithCSRFTrustedOrigins"),
		},
		{
			name:   "CSRF protection enabled twice",
			opts:   []httpsec.Option{httpsec.EnableCSRFProtection(), httpsec.EnableCSRFProtection()},
			assert: misconfigured("EnableCSRFProtection"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts...)
			if err != nil {
				tc.assert(t, served{}, err)

				return
			}

			tc.assert(t, serve(t, chain, csrfRequest(t.Context(), http.MethodPost, api, tc.headers, "")), nil)
		})
	}
}
