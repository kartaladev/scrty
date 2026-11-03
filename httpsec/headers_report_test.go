package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

const (
	cspReportOnly = "Content-Security-Policy-Report-Only"
	reportURL     = "https://reports.example.com/csp"
)

func TestSecurityHeaders_ReportOnly(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.HeaderOption
		assert func(t *testing.T, run headerRun, err error)
	}

	cases := []testCase{
		{
			name: "report-only alone sends the nonce policy as report-only and no enforced policy",
			opts: []httpsec.HeaderOption{httpsec.WithCSPReportOnly()},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				h := run.rec.Header()
				assert.Empty(t, h.Values("Content-Security-Policy"))

				nonce := nonceOf(t, h.Get(cspReportOnly))
				assert.Equal(t, "script-src 'nonce-"+nonce+"' 'strict-dynamic'; object-src 'none'; "+
					"base-uri 'none'; frame-ancestors 'none'", h.Get(cspReportOnly))
				assert.Equal(t, nonce, run.nonce, "the handler reads the nonce the policy carries")
				assert.Empty(t, h.Values("Reporting-Endpoints"))
			},
		},
		{
			name: "the order of report-only and WithCSP does not matter",
			opts: []httpsec.HeaderOption{
				httpsec.WithCSPReportOnly(),
				httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'"))),
			},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				h := run.rec.Header()
				assert.Empty(t, h.Values("Content-Security-Policy"))
				assert.Contains(t, h.Get(cspReportOnly), "img-src 'self'")
			},
		},
		{
			name: "an enforced policy and a report-only candidate share one nonce",
			opts: []httpsec.HeaderOption{
				httpsec.WithCSPReportOnlyPolicy(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'none'"))),
			},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				h := run.rec.Header()
				enforced := h.Get("Content-Security-Policy")
				candidate := h.Get(cspReportOnly)

				assert.NotContains(t, enforced, "img-src")
				assert.Contains(t, candidate, "img-src 'none'")
				assert.Equal(t, nonceOf(t, enforced), nonceOf(t, candidate))
				assert.Equal(t, run.nonce, nonceOf(t, candidate))
			},
		},
		{
			name: "a reporting endpoint is sent and referenced by report-to and report-uri",
			opts: []httpsec.HeaderOption{
				httpsec.WithCSPReportOnly(),
				httpsec.WithReportingEndpoint("csp", reportURL),
			},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				h := run.rec.Header()
				assert.Equal(t, `csp="`+reportURL+`"`, h.Get("Reporting-Endpoints"))
				assert.Contains(t, h.Get(cspReportOnly), "report-to csp")
				assert.Contains(t, h.Get(cspReportOnly), "report-uri "+reportURL)
				assert.Empty(t, h.Values("Content-Security-Policy"))
			},
		},
		{
			name: "an enforced policy with an endpoint reports from both policies",
			opts: []httpsec.HeaderOption{
				httpsec.WithCSPReportOnlyPolicy(httpsec.StrictCSP()),
				httpsec.WithReportingEndpoint("csp", reportURL),
			},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				h := run.rec.Header()
				for _, name := range []string{"Content-Security-Policy", cspReportOnly} {
					assert.Contains(t, h.Get(name), "report-to csp", name)
					assert.Contains(t, h.Get(name), "report-uri "+reportURL, name)
				}
			},
		},
		{
			name: "a plain-HTTP endpoint fails construction naming the reporting endpoint",
			opts: []httpsec.HeaderOption{httpsec.WithReportingEndpoint("csp", "http://reports.example.com/csp")},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithReportingEndpoint")
			},
		},
		{
			name: "a relative endpoint fails construction",
			opts: []httpsec.HeaderOption{httpsec.WithReportingEndpoint("csp", "/csp")},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "an endpoint URL holding a separator fails construction",
			opts: []httpsec.HeaderOption{httpsec.WithReportingEndpoint("csp", "https://r.example.com/a;script-src *")},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "an endpoint name that is not a structured-field key fails construction",
			opts: []httpsec.HeaderOption{httpsec.WithReportingEndpoint("CSP Name", reportURL)},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithReportingEndpoint")
			},
		},
		{
			name: "two endpoints fail construction",
			opts: []httpsec.HeaderOption{
				httpsec.WithReportingEndpoint("csp", reportURL),
				httpsec.WithReportingEndpoint("other", reportURL),
			},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "an endpoint with no policy to report from fails construction",
			opts: []httpsec.HeaderOption{
				httpsec.WithoutHeader("Content-Security-Policy"),
				httpsec.WithReportingEndpoint("csp", reportURL),
			},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithReportingEndpoint")
			},
		},
		{
			name: "report-only with the policy removed fails construction",
			opts: []httpsec.HeaderOption{
				httpsec.WithoutHeader("Content-Security-Policy"),
				httpsec.WithCSPReportOnly(),
			},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithCSPReportOnly")
			},
		},
		{
			name: "report-only and a report-only candidate together fail construction",
			opts: []httpsec.HeaderOption{
				httpsec.WithCSPReportOnly(),
				httpsec.WithCSPReportOnlyPolicy(httpsec.StrictCSP()),
			},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "a candidate that cannot be sent fails construction naming the option",
			opts: []httpsec.HeaderOption{
				httpsec.WithCSPReportOnlyPolicy(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "a;b"))),
			},
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithCSPReportOnlyPolicy")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.EnableSecurityHeaders(tc.opts...))
			if err != nil {
				tc.assert(t, headerRun{}, err)

				return
			}

			var run headerRun

			run.rec = httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				run.nonce, run.nonceOK = httpsec.CSPNonce(r.Context())
			})).ServeHTTP(run.rec, getRequest(t, "/"))

			tc.assert(t, run, nil)
		})
	}
}

func TestSecurityHeaders_HashPreset(t *testing.T) {
	t.Parallel()

	const (
		sha256Hash = "sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI="
		sha384Hash = "sha384-HT2E9NfWiuQ/w1PRai+hTyqW16NIoCGA/m8VQDUopfAtcz6YQjtsMmQd5uRbVDpW"
		sha512Hash = "sha512-+uuYUxxe7oWIShQrWEmMn/fixz/rxDP4qcAZddXLDM3nN8/tpk1ZC2jXQk6N+mXE65jwfzNVUJL/qjA3y9KbuQ=="
	)

	type testCase struct {
		name   string
		policy httpsec.CSPPolicy
		assert func(t *testing.T, run headerRun, err error)
	}

	cases := []testCase{
		{
			name:   "a SHA-256 hash is listed and no nonce is generated",
			policy: httpsec.HashCSP(sha256Hash),
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				assert.Equal(t, "script-src '"+sha256Hash+"'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
					run.rec.Header().Get("Content-Security-Policy"))
				assert.False(t, run.nonceOK, "no nonce is generated")
				assert.NotContains(t, run.rec.Header().Get("Content-Security-Policy"), "nonce")
			},
		},
		{
			name:   "SHA-384 and SHA-512 hashes are listed in the order given",
			policy: httpsec.HashCSP(sha384Hash, sha512Hash),
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.Contains(t, run.rec.Header().Get("Content-Security-Policy"),
					"script-src '"+sha384Hash+"' '"+sha512Hash+"';")
			},
		},
		{
			name:   "a hash already in quotes is accepted once",
			policy: httpsec.HashCSP("'" + sha256Hash + "'"),
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.Contains(t, run.rec.Header().Get("Content-Security-Policy"), "script-src '"+sha256Hash+"';")
			},
		},
		{
			name:   "directives can be added to the preset",
			policy: httpsec.HashCSP(sha256Hash).With(httpsec.CSPDirective("img-src", "'self'")),
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.Contains(t, run.rec.Header().Get("Content-Security-Policy"), "img-src 'self'")
			},
		},
		{
			name:   "malformed base64 fails construction naming the hash preset",
			policy: httpsec.HashCSP("sha256-not-base64!"),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "HashCSP")
			},
		},
		{
			name:   "a digest of the wrong length for its algorithm fails construction",
			policy: httpsec.HashCSP("sha512-" + sha256Hash[len("sha256-"):]),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name:   "an unknown algorithm fails construction",
			policy: httpsec.HashCSP("md5-" + sha256Hash[len("sha256-"):]),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name:   "a hash with only an opening quote fails construction",
			policy: httpsec.HashCSP("'" + sha256Hash),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name:   "a hash with only a closing quote fails construction",
			policy: httpsec.HashCSP(sha256Hash + "'"),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name:   "a nonce source passed as a hash fails construction",
			policy: httpsec.HashCSP("'nonce-abc'"),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name:   "a hash holding a separator fails construction",
			policy: httpsec.HashCSP(sha256Hash + "; script-src *"),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name:   "no hash fails construction",
			policy: httpsec.HashCSP(),
			assert: func(t *testing.T, _ headerRun, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "HashCSP")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.EnableSecurityHeaders(httpsec.WithCSP(tc.policy)))
			if err != nil {
				tc.assert(t, headerRun{}, err)

				return
			}

			var run headerRun

			run.rec = httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				run.nonce, run.nonceOK = httpsec.CSPNonce(r.Context())
			})).ServeHTTP(run.rec, getRequest(t, "/"))

			tc.assert(t, run, nil)
		})
	}
}
