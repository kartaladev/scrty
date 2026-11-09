package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
)

// csrfDownLimiter is a limiter that cannot answer, which every throttle reads as
// a source over its limit. A request that gets a throttle's answer has therefore
// passed CSRF protection and run the throttle.
type csrfDownLimiter struct{}

func (csrfDownLimiter) Exceeded(context.Context, string) (bool, error) {
	return true, assert.AnError
}

func (csrfDownLimiter) RecordFailure(context.Context, string) error { return assert.AnError }

func (csrfDownLimiter) Charge(context.Context, string) (ratelimit.Receipt, bool, error) {
	return ratelimit.Receipt{}, true, assert.AnError
}

func (csrfDownLimiter) Refund(context.Context, ratelimit.Receipt) error { return nil }

// csrfServed is what a cross-site request to a provider's chain got.
type csrfServed struct {
	status   int
	err      error
	passedOn bool
}

func TestCSRF_OIDCProviderExemptions(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	const (
		crossSiteOrigin = "https://rp.example.org"
		issuer          = opIssuer
	)

	// crossSite is what a browser sends for a form a page on another site posts.
	crossSite := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": crossSiteOrigin}

	type testCase struct {
		name     string
		csrf     []httpsec.CSRFOption
		provider []httpsec.OIDCProviderOption
		// noProvider builds a chain with CSRF protection alone.
		noProvider bool
		method     string
		target     string
		assert     func(t *testing.T, s csrfServed)
	}

	// exempt: CSRF protection did not judge the request, and the provider's
	// endpoint answered it.
	exempt := func(t *testing.T, s csrfServed) {
		t.Helper()

		assert.NotErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
		assert.NotEqual(t, http.StatusForbidden, s.status)
		assert.False(t, s.passedOn, "the provider answers it, and the application never sees it")
	}

	// refused: CSRF protection refused it as cross-site, before any handler.
	refused := func(t *testing.T, s csrfServed) {
		t.Helper()

		require.ErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
		assert.Equal(t, http.StatusForbidden, s.status)
		assert.False(t, s.passedOn)
	}

	// refusedAtEntry: the chain refused a dot segment as malformed, before CSRF
	// protection or any exemption was consulted.
	refusedAtEntry := func(t *testing.T, s csrfServed) {
		t.Helper()

		require.ErrorIs(t, s.err, httpsec.ErrMalformedRequest)
		assert.Equal(t, http.StatusBadRequest, s.status)
		assert.False(t, s.passedOn)
	}

	// throttled: the request passed CSRF protection and met the endpoint's throttle.
	throttled := func(status int) func(*testing.T, csrfServed) {
		return func(t *testing.T, s csrfServed) {
			t.Helper()

			assert.NotErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
			assert.Equal(t, status, s.status)
			assert.False(t, s.passedOn)
		}
	}

	post := http.MethodPost

	cases := []testCase{
		{name: "authorization is exempt", method: post, target: issuer + "/oauth2/authorize", assert: exempt},
		{name: "token is exempt", method: post, target: issuer + "/oauth2/token", assert: exempt},
		{name: "revocation is exempt", method: post, target: issuer + "/oauth2/revoke", assert: exempt},
		{name: "introspection is exempt", method: post, target: issuer + "/oauth2/introspect", assert: exempt},
		{name: "end-session is exempt", method: post, target: issuer + "/oauth2/logout", assert: exempt},

		{name: "resume stays protected", method: post, target: issuer + "/oauth2/authorize/resume", assert: refused},
		{name: "the logout confirmation stays protected", method: post, target: issuer + "/oauth2/logout/confirm", assert: refused},
		{name: "the consents endpoint stays protected", method: post, target: issuer + "/oauth2/consents", assert: refused},
		{name: "a consent revocation stays protected", method: http.MethodDelete, target: issuer + "/oauth2/consents", assert: refused},

		// RFC 6750 lets a client POST its access token in a form, but the spec's
		// list is exact and names no UserInfo: it stays judged, and a consumer
		// that wants it exempt states it.
		{name: "UserInfo is not in the exemption list and stays judged", method: post, target: issuer + "/oauth2/userinfo", assert: refused},
		{
			name: "a consumer exempts UserInfo itself",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(post, "/oauth2/userinfo")},
			// UserInfo refuses a request with no token, so the answer is its own.
			method: post, target: issuer + "/oauth2/userinfo", assert: throttled(http.StatusUnauthorized),
		},

		{
			name:     "a moved endpoint path is followed",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/connect/token")},
			method:   post, target: issuer + "/connect/token", assert: exempt,
		},
		{
			name:     "the path an endpoint moved from is judged",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/connect/token")},
			method:   post, target: issuer + "/oauth2/token", assert: refused,
		},
		{
			name:     "a moved prefix is followed",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/idp")},
			method:   post, target: issuer + "/idp/revoke", assert: exempt,
		},
		{
			name:     "the prefix the provider moved from is judged",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/idp")},
			method:   post, target: issuer + "/oauth2/revoke", assert: refused,
		},
		{
			name:     "a moved prefix keeps resume protected",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/idp")},
			method:   post, target: issuer + "/idp/authorize/resume", assert: refused,
		},

		{name: "an escaped spelling of the token path stays judged", method: post, target: issuer + "/oauth2/%74oken", assert: refused},
		{name: "a trailing slash stays judged", method: post, target: issuer + "/oauth2/token/", assert: refused},
		{name: "another case stays judged", method: post, target: issuer + "/oauth2/Token", assert: refused},
		{name: "a dot segment is refused at the entry", method: post, target: issuer + "/oauth2/./token", assert: refusedAtEntry},
		{name: "only POST is exempt", method: http.MethodPut, target: issuer + "/oauth2/token", assert: refused},

		{
			name:       "a chain with no provider judges the same path",
			noProvider: true,
			method:     post, target: issuer + "/oauth2/token", assert: refused,
		},
		{
			name:   "an exemption the consumer also states builds, and exempts",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(post, "/oauth2/token")},
			method: post, target: issuer + "/oauth2/token", assert: exempt,
		},
		{
			name:   "an exemption of the consumer's own route is kept",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(post, "/webhooks/payments")},
			method: post, target: issuer + "/webhooks/payments", assert: func(t *testing.T, s csrfServed) {
				t.Helper()

				assert.NoError(t, s.err)
				assert.True(t, s.passedOn)
			},
		},

		{
			name:     "an exempt authorization still runs its throttle",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCAuthorizeLimiter(csrfDownLimiter{})},
			method:   post, target: issuer + "/oauth2/authorize", assert: throttled(http.StatusTooManyRequests),
		},
		{
			name:     "an exempt token endpoint still runs its throttle",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCTokenLimiter(csrfDownLimiter{})},
			method:   post, target: issuer + "/oauth2/token", assert: throttled(http.StatusUnauthorized),
		},
		{
			name:     "an exempt revocation still runs its throttle",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCRevokeLimiter(csrfDownLimiter{})},
			method:   post, target: issuer + "/oauth2/revoke", assert: throttled(http.StatusUnauthorized),
		},
		{
			name:     "an exempt introspection still runs its throttle",
			provider: []httpsec.OIDCProviderOption{httpsec.WithOIDCIntrospectLimiter(csrfDownLimiter{})},
			method:   post, target: issuer + "/oauth2/introspect", assert: throttled(http.StatusUnauthorized),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got error

			onError := httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
				got = err
				w.WriteHeader(httpsec.StatusForError(err))
			})

			opts := []httpsec.Option{onError}

			if tc.noProvider {
				opts = append(opts, httpsec.EnableCSRFProtection(tc.csrf...))
			} else {
				p := f.provider(t)
				opts = append(opts,
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(tc.csrf...),
					httpsec.EnableOIDCProvider(p, tc.provider...),
				)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			r := httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, nil)
			for name, value := range crossSite {
				r.Header.Set(name, value)
			}

			var passedOn bool

			h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			tc.assert(t, csrfServed{status: rec.Code, err: got, passedOn: passedOn})
		})
	}
}
