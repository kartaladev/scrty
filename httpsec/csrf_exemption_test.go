package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

func TestCSRF_Exemptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		csrf  []httpsec.CSRFOption
		extra func(t *testing.T) []httpsec.Option

		// method and path are those of a cross-site request with no token;
		// path is the request target as sent, before any decoding.
		method string
		path   string

		// assert receives New's error, and the request's outcome when New
		// built the chain.
		assert func(t *testing.T, s served, err error)
	}

	webhook := []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/payments")}
	events := []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/*/events")}

	exempt := func(t *testing.T, s served, err error) {
		require.NoError(t, err)
		passedCSRF(t, s)
	}

	judged := func(t *testing.T, s served, err error) {
		require.NoError(t, err)
		refusedCrossSite(t, s)
	}

	// notRefusedAsCrossSite is the back-channel endpoint reached: it answers
	// the request itself, refusing a missing logout token, but CSRF protection
	// did not refuse it.
	notRefusedAsCrossSite := func(t *testing.T, s served, err error) {
		require.NoError(t, err)
		assert.NotErrorIs(t, s.err, httpsec.ErrCrossSiteRequest)
	}

	misconfigured := func(t *testing.T, _ served, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.ErrorContains(t, err, "WithCSRFExemption")
	}

	oidcLogin := func(opts ...httpsec.OIDCOption) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			h := newOIDCHarness(t)

			return []httpsec.Option{httpsec.EnableOIDCLogin(
				httpsec.OIDCDeps{RelyingParty: h.manager, Handoff: h.handoffs},
				append([]httpsec.OIDCOption{httpsec.WithOIDCTokens(h.tokens), httpsec.WithOIDCSessions(h.sessions)}, opts...)...,
			)}
		}
	}

	backchannel := httpsec.DefaultOIDCBackchannelPath + testOIDCProvider

	cases := []testCase{
		{name: "an exempt route is not judged", csrf: webhook, method: http.MethodPost, path: "/webhooks/payments", assert: exempt},
		{name: "a trailing slash is another route", csrf: webhook, method: http.MethodPost, path: "/webhooks/payments/", assert: judged},
		{name: "a case change is another route", csrf: webhook, method: http.MethodPost, path: "/Webhooks/payments", assert: judged},
		{
			name: "dot segments are another route", csrf: webhook,
			method: http.MethodPost, path: "/webhooks/payments/../../settings", assert: judged,
		},
		{name: "an exempt prefix exempts nothing under it", csrf: webhook, method: http.MethodPost, path: "/webhooks/payments/refunds", assert: judged},
		{name: "another method on an exempt path", csrf: webhook, method: http.MethodDelete, path: "/webhooks/payments", assert: judged},
		{name: "a method in another case", csrf: webhook, method: "post", path: "/webhooks/payments", assert: judged},
		{name: "an encoded trailing slash", csrf: webhook, method: http.MethodPost, path: "/webhooks/payments%2F", assert: judged},
		{name: "an encoded case change", csrf: webhook, method: http.MethodPost, path: "/%57ebhooks/payments", assert: judged},
		{
			name: "encoded dot segments", csrf: webhook,
			method: http.MethodPost, path: "/webhooks/payments%2F..%2F..%2Fsettings", assert: judged,
		},
		{name: "a wildcard matches one segment", csrf: events, method: http.MethodPost, path: "/webhooks/stripe/events", assert: exempt},
		{name: "a wildcard does not match two segments", csrf: events, method: http.MethodPost, path: "/webhooks/a/b/events", assert: judged},
		{name: "a wildcard does not match an empty segment", csrf: events, method: http.MethodPost, path: "/webhooks//events", assert: judged},
		{name: "a wildcard does not match a dot segment", csrf: events, method: http.MethodPost, path: "/webhooks/../events", assert: judged},
		{name: "a wildcard does not match a current-directory segment", csrf: events, method: http.MethodPost, path: "/webhooks/./events", assert: judged},
		{name: "a wildcard pattern does not match a trailing slash", csrf: events, method: http.MethodPost, path: "/webhooks/stripe/events/", assert: judged},
		{
			name:  "back-channel logout is exempt by default",
			extra: oidcLogin(), method: http.MethodPost, path: backchannel, assert: notRefusedAsCrossSite,
		},
		{
			name:  "back-channel logout is judged once its exemption is removed",
			csrf:  []httpsec.CSRFOption{httpsec.WithoutBackchannelLogoutExemption()},
			extra: oidcLogin(), method: http.MethodPost, path: backchannel, assert: judged,
		},
		{
			name:   "the back-channel exemption follows its configured path",
			extra:  oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/logout")),
			method: http.MethodPost, path: "/idp/logout/" + testOIDCProvider, assert: notRefusedAsCrossSite,
		},
		{
			name:   "the default back-channel path is judged once the path is moved",
			extra:  oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/logout")),
			method: http.MethodPost, path: backchannel, assert: judged,
		},
		{
			name:  "the back-channel exemption covers one provider segment only",
			extra: oidcLogin(), method: http.MethodPost, path: backchannel + "/extra", assert: judged,
		},
		{
			name:  "the back-channel exemption is POST only",
			extra: oidcLogin(), method: http.MethodPut, path: backchannel, assert: judged,
		},
		{name: "without OIDC login nothing is exempt", method: http.MethodPost, path: backchannel, assert: judged},
		{name: "an exemption without a method", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption("", "/webhooks/payments")}, assert: misconfigured},
		{name: "an exemption of the root", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/")}, assert: misconfigured},
		{name: "an exemption with an empty pattern", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "")}, assert: misconfigured},
		{name: "an exemption of a relative path", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "webhooks")}, assert: misconfigured},
		{name: "an exemption of a method that is never judged", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodGet, "/feed")}, assert: misconfigured},
		{name: "an exemption whose method is not a token", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption("PO ST", "/webhooks")}, assert: misconfigured},
		{name: "an exemption with a partial wildcard", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/pay*")}, assert: misconfigured},
		{name: "an exemption with a dot segment", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/../settings")}, assert: misconfigured},
		{name: "an exemption with an empty segment", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks//payments")}, assert: misconfigured},
		{name: "an exemption of wildcards alone", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/*")}, assert: misconfigured},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []httpsec.Option{httpsec.EnableCSRFProtection(tc.csrf...)}
			if tc.extra != nil {
				opts = append(opts, tc.extra(t)...)
			}

			chain, err := httpsec.New(opts...)
			if err != nil || tc.path == "" {
				tc.assert(t, served{}, err)

				return
			}

			req := csrfRequest(t.Context(), tc.method, "https://app.example.com"+tc.path,
				map[string]string{"Sec-Fetch-Site": "cross-site"}, "")

			tc.assert(t, serve(t, chain, req), nil)
		})
	}
}
