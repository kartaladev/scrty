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
		{name: "an encoded slash is not the exempt path", csrf: webhook, method: http.MethodPost, path: "/webhooks%2Fpayments", assert: judged},
		{name: "an encoded letter is not the exempt path", csrf: webhook, method: http.MethodPost, path: "/webhooks/p%61yments", assert: judged},
		{name: "a wildcard does not match a segment holding an encoded slash", csrf: events, method: http.MethodPost, path: "/webhooks/a%2Fb/events", assert: judged},
		{name: "a wildcard does not match an encoded dot segment", csrf: events, method: http.MethodPost, path: "/webhooks/%2E%2E/events", assert: judged},
		{name: "a wildcard matches an encoded segment", csrf: events, method: http.MethodPost, path: "/webhooks/str%69pe/events", assert: exempt},
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
		{
			name:   "a wildcard in the back-channel path widens nothing",
			extra:  oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/*/logout")),
			method: http.MethodPost, path: "/idp/settings/logout/" + testOIDCProvider, assert: judged,
		},
		{
			name:   "a back-channel path holding \"*\" is exempt as written",
			extra:  oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/*/logout")),
			method: http.MethodPost, path: "/idp/*/logout/" + testOIDCProvider, assert: notRefusedAsCrossSite,
		},
		{
			name:  "an encoded slash in the provider segment is not the back-channel endpoint",
			extra: oidcLogin(), method: http.MethodPost, path: backchannel + "%2Fextra", assert: judged,
		},
		{
			name:  "an encoded back-channel path is not the back-channel endpoint",
			extra: oidcLogin(), method: http.MethodPost, path: "/l%6Fgout" + backchannel[len("/logout"):], assert: judged,
		},
		{
			name:  "a back-channel exemption that cannot be built fails construction",
			extra: oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/../logout")),
			assert: func(t *testing.T, _ served, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "WithOIDCBackchannelLogoutPath")
				assert.ErrorContains(t, err, "WithoutBackchannelLogoutExemption")
			},
		},
		{
			name:  "a back-channel path that cannot be exempt builds once the exemption is removed",
			csrf:  []httpsec.CSRFOption{httpsec.WithoutBackchannelLogoutExemption()},
			extra: oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/../logout")),
			assert: func(t *testing.T, _ served, err error) {
				require.NoError(t, err)
			},
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
		{name: "an exemption with an encoded dot-dot segment", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/%2e%2e/settings")}, assert: misconfigured},
		{name: "an exemption with an encoded dot segment", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/%2E")}, assert: misconfigured},
		{name: "an exemption with an encoded slash", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/a%2Fb")}, assert: misconfigured},
		{name: "an exemption with a malformed escape", csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/%zz")}, assert: misconfigured},
		{
			name: "an exemption with a segment a request would escape fails construction",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/café")},
			assert: func(t *testing.T, _ served, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "WithCSRFExemption")
				assert.ErrorContains(t, err, "escaped form")
				assert.ErrorContains(t, err, `"caf%C3%A9"`, "the error names the segment's own escaped spelling")
			},
		},
		{
			name: "an exemption with a space in a segment fails construction",
			csrf: []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/a b")},
			assert: func(t *testing.T, _ served, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, `"a%20b"`, "the error names the segment's own escaped spelling")
			},
		},
		{
			name:   "an exemption with an escaped space matches that escaped form",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/a%20b")},
			method: http.MethodPost, path: "/webhooks/a%20b", assert: exempt,
		},
		{
			name:   "an exemption with a wildcard and an escaped segment matches both",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/*/caf%C3%A9")},
			method: http.MethodPost, path: "/webhooks/stripe/caf%C3%A9", assert: exempt,
		},
		{
			name:   "a wildcard exemption still refuses a segment a request would escape",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/*/café")},
			assert: misconfigured,
		},
		{
			name:   "an exemption with a legitimately encoded segment matches that escaped form",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/caf%C3%A9")},
			method: http.MethodPost, path: "/webhooks/caf%C3%A9", assert: exempt,
		},
		{
			name:   "an exemption with a legitimately encoded segment judges another escaping of it",
			csrf:   []httpsec.CSRFOption{httpsec.WithCSRFExemption(http.MethodPost, "/webhooks/caf%C3%A9")},
			method: http.MethodPost, path: "/webhooks/caf%c3%a9", assert: judged,
		},
		{
			name:  "a back-channel path the request would escape fails construction",
			extra: oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/déconnexion")),
			assert: func(t *testing.T, _ served, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "WithOIDCBackchannelLogoutPath")
				assert.ErrorContains(t, err, "WithoutBackchannelLogoutExemption")
			},
		},
		{
			name:  "a back-channel path the request would escape builds once the exemption is removed",
			csrf:  []httpsec.CSRFOption{httpsec.WithoutBackchannelLogoutExemption()},
			extra: oidcLogin(httpsec.WithOIDCBackchannelLogoutPath("/idp/déconnexion")),
			assert: func(t *testing.T, _ served, err error) {
				require.NoError(t, err)
			},
		},
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
