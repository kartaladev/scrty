package httpsecconformance

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
)

// opMetadataCacheControl is the Cache-Control of the provider's metadata under
// the default lifetime of an hour.
const opMetadataCacheControl = "public, max-age=3600"

// The provider's metadata, user info and transport edges: what a response
// carries besides its status and body, and how the chain learns a request was
// secure. They are the rows an adapter that mishandled a header list, a HEAD or
// the connection's scheme would fail.

func opMetadataHeadAnswersNoBody() Scenario {
	return Scenario{
		Name:  "oidcprovider metadata by HEAD answers the headers of a GET and no body",
		Build: opBuild,
		Request: sending(RequestSpec{
			Method: http.MethodHead, Path: opMetadataPath, ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Equal(t, opMetadataCacheControl, res.Header.Get("Cache-Control"))
			assert.Empty(t, res.Body)
			assert.False(t, res.NoRouteRan)
		},
	}
}

func opMetadataWrongMethodIsRefused() Scenario {
	return Scenario{
		Name:  "oidcprovider metadata by POST is 405 with Allow: GET, HEAD",
		Build: opBuild,
		Request: sending(RequestSpec{
			Method: http.MethodPost, Path: opMetadataPath, ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusMethodNotAllowed, res.Status)
			assert.Equal(t, "GET, HEAD", res.Header.Get("Allow"))
			assert.Empty(t, res.Header.Get("Cache-Control"), "a refusal is not cacheable as the document")
			assert.Empty(t, res.Body)
			assert.False(t, res.NoRouteRan)
		},
	}
}

func opUserInfoInvalidTokenChallenges() Scenario {
	return Scenario{
		Name:  "oidcprovider userinfo with a token it did not issue is 401 with an invalid_token challenge",
		Build: opBuild,
		Request: sending(opGet(opUserInfoPath, map[string]string{
			"Authorization": "Bearer not-a-token-the-provider-issued",
		})),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Equal(t, []string{`Bearer error="invalid_token"`}, res.Header.Values("WWW-Authenticate"))
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
			assert.Empty(t, res.Body)
			assert.False(t, res.NoRouteRan)
		},
	}
}

func opUserInfoWrongMethodIsRefused() Scenario {
	return Scenario{
		Name:  "oidcprovider userinfo by PUT is 405 with Allow: GET, POST and no-store",
		Build: opBuild,
		Request: sending(RequestSpec{
			Method: http.MethodPut, Path: opUserInfoPath, ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusMethodNotAllowed, res.Status)
			assert.Equal(t, "GET, POST", res.Header.Get("Allow"))
			assert.Equal(t, []string{"GET, POST"}, res.Header.Values("Allow"))
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.False(t, res.NoRouteRan)
		},
	}
}

// opUserInfoDPoPMalformedOffersBothSchemes is a token sent under the DPoP scheme
// and in the query as well: more than one way of sending it, which RFC 6750
// section 3.1 makes invalid_request, challenged in the scheme the token came in
// as well as Bearer (RFC 9449 section 7.2). The two challenges are two header
// lines, so an adapter that replaces a header instead of adding to it shows as
// one line.
func opUserInfoDPoPMalformedOffersBothSchemes() Scenario {
	return Scenario{
		Name: "oidcprovider userinfo with a DPoP token also in the query is 400 with a DPoP and a Bearer challenge line",
		Build: func(t *testing.T) ChainSpec {
			fx := newDPoPFixture(t)

			return opBuildOver(t, httpsec.WithHTTPSDeployment(), []oidcprovider.Option{oidcprovider.WithDPoP()},
				httpsec.EnableDPoP(httpsec.DPoP{PublicURL: OPIssuer, Replay: fx.replay}))
		},
		Request: sending(opGet(opUserInfoPath+"?access_token=also-here", map[string]string{
			"Authorization": "DPoP a-token",
		})),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusBadRequest, res.Status)

			lines := res.Header.Values("WWW-Authenticate")
			require.Len(t, lines, 2, "one line per scheme: %q", lines)
			assert.Equal(t, `Bearer error="invalid_request"`, lines[0])
			assert.True(t, strings.HasPrefix(lines[1], `DPoP error="invalid_request", algs="`), lines[1])
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.Empty(t, res.Body)
			assert.False(t, res.NoRouteRan)
		},
	}
}

// opViaProxy is req arriving from the trusted proxy, which forwards the
// client's address and says the client's connection used proto.
func opViaProxy(req RequestSpec, proto string) RequestSpec {
	header := map[string]string{"X-Forwarded-For": clientAddress, "X-Forwarded-Proto": proto}
	for k, v := range req.Header {
		header[k] = v
	}

	req.Header, req.ClientAddress = header, proxyAddress

	return req
}

// opOverTransport builds the provider with no HTTPS declaration, so what makes
// a request secure is the transport and nothing the chain was told.
func opOverTransport(transport httpsec.Option) func(*testing.T) ChainSpec {
	return func(t *testing.T) ChainSpec { return opBuildOver(t, transport, nil) }
}

func opFlowsOverATrustedProxyAreSecure() Scenario {
	return Scenario{
		Name:  "oidcprovider authorize and end-session are served when a trusted proxy says the client used https",
		Build: opOverTransport(trustingTheProxy()),
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			authorize := send(opViaProxy(opGet(opAuthorizePath+"?"+opAuthorizeParams(opThirdParty).Encode(), nil), "https"))
			require.NoError(t, authorize.Refusal)
			require.Equal(t, http.StatusSeeOther, authorize.Status, authorize.Body)
			assertHostCookie(t, assertOneSetCookiePerCookie(t, authorize, opFlowCookie)[0])

			endSession := send(opViaProxy(opGet(opLogoutPath, nil), "https"))
			require.NoError(t, endSession.Refusal)
			require.Equal(t, http.StatusSeeOther, endSession.Status, endSession.Body)
			assertHostCookie(t, assertOneSetCookiePerCookie(t, endSession, opFlowCookie)[0])
		},
	}
}

func opPlainHTTPIsRefused() Scenario {
	return Scenario{
		Name:  "oidcprovider authorize and end-session over plain http are refused with nothing parked",
		Build: opOverTransport(nil),
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			opAssertPlainHTTPRefused(t, send, opGet)
		},
	}
}

func opProxyForwardingHTTPIsRefused() Scenario {
	return Scenario{
		Name:  "oidcprovider authorize and end-session are refused when a trusted proxy says the client used http",
		Build: opOverTransport(trustingTheProxy()),
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			opAssertPlainHTTPRefused(t, send, func(target string, header map[string]string) RequestSpec {
				return opViaProxy(opGet(target, header), "http")
			})
		},
	}
}

// opAssertPlainHTTPRefused sends the authorize and end-session requests, built
// by get, and asserts each is refused 400 without a redirect or a cookie.
func opAssertPlainHTTPRefused(
	t *testing.T,
	send func(RequestSpec) Result,
	get func(target string, header map[string]string) RequestSpec,
) {
	t.Helper()

	authorize := send(get(opAuthorizePath+"?"+opAuthorizeParams(opThirdParty).Encode(), nil))
	require.ErrorIs(t, authorize.Refusal, httpsec.ErrOIDCInvalidAuthorization)
	assert.Equal(t, http.StatusBadRequest, authorize.Status)

	endSession := send(get(opLogoutPath, nil))
	require.ErrorIs(t, endSession.Refusal, httpsec.ErrOIDCInvalidEndSession)
	assert.Equal(t, http.StatusBadRequest, endSession.Status)

	for name, res := range map[string]Result{"authorize": authorize, "end-session": endSession} {
		assert.Empty(t, res.Header.Get("Location"), "%s: the browser is not redirected", name)
		assert.Empty(t, res.Header.Values("Set-Cookie"), "%s: nothing is parked", name)
		assert.False(t, res.NoRouteRan, "%s", name)
	}
}
