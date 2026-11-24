package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
)

// undiscoverableRP is a relying party whose provider pins no endpoint, so a login
// start must discover them, from an upstream that serves no discovery document. Its
// flow store is a mock expecting nothing: no flow may be stored.
func undiscoverableRP(t *testing.T, idp *oidcTestProvider, origin string) *oidc.RelyingParty {
	t.Helper()

	reg := idp.provider()
	reg.RedirectURL = origin + httpsec.DefaultOIDCCallbackPath + testOIDCProvider
	reg.AuthorizationEndpoint, reg.TokenEndpoint, reg.JWKSURI = "", "", ""

	return must.Must(oidc.NewRelyingParty(must.Must(oidc.NewRegistry(reg)),
		must.Must(oidc.NewBroker(oidc.NewMemoryLinkStore(), parkedUsers(t))),
		oidc.WithOutboundClient(must.Must(outbound.New(outbound.WithHTTPClient(idp.srv.Client())))),
		oidc.WithFlowStore(NewMockFlowStore(gomock.NewController(t)))))
}

// TestAuthorize_DiscoveryFailureReturnsToLogin pins that a login start for a parked
// request whose provider cannot be discovered returns to the login page with
// temporarily_unavailable, storing no flow and setting no cookie (D3), while an
// ordinary destination, or a parked request the checks refuse, keeps its answer.
func TestAuthorize_DiscoveryFailureReturnsToLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// next is the destination the start asks for, and flow the provider flow
		// cookie it carries, given the parked handle and its own flow cookie.
		next   func(handle string) string
		other  bool
		assert func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string)
	}

	kept := func(t *testing.T, _ *completionFlow, a flowAnswer, _, _ string) {
		t.Helper()

		require.ErrorIs(t, a.err, oidc.ErrDiscoveryFailed)
		assert.Empty(t, a.header.Get("Location"), "no redirect")
	}

	cases := []testCase{
		{
			name: "a parked request's login page",
			next: parkedAt,
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
				t.Helper()

				require.NoError(t, a.err, "nothing reached the error handling")
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, parkedReturn(handle, httpsec.DefaultOIDCLoginErrorParam,
					oidcprovider.CodeTemporarilyUnavailable), a.header.Get("Location"))
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "the request stays parked")
			},
		},
		{name: "an ordinary destination", next: func(string) string { return "/welcome" }, assert: kept},
		{name: "a parked request bound to another browser", next: parkedAt, other: true, assert: kept},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, completionSetup{rp: undiscoverableRP})
			handle, flow := f.park(t, flowWeb)
			if tc.other {
				_, flow = f.park(t, flowWeb)
			}

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				f.issuer+httpsec.DefaultOIDCAuthorizePath+testOIDCProvider+"?"+
					url.Values{httpsec.DefaultOIDCNextParam: {tc.next(handle)}}.Encode(), nil)

			a := f.serve(t, r, []flowChange{flowCookieOf(flowCookie, flow)})

			tc.assert(t, f, a, handle, flow)
			assert.Empty(t, a.header.Values("Set-Cookie"), "no cookie is set")
		})
	}
}
