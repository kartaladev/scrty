package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// published is what a handler behind a resource server saw of the accepted token.
type published struct {
	served

	caller *identity.Principal
	kind   identity.CredentialsType
	token  *httpsec.AccessToken
	again  *httpsec.AccessToken
	found  bool
}

// readPublished serves req through chain, with a handler that reads the published caller and token,
// changes the token it read, and reads it again.
func readPublished(t *testing.T, chain *httpsec.Chain, req *http.Request) published {
	t.Helper()

	var out published

	run := chain.Assemble(func(ex *httpsec.Exchange) error { //nolint:contextcheck // the exchange carries the request's context
		out.handlerRan = true
		ctx := ex.Context()

		out.caller, _ = identity.PrincipalFromContext(ctx)
		if auth, ok := authenticate.AuthenticationFromContext(ctx); ok && auth.Credentials != nil {
			out.kind = auth.Credentials.Type()
		}

		out.token, out.found = httpsec.AccessTokenFromContext(ctx)
		if out.found {
			out.token.Scopes[0] = "changed"
			out.token.Audience = append(out.token.Audience, "changed")
			if out.token.Confirmation != nil {
				out.token.Confirmation["jkt"] = "changed"
			}
			out.again, _ = httpsec.AccessTokenFromContext(ctx)
		}

		return nil
	})

	out.rec = httptest.NewRecorder()
	out.err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))

	return out
}

// TestResourceServer_Publication pins what an accepted token publishes: a caller carrying the token's
// scopes whatever the source's principal carries, an external-access-token credential for a source
// other than the provider, and the token itself, a copy on every read.
func TestResourceServer_Publication(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		src    *httpsec.StubSource
		opts   []httpsec.Option
		assert func(t *testing.T, out published)
	}

	widening := func(context.Context, string) (*identity.Principal, map[string]string, error) {
		return &identity.Principal{ID: "u-1", Kind: identity.KindUser, Scopes: []string{"admin:all"}}, nil, nil
	}

	cases := []testCase{
		{
			name: "the caller is published with an external access token credential and the token's scopes",
			src:  &httpsec.StubSource{Name: "stub", Fallback: true, Unbound: true, TokenScopes: []string{"orders:read"}},
			assert: func(t *testing.T, out published) {
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
				require.NotNil(t, out.caller)
				assert.Equal(t, identity.CredentialsType(factor.ExternalAccessToken), out.kind)
				assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
			},
		},
		{
			name: "a principal widening the scopes carries the token's alone",
			src: &httpsec.StubSource{Name: "stub", Fallback: true, Unbound: true, TokenScopes: []string{"orders:read"},
				Verify: widening},
			assert: func(t *testing.T, out published) {
				require.NoError(t, out.err)
				require.NotNil(t, out.caller)
				assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
			},
		},
		{
			name: "every read of the token is a copy",
			src:  &httpsec.StubSource{Name: "stub", Fallback: true, Unbound: true, TokenScopes: []string{"orders:read"}},
			assert: func(t *testing.T, out published) {
				require.NoError(t, out.err)
				require.True(t, out.found)
				require.NotNil(t, out.again)
				assert.Equal(t, []string{"orders:read"}, out.again.Scopes)
				assert.Equal(t, "urn:orders", out.again.Resource)
				assert.NotContains(t, out.again.Audience, "changed")
			},
		},
		{
			name: "a per-request policy deny refuses the caller",
			src:  &httpsec.StubSource{Name: "stub", Fallback: true, Unbound: true, TokenScopes: []string{"orders:read"}},
			opts: []httpsec.Option{httpsec.WithPolicyEngine(rsDenyingEngine(t))},
			assert: func(t *testing.T, out published) {
				require.Error(t, out.err)
				assert.ErrorIs(t, out.err, errPolicyDenied)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(append(tc.opts,
				httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(tc.src)))...)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/orders", nil)
			req.Header.Set("Authorization", "Bearer opaque-token")

			tc.assert(t, readPublished(t, chain, req))
		})
	}
}

// TestResourceServer_PublicationFromProvider pins what a provider token publishes: the access-token
// credential, the client and scopes it was granted, and no claims.
func TestResourceServer_PublicationFromProvider(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())
	w := newPSWorld(t, psSetup{})

	tok := w.token(t, psJWTClient, &k, func(v url.Values) {
		forAPI(v)
		v.Set("scope", "openid orders:read")
	})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, psAPIURL, nil)
	r.RemoteAddr = tokenAddr
	r.Header.Set("Authorization", "DPoP "+tok)
	r.Header.Set("DPoP", k.validProof("pub-1").with(map[string]any{
		"htu": psAPIURL, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
	}).sign(t))

	out := readPublished(t, w.chain, r)

	require.NoError(t, out.err)
	require.True(t, out.found)
	assert.Equal(t, identity.CredentialsType(factor.AccessToken), out.kind)
	assert.Equal(t, psJWTClient, out.token.ClientID)
	assert.Equal(t, psAPI, out.token.Resource)
	assert.Equal(t, opIssuer, out.token.Issuer)
	assert.Equal(t, "u-1", out.token.Subject)
	assert.Empty(t, out.token.Claims)
	assert.Equal(t, k.jkt, out.again.Confirmation["jkt"])
	assert.ElementsMatch(t, []string{"openid", "orders:read"}, out.again.Scopes)
	assert.False(t, out.again.ExpiresAt.IsZero())
	assert.ElementsMatch(t, []string{"openid", "orders:read"}, out.caller.Scopes)
}

// errPolicyDenied is the reason rsDenyingEngine's policy gives.
var errPolicyDenied = policyDenied{}

type policyDenied struct{}

func (policyDenied) Error() string { return "denied by the test policy" }

// rsDenyingEngine is a policy engine whose one per-request policy denies every caller, after checking
// it is judged as an external access token.
func rsDenyingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: deny all").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
			assert.Equal(t, factor.ExternalAccessToken, in.FirstFactor)

			return policy.Decision{Outcome: policy.Deny, Reason: errPolicyDenied}
		})

	return engineOf(t, p)
}
