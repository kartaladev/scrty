package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// TestResourceServer_SessionTokenOfDeclaredType pins that a session token typed as the chain's
// session generator declares — not only the default scrty+jwt — is never offered to a source, even
// when it names a source's issuer: the signed bearer judges it. Were it offered, the source would
// refuse it (401) and the session would never be honoured on the resource server's paths.
func TestResourceServer_SessionTokenOfDeclaredType(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		typ    string
		source func(t *testing.T, h *authHarness) (*session.Sessions, []httpsec.Option)
		assert func(t *testing.T, out served)
	}

	accepted := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the signed bearer accepted the session token")
		assert.NotEqual(t, http.StatusUnauthorized, out.rec.Code)
	}

	// fromProvider needs a manager that reports sign-in ends to the provider, over the harness store.
	fromProvider := func(t *testing.T, h *authHarness) (*session.Sessions, []httpsec.Option) {
		t.Helper()

		p := f.provider(t)

		m, err := session.New(session.WithStore(h.store), session.WithEndObserver(p))
		require.NoError(t, err)

		return m, []httpsec.Option{
			httpsec.EnableJWKSEndpoint(f.keys),
			httpsec.EnableSecurityHeaders(),
			httpsec.EnableCSRFProtection(),
			httpsec.EnableCertificateBinding(),
			httpsec.EnableOIDCProvider(p),
			httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p)),
		}
	}

	// fromIssuer's key-set URL is never reachable: a token offered to it fails to be verified.
	fromIssuer := func(_ *testing.T, h *authHarness) (*session.Sessions, []httpsec.Option) {
		return h.sessions, []httpsec.Option{httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"),
			httpsec.FromIssuer(opIssuer, httpsec.WithUnboundTokens(), httpsec.WithJWKSURL("https://keys.example/certs")))}
	}

	cases := []testCase{
		{name: "a custom type beside a provider source of the same issuer", typ: "app+jwt", source: fromProvider, assert: accepted},
		{name: "a custom type beside an issuer source of the same issuer", typ: "app+jwt", source: fromIssuer, assert: accepted},
		{name: "a custom type in another spelling", typ: "Application/App+JWT", source: fromIssuer, assert: accepted},
		{name: "the default type beside an issuer source of the same issuer", source: fromIssuer, assert: accepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			genOpts := []token.Option{token.WithIssuer(opIssuer), token.WithoutAudience()}
			if tc.typ != "" {
				genOpts = append(genOpts, token.WithTokenType(tc.typ))
			}

			gen, err := token.NewGenerator(f.keys, genOpts...)
			require.NoError(t, err)

			h := newAuthHarness(t)
			h.expectLiveSessionAndUser(liveSession())

			sessions, sourceOpts := tc.source(t, h)
			opts := append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: sessions, Users: h.users}),
			}, sourceOpts...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			raw, err := gen.Generate(t.Context(), testJTI, &identity.Principal{ID: testUserID, Username: testUsername})
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/api/x", nil)
			req.Header.Set("Authorization", "Bearer "+raw)

			tc.assert(t, serve(t, chain, req))
		})
	}
}
