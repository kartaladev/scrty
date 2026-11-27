package httpsec_test

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
)

// TestSessionCookie_RenewalIgnoresDPoP pins that a renewal on a cookie chain
// that also enables DPoP reads no proof: the request's DPoP header, valid or
// not, neither refuses the renewal nor binds the successor, and the new cookie
// authenticates. A header-bearer chain still judges the proof beside its
// credential, so the same invalid header refuses the renewal there.
func TestSessionCookie_RenewalIgnoresDPoP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "cookie chain: an invalid proof renews, the successor is unbound, and the new cookie works",
			assert: func(t *testing.T) {
				t.Helper()

				w := newBrowserWorld(t)
				w.extra = append(w.extra, dpopFeatures(false)...)
				w.build(t)

				old := w.signedIn(t)
				w.clk.Advance(time.Minute)

				key := newDPoPKey(t, elliptic.P256())
				req := browserRequest(t, httpsec.DefaultSessionRenewalPath, "", "", old, "")
				out := serve(t, w.chain, withProof(req,
					cookieProof(t, key, httpsec.DefaultSessionRenewalPath, "j-renew", w.clk.Now(), true)))
				require.NoError(t, out.err, "the proof beside a cookie is not read")

				c := cookieNamed(out.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, c, "the renewal set the successor's cookie")
				require.NotEqual(t, old, c.Value)

				successor, err := w.sessions.Load(t.Context(), c.Value)
				require.NoError(t, err)
				assert.True(t, successor.KeyBinding.IsZero(), "the successor is unbound")

				next := w.visit(t, c.Value)
				require.NoError(t, next.err, "the new cookie authenticates")
				assert.True(t, next.handlerRan)
			},
		},
		{
			name: "header-bearer chain: an invalid proof still refuses the renewal",
			assert: func(t *testing.T) {
				t.Helper()

				key := newDPoPKey(t, elliptic.P256())
				f := renewalEndpoint(t, httpsec.DPoP{PublicURL: dpopPublicURL})
				send := f.prepare(t, "")

				out := send(t, key.brokenProver("j-broken"))
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// TestSessionCookie_ProviderTokenStillBinds pins that the OpenID Provider on a
// cookie chain with DPoP still binds the tokens it issues: a token request
// with a valid proof gets an access token whose cnf.jkt is the proof key's
// thumbprint, though the chain's sessions are never bound.
func TestSessionCookie_ProviderTokenStillBinds(t *testing.T) {
	t.Parallel()

	w, _, err := newCookieOP(t, func(s *flowSetup) {
		s.provider = append(s.provider, oidcprovider.WithDPoP())
		s.chain = func(t *testing.T, w *opFlow) []httpsec.Option {
			t.Helper()

			return []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: w.issuer})}
		}
	})
	require.NoError(t, err)

	s := w.session(t)
	key := newDPoPKey(t, elliptic.P256())
	proof := key.validProof("j-token").with(map[string]any{
		"htm": http.MethodPost, "htu": w.issuer + "/oauth2/token", "iat": w.clk.Now().Unix(),
	}).sign(t)

	a := accessTokenOf(t, w, s, flowHeader("DPoP", proof))
	require.Equal(t, http.StatusOK, a.status, a.body)

	var doc cookieTokenAnswer
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc))

	parts := strings.Split(doc.AccessToken, ".")
	require.Len(t, parts, 3, "a signed access token")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims struct {
		Cnf map[string]any `json:"cnf"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, map[string]any{"jkt": key.jkt}, claims.Cnf)
}
