package test_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	identitytest "github.com/kartaladev/scrty/test/identity"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// proofVector is testdata/dpop/proof-vector.json: a sign-in's DPoP proof
// that testdata/dpop/record.ts made with the README's dpop.ts over WebCrypto,
// and the thumbprint of its key that record.ts computed on its own.
type proofVector struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	IAT    int64  `json:"iat"`
	JKT    string `json:"jkt"`
	Proof  string `json:"proof"`
}

// TestDPoP_RecordedProofVector signs in to a test server with the proof the
// browser sample produced, at the instant it was made: the proof verifies,
// and the token and the sign-in are bound to the key whose thumbprint the
// sample computed. The same proof with its signature altered is refused.
func TestDPoP_RecordedProofVector(t *testing.T) {
	t.Parallel()

	var vec proofVector
	require.NoError(t, json.Unmarshal(must.Must(os.ReadFile("testdata/dpop/proof-vector.json")), &vec))

	type testCase struct {
		name   string
		proof  func(string) string
		assert func(t *testing.T, res *http.Response, gen *token.JWTGenerator, sessions *session.Sessions)
	}

	cases := []testCase{
		{
			name:  "the recorded proof signs in bound to its key",
			proof: func(p string) string { return p },
			assert: func(t *testing.T, res *http.Response, gen *token.JWTGenerator, sessions *session.Sessions) {
				require.Equal(t, http.StatusOK, res.StatusCode)

				var doc struct {
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
				}
				require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
				assert.Equal(t, string(httpsec.TokenTypeDPoP), doc.TokenType)

				claims, err := gen.Verify(t.Context(), doc.AccessToken)
				require.NoError(t, err)
				assert.Equal(t, vec.JKT, claims.Confirmation().JKT, "the server's thumbprint is the sample's")

				s, err := sessions.Load(t.Context(), claims.ID())
				require.NoError(t, err)
				assert.Equal(t, vec.JKT, s.KeyBinding.JKT)
			},
		},
		{
			name: "the recorded proof with another signature is refused",
			proof: func(p string) string {
				// The signature's first character changed: still base64url,
				// no longer the sample's signature.
				i := strings.LastIndex(p, ".") + 1
				c := byte('A')
				if p[i] == 'A' {
					c = 'B'
				}

				return p[:i] + string(c) + p[i+1:]
			},
			assert: func(t *testing.T, res *http.Response, _ *token.JWTGenerator, _ *session.Sessions) {
				assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
				assert.Equal(t, `DPoP error="invalid_dpop_proof", algs="ES256"`, res.Header.Get("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Unix(vec.IAT, 0))

			// The deployment declares the host the proof was recorded for.
			target := must.Must(url.Parse(vec.URL))

			enc := must.Must(password.NewBcryptEncoder())
			users := identitytest.NewInMemoryStore()
			_, err := users.Provision(t.Context(), "ada",
				identity.WithUserPassword(must.Must(enc.Encode("s3cret-passphrase"))))
			require.NoError(t, err)

			keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
			gen := must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience(), token.WithClock(clk)))
			sessions := must.Must(session.New(session.WithClock(clk)))

			chain := must.Must(httpsec.New(
				httpsec.WithClock(clk),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: must.Must(authenticate.NewUsernamePasswordAuthenticator(users,
						authenticate.WithPasswordEncoder(enc))),
					Sessions: sessions,
					Tokens:   gen,
					Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				}),
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: sessions, Users: users}),
				httpsec.EnableDPoP(httpsec.DPoP{PublicURL: target.Scheme + "://" + target.Host}),
			))

			srv := httptest.NewServer(chain.Middleware()(http.NotFoundHandler()))
			t.Cleanup(srv.Close)

			// The test server listens on a loopback port, and the proof names
			// the URL it was recorded for, so the request is sent with that
			// URL's host.
			req, err := http.NewRequestWithContext(t.Context(), vec.Method, srv.URL+target.Path,
				strings.NewReader(url.Values{"username": {"ada"}, "password": {"s3cret-passphrase"}}.Encode()))
			require.NoError(t, err)
			req.Host = target.Host
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("DPoP", tc.proof(vec.Proof))

			res, err := srv.Client().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = res.Body.Close() })

			tc.assert(t, res, gen, sessions)
		})
	}
}
