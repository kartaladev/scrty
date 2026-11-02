package fibersec_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// proofKey is a client's P-256 DPoP key, with its public JWK members and
// RFC 7638 thumbprint, built by hand so this module needs no JOSE library of
// its own.
type proofKey struct {
	priv *ecdsa.PrivateKey
	x, y string
	jkt  string
}

func newProofKey(t *testing.T) proofKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	raw, err := priv.PublicKey.Bytes() // 0x04 || X || Y
	require.NoError(t, err)

	b64 := base64.RawURLEncoding.EncodeToString
	x, y := b64(raw[1:33]), b64(raw[33:65])

	// The required members in lexicographic order, no white space.
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))

	return proofKey{priv: priv, x: x, y: y, jkt: b64(sum[:])}
}

// proof is an ES256 DPoP proof by k for a GET of htu, issued now, whose ath
// covers credential.
func (k proofKey) proof(t *testing.T, htu, credential string) string {
	t.Helper()

	b64 := base64.RawURLEncoding.EncodeToString

	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": k.x, "y": k.y},
	})
	require.NoError(t, err)

	ath := sha256.Sum256([]byte(credential))
	payload, err := json.Marshal(map[string]any{
		"jti": rand.Text(), "htm": http.MethodGet, "htu": htu,
		"iat": time.Now().Unix(), "ath": b64(ath[:]),
	})
	require.NoError(t, err)

	signing := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signing))

	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	require.NoError(t, err)

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return signing + "." + b64(sig)
}

// TestFiber_DPoPJudgesThePathAsSent pins that the fiber adapter hands DPoP the
// request path as the client sent it, percent-encoding intact, so a proof for
// one spelling of a path is not accepted for another that decodes the same.
func TestFiber_DPoPJudgesThePathAsSent(t *testing.T) {
	t.Parallel()

	const proofURL = "http://example.com/api/orders"

	type testCase struct {
		name   string
		target string
		assert func(t *testing.T, res response)
	}

	cases := []testCase{
		{
			name:   "the path the proof names is accepted",
			target: proofURL,
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusOK, res.status)
			},
		},
		{
			name:   "an escaped spelling of that path is refused",
			target: "http://example.com/api/ord%65rs",
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusUnauthorized, res.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := newProofKey(t)

			sessions, err := session.New()
			require.NoError(t, err)

			live, err := sessions.Create(t.Context(), "u-1",
				session.WithFirstFactor(factor.Password),
				session.WithKeyBinding(session.KeyBinding{JKT: key.jkt}))
			require.NoError(t, err)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
				Return(&identity.Details{
					ID: "u-1", Username: "ada", Active: true,
					PasswordChangedAt: time.Now().Add(-time.Hour),
				}, nil).
				AnyTimes()

			chain := newChain(t,
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
				httpsec.EnableDPoP(httpsec.DPoP{}),
			)

			app := fiber.New()
			app.Use(fibersec.Middleware(chain))
			app.Get("/*", func(c fiber.Ctx) error { return c.SendStatus(http.StatusOK) })

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.target, nil)
			req.Header.Set("Authorization", "DPoP "+live.ID)
			req.Header.Set("DPoP", key.proof(t, proofURL, live.ID))

			tc.assert(t, serveFrom(t, app, req, referencePeer))
		})
	}
}
