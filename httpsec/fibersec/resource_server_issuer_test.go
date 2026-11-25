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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/outbound"
)

// rsAPI is the identifier of the resource server the access-token cases call.
const rsAPI = "urn:example:orders:api"

// rsIssuer is a TLS issuer serving OpenID discovery and one ES256 signing key, and minting at+jwt
// access tokens for rsAPI, so the guards behind a chain see a caller a real resource server
// authenticated.
type rsIssuer struct {
	srv  *httptest.Server
	key  *ecdsa.PrivateKey
	clk  rsClock
	opts []httpsec.Option
}

// newRSIssuer starts an issuer, and returns it with the chain options of a resource server covering
// /api/ that trusts it for unbound tokens, on a chain clock at now.
func newRSIssuer(t *testing.T, now time.Time) *rsIssuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	i := &rsIssuer{key: key, clk: rsClock(now)}

	b64 := base64.RawURLEncoding

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) {
		rsWriteJSON(rw, map[string]any{"issuer": i.srv.URL, "jwks_uri": i.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, _ *http.Request) {
		rsWriteJSON(rw, map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
			"x": b64.EncodeToString(padTo32(key.X.Bytes())), "y": b64.EncodeToString(padTo32(key.Y.Bytes())),
		}}})
	})

	i.srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.srv.Close)

	oc, err := outbound.New(outbound.WithHTTPClient(i.srv.Client()))
	require.NoError(t, err)

	i.opts = []httpsec.Option{
		httpsec.WithClock(i.clk),
		httpsec.EnableResourceServer(rsAPI, httpsec.WithPathPrefix("/api/"),
			httpsec.FromIssuer(i.srv.URL, httpsec.WithOutboundClient(oc), httpsec.WithUnboundTokens())),
	}

	return i
}

// rsClock is a clock standing still at its time, shared by the chain and the guards.
type rsClock time.Time

func (c rsClock) Now() time.Time { return time.Time(c) }

func rsWriteJSON(rw http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(b)
}

// token mints an access token granted scope, whose user signed in at authTime; the zero time leaves
// auth_time out.
func (i *rsIssuer) token(t *testing.T, scope string, authTime time.Time) string {
	t.Helper()

	now := i.clk.Now()
	claims := map[string]any{
		"iss": i.srv.URL, "sub": "42", "aud": rsAPI, "client_id": "web-app", "jti": "t-1",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": scope,
	}
	if !authTime.IsZero() {
		claims["auth_time"] = authTime.Unix()
	}

	b64 := base64.RawURLEncoding
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "k1"})
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signing := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))

	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	require.NoError(t, err)

	sig := append(append(make([]byte, 0, 64), padTo32(r.Bytes())...), padTo32(s.Bytes())...)

	return strings.Join([]string{signing, b64.EncodeToString(sig)}, ".")
}

func padTo32(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
