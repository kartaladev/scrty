package httpsec_test

import (
	"crypto/elliptic"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// TestDPoP_Proof pins every check of RFC 9449 section 4.3 the chain makes on
// a proof, in the order it makes them: each row breaks one part of an
// otherwise valid proof, signed with jwx v4.
func TestDPoP_Proof(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	other := newDPoPKey(t, elliptic.P256())
	p384 := newDPoPKey(t, elliptic.P384())

	const orders = "http://example.com/api/orders"

	type testCase struct {
		name   string
		d      httpsec.DPoP
		req    func(t *testing.T) *http.Request
		token  string // the token the proof accompanies; empty for none
		assert func(t *testing.T, jkt string, signatures int64, err error)
	}

	// get is a GET of target carrying p, signed.
	get := func(target string, p proofParts) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request { return dpopRequest(t, http.MethodGet, target, p.sign(t)) }
	}

	accepted := func(t *testing.T, jkt string, signatures int64, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Equal(t, key.jkt, jkt, "the thumbprint of the proof's own key")
		assert.EqualValues(t, 1, signatures)
	}
	refused := func(t *testing.T, jkt string, _ int64, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrInvalidDPoPProof)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
		assert.Empty(t, jkt)
	}
	// refusedUnsigned is refused before any signature is verified.
	refusedUnsigned := func(t *testing.T, jkt string, signatures int64, err error) {
		t.Helper()

		refused(t, jkt, signatures, err)
		assert.Zero(t, signatures, "refused before the signature was checked")
	}

	valid := key.validProof("j-1")
	tok := "access-token-a"

	// hs256 is valid signed with a MAC under the client's own public JWK:
	// the classic key-confusion shape.
	hs256 := valid
	hs256.alg = jwa.HS256()
	hs256.signKey = []byte("0123456789abcdef0123456789abcdef")

	none := valid
	none.none = true

	private, err := jwk.Import[jwk.Key](key.priv)
	require.NoError(t, err)

	// mismatched names ES256 but carries, and is signed by, a P-384 key.
	mismatched := p384.validProof("j-1")

	// anotherSigner carries key's public JWK but is signed by another key.
	anotherSigner := valid
	anotherSigner.signKey = other.priv

	es384 := p384.validProof("j-1")
	es384.alg = jwa.ES384()

	cases := []testCase{
		{name: "a valid proof", req: get(orders, valid), assert: accepted},
		{
			name:   "a proof larger than the bound is refused unparsed",
			req:    get(orders, valid.with(map[string]any{"pad": strings.Repeat("x", 9<<10)})),
			assert: refusedUnsigned,
		},
		{
			name: "two proof headers",
			req: func(t *testing.T) *http.Request {
				return dpopRequest(t, http.MethodGet, orders, valid.sign(t), valid.sign(t))
			},
			assert: refusedUnsigned,
		},
		{
			name:   "no proof header",
			req:    func(t *testing.T) *http.Request { return dpopRequest(t, http.MethodGet, orders) },
			assert: refusedUnsigned,
		},
		{
			name: "not a compact JWS",
			req: func(t *testing.T) *http.Request {
				return dpopRequest(t, http.MethodGet, orders, " "+valid.sign(t))
			},
			assert: refusedUnsigned,
		},
		{name: "a typ other than dpop+jwt", req: get(orders, valid.withHeader(jws.TypeKey, "JWT")), assert: refusedUnsigned},
		{name: "no typ", req: get(orders, valid.withHeader(jws.TypeKey, nil)), assert: refusedUnsigned},
		{name: "alg none", req: get(orders, none), assert: refusedUnsigned},
		{name: "alg HS256", req: get(orders, hs256), assert: refusedUnsigned},
		{name: "an alg outside the accepted set", req: get(orders, es384), assert: refusedUnsigned},
		{
			name: "an alg the consumer accepts",
			d:    httpsec.DPoP{Algorithms: []jwa.SignatureAlgorithm{jwa.ES384()}},
			req:  get(orders, es384),
			assert: func(t *testing.T, jkt string, signatures int64, err error) {
				require.NoError(t, err)
				assert.Equal(t, p384.jkt, jkt)
				assert.EqualValues(t, 1, signatures)
			},
		},
		{name: "a jwk carrying its private part", req: get(orders, valid.withHeader(jws.JWKKey, private)), assert: refusedUnsigned},
		{name: "no jwk", req: get(orders, valid.withHeader(jws.JWKKey, nil)), assert: refusedUnsigned},
		{name: "a P-384 key under ES256", req: get(orders, mismatched), assert: refusedUnsigned},
		{
			name: "a signature by another key",
			req:  get(orders, anotherSigner),
			assert: func(t *testing.T, jkt string, signatures int64, err error) {
				refused(t, jkt, signatures, err)
				assert.EqualValues(t, 1, signatures, "the signature was checked, and failed")
			},
		},
		{name: "htm POST on a GET", req: get(orders, valid.with(map[string]any{"htm": http.MethodPost})), assert: refused},
		{name: "htm HEAD on a GET", req: get(orders, valid.with(map[string]any{"htm": http.MethodHead})), assert: refused},
		{name: "htm in another case", req: get(orders, valid.with(map[string]any{"htm": "get"})), assert: refused},
		{name: "no htm", req: get(orders, valid.with(map[string]any{"htm": nil})), assert: refused},
		{
			name:   "htu for another path",
			req:    get(orders, valid.with(map[string]any{"htu": "http://example.com/api/payments"})),
			assert: refused,
		},
		{
			name:   "htu for another host",
			req:    get(orders, valid.with(map[string]any{"htu": "http://evil.example/api/orders"})),
			assert: refused,
		},
		{
			name:   "htu for another scheme",
			req:    get(orders, valid.with(map[string]any{"htu": "https://example.com/api/orders"})),
			assert: refused,
		},
		{name: "no htu", req: get(orders, valid.with(map[string]any{"htu": nil})), assert: refused},
		{
			name: "htu with host case, default port and the request's query",
			req: get("https://app.example.com/api/orders?page=2",
				valid.with(map[string]any{"htu": "https://APP.example.com:443/api/orders"})),
			assert: accepted,
		},
		{
			name:   "htu with scheme case and its own query and fragment",
			req:    get(orders, valid.with(map[string]any{"htu": "HTTP://example.com:80/api/orders?x=1#top"})),
			assert: accepted,
		},
		{
			name: "htu on a port that is not the default",
			req: get("http://example.com:8080/api/orders",
				valid.with(map[string]any{"htu": "http://example.com/api/orders"})),
			assert: refused,
		},
		{
			// The path is compared as the client sent it, so a proof for one
			// spelling of a path is not a proof for another.
			name:   "htu path against a percent-encoded request path",
			req:    get("http://example.com/api/ord%65rs", valid),
			assert: refused,
		},
		{
			name: "a percent-encoded htu against the same request path",
			req: get("http://example.com/api/ord%65rs",
				valid.with(map[string]any{"htu": "http://example.com/api/ord%65rs"})),
			assert: accepted,
		},
		{
			// The hex digits of a percent-encoding are the same octet in
			// either case (RFC 3986, 2.1), unlike %65 against e, which is
			// never decoded.
			name: "htu with the hex digits of a percent-encoding in the other case",
			req: get("http://example.com/api/a%2Fb",
				valid.with(map[string]any{"htu": "http://example.com/api/a%2fb"})),
			assert: accepted,
		},
		{
			name:   "iat at the lifetime's edge in the past",
			req:    get(orders, valid.with(map[string]any{"iat": dpopNow.Add(-60 * time.Second).Unix()})),
			assert: accepted,
		},
		{
			name:   "iat 61 seconds old",
			req:    get(orders, valid.with(map[string]any{"iat": dpopNow.Add(-61 * time.Second).Unix()})),
			assert: refused,
		},
		{
			name:   "iat at the lifetime's edge in the future",
			req:    get(orders, valid.with(map[string]any{"iat": dpopNow.Add(60 * time.Second).Unix()})),
			assert: accepted,
		},
		{
			name:   "iat 5 minutes ahead",
			req:    get(orders, valid.with(map[string]any{"iat": dpopNow.Add(5 * time.Minute).Unix()})),
			assert: refused,
		},
		{name: "no iat", req: get(orders, valid.with(map[string]any{"iat": nil})), assert: refused},
		{name: "an iat that is not a number", req: get(orders, valid.with(map[string]any{"iat": "now"})), assert: refused},
		{
			name:   "ath for the token presented",
			req:    get(orders, valid.with(map[string]any{"ath": tokenHash(tok)})),
			token:  tok,
			assert: accepted,
		},
		{
			name:   "ath for another token",
			req:    get(orders, valid.with(map[string]any{"ath": tokenHash("access-token-b")})),
			token:  tok,
			assert: refused,
		},
		{name: "no ath with a token", req: get(orders, valid), token: tok, assert: refused},
		{
			name:   "ath on a request presenting no token",
			req:    get(orders, valid.with(map[string]any{"ath": tokenHash(tok)})),
			assert: refused,
		},
		{name: "no jti", req: get(orders, valid.with(map[string]any{"jti": nil})), assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			checker, err := httpsec.NewDPoPChecker(tc.d, func() time.Time { return dpopNow },
				slog.New(slog.DiscardHandler))
			require.NoError(t, err)

			jkt, err := checker.Verify(t.Context(), httpsec.NewHTTPRequest(tc.req(t)), tc.token)
			tc.assert(t, jkt, checker.Signatures(), err)
		})
	}
}

// TestDPoP_ProofErrorNamesNothing pins that a refusal carries no part of the
// proof, the token or the key, whatever check it failed.
//
// Standalone: one assertion over the refusal text of several proofs at once.
func TestDPoP_ProofErrorNamesNothing(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	proof := key.validProof("jti-secret-value").with(map[string]any{"htu": "http://evil.example/x"}).sign(t)

	checker, err := httpsec.NewDPoPChecker(httpsec.DPoP{}, func() time.Time { return dpopNow },
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	_, err = checker.Verify(t.Context(),
		httpsec.NewHTTPRequest(dpopRequest(t, http.MethodGet, "/api/orders", proof)), "token-secret-value")
	require.ErrorIs(t, err, httpsec.ErrInvalidDPoPProof)

	for _, secret := range []string{"jti-secret-value", "token-secret-value", key.jkt, proof, "evil.example"} {
		assert.NotContains(t, err.Error(), secret)
	}
}

// TestDPoP_ThumbprintKnownAnswer pins the proof key's thumbprint to the
// worked example of RFC 7638 section 3.1, so a bound token's cnf.jkt agrees
// with every other implementation of the RFC, not only with this one.
//
// Standalone: one published key and its one published answer.
func TestDPoP_ThumbprintKnownAnswer(t *testing.T) {
	t.Parallel()

	// The RSA public key of RFC 7638 section 3.1, its n joined onto one line.
	const example = `{
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e": "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29"
	}`

	key, err := jwk.ParseKey([]byte(example))
	require.NoError(t, err)

	got, err := httpsec.ProofKeyThumbprint(key)
	require.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", got)
}
