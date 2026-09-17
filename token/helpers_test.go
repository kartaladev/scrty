package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/token"
)

// accepted and rejected are the two verdicts every verification table asserts.
// They live here, once, so strengthening either strengthens every table.
func accepted(t *testing.T, claims *token.Claims, err error) {
	t.Helper()

	require.NoError(t, err)
	assert.NotNil(t, claims)
}

func rejected(t *testing.T, claims *token.Claims, err error) {
	t.Helper()

	require.ErrorIs(t, err, token.ErrTokenInvalid)
	assert.Nil(t, claims)
}

// newKeySource returns a real key manager to sign with. It is never started,
// so no goroutine outlives the test.
func newKeySource(t *testing.T, algs ...signingkey.Alg) *signingkey.KeyManager {
	t.Helper()

	var opts []signingkey.Option
	if len(algs) > 0 {
		opts = append(opts, signingkey.WithAlgs(algs...))
	}

	return newKeySourceWith(t, opts...)
}

// newKeySourceWith is the one place a key manager is built for these tests. It
// always uses the in-memory store and never calls Start, which is what keeps
// TestMain's goleak check meaningful.
func newKeySourceWith(t *testing.T, opts ...signingkey.Option) *signingkey.KeyManager {
	t.Helper()

	km, err := signingkey.NewKeyManager(
		append([]signingkey.Option{
			signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		}, opts...)...)
	require.NoError(t, err)

	return km
}

// fixedClock is the injectable time source both generator and verifier read.
type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

func (c *fixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func alice() *identity.Principal {
	return &identity.Principal{ID: "u-1", Username: "alice"}
}

// segment decodes one segment of a compact JWS into a claim map.
func segment(t *testing.T, raw string, index int) map[string]any {
	t.Helper()

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3, "a compact JWS has three segments")

	decoded, err := base64.RawURLEncoding.DecodeString(parts[index])
	require.NoError(t, err)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(decoded, &fields))

	return fields
}

// decodeHeader reads the JWS protected header without verifying anything.
func decodeHeader(t *testing.T, raw string) map[string]any {
	t.Helper()

	return segment(t, raw, 0)
}

// decodeClaims reads the payload without verifying anything.
func decodeClaims(t *testing.T, raw string) map[string]any {
	t.Helper()

	return segment(t, raw, 1)
}

// validClaims are claims that pass every check except the one a case targets,
// so a row that is accepted proves the targeted check is what rejected the
// others.
func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"sub": "alice",
		"jti": "s-1",
		"exp": now.Add(time.Hour).Unix(),
	}
}

// signRaw builds a compact JWS by hand: the claims are signed with signer
// under alg, and kid is written into the protected header unless it is empty.
//
// Hand-building is deliberate here. Asking the library to produce a token
// without a kid, or one naming an algorithm the key does not use, would test
// its refusal to build such a token rather than this package's refusal to
// accept one.
func signRaw(t *testing.T, signer crypto.Signer, kid string, alg signingkey.Alg, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	key, err := jwk.Import[jwk.Key](signer)
	require.NoError(t, err)

	if kid != "" {
		require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	}

	signature, ok := jwa.LookupSignatureAlgorithm(alg)
	require.True(t, ok, "unknown algorithm %q", alg)

	signed, err := jws.Sign(payload, jws.WithKey(signature, key))
	require.NoError(t, err)

	return string(signed)
}

// signClaims signs claims with the key source's current RS256 key, naming that
// key in the header — a token that is correct in every respect but the claims
// the caller chose.
func signClaims(t *testing.T, keys signingkey.KeySource, claims map[string]any) string {
	t.Helper()

	kid, signer, ok := keys.GetSigner(signingkey.RS256)
	require.True(t, ok)

	return signRaw(t, signer, kid, signingkey.RS256, claims)
}

// encodeSegment renders one compact-JWS segment.
func encodeSegment(t *testing.T, fields map[string]any) string {
	t.Helper()

	raw, err := json.Marshal(fields)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// tamperPayload changes one character of a real token's sub and leaves the
// original signature in place, so accepting it would mean the signature was
// never checked against the payload.
func tamperPayload(t *testing.T, raw string) string {
	t.Helper()

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)

	claims := decodeClaims(t, raw)
	sub, ok := claims["sub"].(string)
	require.True(t, ok)
	require.NotEmpty(t, sub)
	claims["sub"] = "A" + sub[1:]
	require.NotEqual(t, sub, claims["sub"], "the payload must really differ")

	return parts[0] + "." + encodeSegment(t, claims) + "." + parts[2]
}

// externalKeySource is the shape a consumer's own key source takes: one key,
// no KeyManager anywhere, and deliberately no LifetimeReporter, so a source
// that cannot report its lifetimes gets no lifetime cap.
//
// It is hand-written rather than generated because the test needs it to sign
// real tokens, which a mock cannot do.
type externalKeySource struct {
	kid    string
	signer crypto.Signer
	set    jwk.Set
}

func (s *externalKeySource) GetSigner(alg signingkey.Alg) (string, crypto.Signer, bool) {
	if alg != signingkey.RS256 {
		return "", nil, false
	}

	return s.kid, s.signer, true
}

func (s *externalKeySource) JWKS() (jwk.Set, error) { return s.set, nil }

func newExternalKeySource(t *testing.T) *externalKeySource {
	t.Helper()

	// 2048 is the smallest size the JOSE stack accepts for RS256.
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "consumer-owned-key-1"

	key, err := jwk.Import[jwk.Key](private.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256()))
	require.NoError(t, key.Set(jwk.KeyUsageKey, "sig"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))

	return &externalKeySource{kid: kid, signer: private, set: set}
}
