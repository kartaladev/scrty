package httpsec

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// ErrInvalidDPoPProof refuses a request whose DPoP proof is missing, does not
// verify, or does not fit the token it accompanies: a proof that fails any
// check of RFC 9449 section 4.3, a token bound to a key presented as Bearer or
// with a proof from another key, an unbound token where DPoP is required, and
// a replayed proof. It maps to 401. Its text names no check, token, proof,
// key or jti.
var ErrInvalidDPoPProof = errors.New("httpsec: invalid DPoP proof")

// TokenType is the type of an access credential an issuing endpoint hands
// out, as a token response's token_type names it (RFC 9449 section 5): DPoP
// for one bound to the client's DPoP key, which the client presents under
// the DPoP scheme with a proof, and Bearer for any other.
type TokenType string

// The token types an issuing endpoint reports.
const (
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeDPoP   TokenType = "DPoP"
)

// tokenTypeOf is the type of the credential issued for s: TokenTypeDPoP when
// s is bound to a DPoP key, TokenTypeBearer otherwise. A session bound to a
// client certificate issues a Bearer token, presented over that connection
// (RFC 8705).
func tokenTypeOf(s *session.Session) TokenType {
	if s != nil && s.KeyBinding.JKT != "" {
		return TokenTypeDPoP
	}

	return TokenTypeBearer
}

// The defaults EnableDPoP fills into a DPoP left at its zero value.
const (
	// DefaultDPoPProofMaxAge is how far a proof's iat may lie from the
	// chain's clock, either side.
	DefaultDPoPProofMaxAge = 60 * time.Second

	// DefaultDPoPMaxProofSize is the longest DPoP header, in bytes, the chain
	// parses.
	DefaultDPoPMaxProofSize = 8 << 10

	// DefaultDPoPNonceLifetime is how long a server nonce is accepted after
	// it is issued.
	DefaultDPoPNonceLifetime = 5 * time.Minute

	// MinDPoPNonceLifetime is the shortest NonceLifetime accepted. A nonce
	// is dated in whole seconds, so a shorter lifetime would leave a nonce
	// due for replacement the moment it is sealed, and every request would
	// seal.
	MinDPoPNonceLifetime = 10 * time.Second
)

// DPoP configures sender-constrained tokens (RFC 9449): a client proves, on
// every request, possession of the key its token is bound to. Every field
// left at its zero value takes the default its comment names.
type DPoP struct {
	// Require refuses an unbound token, and a request to an issuing endpoint
	// that carries no proof, before any account is looked up. Default: false,
	// so existing bearer clients keep working while DPoP clients opt in by
	// sending proofs.
	Require bool

	// ProofMaxAge is how far a proof's iat may lie from the chain's clock,
	// either side. A proof's jti is remembered for twice this, from its iat.
	// Default: DefaultDPoPProofMaxAge. Negative is a configuration error.
	ProofMaxAge time.Duration

	// Replay remembers the proofs the chain has accepted. Default: an
	// in-memory store, per process; a deployment with more than one replica
	// supplies one its replicas share, or a proof can be replayed once on
	// each replica.
	Replay ReplayStore

	// Algorithms are the proof signature algorithms accepted. Default: ES256
	// alone. Only asymmetric algorithms are accepted: none and the HMAC
	// family are configuration errors.
	Algorithms []jwa.SignatureAlgorithm

	// Nonce turns on server-issued nonces (RFC 9449 sections 8 and 9): a
	// proof must then carry a nonce the chain issued no longer than
	// NonceLifetime ago, or it is refused with ErrDPoPNonceRequired and a
	// fresh nonce. Default: off, because the proof lifetime and the replay
	// store already bound replay, and a nonce costs the client a round trip
	// whenever it has none.
	//
	// Each replica hands every client the same current nonce, and seals the
	// next once half NonceLifetime has passed: at most one seal per half
	// lifetime per replica, whatever the traffic.
	Nonce bool

	// NonceCipher seals the server nonces, so every replica with the same
	// key material accepts the nonces any of them issued, with no shared
	// store. There is no default: the chain holds no key material of its
	// own. It is required when Nonce is on, and a configuration error when it
	// is off. seal.SessionCipher over a store/seal keyring kept for nonces
	// alone serves; see NonceCipher for why the keyring should be their own.
	NonceCipher NonceCipher

	// NonceLifetime is how long a server nonce is accepted after it is
	// issued. Default: DefaultDPoPNonceLifetime. Below MinDPoPNonceLifetime
	// (a nonce is dated in whole seconds, so a shorter lifetime would have
	// every request seal), negative, or set with Nonce off, is a
	// configuration error.
	NonceLifetime time.Duration

	// PublicURL is the scheme and host proofs' htu is judged against, such as
	// "https://app.example.com". Default: empty, meaning the scheme and host
	// the chain resolved for the request (EnableTrustedProxies,
	// WithHTTPSDeployment). It must be an absolute http or https URL with no
	// query, fragment or user information.
	PublicURL string

	// MaxProofSize is the longest DPoP header, in bytes, the chain parses; a
	// longer one is refused before anything is decoded. Default:
	// DefaultDPoPMaxProofSize. Negative is a configuration error.
	MaxProofSize int
}

// optionDPoP names EnableDPoP in its configuration errors.
const optionDPoP = "EnableDPoP"

// EnableDPoP turns on DPoP (RFC 9449) for the whole chain: a client proves,
// on every request, that it holds the private key its token is bound to, so a
// copied token is of no use without that key.
//
// Once it is on, both bearer modes (EnableBearerToken, EnableSessionBearer)
// accept the DPoP authorization scheme with one DPoP proof header, and refuse
// a bound token presented without a proof from its key, as Bearer included.
// Every issuing endpoint (login, second-factor verification, passkey login,
// magic link, OIDC handoff, recovery and its held finish, re-authentication,
// renewal) verifies a request's proof before it spends anything, binds the
// sign-in it creates and the token it issues to the proof's key (cnf.jkt), and
// tells its responder the token type (TokenType), which the default documents
// carry as token_type. A sign-in's binding is fixed when it is created: a
// second factor and a renewal keep it and never add one, and a
// re-authentication binds an unbound sign-in and keeps a bound one.
//
// Every refusal is ErrInvalidDPoPProof (401), and the chain answers it with
// WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256" (the
// accepted algorithms), naming no check. A request refused for want of a
// caller gets a DPoP challenge, and a Bearer challenge beside it unless DPoP is
// required. With server nonces on, a proof without a current nonce is
// ErrDPoPNonceRequired, answered with error="use_dpop_nonce" and a fresh
// nonce in the DPoP-Nonce header; a response to a proof whose nonce is past
// half its lifetime carries the next one.
//
// Defaults, each a field of d: accepted, not required (Require); a 60-second
// proof lifetime (ProofMaxAge); ES256 alone (Algorithms); an 8 KiB proof
// bound (MaxProofSize); an in-memory replay store per process (Replay); no
// server nonces (Nonce), and when they are on, a five-minute nonce lifetime
// (NonceLifetime) sealed with the consumer's cipher (NonceCipher); the public
// URL built from the scheme and host the chain resolved (PublicURL).
//
// Enabling it with neither EnableBearerToken nor EnableSessionBearer, or more
// than once, is a configuration error from New. So is an issuing endpoint
// whose token generator does not implement token.ConfirmingGenerator, which
// could only issue unbound tokens, and any field the comment of DPoP calls a
// configuration error. Under EnableSessionBearer no endpoint holds a
// generator, and the binding is kept on the session instead.
func EnableDPoP(d DPoP) Option {
	return func(c *config) error {
		if c.dpop != nil {
			return newConfigError("%s was given twice; one chain has one DPoP configuration", optionDPoP)
		}

		v, err := newDPoPVerifier(d, c.now)
		if err != nil {
			return err
		}

		c.dpop = v
		c.dpopEnabled = true

		c.enable(optionDPoP, func() error {
			bearers := 0
			count := func(Interceptor) error {
				bearers++

				return nil
			}
			_ = eachInterceptor(c, func(b *bearerToken) error { return count(b) })
			_ = eachInterceptor(c, func(b *sessionBearer) error { return count(b) })

			if bearers == 0 {
				return newConfigError("%s needs a bearer mode: enable EnableBearerToken or "+
					"EnableSessionBearer, which accept the tokens DPoP binds", optionDPoP)
			}

			return nil
		})

		c.wire(func(ch *Chain) {
			v.log = ch.logger
			v.sampler = ch.sampler
		})

		c.register(&dpopChallenge{v: v}, orderDPoPChallenge)

		return nil
	}
}

// checkBindingGenerator refuses, when DPoP is enabled, a token generator the
// endpoint option issues through (named by field) that cannot bind a token to
// a key: one that does not implement token.ConfirmingGenerator. Such a
// generator would issue every token unbound while DPoP was asked for. It
// checks nothing when DPoP is off, or when g is nil, which is the endpoint's
// own refusal to make.
func checkBindingGenerator(c *config, option, field string, g token.Generator) error {
	if c.dpop == nil || nilcheck.IsNil(g) {
		return nil
	}

	if _, ok := g.(token.ConfirmingGenerator); !ok {
		return newConfigError("%s was given a token generator (%s) that does not implement "+
			"token.ConfirmingGenerator, and %s binds the tokens the chain issues to the client's "+
			"key; supply one that does, such as token.NewGenerator's", option, field, optionDPoP)
	}

	return nil
}

// dpopVerifier verifies DPoP proofs, and records the ones the chain accepts.
type dpopVerifier struct {
	cfg DPoP

	// publicURL is cfg.PublicURL parsed, and nil when the resolved scheme and
	// host are used.
	publicURL *url.URL

	// algorithms is cfg.Algorithms by name, for the header check.
	algorithms map[string]jwa.SignatureAlgorithm

	now     func() time.Time
	log     *slog.Logger
	sampler *logsample.Sampler

	// verifySignature checks a proof's signature. It is a field so a test can
	// count the signatures verified.
	verifySignature func(alg jwa.SignatureAlgorithm, key jwk.Key, compact []byte) error

	// nonce is the replica's current server nonce, when nonces are on.
	nonce currentNonce
}

// dpopProof is what a verified proof establishes.
type dpopProof struct {
	// jkt is the RFC 7638 SHA-256 thumbprint of the proof's key.
	jkt string

	jti string
	iat time.Time
}

// asymmetricAlgorithms are the proof algorithms the chain can accept, by
// name: every asymmetric JWS algorithm whose key type it checks.
var asymmetricAlgorithms = map[string]bool{
	jwa.ES256().String(): true, jwa.ES384().String(): true, jwa.ES512().String(): true,
	jwa.RS256().String(): true, jwa.RS384().String(): true, jwa.RS512().String(): true,
	jwa.PS256().String(): true, jwa.PS384().String(): true, jwa.PS512().String(): true,
	jwa.EdDSA().String(): true, jwa.EdDSAEd25519().String(): true,
}

// newDPoPVerifier builds the verifier for d, filling its defaults and
// refusing a configuration that cannot be honoured.
func newDPoPVerifier(d DPoP, now func() time.Time) (*dpopVerifier, error) {
	if d.ProofMaxAge < 0 {
		return nil, newConfigError("%s was given a negative ProofMaxAge (%s)", optionDPoP, d.ProofMaxAge)
	}
	if d.ProofMaxAge == 0 {
		d.ProofMaxAge = DefaultDPoPProofMaxAge
	}

	if d.MaxProofSize < 0 {
		return nil, newConfigError("%s was given a negative MaxProofSize (%d)", optionDPoP, d.MaxProofSize)
	}
	if d.MaxProofSize == 0 {
		d.MaxProofSize = DefaultDPoPMaxProofSize
	}

	if err := checkNonceConfig(&d); err != nil {
		return nil, err
	}

	if len(d.Algorithms) == 0 {
		d.Algorithms = []jwa.SignatureAlgorithm{jwa.ES256()}
	}
	algorithms := make(map[string]jwa.SignatureAlgorithm, len(d.Algorithms))
	for _, alg := range d.Algorithms {
		if !asymmetricAlgorithms[alg.String()] {
			return nil, newConfigError("%s was given algorithm %q; a proof is signed with an "+
				"asymmetric algorithm, never none or a MAC", optionDPoP, alg.String())
		}
		algorithms[alg.String()] = alg
	}
	d.Algorithms = append([]jwa.SignatureAlgorithm(nil), d.Algorithms...)

	var public *url.URL
	if d.PublicURL != "" {
		u, err := parsePublicURL(d.PublicURL)
		if err != nil {
			return nil, err
		}
		public = u
	}

	v := &dpopVerifier{
		publicURL:  public,
		algorithms: algorithms,
		now:        now,
		log:        slog.New(slog.DiscardHandler),
	}

	switch {
	case d.Replay == nil:
		d.Replay = newMemoryReplayStore(v.clock)
	case nilcheck.IsNil(d.Replay):
		return nil, newConfigError("%s was given a nil Replay store", optionDPoP)
	}

	v.cfg = d
	v.verifySignature = verifyProofSignature

	return v, nil
}

// clock reads the verifier's time source when it is called.
func (v *dpopVerifier) clock() time.Time { return v.now() }

// parsePublicURL parses a configured public URL: an absolute http or https
// URL with a host and nothing a request URL could not be prefixed with.
func parsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, newConfigError("%s was given PublicURL %q; it must be an absolute http or "+
			"https URL with a host and no query, fragment or user information", optionDPoP, raw)
	}

	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = strings.TrimSuffix(u.RawPath, "/")

	return u, nil
}

// dpopHeader is the request header a proof travels in, and dpopScheme the
// authorization scheme a bound token is presented under.
const (
	dpopHeader = "DPoP"
	dpopScheme = "DPoP"
)

// dpopType is the typ every proof's header carries (RFC 9449 section 4.2).
const dpopType = "dpop+jwt"

// verifyProofSignature checks a compact proof's signature with key under alg.
// The header's alg must be alg, which the verifier read from that same header.
func verifyProofSignature(alg jwa.SignatureAlgorithm, key jwk.Key, compact []byte) error {
	_, err := jws.Verify(compact, jws.WithKey(alg, key), jws.WithCompact())

	return err
}

// proofClaims are the claims of a proof the chain reads. A pointer is nil
// when the claim is absent.
type proofClaims struct {
	JTI *string  `json:"jti"`
	HTM *string  `json:"htm"`
	HTU *string  `json:"htu"`
	IAT *float64 `json:"iat"`
	ATH *string  `json:"ath"`

	Nonce *string `json:"nonce"`
}

// The reasons a proof is refused, recorded at debug. They name a check, never
// any part of the proof, the token or the key.
const (
	reasonProofCount     = "header-count"
	reasonProofMissing   = "missing"
	reasonProofSize      = "size"
	reasonProofEncoding  = "encoding"
	reasonProofType      = "typ"
	reasonProofAlgorithm = "alg"
	reasonProofKey       = "jwk"
	reasonProofSignature = "signature"
	reasonProofClaims    = "claims"
	reasonProofMethod    = "htm"
	reasonProofURL       = "htu"
	reasonProofTime      = "iat"
	reasonProofHash      = "ath"
	reasonProofID        = "jti"
	reasonProofReplayed  = "replayed"
	reasonProofBinding   = "binding"
)

// msgDPoPRefused records a refused proof at debug, with the check it failed.
const msgDPoPRefused = "httpsec: a DPoP proof was refused"

// refuse records why a proof was refused and returns the refusal.
func (v *dpopVerifier) refuse(ctx context.Context, reason string) error {
	v.log.LogAttrs(ctx, slog.LevelDebug, msgDPoPRefused, slog.String("check", reason))

	return ErrInvalidDPoPProof
}

// verify checks the one proof r carries, for tok, the token the request
// presents (empty when it presents none), in the order RFC 9449 section 4.3
// gives, and returns what it establishes. It records nothing: the jti is
// recorded by record, once every other check the request faces has passed.
//
// The checks, in order: exactly one DPoP header within the size bound, a
// canonical compact JWS; typ, an accepted asymmetric alg and a public jwk
// whose key type fits it; the signature; htm and htu; iat within the
// lifetime either side; ath for tok, or none without one; a jti. Anything a
// check refuses is ErrInvalidDPoPProof.
func (v *dpopVerifier) verify(ctx context.Context, r Request, tok string) (dpopProof, error) {
	lines := r.HeaderValues(dpopHeader)
	if len(lines) != 1 {
		return dpopProof{}, v.refuse(ctx, reasonProofCount)
	}

	compact := lines[0]

	// Before anything is decoded, so an oversized header costs a length check.
	if len(compact) > v.cfg.MaxProofSize {
		return dpopProof{}, v.refuse(ctx, reasonProofSize)
	}
	if !canonicalCompactJWS(compact) {
		return dpopProof{}, v.refuse(ctx, reasonProofEncoding)
	}

	msg, err := jws.Parse([]byte(compact), jws.WithCompact())
	if err != nil || len(msg.Signatures()) != 1 {
		return dpopProof{}, v.refuse(ctx, reasonProofEncoding)
	}
	headers := msg.Signatures()[0].ProtectedHeaders()

	if typ, ok := headers.Type(); !ok || !strings.EqualFold(typ, dpopType) {
		return dpopProof{}, v.refuse(ctx, reasonProofType)
	}

	named, ok := headers.Algorithm()
	if !ok {
		return dpopProof{}, v.refuse(ctx, reasonProofAlgorithm)
	}
	alg, accepted := v.algorithms[named.String()]
	if !accepted {
		return dpopProof{}, v.refuse(ctx, reasonProofAlgorithm)
	}

	key, ok := headers.JWK()
	if !ok || !publicKeyFits(alg, key) {
		return dpopProof{}, v.refuse(ctx, reasonProofKey)
	}

	if err := v.verifySignature(alg, key, []byte(compact)); err != nil {
		return dpopProof{}, v.refuse(ctx, reasonProofSignature)
	}

	var claims proofClaims
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		return dpopProof{}, v.refuse(ctx, reasonProofClaims)
	}

	if claims.HTM == nil || *claims.HTM != r.Method() {
		return dpopProof{}, v.refuse(ctx, reasonProofMethod)
	}
	if claims.HTU == nil || !v.sameURL(r, *claims.HTU) {
		return dpopProof{}, v.refuse(ctx, reasonProofURL)
	}

	if claims.IAT == nil {
		return dpopProof{}, v.refuse(ctx, reasonProofTime)
	}
	iat := time.Unix(0, 0).UTC().Add(time.Duration(*claims.IAT * float64(time.Second)))
	now := v.now()
	if iat.Before(now.Add(-v.cfg.ProofMaxAge)) || iat.After(now.Add(v.cfg.ProofMaxAge)) {
		return dpopProof{}, v.refuse(ctx, reasonProofTime)
	}

	if !v.hashFits(claims.ATH, tok) {
		return dpopProof{}, v.refuse(ctx, reasonProofHash)
	}

	if v.cfg.Nonce {
		stale, err := v.checkNonce(ctx, claims.Nonce)
		if err != nil {
			return dpopProof{}, err
		}
		if stale {
			v.refreshNonce(ctx)
		}
	}

	if claims.JTI == nil || *claims.JTI == "" {
		return dpopProof{}, v.refuse(ctx, reasonProofID)
	}

	jkt, err := keyThumbprint(key)
	if err != nil {
		return dpopProof{}, v.refuse(ctx, reasonProofKey)
	}

	return dpopProof{
		jkt: jkt,
		jti: *claims.JTI,
		iat: iat,
	}, nil
}

// keyThumbprint is key's RFC 7638 SHA-256 thumbprint, base64url without
// padding: the value a bound token carries as cnf.jkt.
func keyThumbprint(key jwk.Key) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// hashFits reports whether ath is right for tok: the base64url SHA-256 of
// tok when a token is presented, and absent when none is.
func (v *dpopVerifier) hashFits(ath *string, tok string) bool {
	if tok == "" {
		return ath == nil
	}
	if ath == nil {
		return false
	}

	sum := sha256.Sum256([]byte(tok))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(*ath), []byte(want)) == 1
}

// publicKeyFits reports whether key is a public key of the type alg signs
// with: a P-256, P-384 or P-521 key for ES256, ES384 and ES512, an RSA key of
// at least 2048 bits for the RS and PS families, and an Ed25519 key for
// EdDSA. A key carrying a private part never fits.
func publicKeyFits(alg jwa.SignatureAlgorithm, key jwk.Key) bool {
	if private, err := jwk.IsPrivateKey(key); err != nil || private {
		return false
	}

	raw, err := jwk.Export[any](key)
	if err != nil {
		return false
	}

	switch alg.String() {
	case jwa.ES256().String():
		return onCurve(raw, elliptic.P256())
	case jwa.ES384().String():
		return onCurve(raw, elliptic.P384())
	case jwa.ES512().String():
		return onCurve(raw, elliptic.P521())
	case jwa.RS256().String(), jwa.RS384().String(), jwa.RS512().String(),
		jwa.PS256().String(), jwa.PS384().String(), jwa.PS512().String():
		pub, ok := raw.(*rsa.PublicKey)

		return ok && pub.N.BitLen() >= minProofRSABits
	case jwa.EdDSA().String(), jwa.EdDSAEd25519().String():
		_, ok := raw.(ed25519.PublicKey)

		return ok
	default:
		return false
	}
}

// minProofRSABits is the smallest RSA modulus a proof key may have.
const minProofRSABits = 2048

// onCurve reports whether raw is an ECDSA public key on curve.
func onCurve(raw any, curve elliptic.Curve) bool {
	pub, ok := raw.(*ecdsa.PublicKey)

	return ok && pub.Curve == curve
}

// sameURL reports whether htu names the request r: the same scheme, host and
// path once scheme and host case and a default port are normalised away, and
// ignoring the query and fragment of both. The path is compared as the client
// sent it, percent-encoding intact, but for the case of its hex digits.
func (v *dpopVerifier) sameURL(r Request, htu string) bool {
	u, err := url.Parse(htu)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Opaque != "" {
		return false
	}

	return normalisedURL(u.Scheme, u.Host, u.EscapedPath()) == v.requestURL(r)
}

// requestURL is r's public URL, normalised: the configured PublicURL's scheme
// and host, and its path as a prefix, or else the scheme and host the chain
// resolved; then the path as the client sent it.
func (v *dpopVerifier) requestURL(r Request) string {
	path := r.EscapedPath()

	if v.publicURL != nil {
		return normalisedURL(v.publicURL.Scheme, v.publicURL.Host, v.publicURL.EscapedPath()+path)
	}

	scheme := "http"
	if r.Secure() {
		scheme = "https"
	}

	return normalisedURL(scheme, r.Host(), path)
}

// normalisedURL renders scheme, host and path with scheme and host in lower
// case, the scheme's default port dropped, and an empty path as "/".
func normalisedURL(scheme, host, path string) string {
	scheme = strings.ToLower(scheme)
	host = strings.ToLower(host)

	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}

	if path == "" {
		path = "/"
	}

	return scheme + "://" + host + upperEscapes(path)
}

// upperEscapes writes the hex digits of each percent-encoding in path in upper
// case, which is the same octet (RFC 3986, section 2.1). It never decodes: %65
// stays %65, and is not "e".
func upperEscapes(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}

	b := []byte(path)
	for i := 0; i+2 < len(b); i++ {
		if b[i] != '%' {
			continue
		}

		for j := i + 1; j <= i+2; j++ {
			if b[j] >= 'a' && b[j] <= 'f' {
				b[j] -= 'a' - 'A'
			}
		}
	}

	return string(b)
}

// canonicalCompactJWS reports whether s is a compact JWS in its one canonical
// spelling: three "."-separated segments of unpadded base64url, the header
// and signature non-empty. jws.Parse is lenient about white space and
// padding; a proof is refused instead.
func canonicalCompactJWS(s string) bool {
	header, rest, ok := strings.Cut(s, ".")
	if !ok {
		return false
	}
	payload, signature, ok := strings.Cut(rest, ".")
	if !ok || header == "" || signature == "" {
		return false
	}

	return isBase64URL(header) && isBase64URL(payload) && isBase64URL(signature)
}

// isBase64URL reports whether s is made only of base64url characters.
func isBase64URL(s string) bool {
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}

	return true
}

// errConfirmationNotHonoured is joined to the refusal of a credential whose
// binding the chain cannot honour: a confirmation member it does not know,
// both bindings at once, or a certificate binding, which this chain cannot
// check. It is never accepted as a plain bearer credential instead.
var errConfirmationNotHonoured = errors.New("httpsec: the credential's key binding cannot be honoured")

// keyBinding is the binding a presented credential carries: a signed token's
// cnf claim, or a session reference's stored session binding.
type keyBinding struct {
	jkt     string
	x5tS256 string

	// other is true when the binding names a member the chain does not know.
	other bool
}

// presentedBearer reports the credential an Authorization header carries for
// a bearer mode, and whether it came under the DPoP scheme. The DPoP scheme
// is claimed only when DPoP is enabled (v not nil), matched without regard to
// case; otherwise the header is read exactly as the bearer mode reads it.
func presentedBearer(header, scheme string, allowEmptyScheme bool, v *dpopVerifier) (credential string, underDPoP, ok bool) {
	if v != nil {
		if credential, ok := presentedCredential(header, dpopScheme, false); ok {
			return credential, true, true
		}
	}

	credential, ok = presentedCredential(header, scheme, allowEmptyScheme)

	return credential, false, ok
}

// presentedProof verifies the proof a credential presented under the DPoP
// scheme carries, its ath over credential. A credential presented under
// another scheme has no proof to verify, and nil is returned with no error.
func presentedProof(ctx context.Context, v *dpopVerifier, r Request, underDPoP bool, credential string) (*dpopProof, error) {
	if !underDPoP {
		return nil, nil //nolint:nilnil // no proof was presented, and none is refused for that here
	}

	p, err := v.verify(ctx, r, credential)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// admitBinding decides a presented credential against its binding b. It
// records nothing: recordProof records the proof once the session's own
// binding has been judged too. v is nil when DPoP is off; proof is the
// verified proof for a credential presented under the DPoP scheme, and nil
// for one presented otherwise.
//
// A binding the chain cannot honour is refused whatever the scheme. With DPoP
// off a DPoP-bound credential is refused; an unbound one is accepted as
// before. With DPoP on, a credential presented without the DPoP scheme is
// refused when it is bound (RFC 9449 section 7.1) or when DPoP is required;
// one presented under it is accepted only when it is bound to the proof's own
// key.
func admitBinding(ctx context.Context, v *dpopVerifier, proof *dpopProof, b keyBinding) error {
	if b.other || b.x5tS256 != "" {
		return errors.Join(ErrAuthenticationRequired, errConfirmationNotHonoured)
	}

	if v == nil {
		if b.jkt != "" {
			return ErrInvalidDPoPProof
		}

		return nil
	}

	if proof == nil {
		if b.jkt != "" || v.cfg.Require {
			return v.refuse(ctx, reasonProofBinding)
		}

		return nil
	}

	if b.jkt == "" || subtle.ConstantTimeCompare([]byte(b.jkt), []byte(proof.jkt)) != 1 {
		return v.refuse(ctx, reasonProofBinding)
	}

	return nil
}

// recordProof records proof, the last check a request presenting it faces.
// A request that presented no proof records nothing.
func recordProof(ctx context.Context, v *dpopVerifier, proof *dpopProof) error {
	if proof == nil {
		return nil
	}

	return v.record(ctx, *proof)
}

// dpop is the chain's DPoP verifier the exchange runs under, and nil when
// DPoP is off or the exchange runs through no chain.
func (ex *Exchange) dpop() *dpopVerifier {
	if ex.perRequest == nil {
		return nil
	}

	return ex.perRequest.dpop
}

// issuingBinding verifies the proof a request to an issuing endpoint carries,
// and returns the binding the session and credential it issues take: the
// proof's key, or none when the request carries no proof. It is run among
// the endpoint's checks, before anything is spent, so a refused proof spends
// no link, code, attempt or recovery proof.
//
// The proof carries no ath: the credential it binds does not exist yet. It is
// recorded at once, so a replayed proof is refused before anything is spent
// too. With DPoP off (v nil) it binds nothing and checks nothing. With DPoP
// required a request without a proof is refused. Every refusal is
// ErrInvalidDPoPProof; a replay store that fails is a dependency failure, and
// one the caller's hang-up cut short fails with the context's error.
func issuingBinding(ctx context.Context, v *dpopVerifier, r Request) (session.KeyBinding, error) {
	if v == nil {
		return session.KeyBinding{}, nil
	}

	if len(r.HeaderValues(dpopHeader)) == 0 {
		if v.cfg.Require {
			return session.KeyBinding{}, v.refuse(ctx, reasonProofMissing)
		}

		return session.KeyBinding{}, nil
	}

	p, err := v.verify(ctx, r, "")
	if err != nil {
		return session.KeyBinding{}, err
	}

	if err := v.record(ctx, p); err != nil {
		return session.KeyBinding{}, err
	}

	return session.KeyBinding{JKT: p.jkt}, nil
}
