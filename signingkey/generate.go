package signingkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// rsaKeyBits is the modulus size of generated RSA keys.
const rsaKeyBits = 2048

// keyEntry is a key the manager holds: the signer it signs with, the public
// half it publishes, and the public JWK a store records.
type keyEntry struct {
	kid    string
	alg    Alg
	signer crypto.Signer
	// public is the signer's public half, taken once. crypto.Signer.Public
	// builds it afresh for some key types and returns a window onto the
	// private key for others, so taking it once is both the cheaper answer on
	// the verification path and the single value every published copy is made
	// from.
	public    crypto.PublicKey
	publicJWK jwk.Key
	createdAt time.Time
}

// generateKey mints a key for alg and returns it with the record to persist.
//
// The kid is the RFC 7638 thumbprint of the public key, so two processes that
// somehow generate the same key agree on its identifier, and a kid can never
// collide with an unrelated key.
func generateKey(alg Alg, now time.Time) (*keyEntry, Record, error) {
	var signer crypto.Signer

	switch alg {
	case RS256:
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, Record{}, fmt.Errorf("signingkey: generate %s: %w", alg, err)
		}
		signer = key
	case ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, Record{}, fmt.Errorf("signingkey: generate %s: %w", alg, err)
		}
		signer = key
	case EdDSA:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, Record{}, fmt.Errorf("signingkey: generate %s: %w", alg, err)
		}
		signer = key
	default:
		return nil, Record{}, fmt.Errorf("signingkey: unsupported algorithm %q", alg)
	}

	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, Record{}, fmt.Errorf("signingkey: marshal %s key: %w", alg, err)
	}

	entry, err := entryFromSigner(signer, alg, now)
	if err != nil {
		return nil, Record{}, err
	}

	publicJWK, err := json.Marshal(entry.publicJWK)
	if err != nil {
		return nil, Record{}, fmt.Errorf("signingkey: marshal public jwk: %w", err)
	}

	return entry, Record{
		Kid:       entry.kid,
		Alg:       alg,
		Private:   der,
		PublicJWK: publicJWK,
		CreatedAt: now,
	}, nil
}

// entryFromSigner builds the held entry: the public JWK carrying the kid, the
// algorithm and use "sig", which is what a verifier needs to pick the key.
func entryFromSigner(signer crypto.Signer, alg Alg, createdAt time.Time) (*keyEntry, error) {
	public, err := jwk.Import[jwk.Key](signer.Public())
	if err != nil {
		return nil, fmt.Errorf("signingkey: import public key: %w", err)
	}

	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signingkey: thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)

	if err := public.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("signingkey: set kid: %w", err)
	}
	if err := public.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("signingkey: set alg %q: %w", alg, err)
	}
	if err := public.Set(jwk.KeyUsageKey, string(jwk.ForSignature)); err != nil {
		return nil, fmt.Errorf("signingkey: set use: %w", err)
	}

	return &keyEntry{
		kid:       kid,
		alg:       alg,
		signer:    signer,
		public:    signer.Public(),
		publicJWK: public,
		createdAt: createdAt,
	}, nil
}

// algMatchesKey reports whether signer can actually produce alg.
//
// The algorithm a record claims and the key it carries are two independent
// pieces of data, and nothing outside this package has to keep them in step: a
// migration, a hand-edited row or another writer can pair either with either.
// Trusting the claim publishes a key whose declared algorithm it cannot honour.
//
// ES256 checks the curve as well as the key type. RFC 7518 section 3.4 fixes
// ES256 to P-256, so a P-384 key signs 96 bytes where a verifier expects 64.
// jwx verifies its own output, so a round trip inside this package would accept
// it and only a conformant external verifier would refuse.
func algMatchesKey(alg Alg, signer crypto.Signer) error {
	switch alg {
	case RS256:
		if _, ok := signer.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("%w: %s needs an RSA key, got %T", ErrConfig, alg, signer)
		}
	case ES256:
		key, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an ECDSA key, got %T", ErrConfig, alg, signer)
		}

		if key.Curve != elliptic.P256() {
			return fmt.Errorf("%w: %s is defined over P-256, got %s",
				ErrConfig, alg, key.Curve.Params().Name)
		}
	case EdDSA:
		if _, ok := signer.(ed25519.PrivateKey); !ok {
			return fmt.Errorf("%w: %s needs an Ed25519 key, got %T", ErrConfig, alg, signer)
		}
	default:
		return fmt.Errorf("%w: unsupported algorithm %q", ErrConfig, alg)
	}

	return nil
}

// entryFromRecord decodes a stored record.
//
// A record that cannot be decoded is an error, never a skip: skipping it would
// mint a fresh key and orphan every token the unreadable key signed.
//
// Everything the record claims is checked against the key it carries, because a
// store is a boundary: its rows are data this package did not write and must not
// take on trust. An algorithm this package cannot produce is refused here as
// well as in WithAlgs — one rule with two entry points is one rule only if both
// enforce it, and the store path would otherwise adopt, make current and publish
// a key declaring an algorithm the option path rejects outright.
func entryFromRecord(rec Record) (*keyEntry, error) {
	if !supportedAlg(rec.Alg) {
		return nil, fmt.Errorf("signingkey: decode key %q: %w: unsupported algorithm %q",
			rec.Kid, ErrConfig, rec.Alg)
	}

	key, err := x509.ParsePKCS8PrivateKey(rec.Private)
	if err != nil {
		return nil, fmt.Errorf("signingkey: decode key %q: %w", rec.Kid, err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("signingkey: decode key %q: %T cannot sign", rec.Kid, key)
	}

	if err := algMatchesKey(rec.Alg, signer); err != nil {
		return nil, fmt.Errorf("signingkey: decode key %q: %w", rec.Kid, err)
	}

	entry, err := entryFromSigner(signer, rec.Alg, rec.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("signingkey: decode key %q: %w", rec.Kid, err)
	}

	// The recorded identifier must be the one this key hashes to. A record whose
	// private half was replaced still carries the original kid, and holding it
	// under the newly derived one would publish a set missing the kid every
	// live token names — orphaning them exactly as skipping the record would.
	if rec.Kid != "" && entry.kid != rec.Kid {
		return nil, fmt.Errorf(
			"signingkey: decode key %q: %w: the key hashes to %q, so the record's "+
				"private half does not belong to the identifier it carries",
			rec.Kid, ErrConfig, entry.kid)
	}

	return entry, nil
}
