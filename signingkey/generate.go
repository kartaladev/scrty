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

// keyEntry is a key the manager holds: the signer it signs with and the public
// JWK it publishes.
type keyEntry struct {
	kid       string
	alg       Alg
	signer    crypto.Signer
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
		publicJWK: public,
		createdAt: createdAt,
	}, nil
}

// entryFromRecord decodes a stored record.
//
// A record that cannot be decoded is an error, never a skip: skipping it would
// mint a fresh key and orphan every token the unreadable key signed.
func entryFromRecord(rec Record) (*keyEntry, error) {
	key, err := x509.ParsePKCS8PrivateKey(rec.Private)
	if err != nil {
		return nil, fmt.Errorf("signingkey: decode key %q: %w", rec.Kid, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("signingkey: decode key %q: %T cannot sign", rec.Kid, key)
	}

	entry, err := entryFromSigner(signer, rec.Alg, rec.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("signingkey: decode key %q: %w", rec.Kid, err)
	}
	return entry, nil
}
