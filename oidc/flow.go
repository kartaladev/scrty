package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

// DefaultFlowTTL is how long a login flow stays completable after Authorize
// when WithFlowTTL is not given.
const DefaultFlowTTL = 10 * time.Minute

// flowSecretBytes is the length of every random value a flow carries: the
// state, the nonce, the PKCE verifier and the in-memory store's handle. 32
// bytes is 256 bits of entropy.
const flowSecretBytes = 32

// randomURLToken draws n bytes from r and returns them base64url-encoded
// without padding. A short read is an error, never a shorter token.
func randomURLToken(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("oidc: drawing a random value: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// s256Challenge returns the PKCE S256 code challenge for verifier:
// base64url(SHA-256(verifier)) without padding (RFC 7636, section 4.2).
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
