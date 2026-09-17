// Package signingkey manages the asymmetric keys scrty signs tokens with.
//
// A key manager generates a key per configured algorithm, writes it to a key
// store before using it, reloads the store so a restart invalidates no token,
// rotates keys on a schedule, and stops publishing keys past their lifetime. It
// publishes the public keys as a JWK Set.
//
// The default store is in-memory and lasts only as long as the process. A
// consumer supplies any KeyStore instead — a durable one, or one that seals the
// private bytes, which the store treats as opaque.
package signingkey

// Alg names a signature algorithm. It is a string alias so a consumer can pass
// an algorithm name through their own configuration without importing a JOSE
// library.
type Alg = string

// The signature algorithms scrty supports. RS256 is the default.
const (
	RS256 Alg = "RS256"
	ES256 Alg = "ES256"
	EdDSA Alg = "EdDSA"
)

// supportedAlg reports whether alg is one scrty can generate and sign with.
func supportedAlg(alg Alg) bool {
	switch alg {
	case RS256, ES256, EdDSA:
		return true
	default:
		return false
	}
}
