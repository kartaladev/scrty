// Package signingkey manages the asymmetric keys scrty signs tokens with.
//
// A key manager generates a key per configured algorithm, writes it to a key
// store before using it, reloads the store so a restart invalidates no token,
// rotates keys on a schedule, and stops publishing keys past their lifetime. It
// supplies the signer to sign with and the public keys to verify against to
// token issuance and verification through KeySource.
//
// KeySource names no type from a JOSE library, and neither does anything else
// this package exports. A consumer implementing the port describes its keys
// with the standard library's own crypto types, so the JOSE library scrty
// happens to use, and the major version it is pinned to, stay scrty's business
// rather than that consumer's.
//
// # Wiring
//
// NewKeyManager returns a manager that already has a current key and starts no
// goroutine. Start launches the rotation, reload and housekeeping loops; Stop
// ends them and returns only once they have ended, an in-flight store write
// included.
//
//	km, err := signingkey.NewKeyManager(ctx)
//	if err != nil {
//		return err
//	}
//	if err := km.Start(ctx); err != nil {
//		return err
//	}
//	defer func() { _ = km.Stop() }()
//
// # Storage
//
// The default store is in-memory and lasts only as long as the process, so
// every token the previous process signed stops verifying. A consumer supplies
// any KeyStore instead through WithKeyStore — a durable one, or one that wraps
// another and seals Record.Private, which is opaque to every store and is
// where the secrets-at-rest capability hooks in.
//
// # Publishing
//
// Whatever verifies scrty's tokens elsewhere needs the keys they were signed
// with, so KeyManager.JWKS renders the ones it holds as the RFC 7517 document
// a /.well-known/jwks.json endpoint serves — bytes, so writing that response
// needs no JOSE library either. A consumer whose endpoint must say something
// else builds its own document from the keys VerificationKeys reports.
//
// # Two lags a consumer should expect
//
// A rotated key signs immediately, so an external verifier that caches the
// published keys — a JWKS endpoint's response, typically — will reject tokens
// signed with the new key until its cache expires. Keep that cache well inside
// the key lifetime, which is what keeps the replaced key published.
//
// Replicas sharing a store see each other's keys one reload interval later, a
// minute by default, so for up to that long one replica rejects a token
// another has just minted. WithReloadInterval narrows the window.
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

// SupportedAlg reports whether scrty can produce signatures for alg.
//
// It is the single authority on that question, and it is exported because
// another package needs to ask it: a JOSE library's own algorithm registry
// answers a different question — whether the name exists — and resolves HS256
// and none, neither of which this package can produce. Validating against the
// registry therefore accepts a configuration that fails at the first signature.
func SupportedAlg(alg Alg) bool {
	return supportedAlg(alg)
}

func supportedAlg(alg Alg) bool {
	switch alg {
	case RS256, ES256, EdDSA:
		return true
	default:
		return false
	}
}
