// Package passkey adds WebAuthn passkeys to scrty: registration and
// management, passwordless login, the passkey as an MFA method, and clone
// handling.
//
// # Ports
//
// WebAuthn parsing and verification sit behind one port, Verifier. The core
// package carries no WebAuthn dependency, so it supplies no default Verifier;
// the library's implementation lives in the nested module
// github.com/kartaladev/scrty/passkey/webauthn. Any other Verifier may be used
// in its place, and is trusted exactly as the library's own.
//
// Credentials are kept by a CredentialStore and user handles by a HandleStore.
// The in-memory stores are the defaults; they hold one process's records only.
// Durable stores implement the same contracts and may be used in their place.
//
// # The relying party
//
// The relying party has no default: its ID, display name and allowed origins
// are required, and a malformed one is a configuration error at construction.
// Changing the relying-party ID orphans every registered passkey, because
// authenticators scope their credentials to it.
//
// # Secrets
//
// No error this package returns carries a challenge, user handle, public key,
// attestation statement, credential ID or emailed code. A credential is named
// only by its library identifier.
package passkey
