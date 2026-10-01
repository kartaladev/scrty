// Package webauthn implements the passkey package's Verifier port over a
// WebAuthn library, in a module of its own so that the core module carries no
// WebAuthn, CBOR or TPM dependency.
//
// No type of the underlying library appears in this package's exported API;
// callers see only the core passkey types.
package webauthn
