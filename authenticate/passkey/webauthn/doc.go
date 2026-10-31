// Package webauthn implements the passkey package's Verifier port over a
// WebAuthn library, in a module of its own so that the core module carries no
// WebAuthn, CBOR or TPM dependency.
//
// No type of the underlying library appears in this package's exported API;
// callers see only the core passkey types.
//
//	v, err := webauthn.New(passkey.RelyingParty{
//		ID: "example.com", Name: "Example", Origins: []string{"https://example.com"},
//	})
//	// pass v as passkey.Deps.Verifier
//
// # Defaults and overrides
//
// The relying party has no default and is validated by New. Attestation
// conveyance is "none" by default and every authenticator is accepted, keeping
// only its AAGUID. WithAttestationRecord records the format and statement
// without enforcing them; WithTrustedAttestation refuses any registration
// whose attestation does not chain to a trusted FIDO metadata entry.
//
// # Metadata
//
// Trusted attestation needs a MetadataSource: MetadataBlob, for a BLOB the
// consumer fetches, or MetadataFromMDS, which fetches it from the FIDO
// Metadata Service through scrty's confined outbound client. The verification
// library's own HTTP client is never used, neither for the BLOB nor for the
// revocation status of its signing chain, which is therefore not looked up.
package webauthn
