package webauthn_test

import (
	"fmt"

	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/passkey/webauthn"
)

// The examples in this file mirror the passkeys section of the README.

// ExampleNew builds the verifier for a relying party. Attestation is off by
// default: the adapter asks for none and accepts every authenticator, keeping
// only its AAGUID. The result is passkey.Deps.Verifier.
func ExampleNew() {
	verifier, err := webauthn.New(passkey.RelyingParty{
		ID:      "example.com",
		Name:    "Example Co",
		Origins: []string{"https://example.com"},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(verifier.RelyingParty().ID)

	// Output: example.com
}

// ExampleWithAttestationRecord records each authenticator's attestation
// without enforcing it. It collects data about the user's device that the
// default does not.
func ExampleWithAttestationRecord() {
	verifier, err := webauthn.New(passkey.RelyingParty{
		ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
	}, webauthn.WithAttestationRecord())
	if err != nil {
		panic(err)
	}

	fmt.Println(verifier != nil)

	// Output: true
}

// ExampleWithTrustedAttestation refuses any registration whose attestation
// does not chain to a trusted FIDO metadata entry. The metadata is fetched
// through scrty's confined outbound client, whose response cap must be raised:
// the production BLOB is several megabytes, above the client's default. Nothing
// is fetched until a registration needs it. A consumer who fetches the BLOB
// itself uses webauthn.MetadataBlob in place of MetadataFromMDS. Synced
// passkeys carry no attestation, so this excludes them.
func ExampleWithTrustedAttestation() {
	client, err := outbound.New(
		outbound.WithAllowedOrigins("https://mds3.fidoalliance.org"),
		outbound.WithMaxResponseBytes(32<<20),
	)
	if err != nil {
		panic(err)
	}

	verifier, err := webauthn.New(passkey.RelyingParty{
		ID: "example.com", Name: "Example Co", Origins: []string{"https://example.com"},
	}, webauthn.WithTrustedAttestation(webauthn.MetadataFromMDS(client)))
	if err != nil {
		panic(err)
	}

	fmt.Println(verifier != nil)

	// Output: true
}
