package webauthn

// Option configures a Verifier. Every option names the default it replaces.
type Option func(*config)

// attestationMode is how a registration's attestation is requested and
// judged.
type attestationMode uint8

const (
	// attestationNone requests conveyance "none" and keeps nothing of the
	// statement but the AAGUID. It is the default.
	attestationNone attestationMode = iota
	// attestationRecord requests "direct" and returns the format and the raw
	// statement, accepting every authenticator.
	attestationRecord
	// attestationTrusted requests "direct" and refuses unless the statement
	// chains to a trusted metadata entry.
	attestationTrusted
)

type config struct {
	mode    attestationMode
	modes   int // how many attestation options were given
	source  MetadataSource
	allowed [][16]byte
}
