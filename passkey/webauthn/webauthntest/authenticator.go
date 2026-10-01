// Package webauthntest provides a software WebAuthn authenticator for tests.
//
// An Authenticator holds one ES256 credential and answers registration and
// authentication ceremonies with the JSON a browser would post: the WebAuthn
// Level 3 toJSON() shapes of a PublicKeyCredential. Its sign counter, its
// user-verified, backup-eligible and backup-state flags, its AAGUID and its
// transports are plain fields a test sets before a ceremony.
//
// The client data's challenge is the base64url (unpadded) encoding of the
// challenge string's UTF-8 bytes, which is how a relying party built on scrty
// issues challenges.
//
// The package exists for tests. No production code imports it, and its keys
// are generated per Authenticator and never persisted.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// Attestation statement formats Create can produce.
const (
	// AttestationNone produces the "none" format with an empty statement.
	AttestationNone = "none"
	// AttestationPacked produces a self-signed "packed" statement: the
	// credential key signs authData and the client data hash, with no
	// certificate chain.
	AttestationPacked = "packed"
)

// Authenticator flag bits, as WebAuthn §6.1 defines them.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// credentialIDLen is the length of the random credential ID New generates.
const credentialIDLen = 32

// Authenticator is a software authenticator holding one ES256 credential.
//
// The exported fields are read at each ceremony, so a test may change them
// between ceremonies. An Authenticator is not safe for concurrent use.
//
// The testing.TB given to New receives every failure the Authenticator
// reports, so build it inside the test or subtest that uses it, not in a
// parent test whose subtests share it.
type Authenticator struct {
	// Counter is the signature counter. Assert increments it before signing
	// unless it is 0, which models an authenticator that keeps no counter.
	// New sets 0.
	//
	// Because of that first increment, to make the next assertion report N
	// of 2 or more, set Counter to N-1 beforehand. To replay or regress a
	// counter, set the field again to the value wanted.
	Counter uint32
	// UP sets the user-present flag. New sets true. It is a test-only knob:
	// a real authenticator always reports user presence for a ceremony that
	// asked for it, and clearing it lets a negative test check the relying
	// party refuses a response without it.
	UP bool
	// UV sets the user-verified flag. New sets true.
	UV bool
	// BE sets the backup-eligible flag. New sets false.
	BE bool
	// BS sets the backup-state flag. New sets false. BS without BE is
	// invalid under WebAuthn; it is settable only so that negative tests can
	// produce that combination.
	BS bool
	// Transports are reported in the registration response. New sets
	// "internal" and "hybrid".
	Transports []string
	// AAGUID identifies the authenticator model in the attested credential
	// data. New leaves it all zero, as authenticators do under "none"
	// attestation.
	AAGUID [16]byte

	// CrossOrigin sets the client data's crossOrigin member. New sets false.
	// It is a test-only knob modelling a ceremony run in a cross-origin
	// iframe, for negative tests.
	CrossOrigin bool
	// TopOrigin, when not empty, is put in the client data's topOrigin
	// member. New leaves it empty, and the member out. It is a test-only
	// knob: a browser sets topOrigin only alongside crossOrigin, and a test
	// may set either without the other.
	TopOrigin string
	// ClientDataType, when not empty, replaces the client data's type member,
	// which is otherwise "webauthn.create" for Create and "webauthn.get" for
	// Assert. New leaves it empty. It is a test-only knob for presenting one
	// ceremony's response as the other's.
	ClientDataType string

	tb         testing.TB
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
}

// New returns an Authenticator with a fresh ES256 key pair and a random
// 32-byte credential ID. A failure to generate either fails tb.
func New(tb testing.TB) *Authenticator {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("webauthntest: generate key: %v", err)
	}
	credID := make([]byte, credentialIDLen)
	if _, err := rand.Read(credID); err != nil {
		tb.Fatalf("webauthntest: generate credential ID: %v", err)
	}
	return &Authenticator{
		UP:         true,
		UV:         true,
		Transports: []string{"internal", "hybrid"},
		tb:         tb,
		key:        key,
		credID:     credID,
	}
}

// CredentialID returns a copy of the credential's ID.
func (a *Authenticator) CredentialID() []byte {
	return append([]byte(nil), a.credID...)
}

// Create answers a registration ceremony for rpID, as a client at origin that
// was handed challenge, and returns the registration response JSON.
// userHandle is remembered and returned by later assertions. attestation is
// AttestationNone or AttestationPacked; anything else fails the test. The
// counter is reported as it stands and is not incremented.
func (a *Authenticator) Create(rpID, origin, challenge string, userHandle []byte, attestation string) []byte {
	a.tb.Helper()
	a.userHandle = append([]byte(nil), userHandle...)

	clientData := a.clientData("webauthn.create", origin, challenge)
	authData := a.authData(rpID, flagAT)
	authData = append(authData, a.AAGUID[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.credID))) //nolint:gosec // G115: credential ID is 32 bytes
	authData = append(authData, a.credID...)
	authData = append(authData, a.coseKey()...)

	var stmt map[string]any
	switch attestation {
	case AttestationNone:
		stmt = map[string]any{}
	case AttestationPacked:
		stmt = map[string]any{"alg": coseAlgES256, "sig": a.sign(authData, clientData)}
	default:
		a.tb.Fatalf("webauthntest: unsupported attestation format %q", attestation)
	}

	return a.marshal(map[string]any{
		"clientDataJSON":    b64(clientData),
		"attestationObject": b64(a.attestationObject(attestation, stmt, authData)),
		"transports":        a.transports(),
	})
}

// Assert answers an authentication ceremony for rpID, as a client at origin
// that was handed challenge, and returns the authentication response JSON.
// It increments Counter first unless Counter is 0, and carries the user
// handle given to the last Create, if any.
func (a *Authenticator) Assert(rpID, origin, challenge string) []byte {
	a.tb.Helper()
	if a.Counter != 0 {
		a.Counter++
	}
	clientData := a.clientData("webauthn.get", origin, challenge)
	authData := a.authData(rpID, 0)

	response := map[string]any{
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(a.sign(authData, clientData)),
	}
	if len(a.userHandle) > 0 {
		response["userHandle"] = b64(a.userHandle)
	}
	return a.marshal(response)
}

func (a *Authenticator) clientData(typ, origin, challenge string) []byte {
	if a.ClientDataType != "" {
		typ = a.ClientDataType
	}
	data, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
		TopOrigin   string `json:"topOrigin,omitempty"`
	}{typ, b64([]byte(challenge)), origin, a.CrossOrigin, a.TopOrigin})
	if err != nil {
		a.tb.Fatalf("webauthntest: marshal client data: %v", err)
	}
	return data
}

// authData returns rpIdHash, flags and counter, with extra flags set.
func (a *Authenticator) authData(rpID string, extra byte) []byte {
	flags := extra
	if a.UP {
		flags |= flagUP
	}
	if a.UV {
		flags |= flagUV
	}
	if a.BE {
		flags |= flagBE
	}
	if a.BS {
		flags |= flagBS
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	out := append(rpIDHash[:], flags)
	return binary.BigEndian.AppendUint32(out, a.Counter)
}

// sign signs authData followed by the SHA-256 of clientData, ASN.1 encoded.
func (a *Authenticator) sign(authData, clientData []byte) []byte {
	clientDataHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.tb.Fatalf("webauthntest: sign: %v", err)
	}
	return sig
}

func (a *Authenticator) transports() []string {
	if a.Transports == nil {
		return []string{}
	}
	return a.Transports
}

// marshal wraps response in the PublicKeyCredential JSON shape.
func (a *Authenticator) marshal(response map[string]any) []byte {
	id := b64(a.credID)
	data, err := json.Marshal(map[string]any{
		"id":                      id,
		"rawId":                   id,
		"type":                    "public-key",
		"response":                response,
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
	if err != nil {
		a.tb.Fatalf("webauthntest: marshal response: %v", err)
	}
	return data
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
