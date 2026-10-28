package webauthntest

import (
	"github.com/fxamacker/cbor/v2"
)

// coseAlgES256 is the COSE algorithm identifier of ECDSA with SHA-256.
const coseAlgES256 = -7

// COSE key parameters (RFC 9052 §7, RFC 9053 §7.1).
const (
	coseKeyKty   = 1
	coseKeyAlg   = 3
	coseKeyCrv   = -1
	coseKeyX     = -2
	coseKeyY     = -3
	coseKtyEC2   = 2
	coseCrvP256  = 1
	p256CoordLen = 32
)

// encMode encodes in the CTAP2 canonical form authenticators use.
var encMode = func() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// coseKey returns the credential public key as a COSE_Key.
func (a *Authenticator) coseKey() []byte {
	point, err := a.key.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		a.tb.Fatalf("webauthntest: encode public key: %v", err)
	}
	return a.encode(map[int]any{
		coseKeyKty: coseKtyEC2,
		coseKeyAlg: coseAlgES256,
		coseKeyCrv: coseCrvP256,
		coseKeyX:   point[1 : 1+p256CoordLen],
		coseKeyY:   point[1+p256CoordLen:],
	})
}

// attestationObject returns the CBOR attestation object.
func (a *Authenticator) attestationObject(format string, stmt map[string]any, authData []byte) []byte {
	return a.encode(map[string]any{
		"fmt":      format,
		"attStmt":  stmt,
		"authData": authData,
	})
}

func (a *Authenticator) encode(v any) []byte {
	out, err := encMode.Marshal(v)
	if err != nil {
		a.tb.Fatalf("webauthntest: encode CBOR: %v", err)
	}
	return out
}
