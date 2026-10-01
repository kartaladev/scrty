package webauthn

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/kartaladev/scrty/passkey"
)

// WithAttestationRecord records attestation without enforcing it, in place of
// the default, which requests conveyance "none" and keeps nothing of the
// statement but the AAGUID.
//
// It requests "direct" conveyance, verifies the statement's signature where
// the format allows, and returns the format and the raw CBOR statement for the
// core to store with the credential. Every authenticator is still accepted.
// The statement can identify the authenticator's model and batch, so this
// collects data about the user's device that the default does not.
func WithAttestationRecord() Option {
	return func(c *config) {
		c.mode = attestationRecord
		c.modes++
	}
}

// WithTrustedAttestation requires trusted attestation, in place of the
// default, which requests conveyance "none" and accepts every authenticator.
//
// It requests "direct" conveyance and refuses a registration with
// passkey.ErrAttestationRefused unless its statement carries an attestation
// certificate chain (basic, AttCA or anonymisation-CA attestation) that
// verifies against a metadata entry from src for the authenticator's AAGUID,
// and that entry's status reports are not undesired (revoked, compromised and
// the like). With allowedAAGUIDs, the authenticator's AAGUID must also be one
// of them. The format and the raw statement are returned for the core to
// store, with the credential marked as trusted.
//
// This excludes synced passkeys, which carry no attestation, and self
// attestation. It also excludes the android-safetynet format, whose
// certificate chain is not in the statement's x5c. src must not be nil:
// trusted attestation without a metadata source is a configuration error at
// New, as is giving WithAttestationRecord too.
func WithTrustedAttestation(src MetadataSource, allowedAAGUIDs ...[16]byte) Option {
	return func(c *config) {
		c.mode = attestationTrusted
		c.modes++
		c.source = src
		c.allowed = slices.Clone(allowedAAGUIDs)
	}
}

// attestationPolicy requests and judges registration attestation.
type attestationPolicy struct {
	mode    attestationMode
	source  MetadataSource
	allowed [][16]byte
}

// attestationOutcome is what a judged attestation contributes to the new
// credential.
type attestationOutcome struct {
	format    string
	statement []byte
	trusted   bool
}

var errAttestationRefused = fmt.Errorf("webauthn: attestation not trusted: %w", passkey.ErrAttestationRefused)

func newAttestationPolicy(cfg config) (attestationPolicy, error) {
	if cfg.modes > 1 {
		return attestationPolicy{}, fmt.Errorf(
			"%w: webauthn attestation: choose one of WithAttestationRecord and WithTrustedAttestation", passkey.ErrConfig)
	}

	if cfg.mode == attestationTrusted {
		if cfg.source == nil {
			return attestationPolicy{}, fmt.Errorf(
				"%w: webauthn trusted attestation requires a metadata source", passkey.ErrConfig)
		}

		if err := cfg.source.configErr(); err != nil {
			return attestationPolicy{}, configError(err)
		}
	}

	return attestationPolicy{mode: cfg.mode, source: cfg.source, allowed: cfg.allowed}, nil
}

func (a attestationPolicy) conveyance() protocol.ConveyancePreference {
	if a.mode == attestationNone {
		return protocol.PreferNoAttestation
	}

	return protocol.PreferDirectAttestation
}

// judge decides a verified registration's attestation under the mode. data
// has passed Verify, which checked the statement's signature.
func (a attestationPolicy) judge(
	ctx context.Context, data *protocol.ParsedCredentialCreationData,
) (attestationOutcome, error) {
	obj := &data.Response.AttestationObject

	switch a.mode {
	case attestationRecord:
		return attestationOutcome{format: obj.Format, statement: rawStatement(data)}, nil
	case attestationTrusted:
		if err := a.trust(ctx, obj); err != nil {
			return attestationOutcome{}, err
		}

		return attestationOutcome{format: obj.Format, statement: rawStatement(data), trusted: true}, nil
	default:
		return attestationOutcome{}, nil
	}
}

// trust refuses obj unless its certificate chain verifies against a metadata
// entry the source currently trusts.
func (a attestationPolicy) trust(ctx context.Context, obj *protocol.AttestationObject) error {
	switch metadata.AuthenticatorAttestationType(obj.Type) {
	case metadata.BasicFull, metadata.AttCA, metadata.AnonCA:
	default:
		return errAttestationRefused
	}

	x5c, ok := obj.AttStatement["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return errAttestationRefused
	}

	aaguid, err := uuid.FromBytes(obj.AuthData.AttData.AAGUID)
	if err != nil || aaguid == uuid.Nil {
		return errAttestationRefused
	}

	if len(a.allowed) > 0 && !slices.Contains(a.allowed, [16]byte(aaguid)) {
		return errAttestationRefused
	}

	mds, err := a.source.provider(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return err
		}

		return errAttestationRefused
	}

	if e := protocol.ValidateMetadataWithAuthenticatorData(
		ctx, mds, aaguid, obj.Type, obj.Format, x5c, &obj.AuthData,
	); e != nil {
		return errAttestationRefused
	}

	return nil
}

// rawStatement returns the attestation statement exactly as the
// authenticator encoded it, or nil when it is empty.
func rawStatement(data *protocol.ParsedCredentialCreationData) []byte {
	var obj struct {
		AttStmt cbor.RawMessage `cbor:"attStmt"`
	}

	if err := cbor.Unmarshal(data.Raw.AttestationResponse.AttestationObject, &obj); err != nil {
		return nil
	}

	var stmt map[any]any
	if len(obj.AttStmt) == 0 || cbor.Unmarshal(obj.AttStmt, &stmt) != nil || len(stmt) == 0 {
		return nil
	}

	return slices.Clone([]byte(obj.AttStmt))
}
