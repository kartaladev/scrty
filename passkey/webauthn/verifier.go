package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/passkey"
)

// Verifier implements passkey.Verifier over the go-webauthn library. Build one
// with New and pass it as passkey.Deps.Verifier. It is safe for concurrent use.
//
// Everything a ceremony is checked against comes from configuration or from
// the core's expectation: the relying-party ID, the allowed origins, the
// expected challenge and the user-verification requirement. Nothing is taken
// from the client except the response being verified.
//
// No error it returns carries the library's error text, which can quote the
// challenge, the origins and the client data. A response that cannot be read
// is passkey.ErrMalformedResponse, a response that does not verify is
// authenticate.ErrAuthenticationFailed, and an attestation the configured
// policy does not trust is passkey.ErrAttestationRefused.
type Verifier struct {
	rp      passkey.RelyingParty
	origins []string
	params  []protocol.CredentialParameter
	att     attestationPolicy
}

var _ passkey.Verifier = (*Verifier)(nil)

// Fixed refusals. The library's own error never reaches them.
var (
	errUnreadableRegistration = fmt.Errorf("webauthn: unreadable registration response: %w", passkey.ErrMalformedResponse)
	errUnreadableAssertion    = fmt.Errorf("webauthn: unreadable assertion response: %w", passkey.ErrMalformedResponse)
	errRegistrationRefused    = fmt.Errorf("webauthn: registration response did not verify: %w", authenticate.ErrAuthenticationFailed)
	errAssertionRefused       = fmt.Errorf("webauthn: assertion response did not verify: %w", authenticate.ErrAuthenticationFailed)
	errInput                  = errors.New("webauthn: invalid ceremony input")
)

// New returns a Verifier for rp.
//
// The relying party has no default: rp must pass passkey.RelyingParty's
// Validate, or New returns an error wrapping passkey.ErrConfig. By default
// attestation conveyance is "none" and every authenticator is accepted, with
// only its AAGUID kept; WithAttestationRecord and WithTrustedAttestation
// replace that. Every wiring mistake, such as a nil option, both attestation
// options at once or trusted attestation without a metadata source, is an
// error wrapping passkey.ErrConfig.
func New(rp passkey.RelyingParty, opts ...Option) (*Verifier, error) {
	if err := rp.Validate(); err != nil {
		return nil, err
	}

	var cfg config

	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: webauthn option %d is nil", passkey.ErrConfig, i)
		}

		opt(&cfg)
	}

	att, err := newAttestationPolicy(cfg)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		rp: passkey.RelyingParty{
			ID: rp.ID, Name: rp.Name, Origins: slices.Clone(rp.Origins),
		},
		origins: slices.Clone(rp.Origins),
		params:  gowebauthn.CredentialParametersDefault(),
		att:     att,
	}, nil
}

// RelyingParty returns the relying party the verifier checks against.
func (v *Verifier) RelyingParty() passkey.RelyingParty {
	rp := v.rp
	rp.Origins = slices.Clone(rp.Origins)

	return rp
}

// CreationOptions renders the PublicKeyCredentialCreationOptions for the
// browser's navigator.credentials.create(), as JSON: the publicKey member
// only, with binary members in unpadded base64url. The challenge is the
// input's challenge string's bytes.
func (v *Verifier) CreationOptions(ctx context.Context, in passkey.CreationInput) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	uv, ok := uvRequirement(in.UV)
	if !ok || in.Challenge == "" || len(in.UserHandle) == 0 {
		return nil, errInput
	}

	sel := protocol.AuthenticatorSelection{UserVerification: uv}

	switch in.ResidentKey {
	case passkey.ResidentKeyRequired:
		sel.ResidentKey = protocol.ResidentKeyRequirementRequired
		sel.RequireResidentKey = protocol.ResidentKeyRequired()
	case passkey.ResidentKeyPreferred:
		sel.ResidentKey = protocol.ResidentKeyRequirementPreferred
	default:
		return nil, errInput
	}

	opts := protocol.PublicKeyCredentialCreationOptions{
		RelyingParty: protocol.RelyingPartyEntity{
			CredentialEntity: protocol.CredentialEntity{Name: v.rp.Name},
			ID:               v.rp.ID,
		},
		User: protocol.UserEntity{
			CredentialEntity: protocol.CredentialEntity{Name: in.UserName},
			DisplayName:      in.DisplayName,
			ID:               protocol.URLEncodedBase64(slices.Clone(in.UserHandle)),
		},
		Challenge:              protocol.URLEncodedBase64(in.Challenge),
		Parameters:             v.params,
		Timeout:                timeoutMillis(in.Timeout),
		CredentialExcludeList:  descriptors(in.Exclude),
		AuthenticatorSelection: sel,
		Attestation:            v.att.conveyance(),
	}

	return json.Marshal(opts)
}

// RequestOptions renders the PublicKeyCredentialRequestOptions for the
// browser's navigator.credentials.get(), as JSON: the publicKey member only.
// With no allowed credentials, allowCredentials is left out, so any
// discoverable credential for the relying party may answer.
func (v *Verifier) RequestOptions(ctx context.Context, in passkey.RequestInput) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	uv, ok := uvRequirement(in.UV)
	if !ok || in.Challenge == "" {
		return nil, errInput
	}

	return json.Marshal(protocol.PublicKeyCredentialRequestOptions{
		Challenge:          protocol.URLEncodedBase64(in.Challenge),
		Timeout:            timeoutMillis(in.Timeout),
		RelyingPartyID:     v.rp.ID,
		AllowedCredentials: descriptors(in.Allow),
		UserVerification:   uv,
	})
}

// ParseRegistration reads a registration response body, the JSON a browser's
// PublicKeyCredential.toJSON() gives, without verifying it. Its optional
// top-level "name" member is the name the client proposes. A body that cannot
// be read is refused with an error wrapping passkey.ErrMalformedResponse.
func (v *Verifier) ParseRegistration(body []byte) (passkey.ParsedRegistration, error) {
	if len(body) == 0 {
		return nil, errUnreadableRegistration
	}

	data, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil || data == nil {
		return nil, errUnreadableRegistration
	}

	return &parsedRegistration{data: data, name: proposedName(body)}, nil
}

// VerifyRegistration verifies a registration ParseRegistration read against
// the relying party, its origins, exp's challenge and exp's user-verification
// requirement, which is required unless exp says passkey.UVPreferred. User
// presence is always required. The attestation is then judged by the
// configured attestation mode.
func (v *Verifier) VerifyRegistration(
	ctx context.Context, p passkey.ParsedRegistration, exp passkey.RegistrationExpectation,
) (*passkey.NewCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pr, ok := p.(*parsedRegistration)
	if !ok || pr == nil || exp.Challenge == "" {
		return nil, errRegistrationRefused
	}

	data := pr.data

	if _, err := data.Verify(
		encodeChallenge(exp.Challenge), v.rp.ID, v.origins, nil, nil,
		protocol.TopOriginExplicitVerificationMode, false,
		exp.UV != passkey.UVPreferred, true,
		nil, v.params, protocol.AttestationPolicy{}, protocol.SignaturePolicy{},
	); err != nil {
		return nil, errRegistrationRefused
	}

	obj := &data.Response.AttestationObject
	authData := obj.AuthData

	att, err := v.att.judge(ctx, data)
	if err != nil {
		return nil, err
	}

	transports := make([]string, 0, len(data.Response.Transports))
	for _, t := range data.Response.Transports {
		transports = append(transports, string(t))
	}

	return &passkey.NewCredential{
		CredentialID:         slices.Clone(authData.AttData.CredentialID),
		PublicKey:            slices.Clone(authData.AttData.CredentialPublicKey),
		SignCount:            authData.Counter,
		UserVerified:         authData.Flags.HasUserVerified(),
		BackupEligible:       authData.Flags.HasBackupEligible(),
		BackupState:          authData.Flags.HasBackupState(),
		Transports:           transports,
		AAGUID:               reportedAAGUID(authData.AttData.AAGUID),
		AttestationFormat:    att.format,
		AttestationStatement: att.statement,
		AttestationTrusted:   att.trusted,
	}, nil
}

// ParseAssertion reads an assertion response body, the JSON a browser's
// PublicKeyCredential.toJSON() gives, without verifying it. A body that cannot
// be read is refused with an error wrapping passkey.ErrMalformedResponse.
func (v *Verifier) ParseAssertion(body []byte) (passkey.ParsedAssertion, error) {
	if len(body) == 0 {
		return nil, errUnreadableAssertion
	}

	data, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil || data == nil {
		return nil, errUnreadableAssertion
	}

	return &parsedAssertion{data: data}, nil
}

// VerifyAssertion verifies an assertion ParseAssertion read against the stored
// credential c, which must be the credential the assertion names, the relying
// party, its origins, exp's challenge and exp's user-verification requirement,
// which is required unless exp says passkey.UVPreferred. User presence is
// always required. The signature counter is reported, not judged: the core
// decides what a counter that did not advance means.
func (v *Verifier) VerifyAssertion(
	ctx context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation,
) (*passkey.AssertionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pa, ok := p.(*parsedAssertion)
	if !ok || pa == nil || c == nil || exp.Challenge == "" || len(c.PublicKey) == 0 {
		return nil, errAssertionRefused
	}

	data := pa.data
	if !bytes.Equal(data.RawID, c.CredentialID) {
		return nil, errAssertionRefused
	}

	if err := data.Verify(
		encodeChallenge(exp.Challenge), v.rp.ID, "", v.origins, nil, nil,
		protocol.TopOriginExplicitVerificationMode, false,
		exp.UV != passkey.UVPreferred, true,
		c.PublicKey, protocol.SignaturePolicy{},
	); err != nil {
		return nil, errAssertionRefused
	}

	flags := data.Response.AuthenticatorData.Flags

	return &passkey.AssertionResult{
		SignCount:      data.Response.AuthenticatorData.Counter,
		UserVerified:   flags.HasUserVerified(),
		BackupEligible: flags.HasBackupEligible(),
		BackupState:    flags.HasBackupState(),
	}, nil
}

// reportedAAGUID returns aaguid, or nil when it is all zero: an
// authenticator that identifies no model reports zeroes, as under "none"
// attestation.
func reportedAAGUID(aaguid []byte) []byte {
	if !slices.ContainsFunc(aaguid, func(b byte) bool { return b != 0 }) {
		return nil
	}

	return slices.Clone(aaguid)
}

// encodeChallenge is the clientDataJSON form of a challenge string: the
// unpadded base64url of its bytes.
func encodeChallenge(challenge string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(challenge))
}

func uvRequirement(uv passkey.UserVerification) (protocol.UserVerificationRequirement, bool) {
	switch uv {
	case passkey.UVRequired:
		return protocol.VerificationRequired, true
	case passkey.UVPreferred:
		return protocol.VerificationPreferred, true
	default:
		return "", false
	}
}

func timeoutMillis(d time.Duration) int {
	if d <= 0 {
		return 0
	}

	return int(d / time.Millisecond)
}

func descriptors(ds []passkey.Descriptor) []protocol.CredentialDescriptor {
	if len(ds) == 0 {
		return nil
	}

	out := make([]protocol.CredentialDescriptor, 0, len(ds))

	for _, d := range ds {
		var transports []protocol.AuthenticatorTransport
		for _, t := range d.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}

		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: protocol.URLEncodedBase64(slices.Clone(d.ID)),
			Transport:    transports,
		})
	}

	return out
}
