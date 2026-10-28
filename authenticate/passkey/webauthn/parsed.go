package webauthn

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/go-webauthn/webauthn/protocol"
)

// parsedRegistration is a registration response go-webauthn has read. It
// leaves the package only as a passkey.ParsedRegistration and is asserted back
// in VerifyRegistration.
type parsedRegistration struct {
	data *protocol.ParsedCredentialCreationData
	name string
}

func (p *parsedRegistration) Challenge() string {
	return p.data.Response.CollectedClientData.Challenge
}

func (p *parsedRegistration) CredentialID() []byte { return slices.Clone(p.data.RawID) }

func (p *parsedRegistration) Name() string { return p.name }

// parsedAssertion is an assertion response go-webauthn has read. It leaves
// the package only as a passkey.ParsedAssertion and is asserted back in
// VerifyAssertion.
type parsedAssertion struct {
	data *protocol.ParsedCredentialAssertionData
}

func (p *parsedAssertion) Challenge() string {
	return p.data.Response.CollectedClientData.Challenge
}

func (p *parsedAssertion) CredentialID() []byte { return slices.Clone(p.data.RawID) }

func (p *parsedAssertion) UserHandle() []byte { return slices.Clone(p.data.Response.UserHandle) }

// proposedName returns the registration response's optional top-level "name"
// member when it is a JSON string, and "" otherwise. A name of another type is
// ignored rather than refused: the core replaces a missing name with a default.
func proposedName(body []byte) string {
	var envelope struct {
		Name json.RawMessage `json:"name"`
	}

	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}

	raw := bytes.TrimSpace(envelope.Name)
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}

	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return ""
	}

	return name
}
