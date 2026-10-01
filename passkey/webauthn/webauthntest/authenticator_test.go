package webauthntest_test

import (
	"encoding/base64"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
)

const (
	rpID      = "example.com"
	origin    = "https://example.com"
	challenge = "passkey-registration.c2VjcmV0LXRva2Vu"
)

var es256 = []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: -7}}

// verifyCreation parses a registration response and verifies it the way a
// relying party at rpID and origin would, expecting challenge.
func verifyCreation(t *testing.T, body []byte, wantChallenge string, verifyUser bool) (*protocol.ParsedCredentialCreationData, error) {
	t.Helper()
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, err
	}
	_, err = parsed.Verify(encodeChallenge(wantChallenge), rpID, []string{origin}, nil, nil,
		protocol.TopOriginDefaultVerificationMode, false, verifyUser, true, nil, es256,
		protocol.AttestationPolicy{}, protocol.SignaturePolicy{})
	return parsed, err
}

func encodeChallenge(c string) string { return base64.RawURLEncoding.EncodeToString([]byte(c)) }

func TestAuthenticator_Create(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		configure   func(a *webauthntest.Authenticator)
		attestation string
		origin      string // the origin the authenticator's client reports; empty means the RP's
		verifyUser  bool
		assert      func(t *testing.T, a *webauthntest.Authenticator, parsed *protocol.ParsedCredentialCreationData, err error)
	}

	cases := []testCase{
		{
			name:        "none attestation verifies with the default flags",
			attestation: "none",
			verifyUser:  true,
			assert: func(t *testing.T, a *webauthntest.Authenticator, parsed *protocol.ParsedCredentialCreationData, err error) {
				require.NoError(t, err)
				obj := parsed.Response.AttestationObject
				assert.Equal(t, "none", obj.Format)
				assert.Empty(t, obj.AttStatement)
				assert.Equal(t, a.CredentialID(), obj.AuthData.AttData.CredentialID)
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(a.CredentialID()), parsed.ID)
				assert.Equal(t, a.AAGUID[:], obj.AuthData.AttData.AAGUID)
				flags := obj.AuthData.Flags
				assert.True(t, flags.HasUserPresent())
				assert.True(t, flags.HasUserVerified())
				assert.True(t, flags.HasAttestedCredentialData())
				assert.False(t, flags.HasBackupEligible())
				assert.False(t, flags.HasBackupState())
				assert.Equal(t, "webauthn.create", string(parsed.Response.CollectedClientData.Type))
				assert.Equal(t, encodeChallenge(challenge), parsed.Response.CollectedClientData.Challenge)
				assert.Equal(t, []protocol.AuthenticatorTransport{"internal", "hybrid"}, parsed.Response.Transports)
				assert.Equal(t, protocol.Platform, parsed.AuthenticatorAttachment)
			},
		},
		{
			name:        "packed self-attestation verifies",
			attestation: "packed",
			verifyUser:  true,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, parsed *protocol.ParsedCredentialCreationData, err error) {
				require.NoError(t, err)
				obj := parsed.Response.AttestationObject
				assert.Equal(t, "packed", obj.Format)
				assert.EqualValues(t, -7, obj.AttStatement["alg"])
				assert.NotEmpty(t, obj.AttStatement["sig"])
				assert.NotContains(t, obj.AttStatement, "x5c")
			},
		},
		{
			name: "configured AAGUID, transports and backup flags are reported",
			configure: func(a *webauthntest.Authenticator) {
				a.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				a.Transports = []string{"usb"}
				a.BE, a.BS = true, true
			},
			attestation: "packed",
			verifyUser:  true,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, parsed *protocol.ParsedCredentialCreationData, err error) {
				require.NoError(t, err)
				obj := parsed.Response.AttestationObject
				assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, obj.AuthData.AttData.AAGUID)
				assert.Equal(t, []protocol.AuthenticatorTransport{"usb"}, parsed.Response.Transports)
				assert.True(t, obj.AuthData.Flags.HasBackupEligible())
				assert.True(t, obj.AuthData.Flags.HasBackupState())
			},
		},
		{
			name:        "without user verification the UV flag is clear and a UV-requiring RP refuses",
			configure:   func(a *webauthntest.Authenticator) { a.UV = false },
			attestation: "none",
			verifyUser:  true,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, parsed *protocol.ParsedCredentialCreationData, err error) {
				require.Error(t, err)
				require.NotNil(t, parsed)
				assert.False(t, parsed.Response.AttestationObject.AuthData.Flags.HasUserVerified())
			},
		},
		{
			name:        "a response from another origin does not verify",
			attestation: "none",
			origin:      "https://evil.example",
			verifyUser:  true,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ *protocol.ParsedCredentialCreationData, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := webauthntest.New(t)
			if tc.configure != nil {
				tc.configure(a)
			}
			from := origin
			if tc.origin != "" {
				from = tc.origin
			}

			body := a.Create(rpID, from, challenge, []byte("user-handle"), tc.attestation)
			parsed, err := verifyCreation(t, body, challenge, tc.verifyUser)
			tc.assert(t, a, parsed, err)
		})
	}
}

func TestAuthenticator_Assert(t *testing.T) {
	t.Parallel()

	const loginChallenge = "passkey-login.bG9naW4tdG9rZW4"
	userHandle := []byte("the-user-handle")

	type testCase struct {
		name      string
		configure func(a *webauthntest.Authenticator)
		challenge string // the challenge the RP expects; empty means loginChallenge
		assert    func(t *testing.T, parsed *protocol.ParsedCredentialAssertionData, err error)
	}

	cases := []testCase{
		{
			name: "an assertion verifies against the registered key and carries the user handle",
			assert: func(t *testing.T, parsed *protocol.ParsedCredentialAssertionData, err error) {
				require.NoError(t, err)
				assert.Equal(t, userHandle, parsed.Response.UserHandle)
				assert.Equal(t, "webauthn.get", string(parsed.Response.CollectedClientData.Type))
				assert.Equal(t, encodeChallenge(loginChallenge), parsed.Response.CollectedClientData.Challenge)
				assert.True(t, parsed.Response.AuthenticatorData.Flags.HasUserPresent())
				assert.True(t, parsed.Response.AuthenticatorData.Flags.HasUserVerified())
				assert.False(t, parsed.Response.AuthenticatorData.Flags.HasAttestedCredentialData())
				assert.Zero(t, parsed.Response.AuthenticatorData.Counter)
			},
		},
		{
			name:      "a non-zero counter is incremented before signing",
			configure: func(a *webauthntest.Authenticator) { a.Counter = 5 },
			assert: func(t *testing.T, parsed *protocol.ParsedCredentialAssertionData, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 6, parsed.Response.AuthenticatorData.Counter)
			},
		},
		{
			name: "UV, BE and BS are reported as configured",
			configure: func(a *webauthntest.Authenticator) {
				a.UV, a.BE, a.BS = false, true, true
			},
			assert: func(t *testing.T, parsed *protocol.ParsedCredentialAssertionData, err error) {
				require.NoError(t, err)
				flags := parsed.Response.AuthenticatorData.Flags
				assert.False(t, flags.HasUserVerified())
				assert.True(t, flags.HasBackupEligible())
				assert.True(t, flags.HasBackupState())
			},
		},
		{
			name:      "an assertion for another challenge does not verify",
			challenge: "passkey-login.b3RoZXI",
			assert: func(t *testing.T, _ *protocol.ParsedCredentialAssertionData, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := webauthntest.New(t)
			created, err := verifyCreation(t, a.Create(rpID, origin, challenge, userHandle, "none"), challenge, true)
			require.NoError(t, err)
			publicKey := created.Response.AttestationObject.AuthData.AttData.CredentialPublicKey

			if tc.configure != nil {
				tc.configure(a)
			}
			want := loginChallenge
			if tc.challenge != "" {
				want = tc.challenge
			}

			parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Assert(rpID, origin, loginChallenge))
			if err == nil {
				err = parsed.Verify(encodeChallenge(want), rpID, "", []string{origin}, nil, nil,
					protocol.TopOriginDefaultVerificationMode, false, false, true, publicKey, protocol.SignaturePolicy{})
			}
			tc.assert(t, parsed, err)
		})
	}
}
