package webauthn_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/passkey/webauthn"
	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
)

const (
	rpID      = "example.com"
	rpOrigin  = "https://example.com"
	challenge = "passkey-registration.c2VjcmV0LXRva2VuLXN0cmluZw"
)

func relyingParty() passkey.RelyingParty {
	return passkey.RelyingParty{ID: rpID, Name: "Example", Origins: []string{rpOrigin, "https://login.example.com"}}
}

func newVerifier(t *testing.T, opts ...webauthn.Option) *webauthn.Verifier {
	t.Helper()
	v, err := webauthn.New(relyingParty(), opts...)
	require.NoError(t, err)
	return v
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// register runs a registration of a through v and returns the credential the
// core would store.
func register(t *testing.T, v *webauthn.Verifier, a *webauthntest.Authenticator) *passkey.Credential {
	t.Helper()
	p, err := v.ParseRegistration(a.Create(rpID, rpOrigin, challenge, []byte("handle-0123456789"), webauthntest.AttestationNone))
	require.NoError(t, err)
	nc, err := v.VerifyRegistration(t.Context(), p, passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired})
	require.NoError(t, err)
	return &passkey.Credential{CredentialID: nc.CredentialID, PublicKey: nc.PublicKey, SignCount: nc.SignCount}
}

// decode unmarshals rendered options into a generic map.
func decode(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func TestNew(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		rp     passkey.RelyingParty
		opts   []webauthn.Option
		assert func(t *testing.T, v *webauthn.Verifier, err error)
	}

	cases := []testCase{
		{
			name: "a valid relying party is accepted and reported back",
			rp:   relyingParty(),
			assert: func(t *testing.T, v *webauthn.Verifier, err error) {
				require.NoError(t, err)
				assert.Equal(t, relyingParty(), v.RelyingParty())
			},
		},
		{
			name: "a missing relying-party ID is a configuration error",
			rp:   passkey.RelyingParty{Name: "Example", Origins: []string{rpOrigin}},
			assert: func(t *testing.T, _ *webauthn.Verifier, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
			},
		},
		{
			name: "an origin outside the relying party is a configuration error",
			rp:   passkey.RelyingParty{ID: rpID, Name: "Example", Origins: []string{"https://example.org"}},
			assert: func(t *testing.T, _ *webauthn.Verifier, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
			},
		},
		{
			name: "a nil option is a configuration error",
			rp:   relyingParty(),
			opts: []webauthn.Option{nil},
			assert: func(t *testing.T, _ *webauthn.Verifier, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := webauthn.New(tc.rp, tc.opts...)
			tc.assert(t, v, err)
		})
	}
}

func TestVerifier_CreationOptions(t *testing.T) {
	t.Parallel()

	handle := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	type testCase struct {
		name   string
		in     passkey.CreationInput
		assert func(t *testing.T, opts map[string]any, err error)
	}

	base := passkey.CreationInput{
		UserHandle: handle, UserName: "alice@example.com", DisplayName: "Alice",
		Challenge: challenge, Timeout: 5 * time.Minute,
		UV: passkey.UVRequired, ResidentKey: passkey.ResidentKeyRequired,
	}

	cases := []testCase{
		{
			name: "defaults carry the relying party, user, challenge, timeout and requirements",
			in:   base,
			assert: func(t *testing.T, opts map[string]any, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]any{"id": rpID, "name": "Example"}, opts["rp"])
				user := opts["user"].(map[string]any)
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(handle), user["id"])
				assert.Equal(t, "alice@example.com", user["name"])
				assert.Equal(t, "Alice", user["displayName"])
				assert.Equal(t, b64(challenge), opts["challenge"])
				assert.InDelta(t, 300000, opts["timeout"], 0)
				sel := opts["authenticatorSelection"].(map[string]any)
				assert.Equal(t, "required", sel["userVerification"])
				assert.Equal(t, "required", sel["residentKey"])
				assert.Equal(t, true, sel["requireResidentKey"])
				assert.Equal(t, "none", opts["attestation"])
				assert.NotEmpty(t, opts["pubKeyCredParams"])
				assert.NotContains(t, opts, "excludeCredentials")
				assert.NotContains(t, opts, "publicKey", "only the inner options are rendered")
			},
		},
		{
			name: "preferred user verification and resident key are rendered as preferred",
			in: func() passkey.CreationInput {
				in := base
				in.UV, in.ResidentKey = passkey.UVPreferred, passkey.ResidentKeyPreferred
				return in
			}(),
			assert: func(t *testing.T, opts map[string]any, err error) {
				require.NoError(t, err)
				sel := opts["authenticatorSelection"].(map[string]any)
				assert.Equal(t, "preferred", sel["userVerification"])
				assert.Equal(t, "preferred", sel["residentKey"])
				assert.NotContains(t, sel, "requireResidentKey")
			},
		},
		{
			name: "existing credentials are excluded with their transports",
			in: func() passkey.CreationInput {
				in := base
				in.Exclude = []passkey.Descriptor{
					{ID: []byte("cred-one"), Transports: []string{"internal", "hybrid"}},
					{ID: []byte("cred-two")},
				}
				return in
			}(),
			assert: func(t *testing.T, opts map[string]any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []any{
					map[string]any{"type": "public-key", "id": b64("cred-one"), "transports": []any{"internal", "hybrid"}},
					map[string]any{"type": "public-key", "id": b64("cred-two")},
				}, opts["excludeCredentials"])
			},
		},
		{
			name: "an unknown user-verification value is refused",
			in: func() passkey.CreationInput {
				in := base
				in.UV = 0
				return in
			}(),
			assert: func(t *testing.T, _ map[string]any, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "an empty challenge is refused",
			in: func() passkey.CreationInput {
				in := base
				in.Challenge = ""
				return in
			}(),
			assert: func(t *testing.T, _ map[string]any, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := newVerifier(t).CreationOptions(t.Context(), tc.in)
			var opts map[string]any
			if err == nil {
				opts = decode(t, raw)
			}
			tc.assert(t, opts, err)
		})
	}
}

func TestVerifier_RequestOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		in     passkey.RequestInput
		assert func(t *testing.T, opts map[string]any, err error)
	}

	cases := []testCase{
		{
			name: "no allowed credentials leaves allowCredentials out",
			in:   passkey.RequestInput{Challenge: challenge, Timeout: 5 * time.Minute, UV: passkey.UVRequired},
			assert: func(t *testing.T, opts map[string]any, err error) {
				require.NoError(t, err)
				assert.NotContains(t, opts, "allowCredentials")
				assert.Equal(t, rpID, opts["rpId"])
				assert.Equal(t, b64(challenge), opts["challenge"])
				assert.InDelta(t, 300000, opts["timeout"], 0)
				assert.Equal(t, "required", opts["userVerification"])
			},
		},
		{
			name: "allowed credentials are listed with their transports",
			in: passkey.RequestInput{
				Challenge: challenge, Timeout: time.Minute, UV: passkey.UVPreferred,
				Allow: []passkey.Descriptor{{ID: []byte("cred-one"), Transports: []string{"usb"}}},
			},
			assert: func(t *testing.T, opts map[string]any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []any{
					map[string]any{"type": "public-key", "id": b64("cred-one"), "transports": []any{"usb"}},
				}, opts["allowCredentials"])
				assert.Equal(t, "preferred", opts["userVerification"])
			},
		},
		{
			name: "an unknown user-verification value is refused",
			in:   passkey.RequestInput{Challenge: challenge, Timeout: time.Minute},
			assert: func(t *testing.T, _ map[string]any, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := newVerifier(t).RequestOptions(t.Context(), tc.in)
			var opts map[string]any
			if err == nil {
				opts = decode(t, raw)
			}
			tc.assert(t, opts, err)
		})
	}
}

func TestVerifier_Parse_RefusesMalformedInput(t *testing.T) {
	t.Parallel()

	parsers := map[string]func(v *webauthn.Verifier, body []byte) error{
		"registration": func(v *webauthn.Verifier, body []byte) error { _, err := v.ParseRegistration(body); return err },
		"assertion":    func(v *webauthn.Verifier, body []byte) error { _, err := v.ParseAssertion(body); return err },
	}

	type testCase struct {
		name   string
		body   []byte
		assert func(t *testing.T, err error)
	}

	malformed := func(t *testing.T, err error) {
		require.ErrorIs(t, err, passkey.ErrMalformedResponse)
		assert.NotContains(t, err.Error(), "{")
	}

	cases := []testCase{
		{name: "empty body", body: nil, assert: malformed},
		{name: "not JSON", body: []byte("not json"), assert: malformed},
		{name: "a form body", body: []byte("id=abc&type=public-key"), assert: malformed},
		{name: "an empty object", body: []byte("{}"), assert: malformed},
		{name: "truncated JSON", body: []byte(`{"id":"abc","rawId":"abc","type":"public-key","response":{`), assert: malformed},
	}

	for kind, parse := range parsers {
		for _, tc := range cases {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				tc.assert(t, parse(newVerifier(t), tc.body))
			})
		}
	}
}

func TestVerifier_Registration(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		configure func(a *webauthntest.Authenticator)
		origin    string
		presented string // the challenge the client was handed; empty means challenge
		exp       passkey.RegistrationExpectation
		body      func(body []byte) []byte
		assert    func(t *testing.T, a *webauthntest.Authenticator, p passkey.ParsedRegistration, nc *passkey.NewCredential, err error)
	}

	required := passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired}

	cases := []testCase{
		{
			name: "a valid response gives the credential with its flags, transports and AAGUID",
			configure: func(a *webauthntest.Authenticator) {
				a.BE, a.BS = true, true
				a.Transports = []string{"internal", "hybrid"}
				a.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			},
			exp: required,
			assert: func(t *testing.T, a *webauthntest.Authenticator, p passkey.ParsedRegistration, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Equal(t, b64(challenge), p.Challenge())
				assert.Equal(t, a.CredentialID(), p.CredentialID())
				assert.Equal(t, a.CredentialID(), nc.CredentialID)
				assert.NotEmpty(t, nc.PublicKey)
				assert.Equal(t, uint32(0), nc.SignCount)
				assert.True(t, nc.UserVerified)
				assert.True(t, nc.BackupEligible)
				assert.True(t, nc.BackupState)
				assert.Equal(t, []string{"internal", "hybrid"}, nc.Transports)
				assert.Equal(t, a.AAGUID[:], nc.AAGUID)
				assert.Empty(t, nc.AttestationFormat, "the default mode records no format")
				assert.Empty(t, nc.AttestationStatement)
				assert.False(t, nc.AttestationTrusted)
			},
		},
		{
			name:   "a subdomain origin in the configured set is accepted",
			origin: "https://login.example.com",
			exp:    required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.NotNil(t, nc)
			},
		},
		{
			name:   "a wrong origin is refused as authentication failed",
			origin: "https://evil.example",
			exp:    required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, nc *passkey.NewCredential, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, nc)
				assert.NotContains(t, err.Error(), "evil")
			},
		},
		{
			name:      "a challenge other than the expected one is refused",
			presented: "passkey-registration.another-token",
			exp:       required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, nc *passkey.NewCredential, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, nc)
				assert.NotContains(t, err.Error(), "another-token")
				assert.NotContains(t, err.Error(), b64("passkey-registration.another-token"))
			},
		},
		{
			name:      "no user verification under required is refused",
			configure: func(a *webauthntest.Authenticator) { a.UV = false },
			exp:       required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, nc *passkey.NewCredential, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, nc)
			},
		},
		{
			name:      "no user verification under preferred is accepted and reported",
			configure: func(a *webauthntest.Authenticator) { a.UV = false },
			exp:       passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVPreferred},
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.False(t, nc.UserVerified)
			},
		},
		{
			name:      "an unknown user-verification value is treated as required",
			configure: func(a *webauthntest.Authenticator) { a.UV = false },
			exp:       passkey.RegistrationExpectation{Challenge: challenge},
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, _ *passkey.NewCredential, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
		},
		{
			name: "an empty expected challenge is refused",
			exp:  passkey.RegistrationExpectation{UV: passkey.UVRequired},
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedRegistration, _ *passkey.NewCredential, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
		},
		{
			name: "the response's proposed name is read",
			exp:  required,
			body: func(body []byte) []byte { return withMember(t, body, "name", "Work laptop") },
			assert: func(t *testing.T, _ *webauthntest.Authenticator, p passkey.ParsedRegistration, _ *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Equal(t, "Work laptop", p.Name())
			},
		},
		{
			name: "a name that is not a string is ignored, not refused",
			exp:  required,
			body: func(body []byte) []byte { return withMember(t, body, "name", 42) },
			assert: func(t *testing.T, _ *webauthntest.Authenticator, p passkey.ParsedRegistration, _ *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Empty(t, p.Name())
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
			origin := tc.origin
			if origin == "" {
				origin = rpOrigin
			}
			presented := tc.presented
			if presented == "" {
				presented = challenge
			}
			body := a.Create(rpID, origin, presented, []byte("handle-0123456789"), webauthntest.AttestationNone)
			if tc.body != nil {
				body = tc.body(body)
			}

			v := newVerifier(t)
			p, err := v.ParseRegistration(body)
			require.NoError(t, err)
			nc, err := v.VerifyRegistration(t.Context(), p, tc.exp)
			tc.assert(t, a, p, nc, err)
		})
	}
}

// withMember adds a top-level member to a JSON object.
func withMember(t *testing.T, body []byte, key string, value any) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	m[key] = value
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

func TestVerifier_Assertion(t *testing.T) {
	t.Parallel()

	const loginChallenge = "passkey-login.bG9naW4tdG9rZW4"

	type testCase struct {
		name      string
		configure func(a *webauthntest.Authenticator)
		origin    string
		stored    func(c *passkey.Credential) // alters the stored credential
		exp       passkey.AssertionExpectation
		assert    func(t *testing.T, a *webauthntest.Authenticator, p passkey.ParsedAssertion, r *passkey.AssertionResult, err error)
	}

	required := passkey.AssertionExpectation{Challenge: loginChallenge, UV: passkey.UVRequired}

	cases := []testCase{
		{
			name:      "a valid assertion gives the counter and flags",
			configure: func(a *webauthntest.Authenticator) { a.Counter = 41; a.BE, a.BS = true, true },
			exp:       required,
			assert: func(t *testing.T, a *webauthntest.Authenticator, p passkey.ParsedAssertion, r *passkey.AssertionResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, b64(loginChallenge), p.Challenge())
				assert.Equal(t, a.CredentialID(), p.CredentialID())
				assert.Equal(t, []byte("handle-0123456789"), p.UserHandle())
				assert.Equal(t, uint32(42), r.SignCount)
				assert.True(t, r.UserVerified)
				assert.True(t, r.BackupEligible)
				assert.True(t, r.BackupState)
			},
		},
		{
			name:      "no user verification under required is refused",
			configure: func(a *webauthntest.Authenticator) { a.UV = false },
			exp:       required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedAssertion, r *passkey.AssertionResult, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, r)
			},
		},
		{
			name:      "no user verification under preferred is accepted and reported",
			configure: func(a *webauthntest.Authenticator) { a.UV = false },
			exp:       passkey.AssertionExpectation{Challenge: loginChallenge, UV: passkey.UVPreferred},
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedAssertion, r *passkey.AssertionResult, err error) {
				require.NoError(t, err)
				assert.False(t, r.UserVerified)
			},
		},
		{
			name:   "a wrong origin is refused",
			origin: "https://evil.example",
			exp:    required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedAssertion, _ *passkey.AssertionResult, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
		},
		{
			name: "a challenge other than the expected one is refused",
			exp:  passkey.AssertionExpectation{Challenge: "passkey-login.other", UV: passkey.UVRequired},
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedAssertion, _ *passkey.AssertionResult, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.NotContains(t, err.Error(), loginChallenge)
			},
		},
		{
			name:   "a signature that does not verify under the stored key is refused",
			stored: func(c *passkey.Credential) { c.PublicKey = register(t, newVerifier(t), webauthntest.New(t)).PublicKey },
			exp:    required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedAssertion, _ *passkey.AssertionResult, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
		},
		{
			name:   "an assertion for a different credential than the stored one is refused",
			stored: func(c *passkey.Credential) { c.CredentialID = []byte("some-other-credential") },
			exp:    required,
			assert: func(t *testing.T, _ *webauthntest.Authenticator, _ passkey.ParsedAssertion, _ *passkey.AssertionResult, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := newVerifier(t)
			a := webauthntest.New(t)
			stored := register(t, v, a)
			if tc.configure != nil {
				tc.configure(a)
			}
			if tc.stored != nil {
				tc.stored(stored)
			}
			origin := tc.origin
			if origin == "" {
				origin = rpOrigin
			}

			p, err := v.ParseAssertion(a.Assert(rpID, origin, loginChallenge))
			require.NoError(t, err)
			r, err := v.VerifyAssertion(t.Context(), p, stored, tc.exp)
			tc.assert(t, a, p, r, err)
		})
	}
}

func TestVerifier_RefusesForeignParsedValues(t *testing.T) {
	t.Parallel()

	v := newVerifier(t)

	type testCase struct {
		name   string
		call   func() error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "registration",
			call: func() error {
				_, err := v.VerifyRegistration(t.Context(), foreignRegistration{}, passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired})
				return err
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed) },
		},
		{
			name: "assertion",
			call: func() error {
				_, err := v.VerifyAssertion(t.Context(), foreignAssertion{}, &passkey.Credential{}, passkey.AssertionExpectation{Challenge: challenge, UV: passkey.UVRequired})
				return err
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.call())
		})
	}
}

type foreignRegistration struct{}

func (foreignRegistration) Challenge() string    { return b64(challenge) }
func (foreignRegistration) CredentialID() []byte { return []byte("x") }
func (foreignRegistration) Name() string         { return "" }

type foreignAssertion struct{}

func (foreignAssertion) Challenge() string    { return b64(challenge) }
func (foreignAssertion) CredentialID() []byte { return []byte("x") }
func (foreignAssertion) UserHandle() []byte   { return nil }
