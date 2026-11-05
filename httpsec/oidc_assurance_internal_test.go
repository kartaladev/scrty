package httpsec

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/session"
)

func TestDefaultOIDCSignInAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   factor.Kind
		mfa    session.MFAState
		amr    []string // the upstream's, for a federated first factor
		acr    string
		assert func(t *testing.T, amr []string, acr string)
	}

	cases := []testCase{
		{
			name: "a password alone is pwd",
			kind: factor.Password,
			assert: func(t *testing.T, amr []string, acr string) {
				assert.Equal(t, []string{"pwd"}, amr)
				assert.Empty(t, acr)
			},
		},
		{
			name: "basic credentials alone are pwd",
			kind: factor.Basic,
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Equal(t, []string{"pwd"}, amr)
			},
		},
		{
			name: "a password and a second factor are pwd and mfa",
			kind: factor.Password,
			mfa:  session.MFASatisfied,
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Equal(t, []string{"pwd", "mfa"}, amr)
			},
		},
		{
			name: "a passkey alone asserts no method",
			kind: factor.Passkey,
			assert: func(t *testing.T, amr []string, acr string) {
				assert.Empty(t, amr)
				assert.Empty(t, acr)
			},
		},
		{
			name: "a passkey that met the second factor is mfa alone",
			kind: factor.Passkey,
			mfa:  session.MFASatisfied,
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Equal(t, []string{"mfa"}, amr)
			},
		},
		{
			name: "a magic link alone asserts no method",
			kind: factor.MagicLink,
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Empty(t, amr)
			},
		},
		{
			name: "a recovery sign-in asserts no method",
			kind: factor.Recovery,
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Empty(t, amr)
			},
		},
		{
			name: "a consumer's own kind asserts no method",
			kind: factor.Kind("sso-badge"),
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Empty(t, amr)
			},
		},
		{
			name: "an unset kind asserts no method",
			assert: func(t *testing.T, amr []string, acr string) {
				assert.Empty(t, amr)
				assert.Empty(t, acr)
			},
		},
		{
			name: "a federated sign-in states the upstream's amr and acr",
			kind: factor.OIDC,
			amr:  []string{"pwd", "otp"},
			acr:  "urn:example:high",
			assert: func(t *testing.T, amr []string, acr string) {
				assert.Equal(t, []string{"pwd", "otp"}, amr)
				assert.Equal(t, "urn:example:high", acr)
			},
		},
		{
			name: "a federated sign-in with a local second factor adds mfa",
			kind: factor.OIDC,
			mfa:  session.MFASatisfied,
			amr:  []string{"pwd"},
			acr:  "urn:example:high",
			assert: func(t *testing.T, amr []string, acr string) {
				assert.Equal(t, []string{"pwd", "mfa"}, amr)
				assert.Equal(t, "urn:example:high", acr)
			},
		},
		{
			name: "mfa is not repeated when the upstream already said it",
			kind: factor.OIDC,
			mfa:  session.MFASatisfied,
			amr:  []string{"pwd", "mfa"},
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Equal(t, []string{"pwd", "mfa"}, amr)
			},
		},
		{
			name: "a federated sign-in with no upstream amr and a local second factor is mfa",
			kind: factor.OIDC,
			mfa:  session.MFASatisfied,
			assert: func(t *testing.T, amr []string, _ string) {
				assert.Equal(t, []string{"mfa"}, amr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &session.Session{FirstFactor: tc.kind, MFA: tc.mfa}
			if tc.kind == factor.OIDC {
				s.ExternalProvider = "corp"
				s.ExternalIssuer = "https://corp.example.com"
				s.FederatedAMR = tc.amr
				s.FederatedACR = tc.acr
			}

			amr, acr := defaultOIDCSignInAssurance(s)
			tc.assert(t, amr, acr)
		})
	}
}
