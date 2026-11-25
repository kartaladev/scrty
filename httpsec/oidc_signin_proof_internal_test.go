package httpsec

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// TestGrantAMR_MFAWithoutLibraryVerifiedSecondFactor pins that the sign-in a resume records, and
// so every grant made from it, says whether the library verified a second factor and carries the
// federated evidence from the session alone. What the sign-in assurance mapping states as amr is
// kept as amr, and never read as proof.
func TestGrantAMR_MFAWithoutLibraryVerifiedSecondFactor(t *testing.T) {
	t.Parallel()

	claimsMFA := func(*session.Session) ([]string, string) { return []string{"mfa"}, "urn:consumer:gold" }
	claimsNothing := func(*session.Session) ([]string, string) { return nil, "" }

	type testCase struct {
		name    string
		session session.Session
		assure  func(*session.Session) ([]string, string)
		assert  func(t *testing.T, got oidcprovider.SignIn)
	}

	cases := []testCase{
		{
			name:    "a consumer mapping claiming mfa on a password-only session verifies nothing",
			session: session.Session{UserID: "u-1", MFA: session.MFANone},
			assure:  claimsMFA,
			assert: func(t *testing.T, got oidcprovider.SignIn) {
				assert.Equal(t, []string{"mfa"}, got.AMR, "the mapping's amr is kept as amr")
				assert.False(t, got.SecondFactorVerified, "amr saying mfa is no verified second factor")
			},
		},
		{
			name:    "a session whose second factor the library verified is marked",
			session: session.Session{UserID: "u-1", MFA: session.MFASatisfied},
			assure:  claimsNothing,
			assert: func(t *testing.T, got oidcprovider.SignIn) {
				assert.True(t, got.SecondFactorVerified)
			},
		},
		{
			name:    "a pending second factor is not verified",
			session: session.Session{UserID: "u-1", MFA: session.MFAPending},
			assure:  claimsMFA,
			assert: func(t *testing.T, got oidcprovider.SignIn) {
				assert.False(t, got.SecondFactorVerified)
			},
		},
		{
			name: "a federated sign-in carries the session's federated evidence, not the mapping's",
			session: session.Session{
				UserID: "u-1", ExternalProvider: "corp", ExternalIssuer: "https://corp.example",
				ExternalSessionID: "up-1", FederatedAMR: []string{"mfa"}, FederatedACR: "urn:corp:silver",
			},
			assure: claimsNothing,
			assert: func(t *testing.T, got oidcprovider.SignIn) {
				assert.Equal(t, "corp", got.ExternalProvider)
				assert.Equal(t, "https://corp.example", got.ExternalIssuer)
				assert.Equal(t, []string{"mfa"}, got.ExternalAMR)
				assert.Equal(t, "urn:corp:silver", got.ExternalACR)
				assert.False(t, got.SecondFactorVerified, "an upstream amr is no second factor the library verified")
			},
		},
		{
			name:    "a local sign-in carries no federated evidence whatever the mapping claims",
			session: session.Session{UserID: "u-1"},
			assure:  claimsMFA,
			assert: func(t *testing.T, got oidcprovider.SignIn) {
				assert.Empty(t, got.ExternalProvider)
				assert.Empty(t, got.ExternalAMR)
				assert.Empty(t, got.ExternalACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := tc.session
			got := oidcSignInOf(&s, tc.assure)
			tc.assert(t, got)
		})
	}
}

// TestOIDCSignInOf_SharesNothingWithTheSession pins that the federated amr is copied, so a later
// change to the session cannot reach a grant.
func TestOIDCSignInOf_SharesNothingWithTheSession(t *testing.T) {
	t.Parallel()

	s := &session.Session{UserID: "u-1", ExternalProvider: "corp", FederatedAMR: []string{"mfa"}}
	got := oidcSignInOf(s, func(*session.Session) ([]string, string) { return nil, "" })
	s.FederatedAMR[0] = "pwd"

	assert.Equal(t, []string{"mfa"}, got.ExternalAMR)
}
