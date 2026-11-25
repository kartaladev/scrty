package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
)

// asMethod is a second-factor method every user is enrolled on.
type asMethod struct{}

func (asMethod) Name() string                                            { return "totp" }
func (asMethod) Channel() factor.Channel                                 { return factor.AuthenticatorApp }
func (asMethod) Enrolled(context.Context, identity.UserID) (bool, error) { return true, nil }

// asSource is an assurance source meeting only evidence asserting amr "mfa", or nothing when tight.
type asSource struct{ tight bool }

func (s asSource) MeetsAssurance(_ context.Context, _ identity.UserID, ev policy.FederatedAssurance) (bool, error) {
	if s.tight {
		return false, nil
	}

	for _, m := range ev.AMR() {
		if m == "mfa" {
			return true, nil
		}
	}

	return false, nil
}

// undeclared is a policy that hides its challenge declaration, so a chain without EnableMFA can run
// the MFA requirement policy: an access-token caller is never challenged.
type undeclared struct{ policy.Policy }

// requireMFAForAll is a chain option running the MFA requirement policy, required of every user.
func requireMFAForAll(t *testing.T, opts ...policy.MFARequirementOption) httpsec.Option {
	t.Helper()

	p, err := policy.NewMFARequirement(nil, []policy.MFAMethodLookup{asMethod{}},
		append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)...)
	require.NoError(t, err)

	engine, err := policy.NewEngine(undeclared{p})
	require.NoError(t, err)

	return httpsec.WithPolicyEngine(engine)
}

// TestResourceServer_ProviderTokenAssurance pins how a provider token meets an MFA requirement: by
// the grant's library marker, or its federated evidence re-matched now; never by amr.
func TestResourceServer_ProviderTokenAssurance(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		mfa    []policy.MFARequirementOption
		signIn func(*oidcprovider.SignIn)
		assert func(t *testing.T, out psCall, failure error)
	}

	federated := func(s *oidcprovider.SignIn) {
		s.AMR = []string{"mfa"}
		s.ExternalProvider, s.ExternalIssuer, s.ExternalAMR = "corp", "https://idp.example", []string{"mfa"}
	}

	allowed := func(t *testing.T, out psCall, _ error) {
		t.Helper()
		require.Equal(t, http.StatusOK, out.status, out.body)
		assert.True(t, out.passedOn)
	}

	insufficient := func(t *testing.T, out psCall, failure error) {
		t.Helper()
		assert.Equal(t, http.StatusUnauthorized, out.status)
		assert.False(t, out.passedOn)
		assert.Equal(t, []string{`DPoP error="insufficient_user_authentication", algs="ES256"`},
			out.header.Values("WWW-Authenticate"))
		require.ErrorIs(t, failure, httpsec.ErrInsufficientUserAuthentication)
		require.ErrorIs(t, failure, httpsec.ErrReauthenticationRequired)
		assert.NotErrorIs(t, failure, httpsec.ErrInvalidToken)
	}

	cases := []testCase{
		{
			name:   "a password-only grant claiming amr mfa has no library marker and is refused",
			signIn: func(s *oidcprovider.SignIn) { s.AMR = []string{"mfa"} },
			assert: insufficient,
		},
		{
			name:   "a grant with the library's second-factor marker is allowed",
			signIn: func(s *oidcprovider.SignIn) { s.SecondFactorVerified = true },
			assert: allowed,
		},
		{
			name:   "a federated grant whose evidence the assurance source meets is allowed",
			mfa:    []policy.MFARequirementOption{policy.WithFederatedAssuranceSource(asSource{})},
			signIn: federated,
			assert: allowed,
		},
		{
			name:   "a federated grant is refused once the assurance source is tightened",
			mfa:    []policy.MFARequirementOption{policy.WithFederatedAssuranceSource(asSource{tight: true})},
			signIn: federated,
			assert: insufficient,
		},
		{
			name: "a federated grant is allowed in exempt mode",
			mfa: []policy.MFARequirementOption{
				policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt),
			},
			signIn: federated,
			assert: allowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			failure := &atomic.Pointer[error]{}
			w := newPSWorld(t, psSetup{failure: failure, chain: []httpsec.Option{requireMFAForAll(t, tc.mfa...)}})
			w.signIn = tc.signIn

			out := w.call(t, w.token(t, psJWTClient, &k, forAPI), &k, "j-1")

			var err error
			if f := failure.Load(); f != nil {
				err = *f
			}

			tc.assert(t, out, err)
		})
	}
}
