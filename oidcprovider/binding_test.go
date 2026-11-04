package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

const (
	boundKey  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	boundCert = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg4"
)

// requireBinding registers billing-web as requiring what it is given.
func requireBinding(t *testing.T, f *refreshFixture, required oidcprovider.BindingRequirement) {
	t.Helper()

	billingClient(t, f, func(c *oidcprovider.Client) { c.RequireBinding = required })
}

// TestProvider_RequireBinding_Code pins a client's required binding at a code's exchange: a request
// without it is refused before the code is touched, whichever code it answers with, and the code still
// exchanges once the request carries the binding.
func TestProvider_RequireBinding_Code(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		required oidcprovider.BindingRequirement
		binding  oidcprovider.Binding
		// retry is what proves the code unspent, when a row is refused.
		retry  oidcprovider.Binding
		assert func(t *testing.T, res *oidcprovider.TokenResponse, err error)
	}

	refused := func(code string) func(*testing.T, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, res *oidcprovider.TokenResponse, err error) {
			t.Helper()
			assertRefused(t, err, code)
			assert.Nil(t, res)
		}
	}
	answered := func(tokenType string) func(*testing.T, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, res *oidcprovider.TokenResponse, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, tokenType, res.TokenType)
		}
	}

	proved := oidcprovider.Binding{JKT: boundKey}
	presented := oidcprovider.Binding{X5T: boundCert}

	cases := []testCase{
		{
			name:     "DPoP required, no proof",
			required: oidcprovider.BindingDPoP,
			retry:    proved,
			assert:   refused(oidcprovider.CodeInvalidDPoPProof),
		},
		{
			name:     "DPoP required, a certificate only",
			required: oidcprovider.BindingDPoP,
			binding:  presented,
			retry:    proved,
			assert:   refused(oidcprovider.CodeInvalidDPoPProof),
		},
		{
			name:     "DPoP required, a proof",
			required: oidcprovider.BindingDPoP,
			binding:  proved,
			assert:   answered("DPoP"),
		},
		{
			name:     "a certificate required, none presented",
			required: oidcprovider.BindingMTLS,
			retry:    presented,
			assert:   refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name:     "a certificate required, a proof only",
			required: oidcprovider.BindingMTLS,
			binding:  proved,
			retry:    presented,
			assert:   refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name:     "a certificate required, one presented",
			required: oidcprovider.BindingMTLS,
			binding:  presented,
			assert:   answered("Bearer"),
		},
		{
			name:   "nothing required, nothing bound",
			assert: answered("Bearer"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			requireBinding(t, f, tc.required)
			c := f.issueOffline(t)

			req := billingExchange(c, nil)
			req.Binding = tc.binding
			res, err := f.p.Token(t.Context(), req)
			tc.assert(t, res, err)

			if err == nil {
				return
			}

			assertUnspent(t, f.exchangeFixture, c)

			req = billingExchange(c, nil)
			req.Binding = tc.retry
			_, err = f.p.Token(t.Context(), req)
			require.NoError(t, err, "the code was left to exchange once the request carries the binding")
		})
	}
}

// TestProvider_RequireBinding_Refresh pins the same at a refresh, for a confidential client whose
// grant holds no key of its own, so nothing but the requirement can refuse it.
func TestProvider_RequireBinding_Refresh(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		required oidcprovider.BindingRequirement
		binding  oidcprovider.Binding
		retry    oidcprovider.Binding
		assert   func(t *testing.T, f *refreshFixture, res *oidcprovider.TokenResponse, err error)
	}

	refused := func(code string) func(*testing.T, *refreshFixture, *oidcprovider.TokenResponse, error) {
		return func(t *testing.T, f *refreshFixture, res *oidcprovider.TokenResponse, err error) {
			t.Helper()
			assertRefused(t, err, code)
			assert.Nil(t, res)
			assert.Zero(t, f.lineage.supersedes.Load(), "nothing is rotated")
		}
	}
	rotated := func(t *testing.T, f *refreshFixture, res *oidcprovider.TokenResponse, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotEmpty(t, res.AccessToken)
		assert.EqualValues(t, 1, f.lineage.supersedes.Load())
	}

	proved := oidcprovider.Binding{JKT: boundKey}
	presented := oidcprovider.Binding{X5T: boundCert}

	cases := []testCase{
		{
			name:     "DPoP required, no proof",
			required: oidcprovider.BindingDPoP,
			retry:    proved,
			assert:   refused(oidcprovider.CodeInvalidDPoPProof),
		},
		{
			name:     "DPoP required, a proof",
			required: oidcprovider.BindingDPoP,
			binding:  proved,
			assert:   rotated,
		},
		{
			name:     "a certificate required, none presented",
			required: oidcprovider.BindingMTLS,
			retry:    presented,
			assert:   refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name:     "a certificate required, one presented",
			required: oidcprovider.BindingMTLS,
			binding:  presented,
			assert:   rotated,
		},
		{
			name:   "nothing required, no proof",
			assert: rotated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			s := startBilling(t, f)
			requireBinding(t, f, tc.required)

			req := s.again(s.first.RefreshToken)
			req.Binding = tc.binding
			res, err := f.p.Token(t.Context(), req)
			tc.assert(t, f, res, err)

			if err == nil {
				return
			}

			req = s.again(s.first.RefreshToken)
			req.Binding = tc.retry
			again, err := f.p.Token(t.Context(), req)
			require.NoError(t, err, "the token was left to refresh once the request carries the binding")
			assert.NotEqual(t, s.first.RefreshToken, again.RefreshToken)
			assert.False(t, grantNow(t, f, s).Revoked, "a refused request ends no grant")
		})
	}
}

// TestProvider_RequireBinding_Order pins where the requirement stands among a request's other checks.
func TestProvider_RequireBinding_Order(t *testing.T) {
	t.Parallel()

	t.Run("a client that fails to authenticate hears only that", func(t *testing.T) {
		t.Parallel()

		f := newRefreshFixture(t)
		requireBinding(t, f, oidcprovider.BindingDPoP)
		c := f.issueOffline(t)

		req := billingExchange(c, nil)
		req.Credentials.Authorization = basic("billing-web", "the wrong secret")
		_, err := f.p.Token(t.Context(), req)

		assertRefused(t, err, oidcprovider.CodeInvalidClient)
		assertUnspent(t, f.exchangeFixture, c)
	})

	t.Run("a replay without the binding revokes nothing", func(t *testing.T) {
		t.Parallel()

		f := newRefreshFixture(t)
		c := f.issueOffline(t)
		_, err := f.p.Token(t.Context(), billingExchange(c, nil))
		require.NoError(t, err)
		requireBinding(t, f, oidcprovider.BindingDPoP)

		_, err = f.p.Token(t.Context(), billingExchange(c, nil))

		assertRefused(t, err, oidcprovider.CodeInvalidDPoPProof)
		assert.False(t, grantOf(t, f.exchangeFixture, c).Revoked, "only a valid replay revokes")
	})
}
