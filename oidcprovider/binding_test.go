package oidcprovider_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

const (
	boundKey  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	boundCert = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg4"
	// otherCert is a second certificate's thumbprint.
	otherCert = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// pastWindows is longer than a refresh token's default grace, and so its same-successor window.
	// Only from here does a later success prove a token unrotated.
	pastWindows = 31 * time.Second
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
			name:     "a certificate required, a proof beside one",
			required: oidcprovider.BindingMTLS,
			binding:  oidcprovider.Binding{JKT: boundKey, X5T: boundCert},
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
			name:     "a certificate required, a proof beside one",
			required: oidcprovider.BindingMTLS,
			binding:  oidcprovider.Binding{JKT: boundKey, X5T: boundCert},
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

	t.Run("a grant the client is not registered for is refused as that, whatever it lacks", func(t *testing.T) {
		t.Parallel()

		f := newRefreshFixture(t)
		billingClient(t, f, func(c *oidcprovider.Client) {
			c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode}
			c.RequireBinding = oidcprovider.BindingDPoP
		})

		_, err := f.p.Token(t.Context(), byBilling("rt.none"))

		assertRefused(t, err, oidcprovider.CodeUnauthorizedClient)
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

// startPublic is a public client's grant from an exchange proving binding. Its refreshes prove
// nothing until a row says so.
func startPublic(binding oidcprovider.Binding) func(*testing.T, *refreshFixture) *refreshScene {
	return func(t *testing.T, f *refreshFixture) *refreshScene {
		t.Helper()

		c := issueCodeFor(t, f.parkFixture, nativeClient, func(v url.Values) {
			asClient(v, nativeClient, nativeRedirect)
			v.Set("scope", "openid offline_access")
		}, testSignIn(f.parkFixture, "u-1"), "openid", "offline_access")
		first := oidcprovider.TokenRequest{
			Form:    exchangeForm(c, nativeRedirect, func(v url.Values) { v.Set("client_id", nativeClient) }),
			Binding: binding,
		}
		again := func(raw string) oidcprovider.TokenRequest {
			return oidcprovider.TokenRequest{
				Form: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {nativeClient}},
			}
		}

		return sceneOf(t, f, c, first, again)
	}
}

// TestProvider_PublicRefresh_Binding pins what a public client's refresh must prove, which is what its
// exchange proved and nothing else: a refresh token handed out beside a proof must be bound to its key
// (RFC 9449 section 5), and one issued to a certificate stays with it (RFC 8705 section 4). A refused
// request is left to be sent again properly, past the windows that would answer a rotated token too.
func TestProvider_PublicRefresh_Binding(t *testing.T) {
	t.Parallel()

	var (
		byKey  = oidcprovider.Binding{JKT: boundKey}
		byCert = oidcprovider.Binding{X5T: boundCert}
	)

	type testCase struct {
		name     string
		exchange oidcprovider.Binding
		// stale presents a token retry has rotated away from, past its grace.
		stale   bool
		refresh oidcprovider.Binding
		code    string
		// retry is what proves the token left usable, and what the row's success sends.
		retry  oidcprovider.Binding
		assert func(t *testing.T, res *oidcprovider.TokenResponse)
	}

	bearer := func(t *testing.T, res *oidcprovider.TokenResponse) {
		t.Helper()
		assert.Equal(t, "Bearer", res.TokenType)
		_, claims := decodeJWT(t, res.AccessToken)
		assert.NotContains(t, claims, "cnf")
	}
	certBound := func(t *testing.T, res *oidcprovider.TokenResponse) {
		t.Helper()
		assert.Equal(t, "Bearer", res.TokenType)
		_, claims := decodeJWT(t, res.AccessToken)
		assert.Equal(t, map[string]any{"x5t#S256": boundCert}, claims["cnf"])
	}
	keyBound := func(t *testing.T, res *oidcprovider.TokenResponse) {
		t.Helper()
		assert.Equal(t, "DPoP", res.TokenType)
		assert.Equal(t, boundKey, jktOf(t, res.AccessToken))
	}

	cases := []testCase{
		{
			name:    "an unbound grant is refused a proof, and its token stays usable",
			refresh: byKey,
			code:    oidcprovider.CodeInvalidDPoPProof,
			assert:  bearer,
		},
		{
			name:    "an unbound grant is refused a proof beside a certificate",
			refresh: oidcprovider.Binding{JKT: boundKey, X5T: boundCert},
			code:    oidcprovider.CodeInvalidDPoPProof,
			assert:  bearer,
		},
		{
			name:    "an unbound grant's stale token and a proof are refused as the proof, and revoke nothing",
			stale:   true,
			refresh: byKey,
			code:    oidcprovider.CodeInvalidDPoPProof,
		},
		{
			name:     "a certificate-bound grant is refused no certificate",
			exchange: byCert,
			code:     oidcprovider.CodeInvalidRequest,
			retry:    byCert,
			assert:   certBound,
		},
		{
			name:     "a certificate-bound grant is refused another certificate",
			exchange: byCert,
			refresh:  oidcprovider.Binding{X5T: otherCert},
			code:     oidcprovider.CodeInvalidRequest,
			retry:    byCert,
			assert:   certBound,
		},
		{
			name:     "a certificate-bound grant is refused a proof in its place",
			exchange: byCert,
			refresh:  byKey,
			code:     oidcprovider.CodeInvalidRequest,
			retry:    byCert,
			assert:   certBound,
		},
		{
			name:     "a certificate-bound grant is refused a proof beside its certificate",
			exchange: byCert,
			refresh:  oidcprovider.Binding{JKT: boundKey, X5T: boundCert},
			code:     oidcprovider.CodeInvalidRequest,
			retry:    byCert,
			assert:   certBound,
		},
		{
			name:     "a certificate-bound grant's stale token with no certificate revokes nothing",
			exchange: byCert,
			stale:    true,
			code:     oidcprovider.CodeInvalidRequest,
			retry:    byCert,
		},
		{
			name:     "a proof beside a certificate binds to the key alone, so the certificate does not stand in for it",
			exchange: oidcprovider.Binding{JKT: boundKey, X5T: boundCert},
			refresh:  byCert,
			code:     oidcprovider.CodeInvalidDPoPProof,
			retry:    byKey,
			assert:   keyBound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			s := startPublic(tc.exchange)(t, f)

			raw := s.first.RefreshToken
			if tc.stale {
				req := s.again(raw)
				req.Binding = tc.retry
				_, err := f.p.Token(t.Context(), req)
				require.NoError(t, err)
				f.clk.Advance(pastWindows)
			}

			req := s.again(raw)
			req.Binding = tc.refresh
			res, err := f.p.Token(t.Context(), req)
			assertRefused(t, err, tc.code)
			assert.Nil(t, res)

			if tc.stale {
				assert.False(t, grantNow(t, f, s).Revoked, "a stolen token without what binds it ends nothing")

				return
			}

			assertUntouched(t, f, s)
			f.clk.Advance(pastWindows)

			req = s.again(raw)
			req.Binding = tc.retry
			again, err := f.p.Token(t.Context(), req)
			require.NoError(t, err, "the token was left usable")
			assert.NotEqual(t, raw, again.RefreshToken, "and this is its first rotation")
			tc.assert(t, again)
		})
	}
}

// TestProvider_PublicGrant_Binding pins what an exchange writes of a request's binding, on the grant and
// on the lineage, which a token's successors take theirs from.
func TestProvider_PublicGrant_Binding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		start   func(*testing.T, *refreshFixture) *refreshScene
		key     string
		cert    string
		lineage session.KeyBinding
	}

	byBillingWith := func(binding oidcprovider.Binding) func(*testing.T, *refreshFixture) *refreshScene {
		return func(t *testing.T, f *refreshFixture) *refreshScene {
			t.Helper()

			c := f.issueOffline(t)
			req := billingExchange(c, nil)
			req.Binding = binding

			return sceneOf(t, f, c, req, byBilling)
		}
	}

	cases := []testCase{
		{
			name:    "a certificate alone binds to the certificate",
			start:   startPublic(oidcprovider.Binding{X5T: boundCert}),
			cert:    boundCert,
			lineage: session.KeyBinding{X5TS256: boundCert},
		},
		{
			name:    "a proof beside a certificate binds to the key alone",
			start:   startPublic(oidcprovider.Binding{JKT: boundKey, X5T: boundCert}),
			key:     boundKey,
			lineage: session.KeyBinding{JKT: boundKey},
		},
		{
			name:  "nothing proved binds nothing",
			start: startPublic(oidcprovider.Binding{}),
		},
		{
			name:  "a confidential client's certificate is no part of its grant",
			start: byBillingWith(oidcprovider.Binding{X5T: boundCert}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			s := tc.start(t, f)

			assert.Equal(t, tc.key, s.grant.KeyBinding)
			assert.Equal(t, tc.cert, s.grant.CertBinding)
			assert.Equal(t, tc.lineage, s.head(t, f, s.first.RefreshToken).KeyBinding)
		})
	}
}

// TestProvider_PublicRefresh_Certificate pins the rest of what a certificate does at a public client's
// refresh, whichever way its grant went: its successor stays bound to it, and a grant unbound at its
// exchange takes the certificate into the access token alone.
func TestProvider_PublicRefresh_Certificate(t *testing.T) {
	t.Parallel()

	byCert := oidcprovider.Binding{X5T: boundCert}

	withCert := func(s *refreshScene, raw string) oidcprovider.TokenRequest {
		req := s.again(raw)
		req.Binding = byCert

		return req
	}

	type testCase struct {
		name   string
		start  oidcprovider.Binding
		assert func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse)
	}

	cases := []testCase{
		{
			name:  "a token rotated with its certificate needs it too",
			start: byCert,
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse) {
				t.Helper()

				assert.Equal(t, session.KeyBinding{X5TS256: boundCert}, s.head(t, f, res.RefreshToken).KeyBinding)

				_, err := f.p.Token(t.Context(), s.again(res.RefreshToken))
				assertRefused(t, err, oidcprovider.CodeInvalidRequest)
			},
		},
		{
			name: "a grant unbound at its exchange binds the access token, and stays unbound",
			assert: func(t *testing.T, f *refreshFixture, s *refreshScene, res *oidcprovider.TokenResponse) {
				t.Helper()

				_, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, map[string]any{"x5t#S256": boundCert}, claims["cnf"])
				assert.Empty(t, grantNow(t, f, s).CertBinding)

				_, err := f.p.Token(t.Context(), s.again(res.RefreshToken))
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRefreshFixture(t)
			s := startPublic(tc.start)(t, f)

			res, err := f.p.Token(t.Context(), withCert(s, s.first.RefreshToken))
			require.NoError(t, err)

			tc.assert(t, f, s, res)
		})
	}
}
