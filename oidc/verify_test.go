package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

func TestVerifyIDToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	const nonce = "flow-nonce"

	// valid returns the claims of a token corp would accept at now.
	valid := func(p *testProvider, name string) map[string]any {
		return map[string]any{
			"iss":   p.Issuer(),
			"aud":   "client-" + name,
			"sub":   "subject-1",
			"exp":   now.Add(5 * time.Minute).Unix(),
			"iat":   now.Unix(),
			"nonce": nonce,
		}
	}
	with := func(claims map[string]any, kv ...any) map[string]any {
		for i := 0; i < len(kv); i += 2 {
			k := kv[i].(string)
			if kv[i+1] == nil {
				delete(claims, k)
				continue
			}
			claims[k] = kv[i+1]
		}
		return claims
	}

	type testCase struct {
		name     string
		provider string
		nonce    string
		opts     []oidc.ManagerOption
		setup    func(p *testProvider)
		before   func(t *testing.T, m *oidc.Manager, p *testProvider)
		token    func(t *testing.T, p *testProvider) string
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, p *testProvider, got oidc.IDClaimsView, err error)
	}

	invalid := func(t *testing.T, _ *testProvider, got oidc.IDClaimsView, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
		assert.NotErrorIs(t, err, oidc.ErrDiscoveryFailed)
		assert.Equal(t, oidc.IDClaimsView{}, got)
	}
	// refusedWithout is invalid, and also requires the cause not to repeat
	// value: a refusal names the failed rule, never a claim value.
	refusedWithout := func(value string) func(*testing.T, *testProvider, oidc.IDClaimsView, error) {
		return func(t *testing.T, p *testProvider, got oidc.IDClaimsView, err error) {
			t.Helper()
			invalid(t, p, got, err)
			assert.NotContains(t, err.Error(), value)
		}
	}
	// refusedFor is invalid, and also requires the cause to name rule.
	refusedFor := func(rule string) func(*testing.T, *testProvider, oidc.IDClaimsView, error) {
		return func(t *testing.T, p *testProvider, got oidc.IDClaimsView, err error) {
			t.Helper()
			invalid(t, p, got, err)
			assert.Contains(t, err.Error(), rule)
		}
	}
	signed := func(edit func(p *testProvider, c map[string]any) map[string]any, opts ...signOption) func(*testing.T, *testProvider) string {
		return func(t *testing.T, p *testProvider) string {
			c := valid(p, "corp")
			if edit != nil {
				c = edit(p, c)
			}
			return p.Sign(t, c, opts...)
		}
	}

	// withClaims signs a valid corp token with the given claims added.
	withClaims := func(kv ...any) func(*testing.T, *testProvider) string {
		return signed(func(_ *testProvider, c map[string]any) map[string]any { return with(c, kv...) })
	}
	// asserts requires a valid token whose assurance reads as given.
	asserts := func(amr []string, acr string, badAMR, badACR bool) func(*testing.T, *testProvider, oidc.IDClaimsView, error) {
		return func(t *testing.T, _ *testProvider, got oidc.IDClaimsView, err error) {
			t.Helper()
			require.NoError(t, err, "a malformed assurance claim never invalidates the token")
			assert.Equal(t, amr, got.AMR, "amr")
			assert.Equal(t, acr, got.ACR, "acr")
			assert.Equal(t, badAMR, got.MalformedAMR, "amr malformed")
			assert.Equal(t, badACR, got.MalformedACR, "acr malformed")
		}
	}

	cases := []testCase{
		{
			name: "a valid token",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "sid", "provider-session", "email", "alice@corp.example",
					"email_verified", true, "groups", []any{"a", "b"})
			}),
			assert: func(t *testing.T, _ *testProvider, got oidc.IDClaimsView, err error) {
				require.NoError(t, err)
				assert.Equal(t, "subject-1", got.Subject)
				assert.Equal(t, "provider-session", got.SessionID)
				assert.Equal(t, "alice@corp.example", got.Email)
				assert.True(t, got.EmailVerified)
				assert.Equal(t, []any{"a", "b"}, got.Claims["groups"], "claims are returned unchanged")
				assert.Equal(t, "subject-1", got.Claims["sub"])
			},
		},
		{
			name: "an email_verified that is not a JSON true is unverified",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "email", "alice@corp.example", "email_verified", "true")
			}),
			assert: func(t *testing.T, _ *testProvider, got oidc.IDClaimsView, err error) {
				require.NoError(t, err)
				assert.False(t, got.EmailVerified)
			},
		},
		{
			name: "wrong iss",
			token: signed(func(p *testProvider, c map[string]any) map[string]any {
				return with(c, "iss", p.Issuer()+"/")
			}),
			assert: refusedFor("issuer is not the provider"),
		},
		{
			name: "wrong aud",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "aud", "other-client")
			}),
			assert: refusedFor("audience does not name the client"),
		},
		{
			name: "expired",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "exp", now.Add(-2*time.Minute).Unix(), "iat", now.Add(-10*time.Minute).Unix())
			}),
			assert: refusedFor("the token has expired"),
		},
		{
			name: "missing exp",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "exp", nil)
			}),
			assert: refusedFor("a required claim is missing"),
		},
		{
			name: "iat 5 minutes in the future",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "iat", now.Add(5*time.Minute).Unix(), "exp", now.Add(10*time.Minute).Unix())
			}),
			assert: refusedFor("the token was issued in the future"),
		},
		{
			name: "nbf in the future",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "nbf", now.Add(5*time.Minute).Unix())
			}),
			assert: refusedFor("the token is not yet valid"),
		},
		{
			name: "an iat inside the default leeway is accepted",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "iat", now.Add(50*time.Second).Unix())
			}),
			assert: func(t *testing.T, _ *testProvider, _ oidc.IDClaimsView, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "an iat past the default leeway is refused",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "iat", now.Add(70*time.Second).Unix())
			}),
			assert: refusedFor("the token was issued in the future"),
		},
		{
			name: "a consumer skew of 5 minutes accepts an iat 3 minutes ahead",
			opts: []oidc.ManagerOption{oidc.WithClockSkew(5 * time.Minute)},
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "iat", now.Add(3*time.Minute).Unix())
			}),
			assert: func(t *testing.T, _ *testProvider, _ oidc.IDClaimsView, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "bad signature",
			token: func(t *testing.T, p *testProvider) string {
				return p.Sign(t, valid(p, "corp"), withKey(newRSAKey(t, "k1")))
			},
			assert: invalid,
		},
		{
			name: "unknown kid inside the cooldown",
			before: func(t *testing.T, m *oidc.Manager, p *testProvider) {
				_, err := oidc.VerifyIDTokenForTest(t.Context(), m, "corp", p.Sign(t, valid(p, "corp")), nonce)
				require.NoError(t, err)
				_, err = oidc.VerifyIDTokenForTest(t.Context(), m, "corp", p.Sign(t, valid(p, "corp"), withKid("k8")), nonce)
				require.ErrorIs(t, err, oidc.ErrInvalidIDToken)
				require.Equal(t, int64(2), p.jwksCalls.Load(), "one fetch, one refetch for the unknown kid")
			},
			token: signed(nil, withKid("k9")),
			assert: func(t *testing.T, p *testProvider, got oidc.IDClaimsView, err error) {
				invalid(t, p, got, err)
				assert.Equal(t, int64(2), p.jwksCalls.Load(), "inside the cooldown no refetch is sent")
			},
		},
		{
			name:   "no kid on an asymmetric token",
			token:  signed(nil, withKid("")),
			assert: invalid,
		},
		{
			name:   "alg none",
			token:  signed(nil, withNoneAlg()),
			assert: invalid,
		},
		{
			name:   "HS256 signed with the client secret for a provider that never listed it",
			token:  signed(nil, withHS256Secret("secret-corp")),
			assert: invalid,
		},
		{
			name:     "HS256 listed for the provider verifies with the client secret",
			provider: "shared",
			token: func(t *testing.T, p *testProvider) string {
				return p.Sign(t, valid(p, "shared"), withHS256Secret("secret-shared"), withKid(""))
			},
			assert: func(t *testing.T, p *testProvider, got oidc.IDClaimsView, err error) {
				require.NoError(t, err)
				assert.Equal(t, "subject-1", got.Subject)
				assert.Equal(t, int64(0), p.jwksCalls.Load(), "an HS* token never consults the key set")
			},
		},
		{
			name:     "HS256 under another secret is refused",
			provider: "shared",
			token: func(t *testing.T, p *testProvider) string {
				return p.Sign(t, valid(p, "shared"), withHS256Secret("secret-other"), withKid(""))
			},
			assert: invalid,
		},
		{
			name:     "RS256 on a provider that lists only HS256",
			provider: "shared",
			token: func(t *testing.T, p *testProvider) string {
				return p.Sign(t, valid(p, "shared"))
			},
			assert: invalid,
		},
		{
			name:   "wrong nonce",
			nonce:  "another-flow-nonce",
			token:  signed(nil),
			assert: invalid,
		},
		{
			name: "missing nonce claim",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "nonce", nil)
			}),
			assert: invalid,
		},
		{
			name:  "an empty flow nonce fails closed",
			nonce: "-",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "nonce", "")
			}),
			assert: invalid,
		},
		{
			name: "missing sub",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "sub", nil)
			}),
			assert: invalid,
		},
		{
			name: "empty sub",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "sub", "")
			}),
			assert: invalid,
		},
		{
			name: "audiences client and other with no azp",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "aud", []string{"client-corp", "other"})
			}),
			assert: invalid,
		},
		{
			name: "audiences with azp naming another client",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "aud", []string{"client-corp", "other"}, "azp", "other")
			}),
			assert: invalid,
		},
		{
			name: "a single audience with azp naming another client",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "azp", "other")
			}),
			assert: invalid,
		},
		{
			name: "a single audience with a non-string azp is refused",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "azp", 12345)
			}),
			assert: invalid,
		},
		{
			name: "a malformed iat is refused without repeating its value",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "iat", "alice@corp.example")
			}),
			assert: refusedWithout("alice@corp.example"),
		},
		{
			name: "a malformed exp is refused without repeating its value",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "exp", "alice@corp.example")
			}),
			assert: refusedWithout("alice@corp.example"),
		},
		{
			name: "a malformed nbf is refused without repeating its value",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "nbf", "alice@corp.example")
			}),
			assert: refusedWithout("alice@corp.example"),
		},
		{
			name: "a wrong iss is refused without repeating it",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "iss", "https://alice@corp.example")
			}),
			assert: refusedWithout("alice@corp.example"),
		},
		{
			name: "several audiences with azp equal to the client id",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				return with(c, "aud", []string{"client-corp", "other"}, "azp", "client-corp")
			}),
			assert: func(t *testing.T, _ *testProvider, _ oidc.IDClaimsView, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:     "provider configured for ES256 only and a token signed RS256",
			provider: "ec",
			token: func(t *testing.T, p *testProvider) string {
				return p.Sign(t, valid(p, "ec"))
			},
			assert: func(t *testing.T, p *testProvider, got oidc.IDClaimsView, err error) {
				invalid(t, p, got, err)
				assert.Equal(t, int64(0), p.jwksCalls.Load(), "a refused algorithm fetches nothing")
			},
		},
		{
			name:     "an RS384 token under an RS256 key is refused",
			provider: "wide",
			token: func(t *testing.T, p *testProvider) string {
				return p.Sign(t, valid(p, "wide"), withAlg(jwa.RS384()))
			},
			assert: invalid,
		},
		{
			name: "a token that is not a compact JWS",
			token: func(*testing.T, *testProvider) string {
				return "not-a-token"
			},
			assert: invalid,
		},
		{
			name: "a JWS with an extra segment",
			token: func(t *testing.T, p *testProvider) string {
				return signed(nil)(t, p) + ".extra"
			},
			assert: invalid,
		},
		{
			name:  "a key set that cannot be fetched is a provider failure",
			setup: func(p *testProvider) { p.failJWKS.Store(true) },
			token: signed(nil),
			assert: func(t *testing.T, _ *testProvider, got oidc.IDClaimsView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.NotErrorIs(t, err, oidc.ErrInvalidIDToken)
				assert.Equal(t, oidc.IDClaimsView{}, got)
			},
		},
		{
			name:  "an empty key set is a provider failure",
			setup: func(p *testProvider) { p.jwksBody.Store(`{"keys":[]}`) },
			token: signed(nil),
			assert: func(t *testing.T, _ *testProvider, _ oidc.IDClaimsView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.NotErrorIs(t, err, oidc.ErrInvalidIDToken)
			},
		},
		{
			name:  "an HTML key set is a provider failure",
			setup: func(p *testProvider) { p.jwksBody.Store(`<html>oops</html>`) },
			token: signed(nil),
			assert: func(t *testing.T, _ *testProvider, _ oidc.IDClaimsView, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.NotErrorIs(t, err, oidc.ErrInvalidIDToken)
			},
		},
		{
			name:  "a canceled context is neither a refusal nor a verdict",
			token: signed(nil),
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			assert: func(t *testing.T, _ *testProvider, _ oidc.IDClaimsView, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidc.ErrInvalidIDToken)
			},
		},
		{
			name:   "assurance: no amr and no acr assert nothing",
			token:  signed(nil),
			assert: asserts(nil, "", false, false),
		},
		{
			name:   "assurance: an empty amr asserts nothing and is not malformed",
			token:  withClaims("amr", []any{}),
			assert: asserts(nil, "", false, false),
		},
		{
			name:   "assurance: amr is kept in order with duplicates removed",
			token:  withClaims("amr", []any{"pwd", "mfa", "mfa"}),
			assert: asserts([]string{"pwd", "mfa"}, "", false, false),
		},
		{
			name:   "assurance: amr keeps the first occurrence of each value",
			token:  withClaims("amr", []any{"mfa", "pwd", "mfa", "otp", "pwd"}),
			assert: asserts([]string{"mfa", "pwd", "otp"}, "", false, false),
		},
		{
			// A JSON null is present but is neither a list nor a string, so it
			// is malformed, not absent. The with helper would delete the key.
			name: "assurance: null amr and acr are malformed and assert nothing",
			token: signed(func(_ *testProvider, c map[string]any) map[string]any {
				c["amr"], c["acr"] = nil, nil
				return c
			}),
			assert: asserts(nil, "", true, true),
		},
		{
			name:   "assurance: amr as a string is malformed and asserts nothing",
			token:  withClaims("amr", "mfa"),
			assert: asserts(nil, "", true, false),
		},
		{
			// A partial read would assert mfa; the whole claim must be discarded.
			name:   "assurance: amr with a non-string element is malformed and asserts nothing",
			token:  withClaims("amr", []any{"mfa", 1}),
			assert: asserts(nil, "", true, false),
		},
		{
			name:   "assurance: amr with a null element is malformed",
			token:  withClaims("amr", []any{"mfa", nil}),
			assert: asserts(nil, "", true, false),
		},
		{
			name:   "assurance: amr as an object is malformed",
			token:  withClaims("amr", map[string]any{"mfa": true}),
			assert: asserts(nil, "", true, false),
		},
		{
			name:   "assurance: a string acr is asserted",
			token:  withClaims("acr", "urn:corp:loa:2"),
			assert: asserts(nil, "urn:corp:loa:2", false, false),
		},
		{
			name:   "assurance: an empty acr asserts nothing and is not malformed",
			token:  withClaims("acr", ""),
			assert: asserts(nil, "", false, false),
		},
		{
			name:   "assurance: a numeric acr is malformed",
			token:  withClaims("acr", 2),
			assert: asserts(nil, "", false, true),
		},
		{
			name:   "assurance: an array acr is malformed",
			token:  withClaims("acr", []any{"gold"}),
			assert: asserts(nil, "", false, true),
		},
		{
			name:   "assurance: amr and acr are read together",
			token:  withClaims("amr", []any{"pwd", "mfa"}, "acr", "urn:corp:loa:2"),
			assert: asserts([]string{"pwd", "mfa"}, "urn:corp:loa:2", false, false),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			if tc.setup != nil {
				tc.setup(p)
			}
			shared := p.Provider("shared")
			shared.SigningAlgs = []string{"HS256"}
			ec := p.Provider("ec")
			ec.SigningAlgs = []string{"ES256"}
			wide := p.Provider("wide")
			wide.SigningAlgs = []string{"RS256", "RS384"}
			reg, err := oidc.NewRegistry(p.Provider("corp"), shared, ec, wide)
			require.NoError(t, err)

			opts := append([]oidc.ManagerOption{
				oidc.WithOutboundClient(p.Outbound(t)),
				oidc.WithClock(clockwork.NewFakeClockAt(now)),
			}, tc.opts...)
			m, err := oidc.NewManager(reg, stubBroker{}, opts...)
			require.NoError(t, err)

			provider := tc.provider
			if provider == "" {
				provider = "corp"
			}
			want := nonce
			switch tc.nonce {
			case "":
			case "-":
				want = ""
			default:
				want = tc.nonce
			}

			if tc.before != nil {
				tc.before(t, m, p)
			}
			raw := tc.token(t, p)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			got, err := oidc.VerifyIDTokenForTest(ctx, m, provider, raw, want)
			tc.assert(t, p, got, err)
		})
	}
}
