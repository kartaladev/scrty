package token_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
)

// thumbprint returns a well-formed confirmation value: the unpadded base64url
// SHA-256 digest of seed, 43 characters.
func thumbprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestGenerator_Confirmation(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	jkt := thumbprint("dpop key")
	x5t := thumbprint("client certificate")

	type testCase struct {
		name   string
		opts   []token.IssueOption
		assert func(t *testing.T, gen *token.JWTGenerator, raw string, err error)
	}

	refusedAtIssue := func(t *testing.T, _ *token.JWTGenerator, raw string, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.NotErrorIs(t, err, token.ErrInvalid, "issuing passes no verdict on a token")
		assert.Empty(t, raw, "nothing is issued")
	}

	cases := []testCase{
		{
			name: "a DPoP binding is carried as cnf.jkt and returned by verification",
			opts: []token.IssueOption{token.WithConfirmation(token.Confirmation{JKT: jkt})},
			assert: func(t *testing.T, gen *token.JWTGenerator, raw string, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]any{"jkt": jkt}, decodeClaims(t, raw)["cnf"])

				claims, verr := gen.Verify(t.Context(), raw)
				require.NoError(t, verr)
				assert.Equal(t, token.Confirmation{JKT: jkt}, claims.Confirmation())
			},
		},
		{
			name: "a certificate binding is carried as cnf.x5t#S256",
			opts: []token.IssueOption{token.WithConfirmation(token.Confirmation{X5TS256: x5t})},
			assert: func(t *testing.T, gen *token.JWTGenerator, raw string, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]any{"x5t#S256": x5t}, decodeClaims(t, raw)["cnf"])

				claims, verr := gen.Verify(t.Context(), raw)
				require.NoError(t, verr)
				assert.Equal(t, token.Confirmation{X5TS256: x5t}, claims.Confirmation())
			},
		},
		{
			name: "no binding carries no cnf",
			assert: func(t *testing.T, gen *token.JWTGenerator, raw string, err error) {
				require.NoError(t, err)
				assert.NotContains(t, decodeClaims(t, raw), "cnf")

				claims, verr := gen.Verify(t.Context(), raw)
				require.NoError(t, verr)
				assert.Equal(t, token.Confirmation{}, claims.Confirmation())
			},
		},
		{
			name: "the zero confirmation is no binding",
			opts: []token.IssueOption{token.WithConfirmation(token.Confirmation{})},
			assert: func(t *testing.T, _ *token.JWTGenerator, raw string, err error) {
				require.NoError(t, err)
				assert.NotContains(t, decodeClaims(t, raw), "cnf")
			},
		},
		{
			name:   "both bindings are refused at issue",
			opts:   []token.IssueOption{token.WithConfirmation(token.Confirmation{JKT: jkt, X5TS256: x5t})},
			assert: refusedAtIssue,
		},
		{
			name:   "a 10-character thumbprint is refused at issue",
			opts:   []token.IssueOption{token.WithConfirmation(token.Confirmation{JKT: "abcdefghij"})},
			assert: refusedAtIssue,
		},
		{
			name: "a 43-character value outside base64url is refused at issue",
			opts: []token.IssueOption{token.WithConfirmation(token.Confirmation{
				X5TS256: "+" + x5t[1:],
			})},
			assert: refusedAtIssue,
		},
		{
			name: "a member this package cannot check is refused at issue",
			opts: []token.IssueOption{token.WithConfirmation(token.Confirmation{
				JKT: jkt, Other: []string{"jwk"},
			})},
			assert: refusedAtIssue,
		},
		{
			name:   "a nil option is skipped",
			opts:   []token.IssueOption{nil},
			assert: func(t *testing.T, _ *token.JWTGenerator, _ string, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := token.NewGenerator(newKeySource(t),
				token.WithoutIssuer(), token.WithoutAudience(),
				token.WithClock(clockwork.NewFakeClockAt(issuedAt)))
			require.NoError(t, err)

			raw, err := gen.GenerateWith(t.Context(), "s-1", alice(), tc.opts...)
			tc.assert(t, gen, raw, err)
		})
	}
}

func TestVerifier_Confirmation(t *testing.T) {
	t.Parallel()

	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	jkt := thumbprint("dpop key")
	x5t := thumbprint("client certificate")

	type testCase struct {
		name   string
		cnf    any // nil means the token carries no cnf
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	confirmed := func(want token.Confirmation) func(*testing.T, *token.Claims, error) {
		return func(t *testing.T, claims *token.Claims, err error) {
			t.Helper()

			require.NoError(t, err)
			require.NotNil(t, claims)
			assert.Equal(t, want, claims.Confirmation())
		}
	}

	cases := []testCase{
		{name: "no cnf is no binding", assert: confirmed(token.Confirmation{})},
		{name: "jkt is returned", cnf: map[string]any{"jkt": jkt}, assert: confirmed(token.Confirmation{JKT: jkt})},
		{
			name:   "x5t#S256 is returned",
			cnf:    map[string]any{"x5t#S256": x5t},
			assert: confirmed(token.Confirmation{X5TS256: x5t}),
		},
		{
			// Returned as they are: the caller decides what it can honour,
			// and must see both rather than either one alone.
			name:   "both members are returned for the caller to refuse",
			cnf:    map[string]any{"jkt": jkt, "x5t#S256": x5t},
			assert: confirmed(token.Confirmation{JKT: jkt, X5TS256: x5t}),
		},
		{
			name:   "an unknown member is named, never dropped",
			cnf:    map[string]any{"jwk": map[string]any{"kty": "EC"}, "kid": "k-1"},
			assert: confirmed(token.Confirmation{Other: []string{"jwk", "kid"}}),
		},
		{name: "a jkt that is not a string is refused", cnf: map[string]any{"jkt": 7}, assert: rejected},
		{name: "a malformed jkt is refused", cnf: map[string]any{"jkt": "abcdefghij"}, assert: rejected},
		{name: "a malformed x5t#S256 is refused", cnf: map[string]any{"x5t#S256": x5t + "A"}, assert: rejected},
		{name: "an empty cnf is refused", cnf: map[string]any{}, assert: rejected},
		{name: "a string cnf is refused", cnf: jkt, assert: rejected},
		{name: "a null cnf is refused", cnf: jsonNull{}, assert: rejected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			ver, err := token.NewVerifier(
				token.WithVerifyKeySource(keys),
				token.WithoutVerifyIssuer(), token.WithoutVerifyAudience(),
				token.WithVerifyClock(fixedClock{at: at}))
			require.NoError(t, err)

			claims := validClaims(at)
			switch v := tc.cnf.(type) {
			case nil:
			case jsonNull:
				claims["cnf"] = nil
			default:
				claims["cnf"] = v
			}

			got, err := ver.Verify(t.Context(), signClaims(t, keys, claims))
			tc.assert(t, got, err)
		})
	}
}

// jsonNull marks a row whose cnf is present and JSON null, which a nil any
// cannot say in the table.
type jsonNull struct{}
