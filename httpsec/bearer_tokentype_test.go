package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// TestBearer_RefusesOtherTokenTypes pins that the chain's signed bearer accepts
// first-party tokens only. Every token is signed by the chain's own keys, and
// names its own issuer, its own audience, a live session and that session's user,
// so nothing but the declared type can tell the rows apart.
func TestBearer_RefusesOtherTokenTypes(t *testing.T) {
	t.Parallel()

	typed := func(typ string) func(*testing.T, *signingkey.Keys) string {
		return func(t *testing.T, keys *signingkey.Keys) string {
			t.Helper()

			issuer, err := token.NewIssuer(keys, signingkey.RS256, keySourceTestIssuer)
			require.NoError(t, err)

			raw, err := issuer.Issue(t.Context(), token.Issue{
				Type: typ, Subject: string(testUserID), ID: testJTI, Audience: []string{keySourceTestAudience},
			})
			require.NoError(t, err)

			return raw
		}
	}

	refused := func(t *testing.T, _ *authHarness, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.ErrorIs(t, out.err, token.ErrInvalid)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
	}

	type testCase struct {
		name   string
		token  func(t *testing.T, keys *signingkey.Keys) string
		wire   func(h *authHarness)
		assert func(t *testing.T, h *authHarness, out served)
	}

	cases := []testCase{
		{name: "an ID token", token: typed(token.TypeIDToken), assert: refused},
		{name: "an access token", token: typed(token.TypeAccessToken), assert: refused},
		{name: "a logout token", token: typed(token.TypeLogoutToken), assert: refused},
		{
			// The control: the same keys, issuer, audience, session and user, so
			// the rows above were refused for their type and nothing else.
			name: "a first-party token",
			token: func(t *testing.T, keys *signingkey.Keys) string {
				t.Helper()

				gen, err := token.NewGenerator(keys,
					token.WithIssuer(keySourceTestIssuer), token.WithAudience(keySourceTestAudience))
				require.NoError(t, err)

				raw, err := gen.Generate(t.Context(), testJTI, &identity.Principal{ID: testUserID, Username: testUsername})
				require.NoError(t, err)

				return raw
			},
			wire: func(h *authHarness) { h.expectLiveSessionAndUser(liveSession()) },
			assert: func(t *testing.T, _ *authHarness, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
			require.NoError(t, err)

			verifier, err := token.NewVerifier(
				token.WithVerifyKeySource(keys),
				token.WithVerifyIssuer(keySourceTestIssuer),
				token.WithVerifyAudience(keySourceTestAudience),
			)
			require.NoError(t, err)

			// A refused row sets no expectation on the store or the loader: a
			// token of another type names nothing worth looking up.
			h := newAuthHarness(t)
			if tc.wire != nil {
				tc.wire(h)
			}

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: verifier, Sessions: h.sessions, Users: h.users,
				}),
			)
			require.NoError(t, err)

			tc.assert(t, h, serve(t, chain, bearerRequest(t.Context(), "Bearer "+tc.token(t, keys))))
		})
	}
}
