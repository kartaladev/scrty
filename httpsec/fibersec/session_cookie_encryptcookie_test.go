package fibersec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/encryptcookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestSessionCookie_EncryptCookie pins the documented wiring rule: fiber's
// encryptcookie rewrites cookies in fasthttp's parsed copy, and the adapter
// reads the Cookie header as it arrived, so the session cookie must be listed
// in encryptcookie's Config.Except. A browser holds whatever the server set, so
// the cookie value it sends back is the plain identifier when the cookie is
// excepted and the ciphertext when it is not; the second case is refused,
// never authenticated from the ciphertext.
func TestSessionCookie_EncryptCookie(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		except []string
		// held is the value the browser sends back for the session id.
		held   func(t *testing.T, key, id string) string
		assert func(t *testing.T, status int, authenticated bool)
	}

	cases := []testCase{
		{
			name:   "excepted cookie signs in",
			except: []string{httpsec.DefaultSessionCookieName},
			held:   func(_ *testing.T, _, id string) string { return id },
			assert: func(t *testing.T, status int, authenticated bool) {
				assert.Equal(t, http.StatusOK, status)
				assert.True(t, authenticated, "the session id reaches the chain as sent")
			},
		},
		{
			name: "cookie left out of Except is refused, never authenticated from ciphertext",
			held: func(t *testing.T, key, id string) string {
				t.Helper()

				enc, err := encryptcookie.EncryptCookie(httpsec.DefaultSessionCookieName, id, key)
				require.NoError(t, err)

				return enc
			},
			assert: func(t *testing.T, status int, authenticated bool) {
				assert.Equal(t, http.StatusUnauthorized, status)
				assert.False(t, authenticated, "no caller is published from a ciphertext")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New()
			require.NoError(t, err)

			live, err := sessions.Create(t.Context(), "u-1",
				session.WithFirstFactor(factor.Password), session.WithCSRFToken())
			require.NoError(t, err)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(&identity.Details{
				ID: "u-1", Username: "ada", Active: true, PasswordChangedAt: time.Now().Add(-time.Hour),
			}, nil)

			chain, err := httpsec.New(
				httpsec.EnableCSRFProtection(),
				httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
			)
			require.NoError(t, err)

			key := encryptcookie.GenerateKey(32)

			var authenticated bool

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(encryptcookie.New(encryptcookie.Config{Key: key, Except: tc.except}))
			app.Use(fibersec.Middleware(chain))
			app.Get("/*", func(c fiber.Ctx) error {
				_, authenticated = identity.PrincipalFromContext(c.Context())

				return c.SendStatus(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.example.com/x", nil)
			req.Header.Set("Cookie", httpsec.DefaultSessionCookieName+"="+tc.held(t, key, live.ID))
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			res := serveFrom(t, app, req, "198.51.100.7:51000")

			tc.assert(t, res.status, authenticated)
		})
	}
}
