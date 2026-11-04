package httpsecconformance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// twoCookiesPath is the path the two-cookie interceptor answers.
const twoCookiesPath = "/two-cookies"

// twoCookiesAtOnce is an interceptor that sets two cookies on one response.
//
// No endpoint of the library sets two cookies at once, so a framework that
// kept only the last cookie written, or folded the two into one header line,
// could not show in any other scenario. The first cookie carries every
// attribute that has a value, the second as few as a cookie can: a merge or an
// overwrite changes one of them.
func twoCookiesAtOnce() httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
			ex.Writer.SetCookie(&httpsec.Cookie{
				Name: "first", Value: "one", Path: "/a", Domain: "example.com",
				MaxAge: 60, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			ex.Writer.SetCookie(&httpsec.Cookie{
				Name: "second", Value: "two", Path: "/", SameSite: http.SameSiteLaxMode,
			})
			ex.Writer.WriteHeader(http.StatusNoContent)

			return nil
		}),
		httpsec.OrderJWKS,
	)
}

func twoCookiesAreBothSent() Scenario {
	return Scenario{
		Name: "two cookies set on one response are both sent, each with its own attributes",
		Build: func(t *testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{twoCookiesAtOnce()},
				Effects: newEffects(t),
			}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: twoCookiesPath, ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusNoContent, res.Status)

			cookies := assertOneSetCookiePerCookie(t, res, "first", "second")

			first, second := cookies[0], cookies[1]

			assert.Equal(t, "one", first.Value)
			assert.Equal(t, "/a", first.Path)
			assert.Equal(t, "example.com", first.Domain)
			assert.Equal(t, 60, first.MaxAge)
			assert.True(t, first.Secure)
			assert.True(t, first.HttpOnly)
			assert.Equal(t, http.SameSiteStrictMode, first.SameSite)

			assert.Equal(t, "two", second.Value)
			assert.Equal(t, "/", second.Path)
			assert.Empty(t, second.Domain)
			assert.Zero(t, second.MaxAge)
			assert.True(t, second.Expires.IsZero(), "the second cookie is session-only")
			assert.False(t, second.Secure)
			assert.False(t, second.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, second.SameSite)
		},
	}
}
