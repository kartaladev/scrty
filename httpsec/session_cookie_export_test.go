package httpsec

import "net/http"

// SessionCookieOf is the session cookie chain c would set with value and
// maxAge (as http.Cookie reads MaxAge: 0 sets none, a negative one expires
// it), or nil when c has no cookie session. It is how a test reads the
// attributes before any endpoint delivers the cookie.
func SessionCookieOf(c *Chain, value string, maxAge int) *http.Cookie {
	for _, r := range c.registrations {
		if s, ok := r.interceptor.(*sessionCookie); ok {
			return s.cookie(value, maxAge)
		}
	}

	return nil
}

// PresentedToken is the credential the request recorded as presented
// (Exchange.RecordPresentedToken), "" for none.
func PresentedToken(ex *Exchange) string { return ex.bearerCredential }
