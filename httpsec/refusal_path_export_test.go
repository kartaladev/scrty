package httpsec

import "net/http"

// DispatchForTest answers err on c exactly as the chain's net/http dispatch
// answers a run's refusal (handleError), so a test can dispatch through a Chain
// that did not come from New, whose run has no interceptor to refuse with.
func DispatchForTest(c *Chain, w http.ResponseWriter, r *http.Request, err error) {
	ex := NewExchange(r.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(w))
	c.handleError(ex, w, r, err) //nolint:contextcheck // test hook; the exchange's context is r's
}

// IsPerRequestThrottleTarget reports whether target is what errors.As is handed
// when it looks for the per-request throttle's mark, so a test's error can make
// its As method panic for that one question.
func IsPerRequestThrottleTarget(target any) bool {
	_, ok := target.(**perRequestThrottle)

	return ok
}
