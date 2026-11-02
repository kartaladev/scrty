package httpsec

// The three outermost slots, ahead of every other. Each is empty unless its
// layer is enabled, and they are spaced twenty-five apart like the rest, so a
// consumer can register immediately before or after any of them with Before
// and After.
const (
	// OrderSecurityHeaders is the security-headers layer (EnableSecurityHeaders).
	// It is outermost, so every response the chain produces, including a CORS
	// preflight answer and a CSRF refusal, carries its headers.
	OrderSecurityHeaders Order = 25

	// OrderCORS is cross-origin resource sharing: it answers a preflight before
	// CSRF protection could matter.
	OrderCORS Order = 50

	// OrderCSRF is cross-site request forgery protection.
	OrderCSRF Order = 75
)
