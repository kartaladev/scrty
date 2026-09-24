package outbound

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/internal/origin"
)

// ErrConfig is wrapped by every error New returns for a wiring mistake, so a
// consumer can tell a contradictory configuration from a runtime failure
// without matching on message text. A configuration that cannot work is refused
// at construction, before a single request depends on it.
var ErrConfig = errors.New("outbound: invalid configuration")

// The defaults New applies. Each is replaceable by the option named beside it.
const (
	// DefaultMaxRedirects is how many redirects one request may follow
	// (WithMaxRedirects). It matches net/http's own limit, which installing any
	// redirect policy would otherwise discard.
	DefaultMaxRedirects = 10

	// DefaultTimeout bounds one whole call, connection through body
	// (WithTimeout).
	DefaultTimeout = 10 * time.Second

	// DefaultMaxResponseBytes is how much of a response body is read
	// (WithMaxResponseBytes). A key set or a discovery document that does not
	// fit in a mebibyte is not one this library was asked to fetch.
	DefaultMaxResponseBytes int64 = 1 << 20
)

// schemeHTTPS is allowed always; schemeHTTP is the only scheme that may be
// added to it.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// config is what the options write. It is unexported, so the set of options is
// closed: every one of them is a decision this package has reasoned about, and
// a consumer cannot weaken a check by supplying an option of their own.
type config struct {
	hc        *http.Client
	hcSet     bool
	schemes   []string
	origins   []string
	redirects int
	timeout   time.Duration
	maxBytes  int64
}

// Option configures a Client. Every default New applies has an option here that
// replaces it.
type Option func(*config)

// WithHTTPClient sets the client the requests are sent with. Default: a
// zero-value http.Client, which uses http.DefaultTransport.
//
// The client is copied and the copy carries this package's redirect policy, so
// the client the consumer passed keeps its own behaviour everywhere else it is
// used. A nil client fails construction.
//
// The parameter is an *http.Client and not an interface with a Do method on
// purpose. A redirect policy can only be installed on the concrete client, and
// without one a 307 or 308 answer resends the request body — a token request's
// client secret, code and verifier — to whatever origin the redirect names,
// before any check this package makes could run. A check on the response cannot
// unsend that.
//
// Stated limit: a consumer Transport that follows redirects by itself never
// consults CheckRedirect, so it bypasses the pre-send check. Only the
// final-URL re-check remains, and that runs after the request has been sent.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *config) {
		c.hc = hc
		c.hcSet = true
	}
}

// WithAllowedSchemes allows schemes beyond the default. Default: https only.
//
// https is always allowed and cannot be removed, because removing it could not
// make anything safer. http is the only scheme that may be added, and allowing
// it removes transport protection: the request, its credentials and the
// response travel in cleartext to anything on the path. It exists for a
// provider on loopback during development, not for the internet. Any other
// scheme fails construction.
func WithAllowedSchemes(schemes ...string) Option {
	return func(c *config) { c.schemes = append(c.schemes, schemes...) }
}

// WithAllowedOrigins restricts which origins a request may target. Default:
// none declared, so the client sends to the origin the calling component's
// configuration names, subject to every other rule here.
//
// Each entry is a scheme, a host and an optional port, with at most a lone "/"
// after it and no userinfo, path, query or fragment. Ports are compared with a
// port equal to the scheme's default removed, and scheme and host are compared
// with ASCII case folding and nothing else, so https://idp.example.com:443
// matches https://IDP.example.com. Anything else fails construction.
func WithAllowedOrigins(origins ...string) Option {
	return func(c *config) { c.origins = append(c.origins, origins...) }
}

// WithMaxRedirects caps how many redirects one request follows.
// Default: DefaultMaxRedirects.
//
// Zero means a redirect is never followed, which is a configuration and not a
// mistake. A negative cap fails construction. The cap is counted first, before
// the scheme and origin of the new target, because a provider that redirects to
// itself for ever would otherwise be bounded only by the time limit.
func WithMaxRedirects(n int) Option {
	return func(c *config) { c.redirects = n }
}

// WithTimeout bounds one whole call. Default: DefaultTimeout.
//
// The bound is applied as a deadline on the request's context, so it covers the
// connection, the response and the body, whatever timeout the supplied client
// carries. An earlier deadline already on the caller's context wins. A bound of
// zero or less fails construction: a request that may run for ever is how one
// unresponsive provider stops every caller behind it.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithMaxResponseBytes bounds how much of a response body is read.
// Default: DefaultMaxResponseBytes.
//
// A response longer than the bound fails the call and its content is not
// returned, so an oversized document is never parsed rather than parsed in
// part. A limit of zero or less fails construction.
func WithMaxResponseBytes(n int64) Option {
	return func(c *config) { c.maxBytes = n }
}

// resolve applies the options over the defaults and refuses a configuration
// that cannot work, naming the option at fault.
func (c *config) resolve(opts ...Option) error {
	c.redirects = DefaultMaxRedirects
	c.timeout = DefaultTimeout
	c.maxBytes = DefaultMaxResponseBytes

	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	if c.hcSet && c.hc == nil {
		return fmt.Errorf("%w: WithHTTPClient was given no client", ErrConfig)
	}
	if !c.hcSet {
		c.hc = &http.Client{}
	}

	allowed := []string{schemeHTTPS}
	for _, s := range c.schemes {
		if s != schemeHTTP && s != schemeHTTPS {
			return fmt.Errorf(
				"%w: WithAllowedSchemes was given %q; only %q may be added to the default %q",
				ErrConfig, s, schemeHTTP, schemeHTTPS)
		}
		if !slices.Contains(allowed, s) {
			allowed = append(allowed, s)
		}
	}
	c.schemes = allowed

	for _, o := range c.origins {
		if err := validateOrigin(o); err != nil {
			return err
		}
	}

	if c.redirects < 0 {
		return fmt.Errorf("%w: WithMaxRedirects was given %d; a cap is zero or more", ErrConfig, c.redirects)
	}
	if c.timeout <= 0 {
		return fmt.Errorf("%w: WithTimeout was given %s; a request must be bounded in time", ErrConfig, c.timeout)
	}
	if c.maxBytes <= 0 {
		return fmt.Errorf(
			"%w: WithMaxResponseBytes was given %d; a response with no readable bytes could never be used",
			ErrConfig, c.maxBytes)
	}

	return nil
}

// validateOrigin refuses a declaration that is more than an origin.
//
// A path, a query or userinfo in a declared origin reads as if it narrowed what
// may be requested, and it does not: only the origin is ever compared. Refusing
// it at construction is the only way the consumer learns that before the
// request they thought they had restricted goes out.
func validateOrigin(declared string) error {
	u, err := url.Parse(declared)
	if err != nil {
		return fmt.Errorf("%w: WithAllowedOrigins was given %q, which is not a URL", ErrConfig, declared)
	}

	if _, _, _, ok := origin.Normalize(declared); !ok {
		return fmt.Errorf(
			"%w: WithAllowedOrigins was given %q; an origin is an absolute http or https URL with a host",
			ErrConfig, declared)
	}

	switch {
	case u.User != nil:
		return fmt.Errorf("%w: WithAllowedOrigins was given %q, which carries userinfo", ErrConfig, declared)
	case u.Path != "" && u.Path != "/":
		return fmt.Errorf("%w: WithAllowedOrigins was given %q, which carries a path", ErrConfig, declared)
	case u.RawQuery != "" || u.ForceQuery:
		return fmt.Errorf("%w: WithAllowedOrigins was given %q, which carries a query", ErrConfig, declared)
	case u.Fragment != "":
		return fmt.Errorf("%w: WithAllowedOrigins was given %q, which carries a fragment", ErrConfig, declared)
	}

	return nil
}
