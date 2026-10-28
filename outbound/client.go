package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/ascii"
	"github.com/kartaladev/scrty/internal/origin"
)

// ErrRefused is wrapped by every refusal this package makes about where a
// request would go or where a response came from.
var ErrRefused = errors.New("outbound: request refused")

// ErrConfig is wrapped by every error New returns for a wiring mistake, so a
// consumer can tell a contradictory configuration from a runtime failure
// without matching on message text. A configuration that cannot work is refused
// at construction, before a single request depends on it.
var ErrConfig = errors.New("outbound: invalid configuration")

// Response is what a confined request returned, once every check passed.
//
// Body holds the whole response body, already read and bounded, because the
// call is over by the time it is returned: there is no stream left to close and
// no reader a caller could forget to drain. A status is reported as it came;
// judging it belongs to the component that knows what the endpoint promises.
type Response struct {
	// Status is the status the endpoint answered with, reported as it came.
	Status int

	// Header is the response header, unmodified.
	Header http.Header

	// Body is the whole response body, within the configured bound.
	Body []byte
}

// Client sends the HTTP requests scrty itself makes, under the confinement its
// options describe. Build one with New; the zero value sends nothing.
//
// A Client is safe for concurrent use, and is meant to be built once and shared
// by the components that fetch from the same provider.
type Client struct {
	hc           *http.Client
	schemes      []string
	origins      []string
	maxRedirects int
	timeout      time.Duration
	maxBytes     int64
}

// New returns a client confined by the options, or an error naming the option
// that cannot work.
//
// With no options: https only, at most DefaultMaxRedirects redirects, each call
// bounded by DefaultTimeout and each response body by DefaultMaxResponseBytes,
// sent with a zero-value http.Client.
func New(opts ...Option) (*Client, error) {
	var cfg config
	if err := cfg.resolve(opts...); err != nil {
		return nil, err
	}

	c := &Client{
		schemes:      cfg.schemes,
		origins:      cfg.origins,
		maxRedirects: cfg.redirects,
		timeout:      cfg.timeout,
		maxBytes:     cfg.maxBytes,
	}
	c.hc = c.install(cfg.hc)

	return c, nil
}

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

// install copies the consumer's client and puts this package's redirect policy
// on the copy. The consumer's client is never mutated: it may be shared with
// the rest of their application, which did not ask for these rules.
func (c *Client) install(hc *http.Client) *http.Client {
	copied := *hc
	consumer := hc.CheckRedirect

	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// The hop cap first, because installing any CheckRedirect discards
		// net/http's own limit of ten. Without this a provider redirecting to
		// itself for ever would be stopped only by the time bound, which turns
		// one misconfigured provider into a stall for everything behind it.
		if len(via) > c.maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRefused, c.maxRedirects)
		}

		// via is never empty in practice; a redirect with no history would leave
		// nothing to compare the target against, so it is refused rather than
		// waved through.
		if len(via) == 0 {
			return fmt.Errorf("%w: a redirect arrived with no request history", ErrRefused)
		}

		// Against via[0], the URL the request started with, and not the hop
		// before it. Hop-to-hop comparison would judge each step against a URL
		// the answer to the previous step chose.
		if err := c.checkHop(req.URL.String(), via[0].URL.String()); err != nil {
			return err
		}

		// The consumer's own check runs last, so it can refuse more than this
		// package does and can never allow what this package refused.
		if consumer != nil {
			return consumer(req, via)
		}

		return nil
	}

	return &copied
}

// checkHop refuses a redirect target that is not where the request started.
//
// An allowed origin is not enough: a declared origin says where a request may
// be aimed, not where an answer may send it next. Requiring the starting origin
// is also what stops a chain walking somewhere else one step at a time.
func (c *Client) checkHop(target, start string) error {
	if err := c.checkTarget(target); err != nil {
		return err
	}

	if !origin.Same(start, target) {
		return fmt.Errorf("%w: %q is not on the origin the request started with", ErrRefused, target)
	}

	return nil
}

// Get fetches rawURL, which must pass every check before a connection is
// opened.
//
// The header may be nil. Whatever it carries is sent as given: this package
// adds no header of its own, and interprets none, because what a provider needs
// is the calling component's business.
func (c *Client) Get(ctx context.Context, rawURL string, header http.Header) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, header, "")
}

// PostForm sends form to rawURL as application/x-www-form-urlencoded, which is
// what a token exchange is.
//
// The form is the caller's, encoded and sent unchanged. The header may be nil,
// which is the same as no header: whatever it carries is sent as given, except
// Content-Type, which this method always sets to the form content type, replacing
// any the caller supplied. This package adds and interprets nothing else of its
// own — a client authenticating with HTTP
// Basic puts its credentials here. Because the body and the header may both
// carry a client secret, the redirect policy this package installs matters
// most here: a 307 or 308 answer that would resend either somewhere else is
// refused before the redirected request goes out.
func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values, header http.Header) (*Response, error) {
	h := header.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set("Content-Type", "application/x-www-form-urlencoded")

	return c.do(ctx, http.MethodPost, rawURL, h, form.Encode())
}

// AllowsScheme reports whether the client sends requests to URLs with this
// scheme: https always, and http only when WithAllowedSchemes added it. The
// scheme compares case-insensitively, within ASCII only.
//
// It answers from the same allow-set, and with the same normalisation, as the
// check every request passes, so a component can refuse at construction a URL
// the client would refuse at request time.
func (c *Client) AllowsScheme(scheme string) bool {
	return slices.Contains(c.schemes, ascii.ToLower(scheme))
}

// checkTarget refuses a URL before a connection is opened.
//
// Everything here is checked before the request is sent, not after: a token
// request carries a client secret, and a check that runs on the response has
// already let it leave.
func (c *Client) checkTarget(raw string) error {
	scheme, _, _, ok := origin.Normalize(raw)
	if !ok {
		return fmt.Errorf("%w: %q is not an absolute http or https URL with a host", ErrRefused, raw)
	}

	if !c.AllowsScheme(scheme) {
		return fmt.Errorf("%w: the scheme of %q is not allowed", ErrRefused, raw)
	}

	if len(c.origins) > 0 && !slices.ContainsFunc(c.origins, func(o string) bool { return origin.Same(o, raw) }) {
		return fmt.Errorf("%w: %q is not on a declared origin", ErrRefused, raw)
	}

	return nil
}

// checkResponse refuses a response that did not come from where the request was
// aimed, before a byte of it is read.
//
// It is re-checked because a consumer's Transport may have followed a redirect
// without CheckRedirect ever being consulted. This cannot unsend a request,
// which is why the pre-send checks exist — but it does stop the content of
// another origin being handed back as if the provider had answered. A response
// that does not say which URL produced it is refused for the same reason: an
// unknown origin is not a permitted one.
func (c *Client) checkResponse(res *http.Response, rawURL string) error {
	if res.Request == nil || res.Request.URL == nil {
		return fmt.Errorf("%w: the response to %s does not say which URL produced it", ErrRefused, rawURL)
	}

	if err := c.checkHop(res.Request.URL.String(), rawURL); err != nil {
		return fmt.Errorf("outbound: the response came from an unexpected URL: %w", err)
	}

	return nil
}

func (c *Client) do(
	ctx context.Context,
	method, rawURL string,
	header http.Header,
	body string,
) (*Response, error) {
	if err := c.checkTarget(rawURL); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("outbound: building the request: %w", err)
	}
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	res, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("outbound: %s %s: %w", method, rawURL, err)
	}
	defer func() { _ = res.Body.Close() }()

	if err := c.checkResponse(res, rawURL); err != nil {
		return nil, err
	}

	// One byte more than the bound is read, so that a document exactly at it is
	// accepted and the first byte over it is seen without reading the rest.
	read, err := io.ReadAll(io.LimitReader(res.Body, c.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("outbound: reading the response from %s: %w", rawURL, err)
	}
	if int64(len(read)) > c.maxBytes {
		return nil, fmt.Errorf(
			"%w: the response from %s is longer than the %d byte limit, so none of it is used",
			ErrRefused, rawURL, c.maxBytes)
	}

	return &Response{Status: res.StatusCode, Header: res.Header, Body: read}, nil
}
