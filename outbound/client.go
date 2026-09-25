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

	"github.com/kartaladev/scrty/internal/origin"
)

// ErrRefused is wrapped by every refusal this package makes about where a
// request would go or where a response came from.
var ErrRefused = errors.New("outbound: request refused")

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
	return slices.Contains(c.schemes, asciiLower(scheme))
}

// asciiLower folds only A-Z. Unicode case mapping would fold a look-alike
// letter onto an allowed scheme that url.Parse never produces.
func asciiLower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if 'A' <= ch && ch <= 'Z' {
			b[i] = ch + ('a' - 'A')
		}
	}
	return string(b)
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
