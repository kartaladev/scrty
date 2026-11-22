package oidcprovider

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/origin"
)

// DeviceOption customises WithDeviceAuthorization.
type DeviceOption func(*deviceConfig)

// deviceConfig is what the device authorization grant is configured with. A provider
// that did not enable the grant has none.
type deviceConfig struct {
	// entryRaw is the URL as the consumer gave it, until New checks it against the
	// issuer.
	entryRaw string
	// entryURL is the page where the user types the code, parsed and checked.
	entryURL *url.URL
}

// WithDeviceAuthorization enables the device authorization grant (RFC 8628). The
// default is off: with no option, no client may list GrantDeviceCode, and
// Provider.DeviceEnabled is false.
//
// entryURL is the page where a user types the code shown on the device. It must be
// absolute, on the issuer's origin (so https, unless the issuer is the loopback http
// one WithLoopbackHTTPIssuer permits), and carry no fragment or user information. A
// query is allowed. Anything else fails construction with ErrConfig. A nil DeviceOption
// is skipped. Given twice, the last one wins.
func WithDeviceAuthorization(entryURL string, opts ...DeviceOption) Option {
	return func(c *config) {
		d := &deviceConfig{entryRaw: entryURL}
		for _, opt := range opts {
			if opt != nil {
				opt(d)
			}
		}
		c.device = d
	}
}

// DeviceEnabled says whether the provider was built with WithDeviceAuthorization. The
// chain registers the device endpoints only when it is true.
func (p *Provider) DeviceEnabled() bool { return p.cfg.device != nil }

// validate checks the entry URL against the issuer, which only Deps knows, and keeps
// it parsed. Its messages never repeat the value, which could hold a credential.
func (d *deviceConfig) validate(issuer string) error {
	if !utf8.ValidString(d.entryRaw) || strings.IndexFunc(d.entryRaw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must hold no whitespace, control character or invalid UTF-8", ErrConfig)
	}
	u, err := url.Parse(d.entryRaw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must be absolute", ErrConfig)
	}
	if u.User != nil || strings.Contains(d.entryRaw, "#") {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must have no fragment or user information", ErrConfig)
	}
	if !origin.Same(d.entryRaw, issuer) {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must be on the issuer's origin", ErrConfig)
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL's query is malformed", ErrConfig)
	}
	if _, found := query["user_code"]; found {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL's query must not carry user_code", ErrConfig)
	}
	d.entryURL = u

	return nil
}
