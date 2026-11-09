package httpsec

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Header names the report-only and reporting options set.
const (
	headerCSPReportOnly      = "Content-Security-Policy-Report-Only"
	headerReportingEndpoints = "Reporting-Endpoints"
)

// reportingEndpoint is the endpoint WithReportingEndpoint names.
type reportingEndpoint struct {
	name string
	url  string
}

// endpointName is a structured-field key (RFC 8941), which is what a
// Reporting-Endpoints member is named with.
var endpointName = regexp.MustCompile(`^[a-z*][a-z0-9_.*-]*$`)

// WithCSPReportOnly sends the document profile's policy as
// Content-Security-Policy-Report-Only instead of Content-Security-Policy, so a
// browser reports what the policy would block and blocks nothing. It is the
// first step of a rollout.
//
// Default: the policy is enforced. Only the document profile is switched; a
// route profile keeps its own policy enforced. It fails construction when the
// document profile sends no policy (WithoutHeader removed it), and together
// with WithCSPReportOnlyPolicy, which already sends a report-only header. The
// order of this option and WithCSP does not matter.
func WithCSPReportOnly() HeaderOption {
	return func(l *securityHeaders) error {
		if err := l.layerWide("WithCSPReportOnly"); err != nil {
			return err
		}

		l.reportOnly = true

		return nil
	}
}

// WithCSPReportOnlyPolicy sends policy as Content-Security-Policy-Report-Only beside
// the enforced policy, to try a stricter candidate on real traffic. A policy
// with a nonce carries the same nonce as the enforced one, so one handler
// nonce serves both.
//
// Default: no report-only policy. A policy that fails its own check (see
// CSPDirective) fails construction naming this option, as does a policy with no
// directive (the zero CSPPolicy) and using it with WithCSPReportOnly.
func WithCSPReportOnlyPolicy(policy CSPPolicy) HeaderOption {
	return func(l *securityHeaders) error {
		if err := l.layerWide("WithCSPReportOnlyPolicy"); err != nil {
			return err
		}

		if policy.err != nil {
			return newConfigError("WithCSPReportOnlyPolicy was given a policy that cannot be sent: %s", policy.err)
		}

		if len(policy.directives) == 0 {
			return newConfigError("WithCSPReportOnlyPolicy was given a policy with no directive; remove the header with WithoutHeader to send none")
		}

		l.candidate = &policy

		return nil
	}
}

// WithReportingEndpoint names where browsers send policy violation reports. It
// sends Reporting-Endpoints: name="url" and adds report-to name and report-uri
// url to the document profile's policies, the enforced and the report-only
// one, because browsers differ in which of the two they honour.
//
// Default: no endpoint, and a policy carries neither directive. name must be a
// lowercase structured-field key (letters, digits, "_", "-", "." and "*",
// starting with a letter or "*"), and url an absolute https URL with no
// separator, quote or control character. A second endpoint, an endpoint with
// no policy to report from, or a bad name or URL fails construction naming this
// option. The library receives no reports: the endpoint is the consumer's.
func WithReportingEndpoint(name, endpoint string) HeaderOption {
	return func(l *securityHeaders) error {
		if err := l.layerWide("WithReportingEndpoint"); err != nil {
			return err
		}

		if !endpointName.MatchString(name) {
			return newConfigError("WithReportingEndpoint was given the name %q, which is not a "+
				"lowercase structured-field key", name)
		}

		if err := checkReportURL(endpoint); err != nil {
			return newConfigError("WithReportingEndpoint was given %q: %s", endpoint, err)
		}

		if l.endpoint != nil {
			return newConfigError("WithReportingEndpoint was given twice; a policy names one report-to group")
		}

		l.endpoint = &reportingEndpoint{name: name, url: endpoint}

		return nil
	}
}

// checkReportURL accepts an absolute https URL that can sit unquoted in a
// policy and quoted in a structured field.
func checkReportURL(raw string) error {
	if hasControl(raw) || strings.ContainsAny(raw, ";, \t\"'\\") {
		return errors.New("it holds a separator, a quote or a control character")
	}

	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return errors.New("it is not an absolute https URL")
	}

	return nil
}

// finish applies what depends on every option having been read, so the order
// the consumer gave them in does not matter: report-only mode, the candidate
// policy and the reporting endpoint. It fails on a combination that means
// nothing.
func (l *securityHeaders) finish() error {
	if l.reportOnly && l.candidate != nil {
		return newConfigError("WithCSPReportOnly and WithCSPReportOnlyPolicy were both given: " +
			"each sends Content-Security-Policy-Report-Only, and one header carries one policy")
	}

	if l.reportOnly {
		h, ok := l.document.find(headerCSP)
		if !ok {
			return newConfigError("WithCSPReportOnly was given, but the document profile sends no " +
				"Content-Security-Policy to report on")
		}

		l.document.remove(headerCSP)
		h.name = headerCSPReportOnly
		l.document.set(h)
	}

	if l.candidate != nil {
		l.document.set(profileHeader{name: headerCSPReportOnly, policy: l.candidate})
	}

	if l.endpoint == nil {
		return nil
	}

	reported := false

	for i, h := range l.document.headers {
		if h.policy == nil || (h.name != headerCSP && h.name != headerCSPReportOnly) {
			continue
		}

		p := h.policy.With(
			CSPDirective("report-to", l.endpoint.name),
			CSPDirective("report-uri", l.endpoint.url),
		)
		l.document.headers[i].policy = &p
		reported = true
	}

	if !reported {
		return newConfigError("WithReportingEndpoint was given, but the document profile sends no " +
			"policy that refers to it")
	}

	l.document.set(profileHeader{name: headerReportingEndpoints, value: l.endpoint.name + `="` + l.endpoint.url + `"`})

	return nil
}
