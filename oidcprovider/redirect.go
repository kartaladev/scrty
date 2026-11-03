package oidcprovider

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// MatchRedirectURI reports whether uri is one of the client's redirect URIs,
// compared as bytes. The one exception is a native client's http URI to a loopback
// IP literal, whose port may differ and nothing else (RFC 8252 section 7.3). A
// loopback name such as localhost is not an IP literal, so it gets no exception.
func (c Client) MatchRedirectURI(uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	if c.ApplicationType != Native {
		return false
	}

	want, ok := withoutLoopbackPort(uri)
	if !ok {
		return false
	}

	return slices.ContainsFunc(c.RedirectURIs, func(registered string) bool {
		got, ok := withoutLoopbackPort(registered)

		return ok && got == want
	})
}

// withoutLoopbackPort returns uri with its port removed, when uri is http to a
// loopback IP literal. It cuts the string rather than parsing and rebuilding it,
// because a URL type would normalise what has to stay compared as bytes.
func withoutLoopbackPort(uri string) (string, bool) {
	const scheme = "http://"
	if !strings.HasPrefix(uri, scheme) {
		return "", false
	}

	rest := uri[len(scheme):]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	host, ok := loopbackHost(rest[:end])
	if !ok {
		return "", false
	}

	return scheme + host + rest[end:], true
}

// loopbackHost returns the host of authority, a loopback IP literal with or
// without a port. User information makes it not match, as it is no part of a
// loopback redirect.
func loopbackHost(authority string) (string, bool) {
	host := authority
	if cut := strings.LastIndexByte(authority, ':'); cut >= 0 && !strings.HasSuffix(authority, "]") {
		host = authority[:cut]
		if !validPort(authority[cut+1:]) {
			return "", false
		}
	}

	literal := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	addr, err := netip.ParseAddr(literal)
	if err != nil || !addr.IsLoopback() {
		return "", false
	}

	return host, true
}

func validPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)

	return err == nil && n > 0
}
