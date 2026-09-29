package httpsec

// This file holds how the second-factor endpoints read the method a request
// names. The method is one path segment after the endpoint's prefix, and is
// read from the path and nowhere else: a method named in a header, the query or
// the body could be chosen by whoever built the link or the form.

import "strings"

// methodSegment returns the method named by path under prefix. It is ok only
// for prefix, then "/", then one non-empty segment with no further "/": the
// bare prefix, an empty segment, a trailing slash and an extra segment all name
// no method, so none of them can match one by accident.
//
// prefix is as mfaPrefix returns it, with no trailing slash.
func methodSegment(path, prefix string) (name string, ok bool) {
	rest, found := strings.CutPrefix(path, prefix+"/")
	if !found || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}

	return rest, true
}

// underPrefix reports whether path is prefix itself or lies below it. Every
// such path is the endpoint's own, including one that names no method, so the
// endpoint refuses it as unknown rather than letting it through to the
// application or to the gate.
func underPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// mfaPrefix validates a second-factor endpoint prefix and returns it without
// a trailing slash, so "/auth/second-factor" and "/auth/second-factor/" name
// the same endpoints.
//
// An empty prefix is refused, because the consumer asked for an endpoint that
// would then silently not exist; so is one that does not start with "/", which
// matches no request path; and so is the root, which would claim every
// one-segment path of the application as a method name.
func mfaPrefix(option, prefix string) (string, error) {
	switch {
	case prefix == "":
		return "", newConfigError("%s was given no prefix, so a session owing a second factor "+
			"would have no way to resolve it", option)
	case !strings.HasPrefix(prefix, "/"):
		return "", newConfigError("%s was given %q, which does not start with \"/\" and so "+
			"matches no request path", option, prefix)
	}

	trimmed := strings.TrimRight(prefix, "/")
	if trimmed == "" {
		return "", newConfigError("%s was given the root path %q, which would claim every "+
			"one-segment path of the application", option, prefix)
	}

	return trimmed, nil
}
