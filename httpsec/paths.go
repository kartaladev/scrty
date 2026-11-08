package httpsec

import (
	"path"
	"strings"
)

// checkEndpointPath refuses a built-in endpoint path that has not one shape:
// non-empty, starting with "/", not the root, in clean form once one trailing
// slash is set aside, and made only of letters, digits, "-", ".", "_", "~" and
// "/". The character set is what lets every feature publish a path, compare it
// unescaped and join it to a base path by concatenation. setting names what set
// the path, for the error. It has no override: a path outside the rule cannot be
// served correctly.
func checkEndpointPath(setting, p string) error {
	const shape = "a path starts with \"/\", is not \"/\", is clean (no \".\" or \"..\" segment, no \"//\") " +
		"once one trailing slash is set aside, and holds only letters, digits, \"-\", \".\", \"_\", \"~\" and \"/\""

	trimmed := strings.TrimSuffix(p, "/")

	switch {
	case p == "":
		return newConfigError("%s was given no path, so the endpoint would answer nothing", setting)
	case p[0] != '/':
		return newConfigError("%s was given %q, which does not start with \"/\" and so matches no request path: %s",
			setting, p, shape)
	case trimmed == "" || trimmed == "/":
		return newConfigError("%s was given the root path %q, which would claim every one-segment path of the application: %s",
			setting, p, shape)
	case path.Clean(trimmed) != trimmed:
		return newConfigError("%s was given %q, which is not in clean form: %s", setting, p, shape)
	}

	for i := 0; i < len(trimmed); i++ {
		if !endpointPathByte(trimmed[i]) {
			return newConfigError("%s was given %q, which holds %q: %s", setting, p, trimmed[i], shape)
		}
	}

	return nil
}

// endpointPathByte reports whether c may appear in an endpoint path.
func endpointPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}

	return strings.IndexByte("-._~/", c) >= 0
}
