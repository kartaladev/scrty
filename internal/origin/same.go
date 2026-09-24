package origin

import "net/url"

// Same reports whether a and b have the same origin.
//
// Both values must use http or https and must have a host. Scheme and host are
// compared after ASCII case folding, a port equal to the scheme's default is
// removed, and userinfo is ignored. Nothing else is normalised:
//
//   - no Unicode case mapping and no IDNA, because both fold distinct hosts
//     together — U+0130 would become "i" and U+212A would become "k", which is
//     how an attacker's host becomes equal to a declared one;
//   - ports are compared as written, so "0443" is not "443";
//   - a trailing root label is significant, because "example.com." and
//     "example.com" are different names to anything given them literally.
//
// A value that cannot be parsed, uses another scheme or has no host matches
// nothing at all — including another such value. Two unusable strings are not
// evidence of a common origin, and treating them as one would make every
// malformed target equal to every other.
func Same(a, b string) bool {
	as, ah, ap, ok := Normalize(a)
	if !ok {
		return false
	}

	bs, bh, bp, ok := Normalize(b)
	if !ok {
		return false
	}

	return as == bs && ah == bh && ap == bp
}

// Normalize splits raw into the three parts that make up its origin, or reports
// that it has none.
//
// ok is false for anything Same refuses outright: a value that does not parse,
// one whose scheme is neither http nor https, and one with no host. When ok is
// false the three parts are empty, so a caller cannot accidentally compare the
// leftovers of a value that has no origin.
//
// port is "" when the URL carried none, and also when it carried the scheme's
// default, so that https://h and https://h:443 reduce to the same origin.
func Normalize(raw string) (scheme, host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", false
	}

	scheme = asciiLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", "", false
	}

	// Hostname drops userinfo, the port and the brackets around an IPv6
	// literal, which is exactly the part an origin is made of.
	host = asciiLower(u.Hostname())
	if host == "" {
		return "", "", "", false
	}

	port = u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	return scheme, host, port, true
}

// asciiLower folds only A-Z.
//
// strings.ToLower applies Unicode case mapping, which maps U+0130 to "i" and
// U+212A to "k". A host spelled with either would then equal one an allowlist
// declared, so the fold here stays inside ASCII.
//
// Working on bytes is safe because the only bytes it rewrites are in the ASCII
// range, and those never appear inside a multi-byte UTF-8 sequence.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}

	return string(b)
}
