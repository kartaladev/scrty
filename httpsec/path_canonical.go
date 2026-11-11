package httpsec

import (
	"fmt"
	"net/url"
	"strings"
)

// refuseDotSegments refuses a request path a router could resolve to a
// different path than the one the chain judges: one holding a "." or ".."
// segment, as sent or once decoded, and one that does not decode.
//
// escaped is the path as the client sent it (Request.EscapedPath). It is
// decoded once only, because no router in scope decodes more than once: a
// double-encoded "%252e%252e" is "%2e%2e" after one decode, not a dot segment,
// and is let through. The decoded form is checked too, so "%2e%2e", ".%2e"
// and segments joined by an encoded slash ("/a%2F..%2Fb") are refused.
//
// A segment that only holds dots among other characters ("report..v2.txt",
// ".well-known", "...") and repeated slashes are not refused.
//
// The error wraps ErrMalformedRequest. A clean path, one with no "%" and no
// dot segment, is checked without allocating.
func refuseDotSegments(escaped string) error {
	if hasDotSegment(escaped) {
		return fmt.Errorf("%w: the path holds a dot segment", ErrMalformedRequest)
	}

	if !strings.Contains(escaped, "%") {
		// Nothing to decode: the decoded path is the path as sent.
		return nil
	}

	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return fmt.Errorf("%w: the path does not decode", ErrMalformedRequest)
	}

	if hasDotSegment(decoded) {
		return fmt.Errorf("%w: the decoded path holds a dot segment", ErrMalformedRequest)
	}

	return nil
}

// hasDotSegment reports whether p, split on "/", holds a segment equal to "."
// or "..".
func hasDotSegment(p string) bool {
	for len(p) > 0 {
		seg, rest, _ := strings.Cut(p, "/")
		if seg == "." || seg == ".." {
			return true
		}

		p = rest
	}

	return false
}
