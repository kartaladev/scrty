package httpsec

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/kartaladev/scrty/token"
)

// tokenFormat is the shape of a presented token, read without verification.
type tokenFormat int

const (
	// formatOpaque is any token that is neither of the others, a JWT that does not decode included.
	formatOpaque tokenFormat = iota

	// formatProvider is a provider's own opaque format: an access token ("at.") or a refresh token
	// ("rt."). It is read by shape, whichever chain serves the provider, and neither is ever sent to
	// an introspection source.
	formatProvider

	// formatJWT is a compact JWS whose header and payload decode to JSON objects.
	formatJWT
)

// A provider's own opaque token prefixes, the chain's own or a trusted one's alike.
const (
	providerAccessPrefix  = "at."
	providerRefreshPrefix = "rt."
)

// minTokenBound is the least a resource server reads of a token: the 8 KiB a token verifier allows
// by default.
const minTokenBound = 8 << 10

// peeked is what the routing read learned of a token. Nothing is granted on it: the source the
// token is routed to verifies it again.
type peeked struct {
	raw    string
	format tokenFormat

	// typ is the JWT's declared type, lower-cased with any "application/" prefix removed, and ""
	// when it declares none.
	typ string

	// iss is the JWT's issuer as it states it, and "" when it states none or not as a string.
	iss string
}

// accessTyped says the token is typed as an access token (RFC 9068 section 2.1).
func (t peeked) accessTyped() bool { return t.format == formatJWT && t.typ == token.TypeAccessToken }

// sessionTyped says the token is typed as one of the chain's signed session tokens: types holds
// every type the chain's session generators declare, normalized as typ is (sessionTypeOf). Such a
// token is never offered to a source, whatever issuer it names.
func (t peeked) sessionTyped(types map[string]struct{}) bool {
	if t.format != formatJWT {
		return false
	}

	_, ok := types[t.typ]

	return ok
}

// sessionTypeOf normalizes a declared token type as peek normalizes a token's typ: lower-cased,
// with any "application/" prefix removed.
func sessionTypeOf(declared string) string {
	return strings.TrimPrefix(asciiLower(declared), "application/")
}

// peek reads raw for routing. It is bounded by the caller before it is called, decodes at most the
// header and the payload, and never fails: a token it cannot read as a JWT is opaque.
func peek(raw string) peeked {
	t := peeked{raw: raw}

	if strings.HasPrefix(raw, providerAccessPrefix) || strings.HasPrefix(raw, providerRefreshPrefix) {
		t.format = formatProvider

		return t
	}

	header, rest, ok := strings.Cut(raw, ".")
	if !ok {
		return t
	}

	payload, signature, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(signature, ".") {
		return t
	}

	var h struct {
		Typ any `json:"typ"`
	}

	var p struct {
		Iss any `json:"iss"`
	}

	if !decodeSegment(header, &h) || !decodeSegment(payload, &p) {
		return t
	}

	t.format = formatJWT

	if typ, ok := h.Typ.(string); ok {
		t.typ = strings.TrimPrefix(asciiLower(typ), "application/")
	}

	if iss, ok := p.Iss.(string); ok {
		t.iss = iss
	}

	return t
}

// decodeSegment decodes one base64url segment of a compact JWS into v, which must be a JSON
// object.
func decodeSegment(segment string, v any) bool {
	if segment == "" {
		return false
	}

	b, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || len(b) == 0 || b[0] != '{' {
		return false
	}

	return json.Unmarshal(b, v) == nil
}

// asciiLower lower-cases the ASCII letters of s and leaves every other byte as it is, so a type is
// compared without regard to case the way the token package compares it.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}

		return r
	}, s)
}

// route chooses the source of rs a token goes to. refuse is true when the token is an access token
// none of its sources can take, which is refused and never handed on; a nil source with refuse
// false is a token the resource server does not recognise, which passes on.
func (rs *resourceServer) route(t peeked) (src source, refuse bool) {
	if marked := rs.marked(t); marked != nil {
		return marked, false
	}

	switch t.format {
	case formatProvider:
		// The provider's own tokens go to its source alone, never to an introspection endpoint.
		return nil, true
	case formatJWT:
		return nil, t.accessTyped()
	default:
		for _, s := range rs.sources {
			if s.recognises(t) == recFallback {
				return s, false
			}
		}

		return nil, false
	}
}

// marked returns the source of rs that t carries a mark naming, and nil when there is none.
func (rs *resourceServer) marked(t peeked) source {
	for _, s := range rs.sources {
		if s.recognises(t) == recMarked {
			return s
		}
	}

	return nil
}

// covers says whether rs covers path, a canonical path: a resource server with no prefix covers
// every path, and a prefix covers the path it names without its slash and every path beneath it,
// whole segment by whole segment, without regard to ASCII case.
func (rs *resourceServer) covers(path string) bool {
	if len(rs.prefixes) == 0 {
		return true
	}

	for _, prefix := range rs.prefixes {
		if hasPrefixFold(path, prefix) || equalFoldASCII(path, strings.TrimSuffix(prefix, "/")) {
			return true
		}
	}

	return false
}

// hasPrefixFold says s begins with prefix, without regard to ASCII case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && equalFoldASCII(s[:len(prefix)], prefix)
}

// equalFoldASCII says a and b are equal without regard to ASCII case. Every other byte, those of
// a multi-byte character included, must be equal: Unicode folding (the Kelvin sign as "k") is not
// a router's case-insensitive match.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}

		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}

		if x != y {
			return false
		}
	}

	return true
}

// canonicalPath is path as the resource servers match it: repeated slashes collapsed, so that
// "//orders//1" is judged where a router serving "/orders/1" would serve it. The chain has already
// refused a path with a dot segment.
func canonicalPath(path string) string {
	if !strings.Contains(path, "//") {
		return path
	}

	var b strings.Builder

	b.Grow(len(path))

	prev := byte(0)

	for i := range len(path) {
		c := path[i]
		if c == '/' && prev == '/' {
			continue
		}

		b.WriteByte(c)
		prev = c
	}

	return b.String()
}
