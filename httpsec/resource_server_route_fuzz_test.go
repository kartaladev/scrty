package httpsec

import (
	"strings"
	"testing"
)

// FuzzAccessTokenRoute fuzzes the routing read, which parses hostile input before anything is
// verified. Whatever the token, the read never panics, never routes and refuses at once, never
// sends the provider's own formats anywhere but a source that marks them, and never offers a
// session-typed token.
func FuzzAccessTokenRoute(f *testing.F) {
	for _, seed := range []string{
		"", ".", "..", "at.", "rt.x", "at.0123", "a.b.c", "eyJ0eXAiOiJhdCtqd3QifQ.eyJpc3MiOiJodHRwczovL3Nzby5leGFtcGxlLmNvbSJ9.sig",
		"eyJ0eXAiOiJzY3J0eStqd3QifQ.eyJpc3MiOiJodHRwczovL3Nzby5leGFtcGxlLmNvbSJ9.sig",
		"eyJ0eXAiOjF9.eyJpc3MiOltdfQ.x", "e30.e30.", "kc_abc", "%%%.###.!!!",
	} {
		f.Add(seed)
	}

	marked := &resourceServer{sources: []source{
		&fuzzSource{iss: "https://sso.example.com"},
		&fuzzSource{prefix: "kc_"},
	}}
	fallback := &resourceServer{sources: []source{&fuzzSource{fallback: true}}}

	f.Fuzz(func(t *testing.T, raw string) {
		tok := peek(raw)

		if tok.raw != raw {
			t.Fatalf("the read changed the token")
		}

		provider := strings.HasPrefix(raw, providerAccessPrefix) || strings.HasPrefix(raw, providerRefreshPrefix)
		if provider != (tok.format == formatProvider) {
			t.Fatalf("provider format %v for %q", tok.format, raw)
		}

		if tok.format == formatJWT && strings.Count(raw, ".") != 2 {
			t.Fatalf("a JWT read from %d segments", strings.Count(raw, ".")+1)
		}

		if tok.accessTyped() && tok.sessionTyped() {
			t.Fatalf("typed both as an access token and a session token")
		}

		for _, rs := range []*resourceServer{marked, fallback} {
			src, refuse := rs.route(tok)
			if src != nil && refuse {
				t.Fatalf("routed and refused at once")
			}

			if src != nil && tok.format == formatProvider {
				t.Fatalf("the provider's own format was routed to a source that does not mark it")
			}

			if src != nil && tok.sessionTyped() && src.recognises(tok) != recMarked {
				t.Fatalf("a session token was offered by fallback")
			}
		}
	})
}

// fuzzSource is a source for the fuzz target: it marks tokens as the real sources do, and is never
// asked to verify.
type fuzzSource struct {
	source

	iss, prefix string
	fallback    bool
}

func (s *fuzzSource) recognises(t peeked) recognition {
	switch {
	case t.format == formatJWT && s.iss != "" && t.iss == s.iss:
		return recMarked
	case t.format == formatOpaque && s.prefix != "" && strings.HasPrefix(t.raw, s.prefix):
		return recMarked
	case t.format == formatOpaque && s.fallback:
		return recFallback
	default:
		return recNone
	}
}
