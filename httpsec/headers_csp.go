package httpsec

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// CSPDirectiveValue is one directive of a policy: a name and its sources.
type CSPDirectiveValue struct {
	name    string
	sources []string
}

// CSPDirective names a directive and its sources, for StrictCSP. A directive
// with no sources is sent as its name alone.
func CSPDirective(name string, sources ...string) CSPDirectiveValue {
	return CSPDirectiveValue{name: name, sources: sources}
}

// CSPPolicy is a Content-Security-Policy the layer renders per response.
type CSPPolicy struct {
	directives []CSPDirectiveValue

	// err is the first fault of the directives it was built from, reported
	// when the policy reaches WithCSP, because StrictCSP has no error to return.
	err error
}

// StrictCSP is the document policy: a script-src of the response's nonce and
// 'strict-dynamic', object-src 'none', base-uri 'none' and frame-ancestors
// 'none', with directives added. A directive named like one of those replaces
// its sources rather than repeating it, and names compare case-insensitively.
//
// A directive name or source holding a ";", a ",", a control character or a
// line break, or an empty or blank-holding name, makes WithCSP fail
// construction.
func StrictCSP(directives ...CSPDirectiveValue) CSPPolicy {
	p := CSPPolicy{directives: []CSPDirectiveValue{
		CSPDirective("script-src", nonceSentinel, "'strict-dynamic'"),
		CSPDirective("object-src", "'none'"),
		CSPDirective("base-uri", "'none'"),
		CSPDirective("frame-ancestors", "'none'"),
	}}

	return p.With(directives...)
}

// With returns p with directives added, under StrictCSP's rules: a directive
// named like one p has replaces its sources rather than repeating it, names
// compare case-insensitively, and one that fails its check makes WithCSP fail
// construction. p itself is not changed.
func (p CSPPolicy) With(directives ...CSPDirectiveValue) CSPPolicy {
	out := CSPPolicy{directives: slices.Clone(p.directives), err: p.err}

	for _, d := range directives {
		if out.err != nil {
			return out
		}

		if err := d.check(); err != nil {
			out.err = err

			return out
		}

		d.name = strings.ToLower(d.name)

		if i := slices.IndexFunc(out.directives, func(e CSPDirectiveValue) bool { return e.name == d.name }); i >= 0 {
			out.directives[i] = d

			continue
		}

		out.directives = append(out.directives, d)
	}

	return out
}

// hashLengths is the digest size, in bytes, of each hash algorithm a policy
// source may name.
var hashLengths = map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}

// HashCSP is the policy for a static page that is cached and so cannot carry a
// per-response nonce: a script-src listing the script hashes given, in order,
// with object-src 'none', base-uri 'none' and frame-ancestors 'none', and
// directives added with With. It generates no nonce.
//
// A hash is written "sha256-", "sha384-" or "sha512-" and the digest in base64,
// with or without the single quotes a policy puts around it. A hash that is
// not a base64 digest of its algorithm's size, and a call with no hash, make
// WithCSP fail construction naming HashCSP. The library does not read the
// page: computing the hashes is the build's job.
func HashCSP(hashes ...string) CSPPolicy {
	p := CSPPolicy{}

	if len(hashes) == 0 {
		p.err = errors.New("HashCSP was given no hash, so its script-src would admit no script")

		return p
	}

	sources := make([]string, 0, len(hashes))

	for _, h := range hashes {
		src, err := hashSource(h)
		if err != nil {
			p.err = err

			return p
		}

		sources = append(sources, src)
	}

	p.directives = []CSPDirectiveValue{
		CSPDirective("script-src", sources...),
		CSPDirective("object-src", "'none'"),
		CSPDirective("base-uri", "'none'"),
		CSPDirective("frame-ancestors", "'none'"),
	}

	return p
}

// hashSource checks h as a CSP hash source and returns it single-quoted.
func hashSource(h string) (string, error) {
	opened, closed := strings.HasPrefix(h, "'"), strings.HasSuffix(h, "'")
	if opened != closed {
		return "", fmt.Errorf("HashCSP was given %q, whose quotes are not balanced", h)
	}

	bare := strings.TrimSuffix(strings.TrimPrefix(h, "'"), "'")
	algo, digest, found := strings.Cut(bare, "-")
	size, known := hashLengths[algo]

	if !found || !known {
		return "", fmt.Errorf("HashCSP was given %q, which does not start with sha256-, sha384- or sha512-", h)
	}

	raw, err := base64.StdEncoding.Strict().DecodeString(digest)
	if err != nil || len(raw) != size {
		return "", fmt.Errorf("HashCSP was given a %s hash that is not a base64 digest of %d bytes", algo, size)
	}

	return "'" + bare + "'", nil
}

// check refuses what would end the directive early or start a header.
func (d CSPDirectiveValue) check() error {
	if d.name == "" || strings.ContainsAny(d.name, ";, \t") || hasControl(d.name) {
		return fmt.Errorf("the directive name %q is empty or holds a separator", d.name)
	}

	for _, s := range d.sources {
		if strings.ContainsAny(s, ";,") || hasControl(s) {
			return fmt.Errorf("a source of %s holds a \";\", a \",\" or a control character", d.name)
		}
	}

	return nil
}

func (p CSPPolicy) usesNonce() bool {
	for _, d := range p.directives {
		for _, s := range d.sources {
			if s == nonceSentinel {
				return true
			}
		}
	}

	return false
}

// render writes the policy with nonce in place of the sentinel. An empty nonce
// leaves the nonce source out.
func (p CSPPolicy) render(nonce string) string {
	parts := make([]string, 0, len(p.directives))

	for _, d := range p.directives {
		fields := []string{d.name}

		for _, s := range d.sources {
			if s == nonceSentinel {
				if nonce == "" {
					continue
				}

				s = "'nonce-" + nonce + "'"
			}

			fields = append(fields, s)
		}

		parts = append(parts, strings.Join(fields, " "))
	}

	return strings.Join(parts, "; ")
}
