package httpsec

import (
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

	for _, d := range directives {
		if err := d.check(); err != nil {
			p.err = err

			return p
		}

		d.name = strings.ToLower(d.name)

		if i := slices.IndexFunc(p.directives, func(e CSPDirectiveValue) bool { return e.name == d.name }); i >= 0 {
			p.directives[i] = d

			continue
		}

		p.directives = append(p.directives, d)
	}

	return p
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
