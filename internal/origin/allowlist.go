package origin

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// ErrConfig is the refusal every check in this package wraps. A redirect
// allowlist that cannot be built is a wiring fault the consumer sees from the
// constructor, never a surprise on the first request that needs it.
var ErrConfig = errors.New("origin: invalid configuration")

// Allowlist is the set of targets a flow may send a browser to when it is
// done.
//
// The zero value is not usable; build one with NewAllowlist. A value built
// from nothing at all is valid and accepts nothing, so a flow that consults it
// always lands on "/".
type Allowlist struct {
	entries      []string
	declared     []string
	entryOption  string
	originOption string
}

// NewAllowlist checks every configured target and every declared origin, and
// refuses the whole configuration if any one of them is unacceptable.
//
// An entry is acceptable in exactly two forms:
//
//   - a host-relative path: it starts with "/", the next character is neither
//     "/" nor "\", and it contains no whitespace and no control character;
//   - an absolute http or https URL with no userinfo, whose origin is one of
//     declaredOrigins.
//
// A declared origin is a scheme, a host and an optional port, optionally
// followed by a lone "/", with no other path, no query, no fragment and no
// userinfo. It must use https, except that http is permitted on a loopback
// host so a consumer can develop against one.
//
// The default is the safe one: with no declared origins, only host-relative
// targets can ever be accepted, so nothing the consumer configures can send a
// browser to another site. Declaring an origin is how a consumer overrides
// that, and it is deliberately a separate declaration from the entry, so
// widening the set of reachable sites is its own explicit act.
//
// entryOption and originOption are the names of the consumer-facing options
// the two lists arrived through. Every refusal names the offending value and
// the option that carries it, because the consumer has to know which of their
// own settings to go and change; callers therefore pass their own option
// names rather than anything this package invents.
//
// Both slices are copied, so a caller that keeps and later mutates its own
// slice cannot change what was checked.
func NewAllowlist(entries, declaredOrigins []string, entryOption, originOption string) (*Allowlist, error) {
	// Origins first: an entry is judged against them, so an undeclarable
	// origin should be reported as such rather than as an unlisted entry.
	for _, declared := range declaredOrigins {
		if err := validateDeclaredOrigin(declared, originOption); err != nil {
			return nil, err
		}
	}

	for _, entry := range entries {
		if err := validateEntry(entry, declaredOrigins, entryOption, originOption); err != nil {
			return nil, err
		}
	}

	return &Allowlist{
		entries:      slices.Clone(entries),
		declared:     slices.Clone(declaredOrigins),
		entryOption:  entryOption,
		originOption: originOption,
	}, nil
}

// Resolve returns the target to redirect to.
//
// A requested target is used only when it exactly equals a configured entry:
// no prefix matching, no case folding, no normalisation. A redirect target is
// an opaque string the consumer chose, and every way of making two of them
// equal is a way of reaching an entry that was never configured.
//
// The matched entry is re-checked rather than trusted because it passed once.
// The check is cheap, it runs on a value that is about to be handed to a
// browser, and it means a target can only be used while it is still one the
// configuration would accept today.
//
// Anything else — an unlisted value, a near miss, an empty request — becomes
// "/". Falling back rather than refusing keeps a flow that has already
// succeeded from ending in an error page over where to land afterwards.
func (a *Allowlist) Resolve(requested string) string {
	for _, entry := range a.entries {
		if requested != entry {
			continue
		}
		if validateEntry(entry, a.declared, a.entryOption, a.originOption) != nil {
			continue
		}

		return entry
	}

	return "/"
}

// validateEntry accepts a host-relative path, or an absolute URL on a declared
// origin.
//
// Those two forms are the only ones that cannot be made to point somewhere the
// consumer never declared. "//host/path" is refused although it starts with a
// slash, because a browser reads it as protocol-relative and goes to host.
// "/\host" is refused for the same reason: browsers normalise the backslash to
// a slash and follow it off-site. Whitespace and control characters are
// refused because they are how those two shapes are smuggled past a reader,
// and a legitimate target never needs one.
func validateEntry(entry string, declared []string, entryOption, originOption string) error {
	if entry == "" {
		return fmt.Errorf("%w: %s was given an empty redirect target", ErrConfig, entryOption)
	}

	if strings.HasPrefix(entry, "/") {
		if len(entry) > 1 && (entry[1] == '/' || entry[1] == '\\') {
			return fmt.Errorf(
				"%w: %s entry %q is not host-relative: a browser reads a second slash or a "+
					"backslash here as the start of a host", ErrConfig, entryOption, entry)
		}
		if strings.ContainsFunc(entry, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			return fmt.Errorf("%w: %s entry %q contains whitespace or a control character",
				ErrConfig, entryOption, entry)
		}

		return nil
	}

	u, err := url.Parse(entry)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: %s entry %q is neither a host-relative path nor an absolute URL",
			ErrConfig, entryOption, entry)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %s entry %q carries userinfo", ErrConfig, entryOption, entry)
	}
	// Same refuses any scheme but http and https, so a target on another
	// scheme can never match a declared origin.
	if !slices.ContainsFunc(declared, func(d string) bool { return Same(d, entry) }) {
		return fmt.Errorf(
			"%w: %s entry %q is on an origin that was not declared; declare it with %s",
			ErrConfig, entryOption, entry, originOption)
	}

	return nil
}

// validateDeclaredOrigin accepts a scheme, a host and an optional port, and
// nothing more.
//
// Anything beyond that is refused rather than ignored. A declared origin is
// only ever compared as an origin, so a consumer who writes a path into one is
// expressing a restriction the comparison would silently drop, and would be
// declaring a wider set of targets than they meant to.
func validateDeclaredOrigin(declared, originOption string) error {
	u, err := url.Parse(declared)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%w: %s origin %q is not a scheme, a host and an optional port",
			ErrConfig, originOption, declared)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %s origin %q carries userinfo", ErrConfig, originOption, declared)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf(
			"%w: %s origin %q carries a path, a query or a fragment; an origin is a scheme, "+
				"a host and an optional port", ErrConfig, originOption, declared)
	}

	switch scheme := asciiLower(u.Scheme); {
	case scheme == "https":
		return nil
	case scheme == "http" && isLoopback(u.Hostname()):
		return nil
	case scheme == "http":
		return fmt.Errorf(
			"%w: %s origin %q uses cleartext http, which is permitted only on a loopback host",
			ErrConfig, originOption, declared)
	default:
		return fmt.Errorf("%w: %s origin %q must use https, or http on a loopback host",
			ErrConfig, originOption, declared)
	}
}

// isLoopback reports whether host is one a request never leaves the machine
// for: the name "localhost", or a loopback IP literal. It is the one place
// cleartext is permitted, because there is no network hop to protect.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
