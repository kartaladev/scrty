package httpsec

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// optionTrustedProxies names the option every trusted-proxy configuration
// error is reported under.
const optionTrustedProxies = "EnableTrustedProxies"

// ForwardedField is one value a trusted proxy's forwarded headers may supply:
// ForwardedFor (the client address), ForwardedProto (the scheme) or
// ForwardedHost (the host, with its allowlist). Only the fields named in the
// header family are read; every other one is ignored, even from a trusted
// proxy, because a proxy that does not overwrite a header passes the client's
// own value through.
//
// The set is closed: the library's three fields are the only implementations.
type ForwardedField interface {
	forwardedField()
}

// forwardedName is a field that carries nothing but its name.
type forwardedName uint8

func (forwardedName) forwardedField() {}

const (
	// ForwardedFor trusts the client address: X-Forwarded-For, or the "for"
	// parameter of RFC 7239 Forwarded.
	ForwardedFor forwardedName = iota + 1

	// ForwardedProto trusts the scheme: X-Forwarded-Proto, or the "proto"
	// parameter of RFC 7239 Forwarded. Only "http" and "https" are accepted.
	ForwardedProto
)

// forwardedHost is ForwardedHost's field: the host, and the hosts it may name.
type forwardedHost struct{ allowed []string }

func (forwardedHost) forwardedField() {}

// ForwardedHost trusts the host, X-Forwarded-Host or the "host" parameter of
// RFC 7239 Forwarded, and names the hosts a forwarded host may be.
//
// The allowlist is required: the resolved host feeds the CSRF check, the DPoP
// htu and the links the library builds, so a host a client can choose is
// never trusted. There is no default list. Each allowed host is a bare host
// name, such as "app.example.com", or a bracketed IPv6 address; an empty one,
// or one carrying a scheme, a port, a path, a query or userinfo, is a
// configuration error. A port is refused because a forwarded host is compared
// without its port, so an allowed host with one could never match.
func ForwardedHost(allowed ...string) ForwardedField {
	return forwardedHost{allowed: append([]string(nil), allowed...)}
}

// familyKind is which forwarded header family a HeaderFamily reads.
type familyKind uint8

const (
	familyNone familyKind = iota
	familyXForwarded
	familyForwarded
)

// HeaderFamily is the one forwarded header family the chain reads, and the
// fields of it the consumer trusts. Build one with XForwarded or Forwarded;
// the zero value names no family and is a configuration error.
type HeaderFamily struct {
	kind   familyKind
	fields []ForwardedField
}

// XForwarded reads the X-Forwarded-For, X-Forwarded-Proto and
// X-Forwarded-Host headers, each only when its field is named.
// X-Forwarded-Port and X-Forwarded-Prefix are never read.
func XForwarded(fields ...ForwardedField) HeaderFamily {
	return HeaderFamily{kind: familyXForwarded, fields: append([]ForwardedField(nil), fields...)}
}

// Forwarded reads the RFC 7239 Forwarded header's "for", "proto" and "host"
// parameters, each only when its field is named.
func Forwarded(fields ...ForwardedField) HeaderFamily {
	return HeaderFamily{kind: familyForwarded, fields: append([]ForwardedField(nil), fields...)}
}

// TrustedProxies is the trusted-proxy configuration EnableTrustedProxies
// takes.
type TrustedProxies struct {
	// Prefixes are the addresses of the proxies whose forwarded headers are
	// believed. A request whose transport peer is outside every prefix has
	// its forwarded headers ignored. At least one is required, and a prefix
	// covering every IPv4 or every IPv6 address is refused unless
	// TrustAllProxies is given.
	Prefixes []netip.Prefix

	// Headers is the one header family read, and the fields of it trusted.
	Headers HeaderFamily

	// MaxHops is how many trusted proxies, the transport peer included, a
	// request may have passed through. Zero means the default, 1: only the
	// peer is skipped, and the address it forwarded is the client. A negative
	// value is a configuration error.
	MaxHops int
}

// ProxyOption tunes EnableTrustedProxies. A nil ProxyOption is skipped.
type ProxyOption func(*proxySettings)

// proxySettings is what the ProxyOptions set.
type proxySettings struct {
	trustAll    bool
	keepHeaders bool

	// certHeader is WithClientCertificateHeader's header name, canonicalised
	// at construction, and certDecode its decoder, nil for the default.
	certHeader    string
	certHeaderSet bool
	certDecode    func(string) (*x509.Certificate, error)
}

// TrustAllProxies states that every peer is a trusted proxy, which is what
// lets TrustedProxies.Prefixes hold 0.0.0.0/0 or ::/0.
//
// Default: a catch-all prefix is refused, because trusting every peer lets any
// client choose its own address, scheme and host. It exists for tests and for
// a deployment that no client can reach except through the proxy.
func TrustAllProxies() ProxyOption {
	return func(s *proxySettings) { s.trustAll = true }
}

// KeepForwardedHeaders leaves the forwarded headers on the request after the
// chain has read them.
//
// Default: they are removed from every request, so code behind the chain
// cannot read them again with looser rules.
func KeepForwardedHeaders() ProxyOption {
	return func(s *proxySettings) { s.keepHeaders = true }
}

// EnableTrustedProxies believes the forwarded headers of the proxies tp names,
// for the client address, the scheme and the host the chain and the handler
// read (Request.ClientIP, Request.Secure, Request.Host and ClientFromContext).
//
// Default: off. The client is the transport peer, the scheme is the
// connection's, the host is the Host header, and no forwarded header is read
// or removed.
//
// Once enabled, every control is on, and each is replaced only as stated:
//
//   - Only a request whose transport peer is within tp.Prefixes has its
//     forwarded headers read; every other request is resolved from its
//     transport. A catch-all prefix is refused unless TrustAllProxies is given.
//   - Only the one family tp.Headers names is read (XForwarded or Forwarded),
//     and of it only the fields named: ForwardedFor, ForwardedProto,
//     ForwardedHost.
//   - Repeated header lines are joined in order and read right to left,
//     skipping trusted addresses for at most tp.MaxHops hops, 1 by default;
//     the first address not skipped is the client. An entry the walk reaches
//     that is not one IP address leaves the request with no client address,
//     never the proxy's.
//   - The scheme and host come from the client's hop. A forwarded host must
//     be one of ForwardedHost's allowed hosts, compared by name,
//     case-insensitively, without a trailing dot or the port; any other, or
//     one that is not a host name with an optional port, refuses the request
//     with ErrHostNotAllowed (400) before any interceptor runs. The resolved
//     host is lower-cased.
//   - Forwarded, every X-Forwarded-* header and the WithClientCertificateHeader
//     header are removed from every request after resolution, trusted peer or
//     not, so code behind the chain cannot read them again with looser rules.
//     KeepForwardedHeaders keeps them.
//
// It may be given once; a second call is a configuration error, as is giving
// it beside WithHTTPSDeployment.
func EnableTrustedProxies(tp TrustedProxies, opts ...ProxyOption) Option {
	return func(c *config) error {
		if c.proxies != nil {
			return newConfigError("%s was given twice; one chain has one trusted-proxy configuration",
				optionTrustedProxies)
		}

		p, err := newTrustedProxies(tp, applyProxyOptions(opts))
		if err != nil {
			return err
		}

		c.proxies = p

		c.enable(optionTrustedProxies, func() error {
			if c.httpsDeployment {
				return newConfigError("%s and WithHTTPSDeployment were both given: the scheme comes "+
					"either from the trusted proxies' forwarded headers or from the declaration, "+
					"never both; keep one", optionTrustedProxies)
			}

			return nil
		})

		return nil
	}
}

// applyProxyOptions applies opts over the defaults, skipping a nil option.
func applyProxyOptions(opts []ProxyOption) proxySettings {
	var s proxySettings

	for _, o := range opts {
		if o != nil {
			o(&s)
		}
	}

	return s
}

// WithHTTPSDeployment declares that every request reached the deployment over
// TLS, for one whose TLS ends upstream and that forwards no headers. Every
// request is then judged secure; the client address and the host still come
// from the transport peer and the Host header.
//
// Default: a request is secure only when its own connection is TLS.
//
// It switches no feature on, so it is a With option, and it conflicts with
// EnableTrustedProxies, which answers the scheme from the forwarded headers:
// giving both is a configuration error.
func WithHTTPSDeployment() Option {
	return func(c *config) error {
		c.httpsDeployment = true

		return nil
	}
}

// defaultMaxHops is the hop limit when TrustedProxies.MaxHops is zero: only
// the transport peer is a trusted hop.
const defaultMaxHops = 1

// trustedProxies is a validated TrustedProxies, frozen at construction.
type trustedProxies struct {
	// prefixes are the trusted prefixes, masked, with an IPv4-mapped prefix
	// held as its IPv4 prefix so an unmapped peer is compared against it.
	prefixes []netip.Prefix

	family familyKind

	// readFor, readProto and readHost record which fields the family names.
	readFor, readProto, readHost bool

	// allowed is ForwardedHost's allowlist, lower-cased without a trailing dot.
	allowed []string

	maxHops int

	settings proxySettings
}

// newTrustedProxies validates tp and s, naming the setting at fault, and
// returns the frozen configuration. Every slice is copied, so the consumer
// changing theirs afterwards changes nothing.
func newTrustedProxies(tp TrustedProxies, s proxySettings) (*trustedProxies, error) {
	p := &trustedProxies{family: tp.Headers.kind, maxHops: tp.MaxHops, settings: s}

	prefixes, err := checkPrefixes(tp.Prefixes, s.trustAll)
	if err != nil {
		return nil, err
	}

	p.prefixes = prefixes

	if err := p.setFields(tp.Headers); err != nil {
		return nil, err
	}

	if s.certHeaderSet {
		if !validHeaderName(s.certHeader) {
			return nil, newConfigError("%s: WithClientCertificateHeader was given an empty name, or one "+
				"that is not a header name", optionTrustedProxies)
		}

		p.settings.certHeader = textproto.CanonicalMIMEHeaderKey(s.certHeader)
	}

	switch {
	case p.maxHops < 0:
		return nil, newConfigError("%s was given TrustedProxies.MaxHops %d; it must be at least one, "+
			"or zero for the default of one", optionTrustedProxies, p.maxHops)
	case p.maxHops == 0:
		p.maxHops = defaultMaxHops
	}

	return p, nil
}

// checkPrefixes refuses an empty list, an invalid prefix and, unless trustAll,
// a prefix covering every address of its family, and returns the prefixes
// normalised for comparison with an unmapped, zoneless peer.
func checkPrefixes(in []netip.Prefix, trustAll bool) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, newConfigError("%s needs at least one proxy prefix in TrustedProxies.Prefixes",
			optionTrustedProxies)
	}

	out := make([]netip.Prefix, 0, len(in))

	for i, pfx := range in {
		if !pfx.IsValid() {
			return nil, newConfigError("%s was given an invalid prefix in TrustedProxies.Prefixes at index %d",
				optionTrustedProxies, i)
		}

		pfx = pfx.Masked()
		if pfx.Addr().Is4In6() && pfx.Bits() >= 96 {
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
		}

		if pfx.Bits() == 0 && !trustAll {
			return nil, newConfigError("%s was given %s in TrustedProxies.Prefixes, which trusts every peer; "+
				"list the proxies' own prefixes, or give TrustAllProxies() to state that every peer is trusted",
				optionTrustedProxies, pfx)
		}

		out = append(out, pfx)
	}

	return out, nil
}

// setFields records the family's fields, refusing no family, no field, a nil
// field and a host field without a valid allowlist.
func (p *trustedProxies) setFields(h HeaderFamily) error {
	if h.kind == familyNone {
		return newConfigError("%s needs a header family in TrustedProxies.Headers: XForwarded(...) or Forwarded(...)",
			optionTrustedProxies)
	}

	if len(h.fields) == 0 {
		return newConfigError("%s needs at least one field named in TrustedProxies.Headers: "+
			"ForwardedFor, ForwardedProto or ForwardedHost(...)", optionTrustedProxies)
	}

	for i, f := range h.fields {
		switch f := f.(type) {
		case forwardedName:
			switch f {
			case ForwardedFor:
				p.readFor = true
			case ForwardedProto:
				p.readProto = true
			}
		case forwardedHost:
			if err := p.allowHosts(f.allowed); err != nil {
				return err
			}
		default:
			return newConfigError("%s was given a nil field in TrustedProxies.Headers at index %d",
				optionTrustedProxies, i)
		}
	}

	return nil
}

// allowHosts adds allowed to the host allowlist, refusing an empty list and a
// host that is not a bare host name. The host itself is never put in the
// error.
func (p *trustedProxies) allowHosts(allowed []string) error {
	if len(allowed) == 0 {
		return newConfigError("%s: ForwardedHost needs at least one allowed host; a forwarded host "+
			"is never trusted without an allowlist", optionTrustedProxies)
	}

	for i, h := range allowed {
		name := strings.TrimSuffix(strings.ToLower(h), ".")
		if name == "" || strings.ContainsAny(name, "/@?#\\ \t") {
			return newConfigError("%s: ForwardedHost was given an allowed host at index %d that is empty "+
				"or carries a scheme, a path, a query or userinfo; give a bare host name such as "+
				"app.example.com", optionTrustedProxies, i)
		}

		if hostHasPort(name) {
			return newConfigError("%s: ForwardedHost was given an allowed host at index %d that carries a "+
				"port; a forwarded host is compared without its port, so give the host name alone",
				optionTrustedProxies, i)
		}

		if strings.HasPrefix(name, "[") {
			_, canonical, ok := canonicalHost(name)
			if !ok {
				return newConfigError("%s: ForwardedHost was given an allowed host at index %d that is "+
					"bracketed but not an IPv6 address", optionTrustedProxies, i)
			}

			name = canonical
		} else if !validRegName(name) {
			return newConfigError("%s: ForwardedHost was given an allowed host at index %d that is not "+
				"a valid host name and so could never match; use ASCII letters, digits, \"-\", \"_\" and "+
				"\".\" in non-empty labels that do not start or end with \"-\"", optionTrustedProxies, i)
		}

		p.allowed = append(p.allowed, name)
	}

	p.readHost = true

	return nil
}

// The headers each family reads.
const (
	headerForwarded       = "Forwarded"
	headerXForwardedFor   = "X-Forwarded-For"
	headerXForwardedProto = "X-Forwarded-Proto"
	headerXForwardedHost  = "X-Forwarded-Host"
)

// resolution is what resolving one request produced: the Client, whether its
// host came from a forwarded header, and how many forwarded address entries
// were parsed, which is how a test proves the walk stops at the client.
type resolution struct {
	client Client

	// forwardedHost reports whether client.Host came from a trusted proxy's
	// forwarded header. Only such a host is judged against the allowlist: the
	// request's own Host header never is.
	forwardedHost bool

	// trustedPeer reports whether the transport peer is a trusted proxy,
	// whose own connection certificate is then never the client's.
	trustedPeer bool

	// forwardedCert is the raw value of the WithClientCertificateHeader
	// header a trusted peer sent, kept before the header is removed so
	// certificate binding can decode it, and "" when no header is named, the
	// peer is not trusted, or the header is absent or repeated. An untrusted
	// peer's value is never kept.
	forwardedCert string

	parsed int
}

// resolve answers the Client of r.
//
// A peer outside every trusted prefix, or one that does not parse, has every
// forwarded header ignored: the client, scheme and host are the transport's.
// A forwarded host on none of the allowed hosts fails with ErrHostNotAllowed,
// whose text never names it.
func (p *trustedProxies) resolve(r Request) (resolution, error) {
	res := resolution{client: Client{IP: r.ClientIP(), Secure: r.Secure(), Host: r.Host()}}

	peer, ok := parseAddr(res.client.IP)
	if !ok || !p.trusted(peer) {
		return res, nil
	}

	res.trustedPeer = true

	// Only a single line is kept: a proxy sets the header once, and a second
	// line could only be the client's own, which must not be chosen between.
	if p.settings.certHeader != "" {
		if lines := r.HeaderValues(p.settings.certHeader); len(lines) == 1 {
			res.forwardedCert = lines[0]
		}
	}

	if p.family == familyForwarded {
		res = p.resolveForwarded(r, res)
	} else {
		res = p.resolveXForwarded(r, res)
	}

	if res.forwardedHost {
		host, name, ok := canonicalHost(res.client.Host)
		if !ok || !slices.Contains(p.allowed, strings.TrimSuffix(name, ".")) {
			return resolution{}, ErrHostNotAllowed
		}

		// Rebuilt from the validated name and port, never the sent text: a
		// trailing dot is not part of the name the allowlist matched.
		res.client.Host = strings.TrimSuffix(name, ".") + host[len(name):]
	}

	return res, nil
}

// canonicalHost validates a forwarded host and returns it lower-cased, as name
// or name:port, together with its name. A name is a registered name of
// letters, digits, "-", "_" and ".", or a bracketed IPv6 address, which is
// returned in its canonical form; a port is one to five digits, at most
// 65535. Anything else, such as userinfo, a path, an empty or out-of-range
// port, or any other character, is not ok.
func canonicalHost(v string) (host, name string, ok bool) {
	v = strings.ToLower(v)

	var port string

	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return "", "", false
		}

		addr, err := netip.ParseAddr(v[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", false
		}

		name = "[" + addr.String() + "]"

		switch rest := v[end+1:]; {
		case rest == "":
		case rest[0] == ':':
			port = rest[1:]
			if !validNumericPort(port) {
				return "", "", false
			}
		default:
			return "", "", false
		}
	} else {
		name = v
		if i := strings.IndexByte(v, ':'); i >= 0 {
			name, port = v[:i], v[i+1:]
			if !validNumericPort(port) {
				return "", "", false
			}
		}

		if !validRegName(name) {
			return "", "", false
		}
	}

	if port == "" {
		return name, name, true
	}

	return name + ":" + port, name, true
}

// validRegName reports whether name, lower case and with at most one trailing
// dot, is a registered name: non-empty labels of regNameChars that neither
// start nor end with "-". The allowlist check at construction and
// canonicalHost both use it, so a host the allowlist accepts is one a request
// can carry.
func validRegName(name string) bool {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, l := range labels {
		if l == "" || strings.Trim(l, regNameChars) != "" || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}

	return true
}

// regNameChars are the characters a forwarded host name may hold.
const regNameChars = "abcdefghijklmnopqrstuvwxyz0123456789-_"

// validNumericPort reports whether s is one to five digits naming a port no
// larger than 65535.
func validNumericPort(s string) bool {
	if s == "" || len(s) > 5 || strings.Trim(s, "0123456789") != "" {
		return false
	}

	n, err := strconv.Atoi(s)

	return err == nil && n <= 65535
}

// forwardedHeader reports whether name is a header the chain removes after
// resolution: Forwarded, any X-Forwarded-* header, or the named
// client-certificate header.
func (p *trustedProxies) forwardedHeader(name string) bool {
	const xPrefix = "X-Forwarded-"

	return strings.EqualFold(name, headerForwarded) ||
		(len(name) >= len(xPrefix) && strings.EqualFold(name[:len(xPrefix)], xPrefix)) ||
		(p.settings.certHeader != "" && strings.EqualFold(name, p.settings.certHeader))
}

// trusted reports whether addr, unmapped and zoneless, is within a trusted
// prefix.
func (p *trustedProxies) trusted(addr netip.Addr) bool {
	for _, pfx := range p.prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}

	return false
}

// hop is where the walk of a forwarded address list stopped: the client's
// entry, counted from the right starting at one, and its address, or no
// address when the entry is not a single IP address.
type hop struct {
	pos    int
	addr   netip.Addr
	parsed int
}

// walk reads the entries of lines from the right, skipping trusted entries
// until the transport peer and the skipped entries make maxHops trusted hops,
// and stops at the first entry that is not skipped: the client. When every
// entry is skipped, the left-most is the client. parse turns an entry into its
// address; an entry it cannot read stops the walk with no address. It returns
// the zero hop for an empty list.
func (p *trustedProxies) walk(lines []string, parse func(entry string) (netip.Addr, bool)) hop {
	var h hop

	hops := 1 // the transport peer
	w := newRightWalker(lines)

	for {
		entry, ok := w.next()
		if !ok {
			return h // every entry trusted: h is the left-most
		}

		h.pos++
		h.parsed++

		addr, ok := parse(entry)
		if !ok {
			h.addr = netip.Addr{}

			return h
		}

		h.addr = addr

		if hops >= p.maxHops || !p.trusted(addr) {
			return h
		}

		hops++
	}
}

// resolveXForwarded resolves res from the X-Forwarded-* headers the family
// names. The scheme and host come from the client's hop: a list holding one
// value is that value, as the nearest trusted proxy set it, and a list as long
// as the address list is read at the client's position. Any other length is
// ignored, as is a scheme other than http or https.
func (p *trustedProxies) resolveXForwarded(r Request, res resolution) resolution {
	var (
		h     hop
		addrs int
	)

	if p.readFor {
		if lines := r.HeaderValues(headerXForwardedFor); len(lines) > 0 {
			h = p.walk(lines, parseNode)
			addrs = countEntries(lines)
			res.client.IP = addrString(h.addr)
			res.client.ViaProxy = true
		}
	}

	if p.readProto {
		if v, ok := atHop(r.HeaderValues(headerXForwardedProto), h.pos, addrs); ok {
			if secure, ok := parseScheme(v); ok {
				res.client.Secure = secure
				res.client.ViaProxy = true
			}
		}
	}

	if p.readHost {
		if v, ok := atHop(r.HeaderValues(headerXForwardedHost), h.pos, addrs); ok && v != "" {
			res.client.Host = v
			res.client.ViaProxy = true
			res.forwardedHost = true
		}
	}

	res.parsed = h.parsed

	return res
}

// atHop is the value of a scheme or host list at the client's hop: its only
// value when it holds one, or its entry at pos from the right when it holds
// as many entries as the address list, addrs. Any other list is not ok.
func atHop(lines []string, pos, addrs int) (string, bool) {
	n := countEntries(lines)

	switch {
	case n == 1:
		return trimOWS(lines[0]), true
	case n == 0 || pos == 0 || n != addrs:
		return "", false
	}

	w := newRightWalker(lines)

	var v string
	for range pos {
		v, _ = w.next()
	}

	return v, true
}

// countEntries is how many comma-separated entries lines hold, counted
// without parsing any of them.
func countEntries(lines []string) int {
	n := 0
	for _, l := range lines {
		n += strings.Count(l, ",") + 1
	}

	return n
}

// resolveForwarded resolves res from the RFC 7239 Forwarded header: the client
// from the "for" parameters, and the scheme and host from the element that
// named it.
func (p *trustedProxies) resolveForwarded(r Request, res resolution) resolution {
	lines := r.HeaderValues(headerForwarded)
	if len(lines) == 0 {
		return res
	}

	var el forwardedElement

	if p.readFor {
		h := p.walk(lines, func(entry string) (netip.Addr, bool) {
			el = parseForwardedElement(entry)
			if !el.ok {
				return netip.Addr{}, false
			}

			return parseNode(el.forNode)
		})

		res.parsed = h.parsed
		res.client.IP = addrString(h.addr)
		res.client.ViaProxy = true
	} else {
		// No client address is trusted, so the hop is the nearest proxy's:
		// the right-most element.
		entry, _ := newRightWalker(lines).next()
		el = parseForwardedElement(entry)
	}

	if p.readProto && el.ok && el.proto != "" {
		if secure, ok := parseScheme(el.proto); ok {
			res.client.Secure = secure
			res.client.ViaProxy = true
		}
	}

	if p.readHost && el.ok && el.host != "" {
		res.client.Host = el.host
		res.client.ViaProxy = true
		res.forwardedHost = true
	}

	return res
}

// addrString is addr's text, and "" for no address.
func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}

	return addr.String()
}

// parseScheme reads a forwarded scheme: secure for "https", not for "http",
// compared case-insensitively, and not ok for anything else.
func parseScheme(v string) (secure, ok bool) {
	switch {
	case strings.EqualFold(v, "https"):
		return true, true
	case strings.EqualFold(v, "http"):
		return false, true
	default:
		return false, false
	}
}

// rightWalker yields the comma-separated entries of a header's lines from the
// right: the last line's last entry first. Each entry is cut from the line
// with strings.LastIndexByte, so a walk that stops early never looks at the
// entries to the left of where it stopped, however long the line.
//
// Commas inside an RFC 7239 quoted-string are not honoured. No value the
// chain reads may contain one, so such an entry fails to parse and leaves no
// client, rather than naming one.
type rightWalker struct {
	lines  []string
	line   int
	rest   string
	inLine bool
}

func newRightWalker(lines []string) *rightWalker {
	return &rightWalker{lines: lines, line: len(lines)}
}

// next returns the next entry to the left, trimmed of optional whitespace, and
// false once every line is exhausted.
func (w *rightWalker) next() (string, bool) {
	if !w.inLine {
		if w.line == 0 {
			return "", false
		}

		w.line--
		w.rest = w.lines[w.line]
		w.inLine = true
	}

	if i := strings.LastIndexByte(w.rest, ','); i >= 0 {
		entry := w.rest[i+1:]
		w.rest = w.rest[:i]

		return trimOWS(entry), true
	}

	w.inLine = false

	return trimOWS(w.rest), true
}

// trimOWS trims HTTP's optional whitespace.
func trimOWS(s string) string { return strings.Trim(s, " \t") }

// parseAddr parses a bare address, IPv4-mapped IPv6 unmapped and any zone
// dropped, so it compares with the trusted prefixes as the address it names.
func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr.Unmap().WithZone(""), true
}

// parseNode parses one forwarded address entry: a bare IPv4 or IPv6 address,
// an IPv4 address with a port, or a bracketed IPv6 address with or without a
// port. The port is discarded. Anything else, "unknown" and an obfuscated
// identifier included, is not ok.
func parseNode(s string) (netip.Addr, bool) {
	if addr, ok := parseAddr(s); ok {
		return addr, true
	}

	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return netip.Addr{}, false
		}

		if rest := s[end+1:]; rest != "" && (rest[0] != ':' || !validPort(rest[1:])) {
			return netip.Addr{}, false
		}

		// Is6 is asked of the address as written, before it is unmapped, so a
		// bracketed IPv4-mapped address is accepted and then compared as the
		// IPv4 address it names; a bracketed bare IPv4 address is not.
		addr, err := netip.ParseAddr(s[1:end])
		if err != nil || !addr.Is6() {
			return netip.Addr{}, false
		}

		return addr.Unmap().WithZone(""), true
	}

	host, port, found := strings.Cut(s, ":")
	if !found || !validPort(port) {
		return netip.Addr{}, false
	}

	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}

	return addr, true
}

// validPort reports whether s is a port: one to five digits, or an RFC 7239
// obfuscated port ("_" followed by letters, digits, ".", "_" or "-").
func validPort(s string) bool {
	if s == "" {
		return false
	}

	if s[0] == '_' {
		return len(s) > 1 && strings.Trim(s[1:], obfuscatedChars) == ""
	}

	return len(s) <= 5 && strings.Trim(s, "0123456789") == ""
}

const obfuscatedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"

// forwardedElement is one RFC 7239 element's parameters the chain reads. ok
// is false for an element that does not parse: a pair with no "=", a
// parameter given twice, or a malformed quoted-string.
type forwardedElement struct {
	forNode, proto, host string
	ok                   bool
}

// parseForwardedElement parses one element: pairs separated by ";", each a
// case-insensitive name, "=", and a token or a quoted-string. A
// quoted-string holding a backslash escape is refused rather than unescaped:
// no value the chain reads needs one.
func parseForwardedElement(s string) forwardedElement {
	var (
		el                           forwardedElement
		seenFor, seenProto, seenHost bool
	)

	for pair := range strings.SplitSeq(s, ";") {
		pair = trimOWS(pair)
		if pair == "" {
			continue
		}

		name, value, found := strings.Cut(pair, "=")
		if !found {
			return forwardedElement{}
		}

		value, ok := unquote(value)
		if !ok {
			return forwardedElement{}
		}

		var seen *bool

		switch {
		case strings.EqualFold(name, "for"):
			seen, el.forNode = &seenFor, value
		case strings.EqualFold(name, "proto"):
			seen, el.proto = &seenProto, value
		case strings.EqualFold(name, "host"):
			seen, el.host = &seenHost, value
		default:
			continue
		}

		if *seen {
			return forwardedElement{}
		}

		*seen = true
	}

	el.ok = true

	return el
}

// unquote returns a token unchanged and a quoted-string's content, refusing
// an unterminated quote, an inner quote and a backslash escape.
func unquote(v string) (string, bool) {
	if !strings.HasPrefix(v, `"`) {
		return v, !strings.ContainsAny(v, `"\`)
	}

	if len(v) < 2 || !strings.HasSuffix(v, `"`) {
		return "", false
	}

	inner := v[1 : len(v)-1]

	return inner, !strings.ContainsAny(inner, `"\`)
}

// WithClientCertificateHeader names the header in which a trusted proxy that
// terminates TLS forwards the client's certificate, and how to decode it.
//
// Once a header is named, Request.ClientCertificate answers the forwarded
// certificate to every interceptor inside the chain, whether or not
// certificate binding (EnableCertificateBinding) is enabled; an interceptor of
// the consumer's that judges the client by its certificate sees the answer the
// binding judges.
//
// The header is read only from a peer within TrustedProxies.Prefixes, and only
// when it is sent once: on two lines it is ignored, and the request has no
// certificate. A request from any other peer keeps its own connection's
// certificate, and a request from a trusted proxy never has the proxy's own
// connection certificate taken for the client's. Its raw value is kept before
// the header is removed, and decoded once, the first time the request's
// certificate is asked for (Request.ClientCertificate).
//
// The proxy must overwrite or strip the named header on every request,
// including a request that arrives without a client certificate. A proxy that
// sets it only when it has a certificate passes on a copy the client sent, and
// the library cannot tell that copy from the proxy's own.
//
// A nil decode selects the default: the value is a URL-encoded PEM
// certificate, as nginx's $ssl_client_escaped_cert writes it, percent-decoded
// with "+" read as itself and, failing that, as a space (as Go's
// url.QueryEscape writes one). The decoded text must be exactly one
// CERTIFICATE PEM block that parses, with nothing but whitespace before and
// after it: several blocks, text around the block, or a block that does not
// parse is no certificate, so a client's line folded into the proxy's own
// cannot choose the certificate read. A decode of the consumer's own reads any
// other format, such as base64 DER; it is handed the header's value as
// received, and it carries that rule for its format itself. A value decode
// refuses, or answers with no certificate, leaves the request with no
// certificate, so a certificate-bound token on it is refused. The certificate
// is not validated here either: the proxy that terminated TLS judged it.
//
// Default: no certificate header is named, and none is read. The named header
// is removed from every request after resolution, with the forwarded headers,
// unless KeepForwardedHeaders is given. An empty name, or one that is not a
// header name, is a configuration error.
func WithClientCertificateHeader(name string, decode func(string) (*x509.Certificate, error)) ProxyOption {
	return func(s *proxySettings) {
		s.certHeader, s.certHeaderSet = name, true
		s.certDecode = decode
	}
}

// errUndecodableCertificate is decodeEscapedPEM's refusal of a value that is
// not a URL-encoded PEM certificate. Its text carries nothing of the value.
var errUndecodableCertificate = errors.New("httpsec: the forwarded client certificate does not decode")

// decodeEscapedPEM decodes a client certificate a proxy forwarded as
// URL-encoded PEM, the default decoder of WithClientCertificateHeader.
//
// The value is percent-decoded with "+" read as itself, which is how nginx's
// $ssl_client_escaped_cert must be read, since a PEM body may hold "+"; a
// value that then holds no PEM certificate is decoded again with "+" read as
// a space, as an encoder for HTML forms (Go's url.QueryEscape) writes it.
//
// The decoded text must be exactly one CERTIFICATE PEM block that parses, with
// nothing but whitespace before and after it. A proxy that folds a line the
// client sent into its own, or a client's text that comes ahead of the
// proxy's, would otherwise let the client choose which certificate is read.
// Anything else is an error, whose text carries nothing of the value.
func decodeEscapedPEM(value string) (*x509.Certificate, error) {
	for _, unescape := range []func(string) (string, error){url.PathUnescape, url.QueryUnescape} {
		text, err := unescape(value)
		if err != nil {
			continue
		}

		if cert, ok := onlyCertificate(text); ok {
			return cert, nil
		}
	}

	return nil, errUndecodableCertificate
}

// onlyCertificate parses text as one CERTIFICATE PEM block and nothing else,
// bar whitespace around it. pem.Decode skips text ahead of a block and steps
// over a block it cannot decode to the next one, so the text must start at
// the block and hold no second marker, or the certificate read might not be
// the first thing the text says.
func onlyCertificate(text string) (*x509.Certificate, bool) {
	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, pemBegin) || strings.Count(text, pemBegin) != 1 {
		return nil, false
	}

	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}

	return cert, true
}

// pemBegin opens every PEM block.
const pemBegin = "-----BEGIN "

// hostHasPort reports whether host, lower-cased and without a trailing dot,
// carries a port: anything after a bracketed IPv6 literal's closing bracket,
// or a colon in a host that is not bracketed.
func hostHasPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')

		return end < 0 || end != len(host)-1
	}

	return strings.Contains(host, ":")
}

// validHeaderName reports whether name is a non-empty RFC 9110 token.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}

	for i := range len(name) {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),/:;<=>?@[\]{}`, c) >= 0 {
			return false
		}
	}

	return true
}
