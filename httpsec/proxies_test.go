package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// proxyNet is the trusted proxies' network every resolution case uses.
var proxyNet = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}

func TestTrustedProxies_Construction(t *testing.T) {
	t.Parallel()

	// refused asserts a configuration error whose text names every one of names.
	refused := func(names ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	built := func(t *testing.T, err error) { require.NoError(t, err) }

	// refusedWithout is refused, and the refusal never echoes the value.
	refusedWithout := func(value string, names ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			refused(names...)(t, err)
			assert.NotContains(t, err.Error(), value)
		}
	}

	xff := httpsec.XForwarded(httpsec.ForwardedFor)

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a valid configuration builds",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet,
				Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
					httpsec.ForwardedHost("app.example.com")),
			})},
			assert: built,
		},
		{
			name:   "no prefixes",
			opts:   []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Headers: xff})},
			assert: refused("EnableTrustedProxies", "Prefixes"),
		},
		{
			name: "an invalid prefix",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: []netip.Prefix{proxyNet[0], {}}, Headers: xff,
			})},
			assert: refused("EnableTrustedProxies", "Prefixes"),
		},
		{
			name: "the IPv4 catch-all",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Headers: xff,
			})},
			assert: refused("EnableTrustedProxies", "Prefixes", "TrustAllProxies"),
		},
		{
			name: "the IPv6 catch-all",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("::/0")}, Headers: xff,
			})},
			assert: refused("EnableTrustedProxies", "Prefixes", "TrustAllProxies"),
		},
		{
			name: "a catch-all with TrustAllProxies builds",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
				Headers:  xff,
			}, httpsec.TrustAllProxies())},
			assert: built,
		},
		{
			name:   "no header family",
			opts:   []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet})},
			assert: refused("EnableTrustedProxies", "Headers"),
		},
		{
			name: "a family naming no field",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.Forwarded(),
			})},
			assert: refused("EnableTrustedProxies", "Headers"),
		},
		{
			name: "a nil field",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedFor, nil),
			})},
			assert: refused("EnableTrustedProxies", "Headers"),
		},
		{
			name: "the host field with no allowed host",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost()),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host given as a URL",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("https://app.example.com")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an empty allowed host",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("app.example.com", "")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host with a path",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.Forwarded(httpsec.ForwardedHost("a/b")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host with userinfo",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("u@h")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host that is only a trailing dot",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost(".")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host with a port, which could never match",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("app.example.com:8443")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost", "port"),
		},
		{
			name: "a bracketed IPv6 allowed host with a port",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("[2001:db8::1]:443")),
			})},
			assert: refused("EnableTrustedProxies", "ForwardedHost", "port"),
		},
		{
			name: "a bracketed IPv6 allowed host and a trailing-dot name build",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("[2001:db8::1]", "app.example.com.")),
			})},
			assert: built,
		},
		{
			name: "an allowed host that could never match: a wildcard",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("*.example.com")),
			})},
			assert: refusedWithout("*.example.com", "EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host that could never match: a non-ASCII name",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("bücher.example")),
			})},
			assert: refusedWithout("bücher.example", "EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host that could never match: an empty label",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("a..b")),
			})},
			assert: refusedWithout("a..b", "EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host that could never match: a leading hyphen",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("-app.example.com")),
			})},
			assert: refusedWithout("-app.example.com", "EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host that could never match: a label ending in a hyphen",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("app-.example.com")),
			})},
			assert: refusedWithout("app-.example.com", "EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an allowed host that could never match: a leading dot",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost(".example.com")),
			})},
			assert: refusedWithout(".example.com", "EnableTrustedProxies", "ForwardedHost"),
		},
		{
			name: "an empty client-certificate header name",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet, Headers: xff},
				httpsec.WithClientCertificateHeader("", nil))},
			assert: refused("EnableTrustedProxies", "WithClientCertificateHeader"),
		},
		{
			name: "a client-certificate header name that is not a header name",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet, Headers: xff},
				httpsec.WithClientCertificateHeader("X-Client Cert", nil))},
			assert: refused("EnableTrustedProxies", "WithClientCertificateHeader"),
		},
		{
			name: "a client-certificate header with the default decoder builds",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet, Headers: xff},
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil))},
			assert: built,
		},
		{
			name: "a hop limit below one",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: xff, MaxHops: -1,
			})},
			assert: refused("EnableTrustedProxies", "MaxHops"),
		},
		{
			name: "a zero hop limit is the default and builds",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: xff, MaxHops: 0,
			})},
			assert: built,
		},
		{
			name: "enabled twice",
			opts: []httpsec.Option{
				httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet, Headers: xff}),
				httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet, Headers: xff}),
			},
			assert: refused("EnableTrustedProxies", "twice"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.opts...)
			tc.assert(t, err)
		})
	}
}

// header is one header line a request carries, so a case can send a header
// more than once.
type header struct{ name, value string }

// forwardedRequest is a plain request for app.example.com from peer carrying
// lines, in order.
func forwardedRequest(t *testing.T, peer string, lines ...header) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = peer

	for _, l := range lines {
		req.Header.Add(l.name, l.value)
	}

	return req
}

func TestTrustedProxies_Resolve(t *testing.T) {
	t.Parallel()

	const proxy = "10.20.0.2:41000"

	xff := httpsec.TrustedProxies{
		Prefixes: proxyNet,
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto),
	}
	fwd := httpsec.TrustedProxies{
		Prefixes: proxyNet,
		Headers:  httpsec.Forwarded(httpsec.ForwardedFor, httpsec.ForwardedProto),
	}
	withHops := func(tp httpsec.TrustedProxies, n int) httpsec.TrustedProxies {
		tp.MaxHops = n
		return tp
	}

	// clientIs asserts the resolved address and that a proxy supplied it.
	clientIs := func(ip string) func(t *testing.T, c httpsec.Client, parsed int, err error) {
		return func(t *testing.T, c httpsec.Client, _ int, err error) {
			require.NoError(t, err)
			assert.Equal(t, ip, c.IP)
			assert.True(t, c.ViaProxy, "a trusted proxy's header supplied the address")
		}
	}

	type testCase struct {
		name   string
		tp     httpsec.TrustedProxies
		peer   string
		lines  []header
		assert func(t *testing.T, c httpsec.Client, parsed int, err error)
	}

	// A 64 KiB header whose last entry is the client.
	long := strings.Repeat("198.51.100.1, ", 64<<10/len("198.51.100.1, ")) + "203.0.113.7"

	cases := []testCase{
		{
			name:  "a forged left-most entry is never reached",
			tp:    xff,
			peer:  proxy,
			lines: []header{{"X-Forwarded-For", "1.2.3.4, 203.0.113.7"}, {"X-Forwarded-Proto", "https"}},
			assert: func(t *testing.T, c httpsec.Client, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, httpsec.Client{IP: "203.0.113.7", Secure: true, Host: "app.example.com", ViaProxy: true}, c)
			},
		},
		{
			name:  "a peer outside the trusted prefixes has its headers ignored",
			tp:    xff,
			peer:  "198.51.100.9:41000",
			lines: []header{{"X-Forwarded-For", "203.0.113.7"}, {"X-Forwarded-Proto", "https"}},
			assert: func(t *testing.T, c httpsec.Client, parsed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, httpsec.Client{IP: "198.51.100.9", Host: "app.example.com"}, c)
				assert.Zero(t, parsed)
			},
		},
		{
			name:   "two trusted hops are skipped under a hop limit of two",
			tp:     withHops(xff, 2),
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7, 10.20.5.5"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "once the hop limit is reached the next entry is the client",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7, 10.20.5.5"}},
			assert: clientIs("10.20.5.5"),
		},
		{
			name:   "every entry trusted within the limit leaves the left-most",
			tp:     withHops(xff, 3),
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "10.20.9.9, 10.20.5.5"}},
			assert: clientIs("10.20.9.9"),
		},
		{
			name:   "repeated header lines are joined in order",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "1.2.3.4"}, {"X-Forwarded-For", "203.0.113.7"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "an IPv4-mapped peer is compared as IPv4",
			tp:     xff,
			peer:   "[::ffff:10.20.0.2]:41000",
			lines:  []header{{"X-Forwarded-For", "203.0.113.7"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name: "an IPv4-mapped prefix trusts the IPv4 peer it names",
			tp: httpsec.TrustedProxies{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:10.20.0.0/112")}, Headers: xff.Headers,
			},
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "a zoned peer is compared without its zone",
			tp:     httpsec.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("fe80::/10")}, Headers: xff.Headers},
			peer:   "[fe80::1%eth0]:41000",
			lines:  []header{{"X-Forwarded-For", "203.0.113.7"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:  "a bracketed IPv6 entry with a port in Forwarded",
			tp:    fwd,
			peer:  proxy,
			lines: []header{{"Forwarded", `for="[2001:db8::7]:4711";proto=https`}},
			assert: func(t *testing.T, c httpsec.Client, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "2001:db8::7", c.IP)
				assert.True(t, c.Secure)
			},
		},
		{
			name:   "an IPv4 entry with a port in X-Forwarded-For",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7:5555"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "a bracketed IPv4-mapped entry with a port in Forwarded is unmapped",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", `for="[::ffff:203.0.113.7]:80"`}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:  "Forwarded parameter names are case-insensitive",
			tp:    fwd,
			peer:  proxy,
			lines: []header{{"Forwarded", "For=203.0.113.7;PROTO=https"}},
			assert: func(t *testing.T, c httpsec.Client, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, httpsec.Client{IP: "203.0.113.7", Secure: true, Host: "app.example.com", ViaProxy: true}, c)
			},
		},
		{
			name:   "a Forwarded parameter given twice rejects the element",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", "for=1.2.3.4;for=203.0.113.7"}},
			assert: clientIs(""),
		},
		{
			name:   "a backslash-escaped quoted-string rejects the element",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", `for="203.0.113\.7"`}},
			assert: clientIs(""),
		},
		{
			name:   "an unterminated quoted-string rejects the element",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", `for="203.0.113.7`}},
			assert: clientIs(""),
		},
		{
			name:   "Forwarded: two trusted hops are skipped under a hop limit of two",
			tp:     withHops(fwd, 2),
			peer:   proxy,
			lines:  []header{{"Forwarded", "for=203.0.113.7, for=10.20.5.5"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "Forwarded: once the hop limit is reached the next element is the client",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", "for=203.0.113.7, for=10.20.5.5"}},
			assert: clientIs("10.20.5.5"),
		},
		{
			name:   "an IPv4-mapped entry is unmapped",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "::ffff:203.0.113.7"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "for=unknown leaves no client address, never the proxy's",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", "for=unknown"}},
			assert: clientIs(""),
		},
		{
			name:   "an obfuscated identifier leaves no client address",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", "for=_hidden"}},
			assert: clientIs(""),
		},
		{
			name:   "garbage left of the client is never parsed",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "not-an-ip, 203.0.113.7"}},
			assert: clientIs("203.0.113.7"),
		},
		{
			name:   "garbage where the client should be leaves no client, not the proxy",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7, not-an-ip"}},
			assert: clientIs(""),
		},
		{
			name:   "an empty entry where the client should be leaves no client",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7,"}},
			assert: clientIs(""),
		},
		{
			name: "a trusted peer with no header is the client, with the transport's scheme and host",
			tp:   xff,
			peer: proxy,
			assert: func(t *testing.T, c httpsec.Client, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, httpsec.Client{IP: "10.20.0.2", Host: "app.example.com"}, c)
			},
		},
		{
			name:  "the other family is ignored even from a trusted peer",
			tp:    xff,
			peer:  proxy,
			lines: []header{{"Forwarded", "for=1.2.3.4;proto=https"}},
			assert: func(t *testing.T, c httpsec.Client, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, httpsec.Client{IP: "10.20.0.2", Host: "app.example.com"}, c)
			},
		},
		{
			name:  "a 64 KiB header is walked from the right, parsing only the client",
			tp:    xff,
			peer:  proxy,
			lines: []header{{"X-Forwarded-For", long}},
			assert: func(t *testing.T, c httpsec.Client, parsed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "203.0.113.7", c.IP)
				assert.Equal(t, 1, parsed, "only the entry the walk reached is parsed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httpsec.NewHTTPRequest(forwardedRequest(t, tc.peer, tc.lines...))
			c, parsed, err := httpsec.ResolveClient(r, tc.tp)
			tc.assert(t, c, parsed, err)
		})
	}
}

func TestTrustedProxies_SchemeHost(t *testing.T) {
	t.Parallel()

	const proxy = "10.20.0.2:41000"

	allXFF := httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
		httpsec.ForwardedHost("app.example.com", "internal.example"))

	enable := func(h httpsec.HeaderFamily, maxHops int) httpsec.Option {
		return httpsec.EnableTrustedProxies(httpsec.TrustedProxies{Prefixes: proxyNet, Headers: h, MaxHops: maxHops})
	}

	type testCase struct {
		name   string
		opt    httpsec.Option
		peer   string
		lines  []header
		assert func(t *testing.T, seen seenClient, err error)
	}

	cases := []testCase{
		{
			name: "Forwarded: proto and host come from the element that named the client",
			opt: enable(httpsec.Forwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
				httpsec.ForwardedHost("app.example.com")), 0),
			peer: proxy,
			lines: []header{{"Forwarded",
				`for=1.2.3.4;proto=http;host=other.example, for=203.0.113.7;proto=https;host="app.example.com:8443"`}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "203.0.113.7", host: "app.example.com:8443", secure: true}, seen)
			},
		},
		{
			name:  "Forwarded without the address field reads the nearest proxy's element",
			opt:   enable(httpsec.Forwarded(httpsec.ForwardedProto), 0),
			peer:  proxy,
			lines: []header{{"Forwarded", "for=1.2.3.4;proto=http, for=203.0.113.7;proto=https"}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "10.20.0.2", host: "app.example.com", secure: true}, seen)
			},
		},
		{
			name: "a single-valued scheme and host are the nearest proxy's",
			opt:  enable(allXFF, 0),
			peer: proxy,
			lines: []header{
				{"X-Forwarded-For", "1.2.3.4, 203.0.113.7"},
				{"X-Forwarded-Proto", "HTTPS"},
				{"X-Forwarded-Host", "internal.example"},
			},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "203.0.113.7", host: "internal.example", secure: true}, seen)
			},
		},
		{
			name: "aligned lists are read at the client's position",
			opt:  enable(allXFF, 2),
			peer: proxy,
			lines: []header{
				{"X-Forwarded-For", "203.0.113.7, 10.20.5.5"},
				{"X-Forwarded-Proto", "https, http"},
				{"X-Forwarded-Host", "internal.example, app.example.com"},
			},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "203.0.113.7", host: "internal.example", secure: true}, seen)
			},
		},
		{
			name: "a scheme list of another length is ignored",
			opt:  enable(allXFF, 2),
			peer: proxy,
			lines: []header{
				{"X-Forwarded-For", "1.2.3.4, 203.0.113.7, 10.20.0.9"},
				{"X-Forwarded-Proto", "https, http"},
				{"X-Forwarded-Host", "app.example.com, internal.example"},
			},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "203.0.113.7", host: "app.example.com"}, seen,
					"neither list matches one value or the address list's length")
			},
		},
		{
			name:  "an unknown scheme is ignored",
			opt:   enable(allXFF, 0),
			peer:  proxy,
			lines: []header{{"X-Forwarded-Proto", "wss"}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "10.20.0.2", host: "app.example.com"}, seen)
			},
		},
		{
			name:  "X-Forwarded-Port is never read",
			opt:   enable(allXFF, 0),
			peer:  proxy,
			lines: []header{{"X-Forwarded-Host", "internal.example"}, {"X-Forwarded-Port", "8443"}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, "internal.example", seen.host, "the forwarded host, with no port added")
			},
		},
		{
			name:  "a host field not named is ignored",
			opt:   enable(httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto), 0),
			peer:  proxy,
			lines: []header{{"X-Forwarded-Host", "evil.example"}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, "app.example.com", seen.host)
			},
		},
		{
			name:  "a scheme field not named is ignored",
			opt:   enable(httpsec.XForwarded(httpsec.ForwardedFor), 0),
			peer:  proxy,
			lines: []header{{"X-Forwarded-Proto", "https"}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.False(t, seen.secure)
			},
		},
		{
			name:  "an untrusted peer's forwarded scheme and host are ignored",
			opt:   enable(allXFF, 0),
			peer:  "198.51.100.9:41000",
			lines: []header{{"X-Forwarded-Proto", "https"}, {"X-Forwarded-Host", "evil.example"}},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "198.51.100.9", host: "app.example.com"}, seen)
			},
		},
		{
			name: "without trusted proxies the transport answers",
			peer: "198.51.100.7:41000",
			lines: []header{
				{"X-Forwarded-For", "203.0.113.9"}, {"X-Forwarded-Proto", "https"}, {"X-Forwarded-Host", "evil.example"},
			},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "198.51.100.7", host: "app.example.com"}, seen)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			seen, err := resolvedThroughChain(t, forwardedRequest(t, tc.peer, tc.lines...), tc.opt)
			tc.assert(t, seen, err)
		})
	}
}

// hostRun is what one request through the net/http entrypoint produced: the
// response, whether the outermost interceptor and the handler ran, the host
// the interceptor read, and the refusal the error handler saw.
type hostRun struct {
	rec            *httptest.ResponseRecorder
	interceptorRan bool
	handlerRan     bool
	host           string
	refusal        error
}

func TestTrustedProxies_HostNotAllowed(t *testing.T) {
	t.Parallel()

	const proxy = "10.20.0.2:41000"

	xff := httpsec.TrustedProxies{
		Prefixes: proxyNet,
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
	}
	fwd := httpsec.TrustedProxies{
		Prefixes: proxyNet,
		Headers:  httpsec.Forwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
	}

	// refused asserts the host-not-allowed refusal, answered 400 with no body,
	// before any interceptor or the handler, and never echoing the host.
	refused := func(forwarded string) func(t *testing.T, run hostRun) {
		return func(t *testing.T, run hostRun) {
			require.ErrorIs(t, run.refusal, httpsec.ErrHostNotAllowed)
			assert.NotContains(t, run.refusal.Error(), forwarded, "the refusal never echoes the host")
			assert.Equal(t, http.StatusBadRequest, run.rec.Code)
			assert.Empty(t, run.rec.Body.String())
			assert.False(t, run.interceptorRan, "refused before any interceptor")
			assert.False(t, run.handlerRan)
		}
	}

	allowedAs := func(host string) func(t *testing.T, run hostRun) {
		return func(t *testing.T, run hostRun) {
			require.NoError(t, run.refusal)
			assert.True(t, run.handlerRan)
			assert.Equal(t, host, run.host)
		}
	}

	type testCase struct {
		name   string
		tp     httpsec.TrustedProxies
		peer   string
		host   string
		lines  []header
		assert func(t *testing.T, run hostRun)
	}

	cases := []testCase{
		{
			name:   "an unknown forwarded host is refused",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-For", "203.0.113.7"}, {"X-Forwarded-Host", "evil.example"}},
			assert: refused("evil.example"),
		},
		{
			name:   "case and port: the host is allowed and keeps its port",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "App.Example.COM:8443"}},
			assert: allowedAs("app.example.com:8443"),
		},
		{
			name:   "a trailing dot is allowed",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com."}},
			assert: allowedAs("app.example.com"),
		},
		{
			name:   "a trailing dot is dropped and case and port are kept",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "App.Example.COM.:8443"}},
			assert: allowedAs("app.example.com:8443"),
		},
		{
			name:   "a look-alike host is refused",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com.evil.example"}},
			assert: refused("app.example.com.evil.example"),
		},
		{
			name:   "a host with a port and a look-alike name is refused",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "evil.example:443"}},
			assert: refused("evil.example"),
		},
		{
			name:   "a Forwarded host is refused the same way",
			tp:     fwd,
			peer:   proxy,
			lines:  []header{{"Forwarded", `for=203.0.113.7;host="evil.example"`}},
			assert: refused("evil.example"),
		},
		{
			name:   "malformed: userinfo after a port",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com:1@evil.example"}},
			assert: refused("evil.example"),
		},
		{
			name:   "malformed: a path after a port",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com:80/x"}},
			assert: refused("/x"),
		},
		{
			name:   "malformed: an empty port",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com:"}},
			assert: refused("app.example.com:"),
		},
		{
			name:   "malformed: a port above 65535",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com:999999"}},
			assert: refused("999999"),
		},
		{
			name:   "malformed: a port that is not digits",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com:8a"}},
			assert: refused("8a"),
		},
		{
			name:   "malformed: garbage after a bracketed IPv6 host",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "[2001:db8::1]x"}},
			assert: refused("[2001:db8::1]x"),
		},
		{
			name:   "malformed: an @ in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com@evil.example"}},
			assert: refused("evil.example"),
		},
		{
			name:   "malformed: a slash in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com/x"}},
			assert: refused("/x"),
		},
		{
			name:   "malformed: a backslash in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com\\evil.example"}},
			assert: refused("evil.example"),
		},
		{
			name:   "malformed: a question mark in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com?x"}},
			assert: refused("?x"),
		},
		{
			name:   "malformed: a hash in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com#x"}},
			assert: refused("#x"),
		},
		{
			name:   "malformed: a semicolon in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com;x"}},
			assert: refused("x"),
		},
		{
			name:   "malformed: a quote in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com\""}},
			assert: refused("\""),
		},
		{
			name:   "malformed: a space in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com x"}},
			assert: refused(" x"),
		},
		{
			name:   "malformed: a control character in the name",
			tp:     xff,
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "app.example.com\x01"}},
			assert: refused("\x01"),
		},
		{
			name:  "malformed: a comma inside a quoted Forwarded host",
			tp:    fwd,
			peer:  proxy,
			lines: []header{{"Forwarded", `for=203.0.113.7;host="app.example.com,evil.example"`}},
			// The comma splits the element, which then does not parse: no
			// forwarded host is read at all, and the Host header stands.
			assert: allowedAs("app.example.com"),
		},
		{
			name:   "a bracketed IPv6 forwarded host with a port is checked by its address",
			tp:     httpsec.TrustedProxies{Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedHost("[2001:db8::1]"))},
			peer:   proxy,
			lines:  []header{{"X-Forwarded-Host", "[2001:DB8::1]:8443"}},
			assert: allowedAs("[2001:db8::1]:8443"),
		},
		{
			name:   "an untrusted peer's forwarded host is ignored, not refused",
			tp:     xff,
			peer:   "198.51.100.9:41000",
			lines:  []header{{"X-Forwarded-Host", "evil.example"}},
			assert: allowedAs("app.example.com"),
		},
		{
			name:   "the request's own Host header is never judged against the list",
			tp:     xff,
			peer:   proxy,
			host:   "other.example",
			lines:  []header{{"X-Forwarded-For", "203.0.113.7"}},
			assert: allowedAs("other.example"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var run hostRun

			recorder := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				run.interceptorRan = true
				run.host = ex.Request.Host()

				return next(ex)
			})

			chain, err := httpsec.New(
				httpsec.EnableTrustedProxies(tc.tp),
				httpsec.RegisterInterceptor(recorder, httpsec.Before(httpsec.OrderJWKS)),
			)
			require.NoError(t, err)

			req := forwardedRequest(t, tc.peer, tc.lines...)
			if tc.host != "" {
				req.Host = tc.host
			}

			// Cloned first: the run below removes the forwarded headers.
			again := forwardedRequestLike(t, req)

			run.rec = httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				run.handlerRan = true
			})).ServeHTTP(run.rec, req)

			// The default answer is checked above through the recorder; the
			// refusal itself is read through a second chain with an error
			// handler, so both the default and the error are asserted.
			errChain, err := httpsec.New(
				httpsec.EnableTrustedProxies(tc.tp),
				httpsec.WithErrorHandler(func(_ http.ResponseWriter, _ *http.Request, err error) { run.refusal = err }),
			)
			require.NoError(t, err)

			errChain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
				ServeHTTP(httptest.NewRecorder(), again)

			tc.assert(t, run)
		})
	}
}

// forwardedRequestLike is a fresh request carrying req's peer, host and
// headers, for a second run of the same request.
func forwardedRequestLike(t *testing.T, req *http.Request) *http.Request {
	t.Helper()

	again := httptest.NewRequestWithContext(t.Context(), req.Method, "/", nil)
	again.Host, again.RemoteAddr, again.Header = req.Host, req.RemoteAddr, req.Header.Clone()

	return again
}

func TestTrustedProxies_RemovesHeaders(t *testing.T) {
	t.Parallel()

	const proxy = "10.20.0.2:41000"

	tp := httpsec.TrustedProxies{
		Prefixes: proxyNet,
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com")),
	}

	sent := []header{
		{"Forwarded", "for=203.0.113.7"},
		{"X-Forwarded-For", "203.0.113.7"},
		{"X-Forwarded-Proto", "https"},
		{"X-Forwarded-Host", "app.example.com"},
		{"X-Forwarded-Port", "443"},
		{"X-Forwarded-Prefix", "/app"},
		{"X-Forwarded-Server", "edge-1"},
		{"X-Client-Cert", "-----BEGIN%20CERTIFICATE-----"},
		{"X-Request-Id", "r-1"},
	}

	removed := func(t *testing.T, got http.Header) {
		for _, h := range sent[:len(sent)-1] {
			assert.Empty(t, got.Values(h.name), "%s is removed", h.name)
		}

		assert.Equal(t, "r-1", got.Get("X-Request-Id"), "an unrelated header is left alone")
	}

	untouched := func(t *testing.T, got http.Header) {
		for _, h := range sent {
			assert.Equal(t, h.value, got.Get(h.name), "%s is left as sent", h.name)
		}
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		peer   string
		assert func(t *testing.T, got http.Header)
	}

	cases := []testCase{
		{
			name: "removed from a trusted peer's request",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("x-client-cert", nil))},
			peer:   proxy,
			assert: removed,
		},
		{
			name: "removed from an untrusted peer's request too",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil))},
			peer:   "198.51.100.9:41000",
			assert: removed,
		},
		{
			name: "kept with KeepForwardedHeaders",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil), httpsec.KeepForwardedHeaders())},
			peer:   proxy,
			assert: untouched,
		},
		{
			name:   "untouched without trusted proxies",
			peer:   proxy,
			assert: untouched,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts...)
			require.NoError(t, err)

			var got http.Header

			chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
			})).ServeHTTP(httptest.NewRecorder(), forwardedRequest(t, tc.peer, sent...))

			require.NotNil(t, got, "the handler ran")
			tc.assert(t, got)
		})
	}
}

// TestTrustedProxies_HidesHeadersFromInterceptors pins that a custom
// integration's request that cannot remove headers still has the consumed
// forwarded headers hidden from every interceptor, unless they are kept.
func TestTrustedProxies_HidesHeadersFromInterceptors(t *testing.T) {
	t.Parallel()

	tp := httpsec.TrustedProxies{Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedFor)}

	type testCase struct {
		name   string
		opts   []httpsec.ProxyOption
		assert func(t *testing.T, header string, lines []string)
	}

	cases := []testCase{
		{
			name: "hidden by default",
			assert: func(t *testing.T, header string, lines []string) {
				assert.Empty(t, header)
				assert.Empty(t, lines)
			},
		},
		{
			name: "visible with KeepForwardedHeaders",
			opts: []httpsec.ProxyOption{httpsec.KeepForwardedHeaders()},
			assert: func(t *testing.T, header string, lines []string) {
				assert.Equal(t, "203.0.113.7", header)
				assert.Equal(t, []string{"203.0.113.7"}, lines)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				header string
				lines  []string
			)

			chain, err := httpsec.New(httpsec.EnableTrustedProxies(tp, tc.opts...),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					header, lines = ex.Request.Header("X-Forwarded-For"), ex.Request.HeaderValues("X-Forwarded-For")

					return next(ex)
				}), httpsec.OrderJWKS))
			require.NoError(t, err)

			req := stubRequest{clientIP: "10.20.0.2", headers: map[string]string{"X-Forwarded-For": "203.0.113.7"}}
			run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
			require.NoError(t, run(httpsec.NewExchange(t.Context(), req, httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))))

			tc.assert(t, header, lines)
		})
	}
}
