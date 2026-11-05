package httpsec

import (
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// WiredStep runs fn among the chain's wiring steps, as a built-in that wires
// itself to a built manager does.
func WiredStep(fn func()) Option {
	return func(c *config) error {
		c.wire(func(*Chain) { fn() })

		return nil
	}
}

// TestOIDCGroup is an endpoint group of a test's own, to pin the seam the real
// ones plug into.
type TestOIDCGroup struct {
	oidcGroupBase

	// Path is what it routes, and Inner which slot it answers at.
	Path  string
	Inner bool

	SettleErr, FlushErr error
	// Answer is what its handler returns, and nil answers 204.
	Answer error

	calls           atomic.Int32
	settledWith     bool
	settledSessions *session.Sessions
	csrfSettled     bool
	wiredWithLogger bool
}

// WithTestOIDCGroup adds g to the provider's groups.
func WithTestOIDCGroup(g *TestOIDCGroup) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		g.bind(op)
		op.groups = append(op.groups, g)

		return nil
	}
}

// Calls reports how many requests reached g's handler.
func (g *TestOIDCGroup) Calls() int { return int(g.calls.Load()) }

// SettledWithManager reports whether g saw the bearer's manager as it settled.
func (g *TestOIDCGroup) SettledWithManager() bool { return g.settledWith }

// SettledSessions is the session manager g saw as it settled.
func (g *TestOIDCGroup) SettledSessions() *session.Sessions { return g.settledSessions }

// SawCSRFSettled reports whether the CSRF layer had already read the chain's
// settings, trusted origins among them, when g settled.
func (g *TestOIDCGroup) SawCSRFSettled() bool { return g.csrfSettled }

// WiredWithLogger reports whether g was wired with the chain's logger in place.
func (g *TestOIDCGroup) WiredWithLogger() bool { return g.wiredWithLogger }

func (g *TestOIDCGroup) routes() []oidcRoute {
	return []oidcRoute{{path: g.Path, inner: g.Inner, handle: func(ex *Exchange, _ Next) error {
		g.calls.Add(1)

		if g.Answer != nil {
			return g.Answer
		}

		ex.Writer.WriteHeader(204)

		return nil
	}}}
}

func (g *TestOIDCGroup) settle(c *config) error {
	g.settledWith = g.op.sessions != nil
	g.settledSessions = g.op.sessions

	_ = eachInterceptor(c, func(l *csrfLayer) error {
		g.csrfSettled = len(l.trusted) > 0

		return nil
	})

	return g.SettleErr
}

func (g *TestOIDCGroup) wire(*Chain) { g.wiredWithLogger = g.op.log != nil }

func (g *TestOIDCGroup) flushRefusalLogs() error { return g.FlushErr }

// endpointsFor is the provider's state for an issuer, over collaborators that
// are never called: only the issuer is read.
func endpointsFor(t *testing.T, issuer string, opts ...oidcprovider.Option) *oidcEndpoints {
	t.Helper()

	u, err := url.Parse(issuer)
	require.NoError(t, err)

	origin := u.Scheme + "://" + u.Host

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: issuer,
		Clients: []oidcprovider.Client{{
			ID:           "billing-web",
			Type:         oidcprovider.Confidential,
			Secret:       []byte("0123456789abcdef0123456789abcdef"),
			RedirectURIs: []string{"https://rp.example.com/cb"},
		}},
		Keys:         struct{ signingkey.KeySource }{},
		Users:        struct{ identity.UserLoader }{},
		LoginURL:     origin + "/login",
		ConsentURL:   origin + "/consent",
		LogoutURL:    origin + "/logout-page",
		LoggedOutURL: origin + "/bye",
	}, opts...)
	require.NoError(t, err)

	return newOIDCEndpoints(p, nil)
}

func TestOIDCEndpoints_PublicURL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string
		served string
		assert func(t *testing.T, got string)
	}

	equals := func(want string) func(*testing.T, string) {
		return func(t *testing.T, got string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	cases := []testCase{
		{"an issuer at the origin keeps the served path", "https://id.example.com", "/oauth2/token", equals("https://id.example.com/oauth2/token")},
		{"an issuer with a path is put before a path outside it", "https://id.example.com/auth", "/oauth2/token", equals("https://id.example.com/auth/oauth2/token")},
		{"a path under the issuer's path is kept as served", "https://id.example.com/auth", "/auth/oauth2/token", equals("https://id.example.com/auth/oauth2/token")},
		{"the issuer's path itself is kept as served", "https://id.example.com/auth", "/auth", equals("https://id.example.com/auth")},
		{"a path sharing only the issuer path's letters is outside it", "https://id.example.com/auth", "/authority/token", equals("https://id.example.com/auth/authority/token")},
		{"a trailing slash on the issuer is no part of its path", "https://id.example.com/auth/", "/oauth2/token", equals("https://id.example.com/auth/oauth2/token")},
		{"a root issuer keeps the served path", "https://id.example.com/", "/token", equals("https://id.example.com/token")},
		{"an encoded issuer path is kept as served", "https://id.example.com/a%20b", "/a b/token", equals("https://id.example.com/a%20b/token")},
		{"an encoded issuer path is put before a path outside it", "https://id.example.com/a%20b", "/token", equals("https://id.example.com/a%20b/token")},
		{"the issuer's port is kept", "https://id.example.com:8443/auth", "/token", equals("https://id.example.com:8443/auth/token")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, endpointsFor(t, tc.issuer).publicURL(tc.served))
		})
	}
}

func TestOIDCEndpoints_PlainHTTPAllowed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string
		opts   []oidcprovider.Option
		assert func(t *testing.T, allowed bool)
	}

	cases := []testCase{
		{
			name:   "an https issuer does not allow plain http",
			issuer: "https://id.example.com",
			assert: func(t *testing.T, allowed bool) { t.Helper(); assert.False(t, allowed) },
		},
		{
			name:   "a loopback http issuer, stated as such, allows it",
			issuer: "http://localhost:8080",
			opts:   []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()},
			assert: func(t *testing.T, allowed bool) { t.Helper(); assert.True(t, allowed) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, endpointsFor(t, tc.issuer, tc.opts...).plainHTTPAllowed())
		})
	}
}
