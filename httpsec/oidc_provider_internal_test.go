package httpsec

import (
	"sync/atomic"
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

	calls           atomic.Int32
	settledWith     bool
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

// WiredWithLogger reports whether g was wired with the chain's logger in place.
func (g *TestOIDCGroup) WiredWithLogger() bool { return g.wiredWithLogger }

func (g *TestOIDCGroup) routes() []oidcRoute {
	return []oidcRoute{{path: g.Path, inner: g.Inner, handle: func(ex *Exchange, _ Next) error {
		g.calls.Add(1)
		ex.Writer.WriteHeader(204)

		return nil
	}}}
}

func (g *TestOIDCGroup) settle(*config) error {
	g.settledWith = g.op.sessions != nil

	return g.SettleErr
}

func (g *TestOIDCGroup) wire(*Chain) { g.wiredWithLogger = g.op.log != nil }

func (g *TestOIDCGroup) flushRefusalLogs() error { return g.FlushErr }
