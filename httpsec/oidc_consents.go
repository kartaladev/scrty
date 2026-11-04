package httpsec

// oidcConsentsGroup serves the user's list of consents (task 11.5). It answers behind
// the bearer and the gates, and reads the sign-in from ex.Session. This file is a stub
// until its lane replaces it.
type oidcConsentsGroup struct{ oidcGroupBase }

func (g *oidcConsentsGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCConsents], inner: true, handle: oidcNotBuilt},
	}
}
