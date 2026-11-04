package httpsec

// oidcEndSessionGroup serves the end-session endpoint (task 11.1). This file is a stub
// until its lane replaces it.
type oidcEndSessionGroup struct{ oidcGroupBase }

func (g *oidcEndSessionGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCEndSession], handle: oidcNotBuilt},
	}
}
