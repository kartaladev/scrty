package httpsec

// oidcTokenGroup serves the token endpoint (tasks 9.1 and 9.2). This file is a stub
// until its lane replaces it.
type oidcTokenGroup struct{ oidcGroupBase }

func (g *oidcTokenGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCToken], handle: oidcNotBuilt},
	}
}
