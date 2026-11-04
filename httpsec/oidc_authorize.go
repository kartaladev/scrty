package httpsec

// oidcAuthorizeGroup serves the authorization endpoint (task 8.4). This file is a
// stub until its lane replaces it.
type oidcAuthorizeGroup struct{ oidcGroupBase }

func (g *oidcAuthorizeGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCAuthorize], handle: oidcNotBuilt},
	}
}
