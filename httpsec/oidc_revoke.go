package httpsec

// oidcRevokeGroup serves the revocation and introspection endpoints (task 9.3). This
// file is a stub until its lane replaces it.
type oidcRevokeGroup struct{ oidcGroupBase }

func (g *oidcRevokeGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCRevoke], handle: oidcNotBuilt},
		{path: g.op.paths[OIDCIntrospect], handle: oidcNotBuilt},
	}
}
