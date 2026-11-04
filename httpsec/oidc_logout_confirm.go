package httpsec

// oidcLogoutConfirmGroup serves the logout confirmation (task 11.8). This file is a
// stub until its lane replaces it.
type oidcLogoutConfirmGroup struct{ oidcGroupBase }

func (g *oidcLogoutConfirmGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCLogoutConfirm], handle: oidcNotBuilt},
	}
}
