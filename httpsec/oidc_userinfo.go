package httpsec

// oidcUserInfoGroup serves the UserInfo endpoint (task 9.4). This file is a stub until
// its lane replaces it.
type oidcUserInfoGroup struct{ oidcGroupBase }

func (g *oidcUserInfoGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCUserInfo], handle: oidcNotBuilt},
	}
}
