package httpsec

// oidcResumeGroup serves the resume endpoint (task 8.5). It answers behind the
// bearer and the gates, and reads the sign-in from ex.Session. This file is a stub
// until its lane replaces it.
type oidcResumeGroup struct{ oidcGroupBase }

func (g *oidcResumeGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCResume], inner: true, handle: oidcNotBuilt},
	}
}
