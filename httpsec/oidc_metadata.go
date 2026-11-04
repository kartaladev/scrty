package httpsec

// oidcMetadataGroup serves the provider's two metadata documents at their well-known
// paths (group 10), which the issuer decides. This file is a stub until its lane
// replaces it: it routes nothing, and those paths pass through.
type oidcMetadataGroup struct{ oidcGroupBase }

func (g *oidcMetadataGroup) routes() []oidcRoute { return nil }
