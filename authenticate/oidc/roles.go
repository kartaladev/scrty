package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

// rolesFor derives the role names of a login of ext. It is the one resolution
// provisioning and role sync share, so enabling sync cannot bypass the
// mapping or the allowlist.
//
// With a role claim path configured for the provider, the names are the
// values at that path, translated through the provider's mapping; a path
// configured empty yields none, and nothing falls back to the default role.
// Without one, the name is the default role, if any. Either way the
// provider's allowlist applies last, the default role included.
func (b *Broker) rolesFor(ctx context.Context, ext ExternalIdentity) []string {
	var names []string
	path, configured := b.roleClaims[ext.Provider]
	switch {
	case configured && path == "":
		return nil
	case configured:
		names = b.mapRoles(ext.Provider, b.roleClaimValues(ctx, ext, path))
	case b.defaultRole != "":
		names = []string{b.defaultRole}
	}
	return b.allowRoles(ext.Provider, names)
}

// roleClaimValues returns the role values at path in ext's claims: a single
// non-empty string, or an array whose every element is a non-empty string.
// A path that resolves to nothing yields none. Any other shape yields none
// and a sampled log record, which names the provider but never the value.
func (b *Broker) roleClaimValues(ctx context.Context, ext ExternalIdentity, path string) []string {
	v, ok := claimAt(ext.Claims, path)
	if !ok {
		return nil
	}
	switch leaf := v.(type) {
	case string:
		if leaf != "" {
			return []string{leaf}
		}
		return nil
	case []string:
		if !slices.Contains(leaf, "") {
			return slices.Clone(leaf)
		}
	case []any:
		out := make([]string, 0, len(leaf))
		for _, item := range leaf {
			s, ok := item.(string)
			if !ok || s == "" {
				out = nil
				break
			}
			out = append(out, s)
		}
		if out != nil {
			return out
		}
	}
	b.refusal(ctx, slog.LevelWarn,
		"ignoring the role claim: it is not a string or an array of non-empty strings", ext.Provider, ext.Email)
	return nil
}

// mapRoles translates names through provider's role mapping, dropping any
// name with no entry. Without a mapping for provider the names pass through;
// a mapping configured empty drops them all. Matching is exact.
func (b *Broker) mapRoles(provider string, names []string) []string {
	mapping, configured := b.roleMappings[provider]
	if !configured {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if local, ok := mapping[n]; ok {
			out = append(out, local)
		}
	}
	return out
}

// allowRoles keeps the names on provider's allowlist. Without an allowlist
// for provider every name is kept; one configured empty keeps none. Matching
// is exact.
func (b *Broker) allowRoles(provider string, names []string) []string {
	allowed, configured := b.allowedRoles[provider]
	if !configured {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if slices.Contains(allowed, n) {
			out = append(out, n)
		}
	}
	return out
}

// principalFor returns the principal of det for a login of ext. With role
// sync on for ext's provider, its roles are replaced by the roles derived
// from the claims, each carrying only its name and whether it is primary:
// a stored grant's identifier, super-role flag and validity window are not
// inherited. Nothing is written to the user store.
func (b *Broker) principalFor(ctx context.Context, ext ExternalIdentity, det *identity.Details) *identity.Principal {
	p := identity.PrincipalFromDetails(det)
	if !b.roleSync[ext.Provider] {
		return p
	}
	names := b.rolesFor(ctx, ext)
	p.Roles = make([]*identity.AssignedRole, 0, len(names))
	p.ActiveRole = nil
	for i, n := range names {
		p.Roles = append(p.Roles, &identity.AssignedRole{Name: n, Primary: i == 0})
	}
	if len(p.Roles) > 0 {
		p.ActiveRole = p.Roles[0]
	}
	return p
}

// checkRoles refuses role sync with no claim path to derive roles from, which
// would strip every federated user of the provider of their roles.
func (b *Broker) checkRoles() error {
	for provider, on := range b.roleSync {
		if on && b.roleClaims[provider] == "" {
			return fmt.Errorf("%w: WithRoleSync for provider %q needs a non-empty role claim path from WithRoleClaim",
				ErrConfig, provider)
		}
	}
	return nil
}
