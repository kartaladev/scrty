package oidc

import "strings"

// claimAt returns the value at a dotted path through nested claim objects,
// such as "realm_access.roles", and whether the path resolved. Each segment
// but the last must name an object. A claim whose own name contains a dot is
// not reachable by path.
func claimAt(claims map[string]any, path string) (any, bool) {
	cur := any(claims)
	for seg := range strings.SplitSeq(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// stringClaimAt returns the non-empty string at a dotted path, and whether
// there is one.
func stringClaimAt(claims map[string]any, path string) (string, bool) {
	v, ok := claimAt(claims, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}
