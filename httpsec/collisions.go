package httpsec

import (
	"slices"
	"strconv"
	"strings"
)

// checkCollisions refuses a chain on which two operations of eps would answer
// one request path, reporting the first such pair in eps's order, which is the
// chain's, so the error is the same on every run.
//
// Two operations collide when:
//   - some request path is matched by both, given how each matches, and they
//     share a method; an operation whose endpoint answers 405 to other methods
//     claims its path for every method;
//   - or they sit on one path, whatever their methods: the same exact path, the
//     same prefix, or an exact path equal to a prefix with or without its
//     trailing slash. A reader, a proxy rule or a route map cannot tell such
//     operations apart.
//
// The one exemption is declared: two operations of one feature that declare
// the same SharesPath do not collide when they answer different methods, or
// when one matches a path exactly and the other that path followed by one
// segment. Sharing is never inferred from the setting that placed them.
//
// A missed collision lets one endpoint silently answer the other's requests,
// so every pair is judged, within a feature and across features.
func checkCollisions(eps []Endpoint) error {
	claims := make([]pathClaim, len(eps))
	for i, e := range eps {
		claims[i] = claimOf(e)
	}

	for i := range eps {
		for j := i + 1; j < len(eps); j++ {
			if collide(eps[i], eps[j], claims[i], claims[j]) {
				return collisionError(eps[i], eps[j], claims[i], claims[j])
			}
		}
	}

	return nil
}

// pathClaim is the set of request paths an operation matches: its base alone
// (MatchExact), its base followed by one non-empty segment (MatchSegment), or
// its base and everything beneath it (MatchSubtree).
type pathClaim struct {
	match PathMatch

	// base is the operation's Path for MatchExact. For the prefix kinds it is
	// the part of Path before its first {…} segment, without a trailing slash,
	// which is the path every request it matches starts with.
	base string
}

// claimOf reads the request paths e matches from its Path and Match.
func claimOf(e Endpoint) pathClaim {
	base := e.Path
	if i := strings.Index(base, "/{"); i >= 0 {
		base = base[:i]
	}

	if e.Match != MatchExact {
		base = strings.TrimSuffix(base, "/")
	}

	return pathClaim{match: e.Match, base: base}
}

// collide reports whether a and b, whose claims are ca and cb, collide.
func collide(a, b Endpoint, ca, cb pathClaim) bool {
	if declaredSharers(a, b) {
		if !slices.ContainsFunc(a.Methods, func(m string) bool { return slices.Contains(b.Methods, m) }) {
			return false
		}

		if exactBesideSegment(ca, cb) || exactBesideSegment(cb, ca) {
			return false
		}
	}

	if onePath(ca, cb) {
		return true
	}

	return methodsMeet(a, b) && claimsMeet(ca, cb)
}

// declaredSharers reports whether a and b are operations of one feature that
// declare the same shared path.
func declaredSharers(a, b Endpoint) bool {
	return a.feature == b.feature && a.SharesPath != "" && a.SharesPath == b.SharesPath
}

// exactBesideSegment reports whether exact matches a path exactly and segment
// that same path followed by one segment.
func exactBesideSegment(exact, segment pathClaim) bool {
	return exact.match == MatchExact && segment.match == MatchSegment &&
		strings.TrimSuffix(exact.base, "/") == segment.base
}

// onePath reports whether a and b sit on one path: two exact paths that are
// equal, or a prefix equal to the other's path or prefix, a trailing slash set
// aside.
func onePath(a, b pathClaim) bool {
	if a.match == MatchExact && b.match == MatchExact {
		return a.base == b.base
	}

	return strings.TrimSuffix(a.base, "/") == strings.TrimSuffix(b.base, "/")
}

// methodsMeet reports whether some request method is answered by both a and b.
// An endpoint that answers 405 to the methods it does not serve answers every
// method.
func methodsMeet(a, b Endpoint) bool {
	if a.OtherMethods == Refused || b.OtherMethods == Refused {
		return true
	}

	return slices.ContainsFunc(a.Methods, func(m string) bool { return slices.Contains(b.Methods, m) })
}

// claimsMeet reports whether some request path is matched by both a and b.
func claimsMeet(a, b pathClaim) bool {
	if a.match > b.match {
		a, b = b, a
	}

	switch {
	case a.match == MatchExact && b.match == MatchExact:
		return a.base == b.base
	case a.match == MatchExact && b.match == MatchSegment:
		return isOneSegmentBelow(a.base, b.base)
	case a.match == MatchExact && b.match == MatchSubtree:
		return underPrefix(a.base, b.base)
	case a.match == MatchSegment && b.match == MatchSegment:
		return a.base == b.base
	case a.match == MatchSegment && b.match == MatchSubtree:
		// The segment's paths lie under the subtree when its prefix does, or
		// when the subtree's root is one of them.
		return underPrefix(a.base, b.base) || isOneSegmentBelow(b.base, a.base)
	default: // two subtrees
		return underPrefix(a.base, b.base) || underPrefix(b.base, a.base)
	}
}

// isOneSegmentBelow reports whether path is prefix followed by exactly one
// non-empty segment.
func isOneSegmentBelow(path, prefix string) bool {
	rest, ok := strings.CutPrefix(path, prefix+"/")

	return ok && rest != "" && !strings.Contains(rest, "/")
}

// collisionError names both settings, both operations with their paths, and
// what the collision would break.
func collisionError(a, b Endpoint, ca, cb pathClaim) error {
	return newConfigError("two endpoints collide: %s, while %s, so %s; give each its own path",
		placement(a), placement(b), consequence(a, b, ca, cb))
}

// placement names the setting that placed e, the feature it belongs to, the
// operation and where it answers.
func placement(e Endpoint) string {
	setting := e.PlacedBy
	if e.PlacedBy != e.feature {
		setting += " (" + e.feature + ")"
	}

	where := strings.Join(e.Methods, ", ")
	if e.OtherMethods == Refused {
		where = "every method, answering 405 to all but " + where
	}

	at := strconv.Quote(e.Path)
	if e.Match == MatchSubtree {
		at += " (everything beneath " + strconv.Quote(claimOf(e).base) + ")"
	}

	return setting + " places " + e.OperationID + " (" + where + ") at " + at
}

// consequence says what the collision of a and b would break.
func consequence(a, b Endpoint, ca, cb pathClaim) string {
	if !claimsMeet(ca, cb) {
		return "one path would name both, as an exact path and a prefix, and a reader, a proxy " +
			"rule or a route map could not tell the two apart"
	}

	if !methodsMeet(a, b) {
		return "one path would carry two operations told apart only by method, which only " +
			"operations of one feature that declare a shared path may do"
	}

	signOut, other := a, b
	if b.OperationID == OperationSignOut {
		signOut, other = b, a
	}

	if signOut.OperationID == OperationSignOut {
		switch {
		case other.Requires == RequiresPendingSecondFactor:
			return "a session owing a second factor could not sign out"
		case other.Requires == RequiresPendingEnrolment:
			return "an enrolment-only session could not sign out"
		case other.OperationID == OperationSessionRenewal:
			return "a sign-out could renew the session it meant to end"
		default:
			return "a sign-out could be answered by " + other.OperationID + ", so a session might not sign out"
		}
	}

	return "whichever matches first would answer the other's requests, and the other would never be reached"
}
