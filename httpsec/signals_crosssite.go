package httpsec

import (
	"log/slog"
	"slices"
	"strings"
)

const (
	// msgCrossSiteStream is the record a refused stream logs.
	msgCrossSiteStream = "httpsec: cross-site signal stream refused"

	// crossSiteFlow is the sampling flow and the flow attribute of that record. It is
	// the whole sampling key: an Origin is the refused party's to choose, so a key
	// holding one would let it choose how many records it writes.
	crossSiteFlow = "session-signals-cross-site"

	// crossSiteOriginLogLimit bounds what the record quotes of an Origin. A real one is
	// far shorter, and the header's size is the refused party's to choose.
	crossSiteOriginLogLimit = 256

	// nullOrigin is the Origin of a sandboxed document or a local file, which identifies
	// no site.
	nullOrigin = "null"
)

// crossSiteAllowed refuses, with an error matching ErrCrossSiteStream, a stream from an
// origin the chain does not trust, and answers nil otherwise. It runs whether or not CSRF
// protection is enabled, after authentication and before anything is read or registered,
// so a refusal costs the sign-in no place.
//
// The rule is the one the CSRF layer applies to unsafe methods, made stricter for a
// request that takes a place:
//
//   - Origin: null never passes, whatever else the request says.
//   - Sec-Fetch-Site of same-origin or none passes.
//   - Any other Sec-Fetch-Site passes only for a trusted origin, same-site included.
//   - With no Sec-Fetch-Site, no Origin passes, as does the request's own origin, and any
//     other origin only when trusted: old browsers and non-browser clients send neither.
//
// byCookie comes from streamByCookie, and says which origins are trusted (trustedByCORS).
//
// There is no switch to turn this off, because a stream a foreign page can hold open is
// the denial of service it exists to prevent. A consumer trusts an origin through the
// CORS allowlist (EnableCORS). Vary: Origin needs nothing here: the CORS layer ran first,
// and adds it to every response whether or not the origin was allowed.
//
// A refusal is logged with sampling, as an attempt to get past a control, and emits no
// CSRF event, because a page that merely tried is not reported as an attack. The record
// quotes the origin, cut short, and no credential.
func (e *sessionSignals) crossSiteAllowed(ex *Exchange, byCookie bool) error {
	origin := ex.Request.Header(headerOrigin)
	if e.originAllowed(ex.Request.Header(headerSecFetchSite), origin, ex.Request, byCookie) {
		return nil
	}

	logSampled(ex.Context(), e.sampler, e.log, slog.LevelWarn, e.clock.Now(),
		crossSiteFlow, msgCrossSiteStream,
		slog.String("flow", crossSiteFlow),
		slog.String("origin", origin[:min(len(origin), crossSiteOriginLogLimit)]),
		slog.Bool("by_cookie", byCookie),
	)

	return ErrCrossSiteStream
}

// originAllowed is the rule crossSiteAllowed states. Sec-Fetch-Site is compared exactly,
// so a value spelled differently is judged as an unknown one is, by its origin.
func (e *sessionSignals) originAllowed(site, origin string, req Request, byCookie bool) bool {
	if strings.EqualFold(origin, nullOrigin) {
		return false
	}

	switch site {
	case fetchSameOrigin, fetchNone:
		return true
	case "":
		return origin == "" || sameOriginAsRequest(origin, req) || e.trustedByCORS(origin, byCookie)
	default:
		return e.trustedByCORS(origin, byCookie)
	}
}

// trustedByCORS reports whether the chain's CORS policy trusts origin for this stream. With
// no CORS layer it trusts nothing.
//
// A browser sends a cookie on its own, so a cookie stream needs an origin the policy names,
// exactly or by pattern, with credentials allowed, and a wildcard never counts. A page can
// send an Authorization header only if it already holds the credential, so that stream
// needs only an origin the policy allows, and a wildcard counts for any origin present.
//
// It does not reuse corsLayer.allowedOrigin, which says yes to every origin under "*", null
// included, nor the CSRF layer's trusted list, which ignores credentials and does not exist
// with CSRF protection off. Named origins are compared as the CORS layer compares them, each
// normalised to a lower-case scheme and host with no default port.
func (e *sessionSignals) trustedByCORS(origin string, byCookie bool) bool {
	if e.cors == nil || origin == "" {
		return false
	}

	if byCookie && !e.cors.credentials {
		return false
	}

	if !byCookie && slices.Contains(e.cors.exact, corsAnyOrigin) {
		return true
	}

	scheme, host, port, err := parseOrigin(origin)
	if err != nil {
		return false
	}

	if slices.Contains(e.cors.exact, joinOrigin(scheme, host, port)) {
		return true
	}

	return slices.ContainsFunc(e.cors.patterns, func(p originPattern) bool {
		return p.matches(scheme, host, port)
	})
}
