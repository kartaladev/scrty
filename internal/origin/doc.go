// Package origin compares URL origins and validates redirect targets.
//
// The comparison is deliberately narrow. Every normalisation step makes more
// strings equal, and the two kinds of caller pull in opposite directions: a
// discovery check wants a lenient comparison so a provider's own spelling
// variants match, and a redirect allowlist wants a strict one so an attacker's
// host does not match the one a consumer declared. Strict is the safe
// direction, because a comparison that is too strict refuses a request that
// would have been fine, while one that is too lenient sends a browser, or a
// client secret, somewhere nobody declared.
//
// Only ASCII case folding and default-port removal are therefore applied.
// Adding a step is a decision to be argued for each caller separately, not a
// tidy-up.
//
// The package is internal because the comparison is a detail of how scrty
// confines its own requests and redirects. Exporting it would make that detail
// something consumers depend on, and every later narrowing a breaking change.
package origin
