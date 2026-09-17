// Package test is the root of scrty's shared test helpers and conformance
// suites. The suites themselves live in subpackages, one per capability they
// check.
//
// No other scrty module imports this one, test files included: a test-only
// import still adds these helpers' dependencies to that module's go.mod, and
// from there to the module graph of every application that embeds scrty.
//
// A consumer implementing scrty's ports over their own storage runs the
// matching conformance suite from their own tests, to check that implementation
// against every contract scrty relies on.
package test
