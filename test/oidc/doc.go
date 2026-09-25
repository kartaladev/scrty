// Package oidctest holds conformance suites and a test identity provider for
// the oidc package.
//
// A consumer implementing one of oidc's store ports over their own storage
// runs the matching suite (RunFlowStoreSuite, RunLinkStoreSuite,
// RunHandoffStoreSuite) from a test in their own module, to check the
// implementation keeps the contract the library relies on.
package oidctest
