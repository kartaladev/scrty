// Package identitytest holds the conformance suite for scrty's identity ports,
// and an in-memory implementation to run it against.
//
// These live in scrty's test module, not in the identity package, so that no
// consumer's module graph gains them. scrty wires no in-memory port
// implementation by default: a component given no port fails at construction.
// This one exists for tests and local development.
//
// A consumer implementing the identity ports over their own user tables runs
// RunConformanceSuite against their implementation, which checks it against
// every contract scrty relies on — including the ones that are easy to get
// wrong, such as deciding a username collision by the write rather than by a
// preceding read.
package identitytest
