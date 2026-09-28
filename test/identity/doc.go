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
// preceding read. RunUserLoaderSuite, RunRoleLoaderSuite, RunProvisionerSuite
// and RunMFALookupSuite run one part each.
//
// An implementation that takes part in a caller's transaction also runs
// RunAmbientTx, whose AmbientHarness adds hooks to begin a caller-owned
// transaction, write and read back an unrelated row, and make a grant write
// fail.
//
// An implementation of password.History, the optional password-history port,
// runs RunPasswordHistory, whose HistoryHarness adds one hook that begins a
// caller-owned transaction; it needs no Fixture hook, and RunConformanceSuite
// needs none of its. InMemoryHistory implements it over process memory.
//
// Every hook of Fixture and AmbientHarness is required. A seeding hook the
// implementation cannot provide returns ErrHookUnsupported, and the run fails
// before any case, naming the hook; a case is never skipped for want of one.
//
// One database may host a whole run, and several parts may run under one
// *testing.T over it: every name the suite uses is unique to its case, to the
// run and to each preflight. InMemoryStore.Share gives another store over the
// same records with fault hooks of its own, which is how the in-memory store
// hosts a run the way one database would.
package identitytest
