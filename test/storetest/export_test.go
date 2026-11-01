package storetest

// RunSessionStrictRotationSuite exposes runSessionStrictRotationSuite to this
// package's own tests only: the in-memory runs and the broken variants. It is
// removed once RunSessionStoreSuite carries the strict-rotation cases for
// every session store.
var RunSessionStrictRotationSuite = runSessionStrictRotationSuite
