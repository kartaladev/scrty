// Package idgentest holds the generated test double for [id.Generator].
//
// The double lives here, outside the production packages, because the tests of
// many packages need it and a mock kept in a _test.go file is visible to its
// own package's tests only. A mock in a production file would put exported
// Mock types and go.uber.org/mock on the import graph of every consumer of the
// library. Only tests import this package.
package idgentest
