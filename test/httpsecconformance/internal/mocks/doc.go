// Package mocks holds the generated doubles the conformance scenarios build
// their chains from.
//
// They live in a package of their own, below the conformance package, because
// the scenarios are ordinary (non-test) files that other modules import: a mock
// generated into a _test.go file is invisible to them, and one generated into
// the conformance package itself would put exported Mock types on its API.
// Being internal, this package puts neither on any consumer's API.
//
//go:generate mockgen -destination=store_mock.go -package=mocks -typed github.com/kartaladev/scrty/session Store
//go:generate mockgen -destination=policy_mock.go -package=mocks -typed github.com/kartaladev/scrty/policy Policy
package mocks
