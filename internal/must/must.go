// Package must unwraps a constructor's result for call sites that cannot
// recover from its error: test fixtures and examples whose configuration is
// fixed and known to be valid.
package must

// Must returns v, and panics with err when err is not nil. It is meant to
// wrap a constructor call directly, as in must.Must(NewThing(opts...)).
func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}
