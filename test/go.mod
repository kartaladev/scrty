module github.com/kartaladev/scrty/test

go 1.27

require (
	github.com/kartaladev/scrty v0.0.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/jwx/v4 v4.5.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// The core module is not tagged yet, so there is no version to require. The
// replace keeps this module buildable on its own — without it, the workspace is
// the only thing holding the two together, and a consumer running the
// conformance suite from their own repository could not resolve it. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../

// The adapter modules are not tagged either, and the direction of the
// dependency is deliberate: this module imports them so the conformance suite
// can run one scenario table through all three frameworks. Neither adapter
// module may require this one, because a test-only import still puts these
// helpers' dependencies into a consumer's module graph.
replace github.com/kartaladev/scrty/ginsec => ../ginsec

replace github.com/kartaladev/scrty/fibersec => ../fibersec
