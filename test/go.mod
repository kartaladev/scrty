module github.com/kartaladev/scrty/test

go 1.27

require (
	github.com/kartaladev/scrty v0.0.0
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

// The core module is not tagged yet, so there is no version to require. The
// replace keeps this module buildable on its own — without it, the workspace is
// the only thing holding the two together, and a consumer running the
// conformance suite from their own repository could not resolve it. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../
