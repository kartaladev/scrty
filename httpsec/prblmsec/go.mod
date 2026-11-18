module github.com/kartaladev/scrty/httpsec/prblmsec

go 1.27

require (
	github.com/kartaladev/prblm v0.2.0
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

// The core module is not tagged yet, so there is no version to require. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../../
