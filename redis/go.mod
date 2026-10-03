module github.com/kartaladev/scrty/redis

go 1.27

require (
	github.com/jonboulle/clockwork v0.5.0
	github.com/kartaladev/scrty v0.0.0
	github.com/redis/go-redis/v9 v9.22.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// The core module is not tagged yet, so there is no version to require. The
// replace keeps this module buildable on its own, outside the workspace. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../
