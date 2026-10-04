module github.com/kartaladev/scrty/sweep

go 1.27

require (
	github.com/go-co-op/gocron/v2 v2.22.0
	github.com/google/uuid v1.6.0
	github.com/jonboulle/clockwork v0.5.0
	github.com/kartaladev/scrty v0.0.0
	github.com/stretchr/testify v1.12.1
	go.uber.org/goleak v1.3.0
	go.uber.org/mock v0.6.0
)

require (
	github.com/robfig/cron/v3 v3.0.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
)

// The core module is not tagged yet, so there is no version to require. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../
