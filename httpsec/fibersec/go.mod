module github.com/kartaladev/scrty/httpsec/fibersec

go 1.27

require (
	github.com/gofiber/fiber/v3 v3.6.1
	github.com/kartaladev/scrty v0.0.0
	github.com/stretchr/testify v1.12.1
	github.com/valyala/fasthttp v1.75.0
	go.uber.org/mock v0.6.0
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/gofiber/schema v1.8.8 // indirect
	github.com/gofiber/utils/v2 v2.6.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/jwx/v4 v4.5.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/molecule-man/go-brrr v1.3.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	github.com/tinylib/msgp v1.6.5 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

// The core module is not tagged yet, so there is no version to require. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../../
