module github.com/kartaladev/scrty

go 1.27

require (
	github.com/jonboulle/clockwork v0.5.0
	github.com/lestrrat-go/jwx/v4 v4.5.0
	github.com/pquerna/otp v1.5.0
	github.com/stretchr/testify v1.12.1
	go.uber.org/goleak v1.3.0
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sync v0.24.0
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

// v0.1.0 has three security defects in the httpsec chain, fixed in v0.1.1.
// See the Security section of the 0.1.1 entry in CHANGELOG.md.
retract v0.1.0
