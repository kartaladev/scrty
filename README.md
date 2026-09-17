# scrty

Authentication and authorization for Go applications.

## Modules

| Module | Contents |
|---|---|
| `github.com/kartaladev/scrty` | Core packages. Production builds import only the standard library. |
| `github.com/kartaladev/scrty/test` | Shared test helpers and conformance suites. No other scrty module imports it; run the suites from your own tests to check your implementations. |
| `github.com/kartaladev/scrty/<integration>` | One nested module per framework, driver, scheduler or DI container, added as scrty grows. |

Importing the core module adds no framework, driver or test tooling to your module graph. A test in
this repository enforces that.

## Supported Go versions

scrty requires **Go 1.27** or later. Every module declares `go 1.27`.

The floor is 1.27, not 1.26, because scrty's JOSE stack reads and writes JSON through
`encoding/json/v2`, which reaches the standard library in Go 1.27. On Go 1.26 it builds only under
`GOEXPERIMENT=jsonv2`, and scrty does not ask the applications that embed it to set a
build-environment flag.

## Identifiers are not secrets

`pkg/id` identifiers are sortable UUIDv7 values. They embed a timestamp and a partly predictable
counter, so never use one as a credential, session token or link secret. Those come from
`crypto/rand` in the packages that mint them.

## Development

```sh
make tools   # install pinned golangci-lint, mockgen and govulncheck into ./.bin
make check   # gofmt, go vet, golangci-lint, go test -race, govulncheck, go generate
```

`make check` is what continuous integration runs.

## License

[Apache-2.0](LICENSE).
