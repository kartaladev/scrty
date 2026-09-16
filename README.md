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

scrty supports the two most recent Go releases, currently **Go 1.26** and **Go 1.27**. Every module
declares `go 1.26`.

## Identifiers are not secrets

`pkg/id` identifiers are sortable UUIDv7 values. They embed a timestamp and a partly predictable
counter, so never use one as a credential, session token or link secret. Those come from
`crypto/rand` in the packages that mint them.

## Development

```sh
make tools   # install pinned golangci-lint, mockgen and govulncheck into ./.bin
make check   # gofmt, go vet, golangci-lint, go test -race, govulncheck, go generate
```

`make check` is what continuous integration runs, on both supported Go versions.

## License

[Apache-2.0](LICENSE).
