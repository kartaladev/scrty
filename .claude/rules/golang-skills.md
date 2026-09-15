# Rule: Consult `/golang-how-to` for Golang work

**Always** invoke the `cc-skills-golang:golang-how-to` skill (`/golang-how-to`) **before** working on
any Golang-related artifact, including:

- `*.go` / `**/*.go` source and test files
- `go.mod`, `go.sum`, `go.work`, `go.work.sum`
- `.golangci.yml` / `.golangci.yaml`, `Makefile` targets that drive the Go toolchain
- `*.proto` files and generated Go stubs, `tools.go` / `tool` directives
- Any task described in Go terms (goroutines, modules, `go test`, `go build`, panics, etc.)

`/golang-how-to` is the orchestrator: it reads the task at hand and tells you which of the
`cc-skills-golang` skills to load (often several at once — e.g. gRPC work pulls in
`golang-grpc` + `golang-testing` + `golang-error-handling`). Load the skills it recommends and
follow them.

Do this even when the change looks trivial — a one-line edit to a `.go` file still counts.
Only skip it if `/golang-how-to` has already been invoked earlier in the same session and the
task has not changed shape.
