# Rule: Navigate Go code with `gopls`

**Always** use `gopls` (the official Go language server) — not plain text search — when navigating
or refactoring Go code in this codebase:

- Go-to-definition, find references, call hierarchy, implementations
- Workspace/package symbol search and package API discovery
- Diagnostics after an edit, safe rename, and refactors (extract / inline / fill)

Reach it via the `gopls-lsp` plugin's native `LSP` tool, the gopls MCP server (`go_*` tools), or the
`gopls` CLI. See the `cc-skills-golang:golang-gopls` skill for usage details.

`grep` / `rg` are a fallback for non-semantic lookups (comments, strings, config files) — never a
substitute for a semantic lookup that gopls can answer.

## If `gopls` seems to be missing

`gopls not found` usually means **"not on `PATH`"**, not **"not installed"**. `go install` drops
binaries into `$(go env GOPATH)/bin`, which is not on `PATH` by default. Check there before
concluding anything:

```sh
ls "$(go env GOPATH)/bin/gopls" && "$(go env GOPATH)/bin/gopls" version
```

If it is there, it is installed — use it via its absolute path for the task at hand, and tell the
user their `PATH` is missing `$(go env GOPATH)/bin` so their other Go tools (`golangci-lint`,
`govulncheck`, `dlv`, ...) are hidden too. The fix belongs in their shell profile:

```sh
export PATH="$(go env GOPATH)/bin:$PATH"
```

Only if the binary is genuinely absent, stop and ask the user to install it:

```sh
go install golang.org/x/tools/gopls@latest
```

Do **not** silently fall back to text search in either case. Confirm with `gopls version` and resume
the Go navigation work once it is available.
