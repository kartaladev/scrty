## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** The repository holds only project rules, skills and OpenSpec configuration. There is no Go code, and no consumers or tags.
- **Product decisions already made:**
  - scrty is public and depends on no private libraries;
  - identifiers for library-owned records are sortable and default to UUIDv7;
  - the user reference is an opaque, consumer-owned value, stored as `text`;
  - integrations are nested modules;
  - the core HTTP package is `httpsec`;
  - errors propagate to the consumer's handling instead of being rendered by the library;
  - each persistence adapter owns its own transaction context.
- **Project rules:**
  - every default must be documented and replaceable (library-design);
  - every behaviour is driven by a test first seen to fail (golang-tdd);
  - table tests use the `assert` closure form (table-test);
  - mocks stay out of production builds (use-mockgen);
  - heavy services come from testcontainers helpers (use-testcontainers).
- **Tooling available locally:** Go 1.27.1, golangci-lint 2.13.2, mockgen 0.6.0, govulncheck, gopls 0.23.0.

## Goals / Non-Goals

**Goals:**
- A layout and set of gates every later change can follow without revisiting them.
- An identifier whose ordering guarantee is written down and tested in scrty, not inherited from a dependency's internals.
- A sampler whose suppressed counts can be complete.

**Non-Goals:**
- Any security package, including the consumer-owned user reference type, which belongs to the identity change.
- Creating the `test` module or any integration module. Each is created by the change that first puts code in it, so no module exists empty.
- An ambient-transaction abstraction.
- Release automation and tagging.

## Decisions

### 1. Module path, workspace and nesting

The core module is `github.com/kartaladev/scrty` at the repository root, with a `go.work` listing every module. Nested modules follow one rule: a third-party framework, driver, scheduler or DI container gets its own module named after its role (`ginsec`, `fibersec`, `gorm`, `pgx`, `sweep`, `do`), and shared test helpers go in `test`. Tags will be per module (`v0.1.0`, `ginsec/v0.1.0`).

- **Default:** a consumer requiring only the core gets no framework, driver or test dependency.
- **Override:** a consumer opts into an integration by requiring its module.
- **Alternative rejected:** a single module, which is simpler to tag but makes every consumer download every framework and driver scrty integrates with, including a consumer who uses only net/http.

### 2. Minimum Go version: 1.26

With Go 1.27 released, the Go project supports 1.27 and 1.26, so every module declares `go 1.26` and CI tests both. Code may use features up to 1.26, such as `omitzero`, `t.Context()`, `testing/synctest` and `sync.WaitGroup.Go`.

- **Override:** none. The minimum version is a compatibility line, documented in the README as a limit.
- **Alternative rejected:** an older floor. It would target releases without upstream security fixes and forgo `synctest` for concurrency tests.

### 3. `pkg/id.ID` is a 16-byte array owned by scrty

`type ID [16]byte`, with `Nil`, `IsZero`, `String`, `Parse`, `MustParse` (for tests and constants only), `MarshalText`/`UnmarshalText` (which also serve JSON), and `Scan`/`Value`.

- **Why an array:** it is comparable, so it works as a map key and with `==`. Its zero value is meaningful. Bytewise order equals time order for v7.
- **Why not expose a third-party UUID type:** a public signature would then be tied to another module's major version.
- **Alternatives rejected:** a string type, which allows invalid values to exist unparsed; `int64`, which cannot hold a UUID; Xid, which has no native PostgreSQL type and is not an RFC standard.

### 4. UUIDv7 is implemented in scrty, with a 26-bit monotonic counter

The default `Generator` implements RFC 9562 §5.7 layout with §6.2 Method 1 (a fixed-length dedicated counter):

```
 0                   48      52          64    66                    128
 +-------------------+-------+-----------+-----+----------------------+
 | unix_ts_ms (48)   | ver=7 | counter   | var | counter  | random    |
 |                   |  (4)  | high (12) | (2) | low (14) | (48)      |
 +-------------------+-------+-----------+-----+----------+-----------+
```

Behaviour:
- **New millisecond:** the counter is re-seeded with 25 random bits, leaving its top bit clear, which guarantees at least 2^25 increments of headroom.
- **Same millisecond, or the clock moved backwards:** the generator keeps its last timestamp and increments the counter.
- **Counter overflow:** the timestamp advances by 1 ms and the counter is re-seeded.
- **Concurrency:** one mutex guards the last timestamp and counter.

Randomness errors are returned, never swallowed.

API:
```go
type Generator interface { NewID() (ID, error) }
func NewV7Generator(opts ...V7Option) *V7Generator       // default
func WithClock(now func() time.Time) V7Option             // default time.Now
func WithRandom(r io.Reader) V7Option                      // default crypto/rand.Reader
```

- **Default:** `NewV7Generator()`. Components that create library-owned records accept a `Generator` option and fall back to it.
- **Override:** any `Generator`. A consumer's identifiers are used exactly as returned.
- **Why not a UUID library:** common Go UUID libraries do not document a monotonicity guarantee for v7 generation, so the "strictly increasing" spec requirement would rest on unexported behaviour. The implementation is small and is checked against the RFC 9562 Appendix A.6 test vector.
- **Why 26 bits:** 67 million identifiers per millisecond per generator before the timestamp is borrowed, with 48 random bits left for resistance to collisions between processes. A 12-bit counter would borrow the timestamp above 4,096 identifiers per millisecond; a 42-bit counter would leave 32 random bits.
- **Not secret:** identifiers embed a timestamp and a partly predictable counter, so they are **not** unguessable. The godoc must say they are never to be used as credentials, session tokens or link secrets. Those come from `crypto/rand` in the packages that mint them.

### 5. Encodings: canonical text, strict parsing, SQL as text

- **Text and JSON:** lowercase canonical output; parsing accepts exactly 36 characters in either case and nothing else, empty string included.
  - **Why strict:** a security library should not silently widen what it accepts, and treating `""` as the zero value would hide missing identifiers.
  - **For optional fields:** use `omitzero` or `*id.ID`.
- **SQL:** `Value` sends the canonical string, which PostgreSQL casts to `uuid` and stores as-is in `text`. `Scan` accepts string, 36-byte `[]byte` and 16-byte `[]byte`, and rejects `NULL` and every other type.
  - **Limit, stated:** a consumer writing to a MySQL `BINARY(16)` column must pass `id.ID[:]` explicitly. The default favours PostgreSQL, the backend scrty's adapters target.

### 6. `pkg/logsample`: fixed windows, an optional reporter and `Flush`

```go
func New(window time.Duration, opts ...Option) *Sampler
func WithReporter(fn func(key string, suppressed int)) Option  // default: none
func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int)
func (s *Sampler) Flush()
```

State:
- **Two maps of per-key counts:** `current` and `previous`, so memory is bounded to two windows of keys.
- **Windows:** fixed length, anchored to the first call.
- **First call for a key in a window:** it writes and receives the key's count from `previous`.
- **Later calls in the same window:** they increment the key's count in `current` and do not write.

Rotation and reporting:
- **Rotation happens inside `Allow`:**
  - within two windows, `current` becomes `previous`;
  - at two windows or more, both maps are dropped.
- **What gets reported:** every non-zero count in a map about to be discarded, and on `Flush`, every non-zero count in both maps before they are cleared.
- **How:** the collected pairs are passed to the reporter after the mutex is released, on the calling goroutine.
- **Backwards clock:** a `now` earlier than the window start moves the start back without rotating. Rotating would re-write every key whenever concurrent callers' timestamps arrive slightly out of order, while not rotating still cannot extend suppression.
- **Disabled:** a nil `*Sampler` or a window of zero or less writes everything.

Default and override:
- **Default:** no reporter, which gives a documented lower bound.
- **Override:** a reporter that logs a summary record or increments a metric.
- **Accuracy:** with a reporter, the spec's exactly-once property holds.
- **scrty's own callers:** later security packages always configure a reporter, decided in their changes.

Alternatives rejected:
- **A built-in counter metric:** it adds a metrics dependency to the core. A reporter can feed any metrics library.
- **Writing a log record on rotation from inside the sampler:** the sampler has no logger and should not own one.
- **A background goroutine that flushes on a timer:** that is a lifecycle the consumer must stop. `Flush` lets the consumer or a sweeper decide.
- **Placing the sampler under `internal/`:** the reporter is a consumer-facing override, and consumers' own middleware can reuse the sampler.

### 7. The dependency guard is a test, not a lint rule

A `module_test.go` at the core root:
- runs `go list -deps` over the core module's packages and walks their production imports (the `Imports` of every non-test package);
- reads `go.mod`. A direct requirement on a listed integration module, or any requirement at all on the `test` module, is a violation. Other indirect requirements are allowed, because the `go list -deps` walk already catches transitive production imports;
- parses production files with `go/parser` to find exported `Mock*` types;
- parses every Go file, test files included, for imports of `github.com/kartaladev/scrty/test`, and reads `go.mod` for a requirement on it (decision 9).

It uses only the standard library and the `go` tool, so it adds no dependency. To prove the checks can fail without breaking the real tree, the tests run them against small fixture modules under `testdata/`. Nested modules copy the same guard when they are created.

- **Alternative rejected:** `depguard` in golangci-lint. It sees import paths, not the transitive production graph, and cannot tell a test-only requirement from a production one.

### 8. Build gates: one Makefile entry point, mirrored in CI

- **Makefile:** `make check` runs, for each module listed by `go work edit -json`:
  1. `gofmt -l` (fails on any output);
  2. `go vet ./...`;
  3. `golangci-lint run`;
  4. `go test -race ./...`;
  5. `govulncheck ./...`;
  6. `go generate ./... && git diff --exit-code`.
- **CI:** GitHub Actions runs the same target on a matrix of Go 1.26.x and 1.27.x.
- **`.golangci.yml`:** the v2 schema with `formatters: [gofmt, goimports]` and linters `errorlint`, `gosec`, `bodyclose`, `noctx`, `contextcheck`, `nilerr`, `errcheck`, `staticcheck`, `revive` and `misspell`.
  - **Why an explicit `gofmt -l`:** golangci-lint's default linter set does not include formatting checks, so a repository without this configuration lets formatting drift through.
- **Pinned tool versions:** golangci-lint `v2.13.x`, mockgen `v0.6.0` and govulncheck, as `tool` directives in a separate `tools/go.mod`. It is not listed in `go.work` and is never required by a published module. `make tools` installs them into a git-ignored `.bin/` with `go install tool`, so local runs and CI use the same versions.
  - **Why not the core `go.mod`:** tool requirements there would list the tools' whole dependency tree in every consumer's `go list -m all`. That is the same class of leak decision 9 closes for the `test` module.

### 9. Test helpers: layout now, module later

The decision recorded here is where helpers, and the tests that use them, go: `github.com/kartaladev/scrty/test`.
- **No other scrty module imports it**, from any file, `_test.go` included.
- **Tests that need shared helpers run from inside the `test` module**, which imports the modules under test. That covers integration tests and conformance-suite runs against implementations in other modules: core's `database/sql` adapters, core's in-memory defaults, and the `pgx` and `gorm` adapters.
- **Creation:** the module is created by the first change that needs a shared helper, the persistence adapters, together with `RunTestPostgres`.
- **Skill:** the `use-testcontainers` skill is amended in this change so every later change follows the same rule.

Why:
- **Not from `_test.go` files:** a test-only import still becomes a `go.mod` requirement. Reproduced: a core `_test.go` file importing a helper module that uses pgx adds `github.com/jackc/pgx/v5 // indirect` to core's `go.mod`, and pgx then appears in a core-only consumer's `go list -m all`. That breaks the module-layout guarantee. Nested modules would leak testcontainers to their consumers the same way.
- **Not the skill's default (a `testutils.go` in the producer module):** the producer of the `database/sql` adapter is the core module, so testcontainers and testify would enter every consumer's module graph.

Default, override and limits:
- **Default:** a test that needs a shared helper lives in the `test` module.
- **Override:** none for scrty's own modules; this is a layout guarantee, stated as a limit. Consumers may import the `test` module freely from their own tests to run the conformance suites against their implementations.
- **Alternative rejected:** a separate integration-test module per producer. It means more modules to version and wire into `go.work`, while one `test` module already requires every driver the suites need.

### 10. Test-first throughout

Everything in this change is new code:
- **`pkg/id`:** table tests in the project's `assert` closure form; the RFC test vector; a property test for ordering under a frozen clock; `testing/synctest` and the race detector for concurrency; a fuzz test for `Parse` round trips.
- **`pkg/logsample`:** table tests per scenario; a randomized totals-balance property test; a re-entrancy test for the reporter.
- **Dependency guard:** each fixture module is added with its failing test first.

Each group ends with a `/simplify` pass and a re-run of the tests.

## Risks / Trade-offs

- [A home-grown UUIDv7 has a bit-layout bug] → Test against the RFC 9562 A.6 vector. Assert version and variant bits and embedded timestamps independently of the implementation's own accessors. Fuzz `Parse`/`String` round trips.
- [A burst above 2^25 identifiers per millisecond borrows future timestamps, so identifiers can read slightly ahead of wall-clock time] → Document the limit on `V7Generator`. Store creation times in their own columns; never derive them from identifiers.
- [A reporter that blocks or panics stalls or crashes the caller of `Allow`] → Document that the reporter runs on the caller's goroutine and must be fast and must not panic.
- [Without a reporter, counts are a lower bound] → That is the stated default. scrty's own callers configure a reporter, pinned by tests in their changes.
- [Tools in their own module can drift from the workspace's Go version] → `tools/go.mod` declares the same `go 1.26` line, and CI installs the tools with each matrix Go version before running the gates.
- [Two supported Go versions double CI time] → The core is small at this stage. Revisit when larger packages land.
- [Strict `Scan` rejects `NULL`, which surprises a consumer with nullable columns] → State it in godoc, with the nullable-wrapper recipe (`sql.Null[id.ID]`).

## Migration Plan

Not applicable: a new library with no consumers and no tags.

## Open Questions

- **License.** Which license does scrty ship under (for example Apache-2.0 or MIT)? It must be settled before the `LICENSE` task is applied, and before any tag. It changes no spec, design or task structure.
