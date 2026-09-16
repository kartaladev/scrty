# Project Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each plan task names the `tasks.md` item(s) it delivers; tick the matching `tasks.md` checkbox when the plan task's last step passes.

**Goal:** Create scrty's core Go module with its layout guard, the `pkg/id` UUIDv7 identifier, the `pkg/logsample` refusal-log sampler, and the build gates every later change relies on.

**Architecture:**
- **Modules:**
  - `github.com/kartaladev/scrty` is the core module at the repository root, listed in `go.work`.
  - Lint and mock tools live in a separate, unpublished `tools/` module.
- **Layout guard:** a test-only package at the repository root enforces the module-layout guarantees against the real tree and against small fixture modules under `testdata/`.
- **Packages:** `pkg/id` and `pkg/logsample` are standard-library-only packages, built test-first.
- **Gates:** one `make check` runs the gates for every workspace module, and GitHub Actions runs the same target.

**Tech Stack:**
- Go 1.26 (toolchain 1.27.1 locally);
- `github.com/stretchr/testify` (tests only);
- golangci-lint v2.13.x, mockgen v0.6.0, govulncheck;
- GNU make and GitHub Actions.

**Spec:** `openspec/changes/project-foundation/` — `proposal.md`, `design.md`, `specs/id-generation/spec.md`, `specs/log-sampling/spec.md`, `specs/module-layout/spec.md`, `tasks.md`.

## Global Constraints

- **Module:**
  - Module path `github.com/kartaladev/scrty`.
  - Every `go.mod` declares `go 1.26`.
  - CI tests Go 1.26.x and 1.27.x.
- **Dependencies:**
  - The core module's production build imports only the standard library. No `go.uber.org/mock`, `github.com/stretchr/testify` or `github.com/testcontainers/testcontainers-go` outside `_test.go` files.
  - The core `go.mod` never directly requires `github.com/gin-gonic/gin`, `github.com/gofiber/fiber`, `gorm.io/gorm`, `github.com/jackc/pgx`, `github.com/go-co-op/gocron` or `github.com/samber/do`.
  - No scrty module imports or requires `github.com/kartaladev/scrty/test`, from any file, `_test.go` included.
  - No exported type named `Mock*` in a production file of any module.
- **Tools:** tools are pinned in `tools/go.mod` (not in `go.work`) and installed into the git-ignored `.bin/`.
- **Tests:**
  - Table-driven tests use the `assert` closure form, `t.Context()` and testify `assert`/`require` (`.claude/skills/table-test/SKILL.md`).
  - Every behaviour is seen to fail before its implementation exists (`.claude/rules/golang-tdd.md`). When a test cannot fail against the current code, temporarily break the code, watch the test fail, then restore it.
  - Invoke `/golang-how-to` before starting Go work (`.claude/rules/golang-skills.md`), and navigate Go code with gopls (`.claude/rules/gopls-navigation.md`).
- **`pkg/id`:**
  - Identifiers are not secrets. Godoc must say so.
  - Canonical text is lowercase `8-4-4-4-12` hex.
  - Parsing accepts exactly 36 characters, in either letter case.
  - Every parse failure wraps `id.ErrInvalid`, whose message contains `invalid identifier`.
- **`pkg/logsample`:** the default is no reporter, which gives a lower bound. The reporter runs on the caller's goroutine after the internal lock is released.
- **Every default is documented and replaceable** (`.claude/rules/library-design.md`). Every option's godoc names the default it replaces.

---

## File Structure

| Path | Responsibility |
|---|---|
| `go.mod`, `go.work` | Core module definition; workspace listing core only (later changes add nested modules) |
| `.gitignore` | Add `.bin/` |
| `README.md`, `LICENSE` | Module layout, supported Go versions, identifier-secrecy note; license text |
| `layout_guard_test.go` | Guard helpers: `go list` walk, file scan, `go.mod` reader, violation type |
| `layout_test.go` | `TestModuleLayout` (real tree + fixtures), `TestConsumerModuleGraph` |
| `testdata/layout/<fixture>/…` | Fixture modules, one violation (or allowed pattern) each |
| `testdata/graph/{clean,leaky}/…` | Fixture module graphs for consumer-graph checks |
| `pkg/id/doc.go` | Package documentation |
| `pkg/id/id.go` | `ID`, `Nil`, `ErrInvalid`, `IsZero`, `String`, `Parse`, `MustParse` |
| `pkg/id/encoding.go` | `MarshalText`, `UnmarshalText`, `UnmarshalJSON`, `Scan`, `Value` |
| `pkg/id/generator.go` | `Generator`, `V7Generator`, `V7Option`, `WithClock`, `WithRandom`, `NewV7Generator`, `layout` |
| `pkg/id/id_test.go`, `encoding_test.go`, `generator_test.go` | Black-box tests (`package id_test`) |
| `pkg/id/generator_internal_test.go` | Layout vector and counter overflow (`package id`) |
| `pkg/id/example_test.go` | `ExampleNewV7Generator` |
| `pkg/logsample/logsample.go` | `Sampler`, `Option`, `WithReporter`, `New`, `Allow`, `Flush` |
| `pkg/logsample/logsample_test.go` | Black-box tests |
| `pkg/logsample/logsample_internal_test.go` | Bounded-memory check (`package logsample`) |
| `pkg/logsample/example_test.go` | `ExampleNew` |
| `tools/go.mod`, `tools/go.sum` | Pinned tool versions (`tool` directives) |
| `Makefile` | `tools`, `check` and the individual gates |
| `.golangci.yml` | golangci-lint v2 configuration |
| `.github/workflows/ci.yml` | CI matrix running `make check` |
| `.claude/skills/use-testcontainers/SKILL.md` | Helper placement rule for scrty |

---

### Task 1: Core module and workspace (tasks.md 1.1)

**Files:**
- Create: `go.mod`, `go.work`

**Interfaces:**
- Produces: module path `github.com/kartaladev/scrty`; workspace at repository root.

- [ ] **Step 1: Write the core `go.mod`**

```
module github.com/kartaladev/scrty

go 1.26
```

- [ ] **Step 2: Write `go.work`**

```
go 1.26

use .
```

- [ ] **Step 3: Verify the workspace and build**

Run: `go work edit -json`
Expected: JSON whose `Use` array contains `{"DiskPath": "."}`.

Run: `go build ./...`
Expected: exit 0 (a "matched no packages" warning is fine at this point).

- [ ] **Step 4: Commit**

```bash
git add go.mod go.work
git commit -m "build: create the core module and workspace"
```

---

### Task 2: License and README (tasks.md 1.2)

**Files:**
- Create: `LICENSE`, `README.md`

- [ ] **Step 1: Confirm the license with the user**

The design lists the license as an open question. The decision register recommends Apache-2.0, pending the company's approval to publish. **Stop and ask the user** which license to use. Do not continue this task until they answer.

- [ ] **Step 2: Add the license text**

For Apache-2.0:

```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```

For another license, fetch its canonical text from its official source into `LICENSE`.

- [ ] **Step 3: Write `README.md`**

```markdown
# scrty

Authentication and authorization for Go applications.

## Modules

| Module | Contents |
|---|---|
| `github.com/kartaladev/scrty` | Core packages. Standard library only in production builds. |
| `github.com/kartaladev/scrty/test` | Shared test helpers and conformance suites. Never imported by other scrty modules; run the suites from your own tests to check your implementations. |
| `github.com/kartaladev/scrty/<integration>` | One nested module per framework, driver, scheduler or DI container, added as scrty grows. |

Importing the core module adds no framework, driver or test tooling to your module graph.

## Supported Go versions

scrty supports the two most recent Go releases: **Go 1.26** and **Go 1.27**. Every module declares `go 1.26`.

## Identifiers are not secrets

`pkg/id` identifiers are sortable UUIDv7 values. They embed a timestamp and a partly predictable counter, so never use one as a credential, session token or link secret.
```

- [ ] **Step 4: Verify**

Run: `test -s LICENSE && grep -q "Go 1.26" README.md && grep -q "Go 1.27" README.md && echo ok`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add LICENSE README.md
git commit -m "docs: add license and README"
```

---

### Task 3: Guard production imports (tasks.md 2.1)

**Files:**
- Create: `layout_guard_test.go`, `layout_test.go`
- Create: `testdata/layout/prodtestify/go.mod`, `testdata/layout/prodtestify/app/app.go`, `testdata/layout/prodtestify/stub/testify/go.mod`, `testdata/layout/prodtestify/stub/testify/require/require.go`
- Modify: `go.mod`, `go.sum` (testify, added by `go get`)

**Interfaces:**
- Produces, in `package scrty_test`:
  - `type violation struct{ Where, What string }`;
  - `func checkModule(t *testing.T, dir string) []violation`;
  - `func copyFixture(t *testing.T, root string) string`;
  - `func goCmd(t *testing.T, dir string, env []string, args ...string) string`;
  - `func hasViolation(where, what string) func(t *testing.T, vs []violation)`;
  - `const testModule = "github.com/kartaladev/scrty/test"`.

- [ ] **Step 1: Add testify for tests**

Run: `go get github.com/stretchr/testify@latest`
Expected: `go.mod` gains a `require github.com/stretchr/testify vX.Y.Z` line.

- [ ] **Step 2: Create the fixture module**

`testdata/layout/prodtestify/go.mod`:

```
module example.com/fixture

go 1.26

require github.com/stretchr/testify v0.0.0

replace github.com/stretchr/testify => ./stub/testify
```

`testdata/layout/prodtestify/app/app.go`:

```go
// Package app imports test tooling from a production file.
package app

import _ "github.com/stretchr/testify/require"
```

`testdata/layout/prodtestify/stub/testify/go.mod`:

```
module github.com/stretchr/testify

go 1.26
```

`testdata/layout/prodtestify/stub/testify/require/require.go`:

```go
// Package require is a stand-in used only by guard fixtures.
package require
```

- [ ] **Step 3: Write the failing test**

`layout_test.go`:

```go
package scrty_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModuleLayout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		fixture string // empty means the real repository tree
		assert  func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name: "real tree has no violations",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:    "production file imports testify",
			fixture: "testdata/layout/prodtestify",
			assert:  hasViolation("example.com/fixture/app", "github.com/stretchr/testify"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := "."
			if tc.fixture != "" {
				dir = copyFixture(t, tc.fixture)
			}

			tc.assert(t, checkModule(t, dir))
		})
	}
}
```

`layout_guard_test.go` (only the scaffolding; `checkModule` finds nothing yet):

```go
package scrty_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testModule = "github.com/kartaladev/scrty/test"

type violation struct {
	Where string
	What  string
}

func (v violation) String() string { return v.Where + ": " + v.What }

func checkModule(t *testing.T, dir string) []violation {
	t.Helper()
	return nil
}

func copyFixture(t *testing.T, root string) string {
	t.Helper()
	dst := t.TempDir()
	require.NoError(t, os.CopyFS(dst, os.DirFS(root)))
	return dst
}

func goCmd(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOWORK=off"), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "go %s in %s: %s", strings.Join(args, " "), dir, stderr.String())
	return string(out)
}

func hasViolation(where, what string) func(t *testing.T, vs []violation) {
	return func(t *testing.T, vs []violation) {
		t.Helper()
		for _, v := range vs {
			if v.Where == where && strings.Contains(v.What, what) {
				return
			}
		}
		require.Failf(t, "missing violation", "want a violation at %q mentioning %q, got %v", where, what, vs)
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `go test -run 'TestModuleLayout' -count=1 .`
Expected: FAIL in `production_file_imports_testify` with `missing violation`, because `checkModule` returns nil. `real_tree_has_no_violations` passes.

- [ ] **Step 5: Implement the production-import walk**

Replace `checkModule` in `layout_guard_test.go`, and add the walk below it (merge imports: `bytes`, `encoding/json`):

```go
// forbiddenProduction lists modules no production build may import.
var forbiddenProduction = []string{
	"go.uber.org/mock",
	"github.com/stretchr/testify",
	"github.com/testcontainers/testcontainers-go",
}

type listedPackage struct {
	ImportPath string
	Imports    []string
	Standard   bool
}

func checkModule(t *testing.T, dir string) []violation {
	t.Helper()
	return productionImportViolations(listDeps(t, dir))
}

// listDeps lists every package in dir's production build, dependencies included.
// go list -deps without -test never loads _test.go files.
func listDeps(t *testing.T, dir string) []listedPackage {
	t.Helper()
	out := goCmd(t, dir, nil, "list", "-deps", "-json=ImportPath,Imports,Standard", "./...")
	dec := json.NewDecoder(bytes.NewReader([]byte(out)))
	var pkgs []listedPackage
	for dec.More() {
		var p listedPackage
		require.NoError(t, dec.Decode(&p))
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func productionImportViolations(pkgs []listedPackage) []violation {
	var vs []violation
	for _, p := range pkgs {
		if p.Standard {
			continue
		}
		for _, imp := range p.Imports {
			for _, bad := range forbiddenProduction {
				if imp == bad || strings.HasPrefix(imp, bad+"/") {
					vs = append(vs, violation{Where: p.ImportPath, What: "imports " + imp + " (module " + bad + ")"})
				}
			}
		}
	}
	return vs
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test -run 'TestModuleLayout' -count=1 .`
Expected: PASS (both subtests).

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum layout_guard_test.go layout_test.go testdata/layout/prodtestify
git commit -m "test: guard the core production build against test tooling imports"
```

---

### Task 4: Guard test-only imports, mock types and test-module imports (tasks.md 2.2)

**Files:**
- Create: `testdata/layout/testtestify/{go.mod,app/app.go,app/app_test.go,stub/testify/go.mod,stub/testify/require/require.go}`
- Create: `testdata/layout/prodmock/{go.mod,app/app.go}`
- Create: `testdata/layout/prodtestmodule/{go.mod,app/app.go,stub/test/go.mod,stub/test/postgrestest/postgrestest.go}`
- Create: `testdata/layout/testfiletestmodule/{go.mod,app/app.go,app/app_test.go,stub/test/go.mod,stub/test/postgrestest/postgrestest.go}`
- Modify: `layout_guard_test.go`, `layout_test.go`

**Interfaces:**
- Consumes: `checkModule`, `violation`, `hasViolation`, `copyFixture` (Task 3).
- Produces: `func fileViolations(t *testing.T, dir string) []violation`.

- [ ] **Step 1: Create the fixtures**

`testdata/layout/testtestify/go.mod`:

```
module example.com/fixture

go 1.26

require github.com/stretchr/testify v0.0.0

replace github.com/stretchr/testify => ./stub/testify
```

`testdata/layout/testtestify/app/app.go`:

```go
// Package app has a clean production build.
package app

// Answer returns a constant.
func Answer() int { return 42 }
```

`testdata/layout/testtestify/app/app_test.go`:

```go
package app_test

import (
	"testing"

	_ "github.com/stretchr/testify/require"
)

func TestAnswer(t *testing.T) {}
```

`testdata/layout/testtestify/stub/testify/go.mod` and `stub/testify/require/require.go`: identical to Task 3's stub files.

`testdata/layout/prodmock/go.mod`:

```
module example.com/fixture

go 1.26
```

`testdata/layout/prodmock/app/app.go`:

```go
// Package app declares a mock in a production file.
package app

// MockStore is a generated double that belongs in a _test.go file.
type MockStore struct{}
```

`testdata/layout/prodtestmodule/go.mod`:

```
module example.com/fixture

go 1.26

require github.com/kartaladev/scrty/test v0.0.0

replace github.com/kartaladev/scrty/test => ./stub/test
```

`testdata/layout/prodtestmodule/app/app.go`:

```go
// Package app imports the shared test module from production code.
package app

import _ "github.com/kartaladev/scrty/test/postgrestest"
```

`testdata/layout/prodtestmodule/stub/test/go.mod`:

```
module github.com/kartaladev/scrty/test

go 1.26
```

`testdata/layout/prodtestmodule/stub/test/postgrestest/postgrestest.go`:

```go
// Package postgrestest is a stand-in used only by guard fixtures.
package postgrestest
```

`testdata/layout/testfiletestmodule/go.mod`: identical to `prodtestmodule/go.mod`.

`testdata/layout/testfiletestmodule/app/app.go`:

```go
// Package app has a clean production build.
package app

// Answer returns a constant.
func Answer() int { return 42 }
```

`testdata/layout/testfiletestmodule/app/app_test.go`:

```go
package app_test

import (
	"testing"

	_ "github.com/kartaladev/scrty/test/postgrestest"
)

func TestAnswer(t *testing.T) {}
```

`testdata/layout/testfiletestmodule/stub/test/go.mod` and `stub/test/postgrestest/postgrestest.go`: identical to the `prodtestmodule` stub files.

- [ ] **Step 2: Add the failing cases**

Append to `cases` in `TestModuleLayout`:

```go
		{
			name:    "test file imports testify is allowed",
			fixture: "testdata/layout/testtestify",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:    "production file declares an exported mock",
			fixture: "testdata/layout/prodmock",
			assert:  hasViolation("app/app.go", "MockStore"),
		},
		{
			name:    "production file imports the test module",
			fixture: "testdata/layout/prodtestmodule",
			assert:  hasViolation("app/app.go", testModule),
		},
		{
			name:    "test file imports the test module",
			fixture: "testdata/layout/testfiletestmodule",
			assert:  hasViolation("app/app_test.go", testModule),
		},
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test -run 'TestModuleLayout' -count=1 .`
Expected: FAIL in `production_file_declares_an_exported_mock`, `production_file_imports_the_test_module` and `test_file_imports_the_test_module`, each with `missing violation`. `test_file_imports_testify_is_allowed` passes.

- [ ] **Step 4: Implement the file scan**

In `layout_guard_test.go`, add the imports `go/ast`, `go/parser`, `go/token`, `io/fs`, `path/filepath`, `strconv`, then:

```go
func checkModule(t *testing.T, dir string) []violation {
	t.Helper()
	var vs []violation
	vs = append(vs, productionImportViolations(listDeps(t, dir))...)
	vs = append(vs, fileViolations(t, dir)...)
	return vs
}

// fileViolations scans every Go file of the module rooted at dir, skipping
// testdata, dot and underscore directories, and nested modules.
func fileViolations(t *testing.T, dir string) []violation {
	t.Helper()
	var vs []violation
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == dir {
				return nil
			}
			name := d.Name()
			if name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		for _, imp := range f.Imports {
			p, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if p == testModule || strings.HasPrefix(p, testModule+"/") {
				vs = append(vs, violation{Where: rel, What: "imports " + p})
			}
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if ok && ts.Name.IsExported() && strings.HasPrefix(ts.Name.Name, "Mock") {
					vs = append(vs, violation{Where: rel, What: "declares exported type " + ts.Name.Name})
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	return vs
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -run 'TestModuleLayout' -count=1 .`
Expected: PASS (all six subtests).

- [ ] **Step 6: Commit**

```bash
git add layout_guard_test.go layout_test.go testdata/layout
git commit -m "test: guard against mocks in production files and any import of the test module"
```

---

### Task 5: Guard `go.mod` requirements (tasks.md 2.3)

**Files:**
- Create: `testdata/layout/requiresgin/{go.mod,app/app.go,stub/gin/go.mod,stub/gin/gin.go}`
- Create: `testdata/layout/requirestestmodule/{go.mod,app/app.go,stub/test/go.mod,stub/test/postgrestest/postgrestest.go}`
- Modify: `layout_guard_test.go`, `layout_test.go`

**Interfaces:**
- Consumes: `checkModule`, `testModule`, `hasViolation` (Tasks 3–4).
- Produces:
  - `var integrationModules []string`;
  - `type requirement struct{ Path string; Indirect bool }`;
  - `func readRequires(t *testing.T, gomod string) []requirement`;
  - `func requireViolations(reqs []requirement) []violation`.

- [ ] **Step 1: Create the fixtures**

`testdata/layout/requiresgin/go.mod`:

```
module example.com/fixture

go 1.26

require github.com/gin-gonic/gin v0.0.0

replace github.com/gin-gonic/gin => ./stub/gin
```

`testdata/layout/requiresgin/app/app.go`:

```go
// Package app has a clean production build.
package app

// Answer returns a constant.
func Answer() int { return 42 }
```

`testdata/layout/requiresgin/stub/gin/go.mod`:

```
module github.com/gin-gonic/gin

go 1.26
```

`testdata/layout/requiresgin/stub/gin/gin.go`:

```go
// Package gin is a stand-in used only by guard fixtures.
package gin
```

`testdata/layout/requirestestmodule/go.mod`:

```
module example.com/fixture

go 1.26

require github.com/kartaladev/scrty/test v0.0.0 // indirect

replace github.com/kartaladev/scrty/test => ./stub/test
```

`testdata/layout/requirestestmodule/app/app.go`: identical to `requiresgin/app/app.go`.

`testdata/layout/requirestestmodule/stub/test/go.mod` and `stub/test/postgrestest/postgrestest.go`: identical to Task 4's `prodtestmodule` stub files.

- [ ] **Step 2: Add the failing cases**

Append to `cases` in `TestModuleLayout`:

```go
		{
			name:    "go.mod requires an integration module",
			fixture: "testdata/layout/requiresgin",
			assert:  hasViolation("go.mod", "github.com/gin-gonic/gin"),
		},
		{
			name:    "go.mod requires the test module indirectly",
			fixture: "testdata/layout/requirestestmodule",
			assert:  hasViolation("go.mod", testModule),
		},
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test -run 'TestModuleLayout' -count=1 .`
Expected: FAIL in both new subtests with `missing violation`.

- [ ] **Step 4: Implement the requirement check**

In `layout_guard_test.go`:

```go
// integrationModules lists modules the core go.mod must never require directly.
var integrationModules = []string{
	"github.com/gin-gonic/gin",
	"github.com/gofiber/fiber",
	"gorm.io/gorm",
	"github.com/jackc/pgx",
	"github.com/go-co-op/gocron",
	"github.com/samber/do",
}

type requirement struct {
	Path     string
	Indirect bool
}

func checkModule(t *testing.T, dir string) []violation {
	t.Helper()
	var vs []violation
	vs = append(vs, productionImportViolations(listDeps(t, dir))...)
	vs = append(vs, fileViolations(t, dir)...)
	vs = append(vs, requireViolations(readRequires(t, filepath.Join(dir, "go.mod")))...)
	return vs
}

// readRequires parses the require directives of a go.mod file.
func readRequires(t *testing.T, gomod string) []requirement {
	t.Helper()
	data, err := os.ReadFile(gomod)
	require.NoError(t, err)
	var reqs []requirement
	inBlock := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !inBlock:
			continue
		}
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		reqs = append(reqs, requirement{
			Path:     strings.Fields(line)[0],
			Indirect: strings.Contains(line, "// indirect"),
		})
	}
	return reqs
}

func requireViolations(reqs []requirement) []violation {
	var vs []violation
	for _, r := range reqs {
		if r.Path == testModule || strings.HasPrefix(r.Path, testModule+"/") {
			vs = append(vs, violation{Where: "go.mod", What: "requires " + r.Path})
			continue
		}
		if r.Indirect {
			continue
		}
		for _, bad := range integrationModules {
			if r.Path == bad || strings.HasPrefix(r.Path, bad+"/") {
				vs = append(vs, violation{Where: "go.mod", What: "requires " + r.Path})
			}
		}
	}
	return vs
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -run 'TestModuleLayout' -count=1 .`
Expected: PASS (all eight subtests, including `real_tree_has_no_violations`).

- [ ] **Step 6: Commit**

```bash
git add layout_guard_test.go layout_test.go testdata/layout
git commit -m "test: guard the core go.mod against integration and test-module requirements"
```

---

### Task 6: Consumer module graphs (tasks.md 2.4)

**Files:**
- Create: `testdata/graph/clean/{core/go.mod,core/core.go,helpers/go.mod,helpers/helpers.go,driver/go.mod,driver/driver.go,consumer/go.mod}`
- Create: `testdata/graph/leaky/{core/go.mod,core/core.go,core/core_test.go,helpers/go.mod,helpers/helpers.go,driver/go.mod,driver/driver.go,consumer/go.mod}`
- Modify: `layout_test.go`, `layout_guard_test.go`

**Interfaces:**
- Consumes: `copyFixture`, `goCmd`, `integrationModules` (Tasks 3–5).
- Produces:
  - `func listModules(t *testing.T, dir string, env []string) []string`;
  - `func realCoreConsumer(t *testing.T) (dir string, env []string)`.

- [ ] **Step 1: Create the clean graph**

`testdata/graph/clean/core/go.mod`:

```
module example.com/core

go 1.26
```

`testdata/graph/clean/core/core.go`:

```go
// Package core stands in for the published core module.
package core

// Answer returns a constant.
func Answer() int { return 42 }
```

`testdata/graph/clean/helpers/go.mod`:

```
module example.com/core/test

go 1.26

require (
	example.com/core v0.0.0
	example.com/driver v0.0.0
)

replace (
	example.com/core => ../core
	example.com/driver => ../driver
)
```

`testdata/graph/clean/helpers/helpers.go`:

```go
// Package helpers stands in for the shared test module; it uses the driver and the core.
package helpers

import (
	_ "example.com/core"
	_ "example.com/driver"
)
```

`testdata/graph/clean/driver/go.mod`:

```
module example.com/driver

go 1.26
```

`testdata/graph/clean/driver/driver.go`:

```go
// Package driver stands in for a database driver.
package driver
```

`testdata/graph/clean/consumer/go.mod`:

```
module example.com/consumer

go 1.26

require example.com/core v0.0.0

replace (
	example.com/core => ../core
	example.com/core/test => ../helpers
	example.com/driver => ../driver
)
```

- [ ] **Step 2: Create the leaky control graph**

Copy the `helpers/` and `driver/` directories, and the `consumer/go.mod` file, from `clean` unchanged. Then:

`testdata/graph/leaky/core/go.mod` (what `go mod tidy` writes once a core test imports the helper):

```
module example.com/core

go 1.26

require example.com/core/test v0.0.0

require example.com/driver v0.0.0 // indirect
```

`testdata/graph/leaky/core/core.go`: identical to the clean `core.go`.

`testdata/graph/leaky/core/core_test.go`:

```go
package core_test

import (
	"testing"

	_ "example.com/core/test"
)

func TestAnswer(t *testing.T) {}
```

- [ ] **Step 3: Write the failing test**

Add to `layout_guard_test.go`:

```go
// listModules returns the module paths in dir's module graph.
func listModules(t *testing.T, dir string, env []string) []string {
	t.Helper()
	return strings.Fields(goCmd(t, dir, env, "list", "-m", "-f", "{{.Path}}", "all"))
}

// realCoreConsumer writes a consumer module that requires the repository's core
// module through a replace directive, in a temporary directory.
func realCoreConsumer(t *testing.T) (string, []string) {
	t.Helper()
	root, err := filepath.Abs(".")
	require.NoError(t, err)
	dir := t.TempDir()
	gomod := "module example.com/consumer\n\ngo 1.26\n\nrequire github.com/kartaladev/scrty v0.0.0\n\nreplace github.com/kartaladev/scrty => " + root + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600))
	// -mod=mod lets go list record go.sum entries for the core's own requirements, in the temp dir only.
	return dir, []string{"GOFLAGS=-mod=mod"}
}
```

Add to `layout_test.go` (merge the import `strings`):

```go
func TestConsumerModuleGraph(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		consumer func(t *testing.T) (dir string, env []string)
		assert   func(t *testing.T, modules []string)
	}

	fixtureConsumer := func(graph string) func(t *testing.T) (string, []string) {
		return func(t *testing.T) (string, []string) {
			return filepath.Join(copyFixture(t, graph), "consumer"), nil
		}
	}

	cases := []testCase{
		{
			name:     "helper used only inside its own module keeps the driver out",
			consumer: fixtureConsumer("testdata/graph/clean"),
			assert: func(t *testing.T, modules []string) {
				assert.NotContains(t, modules, "example.com/driver")
				assert.NotContains(t, modules, "example.com/core/test")
			},
		},
		{
			name:     "control: a core test file importing the helper leaks the driver",
			consumer: fixtureConsumer("testdata/graph/leaky"),
			assert: func(t *testing.T, modules []string) {
				assert.Contains(t, modules, "example.com/driver")
			},
		},
		{
			name:     "consumer of the real core sees no integration module",
			consumer: realCoreConsumer,
			assert: func(t *testing.T, modules []string) {
				for _, m := range modules {
					for _, bad := range append(slices.Clone(integrationModules), testModule) {
						assert.False(t, m == bad || strings.HasPrefix(m, bad+"/"), "consumer graph contains %s", m)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir, env := tc.consumer(t)
			tc.assert(t, listModules(t, dir, env))
		})
	}
}
```

(`layout_test.go` imports: `path/filepath`, `slices`, `strings`, `testing`, `github.com/stretchr/testify/assert`.)

- [ ] **Step 4: Run the test and see the clean case fail when broken**

Temporarily add `require example.com/core/test v0.0.0` and `require example.com/driver v0.0.0 // indirect` to `testdata/graph/clean/core/go.mod`.

Run: `go test -run 'TestConsumerModuleGraph' -count=1 .`
Expected: FAIL in `helper_used_only_inside_its_own_module_keeps_the_driver_out`, with `should not contain "example.com/driver"`.

Revert the two lines.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -run 'TestConsumerModuleGraph|TestModuleLayout' -count=1 .`
Expected: PASS. The real-core case needs the module cache or network access to resolve testify.

- [ ] **Step 6: Commit**

```bash
git add layout_guard_test.go layout_test.go testdata/graph
git commit -m "test: prove consumers of the core never see helper drivers or integration modules"
```

---

### Task 7: `ID` zero value (tasks.md 3.1)

**Files:**
- Create: `pkg/id/id.go`, `pkg/id/id_test.go`

**Interfaces:**
- Produces: `type ID [16]byte`; `var Nil ID`; `func (i ID) IsZero() bool`.

- [ ] **Step 1: Write the failing test**

`pkg/id/id_test.go`:

```go
package id_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/pkg/id"
)

func TestID_IsZero(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  id.ID
		assert func(t *testing.T, zero bool)
	}

	cases := []testCase{
		{
			name:   "unassigned value",
			value:  id.ID{},
			assert: func(t *testing.T, zero bool) { assert.True(t, zero) },
		},
		{
			name:   "Nil",
			value:  id.Nil,
			assert: func(t *testing.T, zero bool) { assert.True(t, zero) },
		},
		{
			name:   "any non-zero byte",
			value:  id.ID{15: 1},
			assert: func(t *testing.T, zero bool) { assert.False(t, zero) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.value.IsZero())
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -run 'TestID_IsZero' -count=1 ./pkg/id`
Expected: FAIL to compile with `undefined: id.ID` (package missing). Then create an empty `pkg/id/id.go` with only `package id` and re-run.
Expected: FAIL with `undefined: id.ID`.

- [ ] **Step 3: Write the minimal implementation**

`pkg/id/id.go`:

```go
package id

// ID is a 16-byte identifier for records scrty owns.
type ID [16]byte

// Nil is the zero ID. It means "no identifier", and no generator scrty ships returns it.
var Nil ID

// IsZero reports whether i is the zero ID.
func (i ID) IsZero() bool { return i == Nil }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -run 'TestID_IsZero' -count=1 ./pkg/id`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/id.go pkg/id/id_test.go go.mod go.sum
git commit -m "feat(id): add the ID type and its zero value"
```

---

### Task 8: Canonical text and strict parsing (tasks.md 3.2)

**Files:**
- Modify: `pkg/id/id.go`, `pkg/id/id_test.go`

**Interfaces:**
- Consumes: `ID`, `Nil` (Task 7).
- Produces:
  - `var ErrInvalid error` (message `id: invalid identifier`);
  - `func (i ID) String() string`;
  - `func Parse(s string) (ID, error)`;
  - `func MustParse(s string) ID`.

- [ ] **Step 1: Write the failing test**

Append to `pkg/id/id_test.go` (merge the imports `strings`, `github.com/stretchr/testify/require`):

```go
const vector = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" // RFC 9562 Appendix A.6

func TestParse(t *testing.T) {
	t.Parallel()

	sample := id.ID{0: 0xde, 7: 0x42, 15: 0xad}

	type testCase struct {
		name   string
		input  string
		assert func(t *testing.T, got id.ID, err error)
	}

	invalid := func(t *testing.T, got id.ID, err error) {
		require.ErrorIs(t, err, id.ErrInvalid)
		assert.Contains(t, err.Error(), "invalid identifier")
		assert.Equal(t, id.Nil, got)
	}

	cases := []testCase{
		{
			name:  "canonical vector",
			input: vector,
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vector, got.String())
			},
		},
		{
			name:  "uppercase input formats lowercase",
			input: strings.ToUpper(vector),
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vector, got.String())
			},
		},
		{
			name:  "formatted identifier round trips",
			input: sample.String(),
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, sample, got)
			},
		},
		{
			name:  "version 4 identifier parses unchanged",
			input: "9b2f8c1e-4a5d-4c3b-8e2f-1a2b3c4d5e6f",
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, "9b2f8c1e-4a5d-4c3b-8e2f-1a2b3c4d5e6f", got.String())
			},
		},
		{name: "empty string", input: "", assert: invalid},
		{name: "braces", input: "{" + vector + "}", assert: invalid},
		{name: "urn prefix", input: "urn:uuid:" + vector, assert: invalid},
		{name: "no hyphens", input: strings.ReplaceAll(vector, "-", ""), assert: invalid},
		{name: "non-hex character", input: vector[:35] + "g", assert: invalid},
		{name: "hyphen in the wrong place", input: vector[:7] + "-" + vector[8:], assert: invalid},
		{
			name:  "long input is not echoed in full",
			input: strings.Repeat("a", 10_000),
			assert: func(t *testing.T, got id.ID, err error) {
				invalid(t, got, err)
				assert.Less(t, len(err.Error()), 200)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := id.Parse(tc.input)
			tc.assert(t, got, err)
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -run 'TestParse' -count=1 ./pkg/id`
Expected: FAIL to compile with `undefined: id.Parse`, `undefined: id.ErrInvalid` and `sample.String undefined`.

- [ ] **Step 3: Write the minimal implementation**

Append to `pkg/id/id.go`, with imports `encoding/hex`, `errors`, `fmt`, `strconv`:

```go
// ErrInvalid is wrapped by every error returned for input that is not a canonical identifier.
var ErrInvalid = errors.New("id: invalid identifier")

// String formats i as a lowercase RFC 9562 string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func (i ID) String() string {
	var buf [36]byte
	hex.Encode(buf[0:8], i[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], i[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], i[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], i[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], i[10:16])
	return string(buf[:])
}

// Parse accepts exactly the 36-character hyphenated layout, in either letter case,
// and rejects everything else, the empty string included. It does not check the
// version field, so identifiers from a consumer's generator parse unchanged.
func Parse(s string) (ID, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return Nil, fmt.Errorf("%w: %s", ErrInvalid, describe(s))
	}
	var i ID
	groups := [...][2]int{{0, 8}, {9, 13}, {14, 18}, {19, 23}, {24, 36}}
	pos := 0
	for _, g := range groups {
		n, err := hex.Decode(i[pos:], []byte(s[g[0]:g[1]]))
		if err != nil {
			return Nil, fmt.Errorf("%w: %s", ErrInvalid, describe(s))
		}
		pos += n
	}
	return i, nil
}

// MustParse is Parse for tests and constants; it panics on invalid input.
func MustParse(s string) ID {
	i, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return i
}

// describe quotes short input and summarises long input, so errors never echo unbounded data.
func describe(s string) string {
	const maxEcho = 64
	if len(s) > maxEcho {
		return strconv.Itoa(len(s)) + "-byte input"
	}
	return strconv.Quote(s)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -run 'TestParse|TestID_IsZero' -count=1 ./pkg/id`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/id.go pkg/id/id_test.go
git commit -m "feat(id): format canonical text and parse strictly"
```

---

### Task 9: JSON encoding (tasks.md 3.3)

**Files:**
- Create: `pkg/id/encoding.go`, `pkg/id/encoding_test.go`

**Interfaces:**
- Consumes: `ID`, `Parse`, `ErrInvalid`, `describe` (Task 8).
- Produces:
  - `func (i ID) MarshalText() ([]byte, error)`;
  - `func (i *ID) UnmarshalText(b []byte) error`;
  - `func (i *ID) UnmarshalJSON(data []byte) error`.

- [ ] **Step 1: Write the failing tests**

`pkg/id/encoding_test.go`:

```go
package id_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

type record struct {
	ID       id.ID `json:"id"`
	Optional id.ID `json:"optional,omitzero"`
}

func TestID_MarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		input  record
		assert func(t *testing.T, got []byte, err error)
	}

	cases := []testCase{
		{
			name:  "identifier encodes as a JSON string and a zero optional is omitted",
			input: record{ID: id.MustParse(vector)},
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"id":"`+vector+`"}`, string(got))
			},
		},
		{
			name:  "non-zero optional is present",
			input: record{ID: id.MustParse(vector), Optional: id.MustParse(vector)},
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"id":"`+vector+`","optional":"`+vector+`"}`, string(got))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.input)
			tc.assert(t, got, err)
		})
	}
}

func TestID_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		input  string
		assert func(t *testing.T, got id.ID, err error)
	}

	cases := []testCase{
		{
			name:  "JSON string",
			input: `"` + vector + `"`,
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, id.MustParse(vector), got)
			},
		},
		{
			name:  "JSON number",
			input: `42`,
			assert: func(t *testing.T, _ id.ID, err error) {
				require.ErrorIs(t, err, id.ErrInvalid)
			},
		},
		{
			name:  "empty JSON string",
			input: `""`,
			assert: func(t *testing.T, _ id.ID, err error) {
				require.ErrorIs(t, err, id.ErrInvalid)
			},
		},
		{
			name:  "JSON null into a non-pointer identifier",
			input: `null`,
			assert: func(t *testing.T, _ id.ID, err error) {
				require.ErrorIs(t, err, id.ErrInvalid)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got id.ID
			err := json.Unmarshal([]byte(tc.input), &got)
			tc.assert(t, got, err)
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestID_MarshalJSON|TestID_UnmarshalJSON' -count=1 ./pkg/id`
Expected: FAIL. Marshal encodes a byte array (`"id":[1,127,...]`), and the unmarshal error cases don't wrap `ErrInvalid`.

- [ ] **Step 3: Write the minimal implementation**

`pkg/id/encoding.go`:

```go
package id

import (
	"encoding/json"
	"fmt"
)

// MarshalText returns the canonical lowercase text form. It also serves JSON encoding.
func (i ID) MarshalText() ([]byte, error) { return []byte(i.String()), nil }

// UnmarshalText parses b with Parse. On error, i is left unchanged.
func (i *ID) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*i = parsed
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a canonical identifier.
// JSON null, numbers and other values fail; use *ID or omitzero for optional fields.
func (i *ID) UnmarshalJSON(data []byte) error {
	var s string
	if string(data) == "null" || json.Unmarshal(data, &s) != nil {
		return fmt.Errorf("%w: JSON value %s is not an identifier string", ErrInvalid, describe(string(data)))
	}
	return i.UnmarshalText([]byte(s))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./pkg/id`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/encoding.go pkg/id/encoding_test.go
git commit -m "feat(id): encode identifiers as JSON strings and decode strictly"
```

---

### Task 10: SQL encoding (tasks.md 3.4)

**Files:**
- Modify: `pkg/id/encoding.go`, `pkg/id/encoding_test.go`

**Interfaces:**
- Consumes: `UnmarshalText`, `ErrInvalid` (Task 9).
- Produces:
  - `func (i *ID) Scan(src any) error`;
  - `func (i ID) Value() (driver.Value, error)`.

The native PostgreSQL `uuid` round-trip scenario is verified later by the persistence change, in the `test` module.

- [ ] **Step 1: Write the failing tests**

Append to `pkg/id/encoding_test.go` (merge the import `database/sql/driver`):

```go
func TestID_Scan(t *testing.T) {
	t.Parallel()

	vectorID := id.MustParse(vector)
	sentinel := id.ID{0: 0xff, 15: 0xff}

	type testCase struct {
		name   string
		src    any
		assert func(t *testing.T, got id.ID, err error)
	}

	rejected := func(t *testing.T, got id.ID, err error) {
		require.ErrorIs(t, err, id.ErrInvalid)
		assert.Equal(t, sentinel, got, "a failed scan leaves the value unchanged")
	}

	cases := []testCase{
		{
			name: "canonical string",
			src:  vector,
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vectorID, got)
			},
		},
		{
			name: "canonical text as bytes",
			src:  []byte(vector),
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vectorID, got)
			},
		},
		{
			name: "16-byte binary keeps byte order",
			src:  vectorID[:],
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vectorID, got)
			},
		},
		{name: "SQL NULL", src: nil, assert: rejected},
		{name: "15-byte value", src: make([]byte, 15), assert: rejected},
		{name: "malformed string", src: "not-an-id", assert: rejected},
		{name: "unsupported type", src: int64(7), assert: rejected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sentinel
			err := got.Scan(tc.src)
			tc.assert(t, got, err)
		})
	}
}

func TestID_Value(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  id.ID
		assert func(t *testing.T, got driver.Value, err error)
	}

	cases := []testCase{
		{
			name:  "canonical text",
			value: id.MustParse(vector),
			assert: func(t *testing.T, got driver.Value, err error) {
				require.NoError(t, err)
				assert.Equal(t, vector, got)
			},
		},
		{
			name:  "zero identifier is canonical zero text",
			value: id.Nil,
			assert: func(t *testing.T, got driver.Value, err error) {
				require.NoError(t, err)
				assert.Equal(t, "00000000-0000-0000-0000-000000000000", got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.value.Value()
			tc.assert(t, got, err)
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestID_Scan|TestID_Value' -count=1 ./pkg/id`
Expected: FAIL to compile with `got.Scan undefined` and `tc.value.Value undefined`.

- [ ] **Step 3: Write the minimal implementation**

Append to `pkg/id/encoding.go` (merge the import `database/sql/driver`):

```go
// Scan implements sql.Scanner. It accepts canonical text (string or []byte) and
// 16-byte binary. SQL NULL and every other type fail; scan nullable columns with
// sql.Null[id.ID]. On error, i is left unchanged.
func (i *ID) Scan(src any) error {
	switch v := src.(type) {
	case string:
		return i.UnmarshalText([]byte(v))
	case []byte:
		switch len(v) {
		case 16:
			copy(i[:], v)
			return nil
		case 36:
			return i.UnmarshalText(v)
		}
		return fmt.Errorf("%w: %d-byte SQL value", ErrInvalid, len(v))
	case nil:
		return fmt.Errorf("%w: SQL NULL", ErrInvalid)
	default:
		return fmt.Errorf("%w: unsupported SQL type %T", ErrInvalid, src)
	}
}

// Value implements driver.Valuer and sends canonical text, which PostgreSQL accepts
// for uuid and text columns. For a BINARY(16) column, pass i[:] explicitly.
func (i ID) Value() (driver.Value, error) { return i.String(), nil }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./pkg/id`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/encoding.go pkg/id/encoding_test.go
git commit -m "feat(id): scan and value identifiers for database/sql"
```

---

### Task 11: UUIDv7 layout and deterministic generation (tasks.md 3.5)

**Files:**
- Create: `pkg/id/generator.go`, `pkg/id/generator_test.go`, `pkg/id/generator_internal_test.go`

**Interfaces:**
- Consumes: `ID` (Task 7).
- Produces:
  - `type Generator interface{ NewID() (ID, error) }`;
  - `type V7Generator struct{...}`;
  - `type V7Option func(*V7Generator)`;
  - `func WithClock(now func() time.Time) V7Option`;
  - `func WithRandom(r io.Reader) V7Option`;
  - `func NewV7Generator(opts ...V7Option) *V7Generator`;
  - `func (g *V7Generator) NewID() (ID, error)`;
  - unexported `func layout(ms int64, counter uint32, random []byte) ID`.

- [ ] **Step 1: Write the failing tests**

`pkg/id/generator_internal_test.go`:

```go
package id

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Layout reproduces the RFC 9562 Appendix A.6 vector from its fields. The 26-bit
// counter is rand_a (12 bits) followed by the top 14 bits of rand_b.
func TestLayout_RFC9562Vector(t *testing.T) {
	t.Parallel()

	tail, err := hex.DecodeString("dc0c0c07398f")
	require.NoError(t, err)

	got := layout(0x017F22E279B0, 0xCC3<<14|0x18C4, tail)

	assert.Equal(t, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f", got.String())
}
```

`pkg/id/generator_test.go`:

```go
package id_test

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

var t0 = time.Date(2022, 2, 22, 19, 22, 22, 0, time.UTC)

func frozen(at time.Time) func() time.Time { return func() time.Time { return at } }

func seeded(seed byte) *rand.ChaCha8 { return rand.NewChaCha8([32]byte{seed}) }

func TestV7Generator_Layout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, newGen func() *id.V7Generator)
	}

	cases := []testCase{
		{
			name: "version, variant and millisecond timestamp",
			assert: func(t *testing.T, newGen func() *id.V7Generator) {
				got, err := newGen().NewID()
				require.NoError(t, err)
				assert.Equal(t, byte(7), got[6]>>4, "version")
				assert.Equal(t, byte(0b10), got[8]>>6, "variant")
				var ms [8]byte
				copy(ms[2:], got[:6])
				assert.Equal(t, uint64(1645557742000), binary.BigEndian.Uint64(ms[:]))
				assert.False(t, got.IsZero())
			},
		},
		{
			name: "identically configured generators produce the same sequence",
			assert: func(t *testing.T, newGen func() *id.V7Generator) {
				a, b := newGen(), newGen()
				for range 10 {
					x, errA := a.NewID()
					y, errB := b.NewID()
					require.NoError(t, errA)
					require.NoError(t, errB)
					assert.Equal(t, x, y)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, func() *id.V7Generator {
				return id.NewV7Generator(id.WithClock(frozen(t0)), id.WithRandom(seeded(1)))
			})
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestLayout_RFC9562Vector|TestV7Generator_Layout' -count=1 ./pkg/id`
Expected: FAIL to compile with `undefined: layout`, `undefined: id.NewV7Generator`, `undefined: id.WithClock` and `undefined: id.WithRandom`.

- [ ] **Step 3: Write the minimal implementation**

`pkg/id/generator.go` (no counter carry-over yet: each call seeds a fresh counter):

```go
package id

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"
)

// Generator creates identifiers for library-owned records. Components accept a
// Generator option and use NewV7Generator when none is configured.
type Generator interface {
	NewID() (ID, error)
}

const (
	counterBits = 26
	seedBits    = 25
	counterMax  = 1<<counterBits - 1
	seedMask    = 1<<seedBits - 1
)

// V7Generator produces RFC 9562 version 7 identifiers.
type V7Generator struct {
	now    func() time.Time
	random io.Reader
}

// V7Option configures a V7Generator.
type V7Option func(*V7Generator)

// WithClock replaces the time source. Default: time.Now. A nil function keeps the default.
func WithClock(now func() time.Time) V7Option {
	return func(g *V7Generator) {
		if now != nil {
			g.now = now
		}
	}
}

// WithRandom replaces the random source. Default: crypto/rand.Reader. A nil reader keeps the default.
func WithRandom(r io.Reader) V7Option {
	return func(g *V7Generator) {
		if r != nil {
			g.random = r
		}
	}
}

// NewV7Generator returns the default generator.
func NewV7Generator(opts ...V7Option) *V7Generator {
	g := &V7Generator{now: time.Now, random: rand.Reader}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g
}

// NewID returns the next identifier.
func (g *V7Generator) NewID() (ID, error) {
	var rnd [10]byte
	_, _ = io.ReadFull(g.random, rnd[:])
	seed := binary.BigEndian.Uint32(rnd[0:4]) & seedMask
	return layout(g.now().UnixMilli(), seed, rnd[4:10]), nil
}

// layout places a 48-bit millisecond timestamp, the version, a 26-bit counter
// (12 bits in rand_a, 14 bits at the top of rand_b), the variant and 48 random bits.
func layout(ms int64, counter uint32, random []byte) ID {
	var i ID
	i[0] = byte(ms >> 40)
	i[1] = byte(ms >> 32)
	i[2] = byte(ms >> 24)
	i[3] = byte(ms >> 16)
	i[4] = byte(ms >> 8)
	i[5] = byte(ms)
	hi := uint16(counter >> 14)
	lo := uint16(counter & 0x3FFF)
	i[6] = 0x70 | byte(hi>>8)
	i[7] = byte(hi)
	i[8] = 0x80 | byte(lo>>8)
	i[9] = byte(lo)
	copy(i[10:], random)
	return i
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -run 'TestLayout_RFC9562Vector|TestV7Generator_Layout' -count=1 ./pkg/id`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/generator.go pkg/id/generator_test.go pkg/id/generator_internal_test.go
git commit -m "feat(id): lay out RFC 9562 version 7 identifiers"
```

---

### Task 12: Strictly increasing order (tasks.md 3.6)

**Files:**
- Modify: `pkg/id/generator.go`, `pkg/id/generator_test.go`, `pkg/id/generator_internal_test.go`

**Interfaces:**
- Consumes: `V7Generator`, `layout`, `counterMax`, `seedMask` (Task 11).
- Produces: `V7Generator` fields `lastMS int64` and `counter uint32`.

- [ ] **Step 1: Write the failing tests**

Append to `pkg/id/generator_test.go` (merge the imports `bytes`, `strings`):

```go
func assertStrictlyIncreasing(t *testing.T, ids []id.ID) {
	t.Helper()
	for n := 1; n < len(ids); n++ {
		prev, cur := ids[n-1], ids[n]
		require.Negative(t, bytes.Compare(prev[:], cur[:]), "bytes at %d", n)
		require.Negative(t, strings.Compare(prev.String(), cur.String()), "string at %d", n)
	}
}

func TestV7Generator_Ordering(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		drive  func(t *testing.T) []id.ID
		assert func(t *testing.T, ids []id.ID)
	}

	cases := []testCase{
		{
			name: "many identifiers within one millisecond",
			drive: func(t *testing.T) []id.ID {
				gen := id.NewV7Generator(id.WithClock(frozen(t0)), id.WithRandom(seeded(2)))
				ids := make([]id.ID, 100_000)
				for n := range ids {
					v, err := gen.NewID()
					require.NoError(t, err)
					ids[n] = v
				}
				return ids
			},
			assert: assertStrictlyIncreasing,
		},
		{
			name: "time source moves backwards",
			drive: func(t *testing.T) []id.ID {
				now := t0
				gen := id.NewV7Generator(id.WithClock(func() time.Time { return now }), id.WithRandom(seeded(3)))
				first, err := gen.NewID()
				require.NoError(t, err)
				now = t0.Add(-time.Second)
				second, err := gen.NewID()
				require.NoError(t, err)
				return []id.ID{first, second}
			},
			assert: assertStrictlyIncreasing,
		},
		{
			name: "later time sorts later across generators",
			drive: func(t *testing.T) []id.ID {
				early, err := id.NewV7Generator(id.WithClock(frozen(t0))).NewID()
				require.NoError(t, err)
				late, err := id.NewV7Generator(id.WithClock(frozen(t0.Add(time.Millisecond)))).NewID()
				require.NoError(t, err)
				return []id.ID{early, late}
			},
			assert: assertStrictlyIncreasing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.drive(t))
		})
	}
}
```

Append to `pkg/id/generator_internal_test.go` (merge the imports `bytes`, `encoding/binary`, `math/rand/v2`, `time`):

```go
// Overflow is forced by setting the counter directly: a seed never starts within
// 2^25 of the limit, so reaching it through NewID would take 33 million calls.
func TestV7Generator_CounterOverflowBorrowsNextMillisecond(t *testing.T) {
	t.Parallel()

	at := time.UnixMilli(1_700_000_000_000)
	g := NewV7Generator(WithClock(func() time.Time { return at }), WithRandom(rand.NewChaCha8([32]byte{7})))

	first, err := g.NewID()
	require.NoError(t, err)
	g.counter = counterMax

	next, err := g.NewID()
	require.NoError(t, err)

	var ms [8]byte
	copy(ms[2:], next[:6])
	assert.Equal(t, at.UnixMilli()+1, int64(binary.BigEndian.Uint64(ms[:])))
	assert.Positive(t, bytes.Compare(next[:], first[:]))
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestV7Generator_Ordering|TestV7Generator_CounterOverflow' -count=1 ./pkg/id`
Expected: first a compile FAIL with `g.counter undefined`. Once the fields exist but `NewID` still seeds per call, ordering FAILs with `Should be negative` in `many_identifiers_within_one_millisecond`.

- [ ] **Step 3: Write the minimal implementation**

In `pkg/id/generator.go`, add the fields and replace `NewID`:

```go
// V7Generator produces RFC 9562 version 7 identifiers that strictly increase.
type V7Generator struct {
	now     func() time.Time
	random  io.Reader
	lastMS  int64
	counter uint32
}

// NewID returns the next identifier.
//
// In a new millisecond the 26-bit counter is re-seeded with 25 random bits. In the
// same millisecond, or when the clock moved backwards, the last timestamp is kept
// and the counter increments. On overflow the timestamp advances by 1 ms.
func (g *V7Generator) NewID() (ID, error) {
	var rnd [10]byte
	_, _ = io.ReadFull(g.random, rnd[:])
	seed := binary.BigEndian.Uint32(rnd[0:4]) & seedMask

	ms := g.now().UnixMilli()
	switch {
	case ms > g.lastMS:
		g.lastMS = ms
		g.counter = seed
	case g.counter < counterMax:
		g.counter++
	default:
		g.lastMS++
		g.counter = seed
	}
	return layout(g.lastMS, g.counter, rnd[4:10]), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./pkg/id`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/generator.go pkg/id/generator_test.go pkg/id/generator_internal_test.go
git commit -m "feat(id): keep identifiers strictly increasing within and across milliseconds"
```

---

### Task 13: Concurrency and random-source failure (tasks.md 3.7)

**Files:**
- Modify: `pkg/id/generator.go`, `pkg/id/generator_test.go`

**Interfaces:**
- Consumes: `V7Generator.NewID` (Task 12).
- Produces: `V7Generator` is safe for concurrent use; `NewID` returns an error wrapping the random source's error.

- [ ] **Step 1: Write the failing tests**

Append to `pkg/id/generator_test.go` (merge the imports `errors`, `slices`, `sync`, `testing/iotest`). The two tests set up differently (a shared generator driven by 64 goroutines, and a failing reader), so they are separate functions:

```go
func TestV7Generator_Concurrent(t *testing.T) {
	t.Parallel()

	const workers, perWorker = 64, 1_000
	gen := id.NewV7Generator()
	results := make(chan id.ID, workers*perWorker)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range perWorker {
				v, err := gen.NewID()
				if err != nil {
					t.Error(err)
					return
				}
				results <- v
			}
		})
	}
	wg.Wait()
	close(results)

	seen := make(map[id.ID]struct{}, workers*perWorker)
	all := make([]id.ID, 0, workers*perWorker)
	for v := range results {
		_, dup := seen[v]
		assert.False(t, dup, "duplicate %s", v)
		seen[v] = struct{}{}
		all = append(all, v)
	}

	byBytes := slices.Clone(all)
	slices.SortFunc(byBytes, func(a, b id.ID) int { return bytes.Compare(a[:], b[:]) })
	byString := slices.Clone(all)
	slices.SortFunc(byString, func(a, b id.ID) int { return strings.Compare(a.String(), b.String()) })

	assert.Len(t, seen, workers*perWorker)
	assert.Equal(t, byBytes, byString)
}

func TestV7Generator_RandomSourceFailure(t *testing.T) {
	t.Parallel()

	errEntropy := errors.New("entropy exhausted")
	gen := id.NewV7Generator(id.WithRandom(iotest.ErrReader(errEntropy)))

	got, err := gen.NewID()

	require.ErrorIs(t, err, errEntropy)
	assert.True(t, got.IsZero())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -race -run 'TestV7Generator_Concurrent|TestV7Generator_RandomSourceFailure' -count=1 ./pkg/id`
Expected: FAIL. `TestV7Generator_Concurrent` fails with `WARNING: DATA RACE` (and possibly duplicates). `TestV7Generator_RandomSourceFailure` fails with `An error is expected but got nil`.

- [ ] **Step 3: Write the minimal implementation**

In `pkg/id/generator.go`, add `fmt` and `sync` to the imports, add `mu sync.Mutex` as the first field of `V7Generator`, and replace `NewID`:

```go
// NewID returns the next identifier. It is safe for concurrent use.
//
// In a new millisecond the 26-bit counter is re-seeded with 25 random bits. In the
// same millisecond, or when the clock moved backwards, the last timestamp is kept
// and the counter increments. On overflow the timestamp advances by 1 ms. When the
// random source fails, NewID returns an error wrapping it and no identifier.
func (g *V7Generator) NewID() (ID, error) {
	var rnd [10]byte
	if _, err := io.ReadFull(g.random, rnd[:]); err != nil {
		return Nil, fmt.Errorf("id: read random source: %w", err)
	}
	seed := binary.BigEndian.Uint32(rnd[0:4]) & seedMask

	g.mu.Lock()
	ms := g.now().UnixMilli()
	switch {
	case ms > g.lastMS:
		g.lastMS = ms
		g.counter = seed
	case g.counter < counterMax:
		g.counter++
	default:
		g.lastMS++
		g.counter = seed
	}
	ts, ctr := g.lastMS, g.counter
	g.mu.Unlock()

	return layout(ts, ctr, rnd[4:10]), nil
}
```

In `TestV7Generator_CounterOverflowBorrowsNextMillisecond`, wrap the counter assignment in the lock:

```go
	g.mu.Lock()
	g.counter = counterMax
	g.mu.Unlock()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./pkg/id`
Expected: PASS, with no race report.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/generator.go pkg/id/generator_test.go pkg/id/generator_internal_test.go
git commit -m "feat(id): make generation concurrency-safe and report random-source failures"
```

---

### Task 14: Fuzzing, package docs and example (tasks.md 3.8)

**Files:**
- Create: `pkg/id/doc.go`, `pkg/id/example_test.go`
- Modify: `pkg/id/id_test.go`

**Interfaces:**
- Consumes: `Parse`, `String`, `ErrInvalid`, `NewV7Generator` (Tasks 8–13).

- [ ] **Step 1: Write the fuzz test**

Append to `pkg/id/id_test.go`:

```go
func FuzzParse(f *testing.F) {
	f.Add(vector)
	f.Add(strings.ToUpper(vector))
	f.Add("")
	f.Add("{" + vector + "}")
	f.Add(strings.ReplaceAll(vector, "-", ""))

	f.Fuzz(func(t *testing.T, s string) {
		got, err := id.Parse(s)
		if err != nil {
			require.ErrorIs(t, err, id.ErrInvalid)
			return
		}
		require.Equal(t, strings.ToLower(s), got.String())

		again, err := id.Parse(got.String())
		require.NoError(t, err)
		require.Equal(t, got, again)
	})
}
```

- [ ] **Step 2: See the fuzz test fail against a broken implementation**

Temporarily change `hex.Encode(buf[0:8], i[0:4])` in `String` to write uppercase, by appending `copy(buf[0:8], bytes.ToUpper(buf[0:8]))` right after it (add the `bytes` import).

Run: `go test -run=^$ -fuzz=FuzzParse -fuzztime=10s ./pkg/id`
Expected: FAIL, reporting a failing input under `testdata/fuzz/FuzzParse/`.

Revert the change, and delete the generated `pkg/id/testdata/fuzz/FuzzParse` corpus entry.

- [ ] **Step 3: Write the package docs and example**

`pkg/id/doc.go`:

```go
// Package id provides sortable identifiers for the records scrty owns.
//
// An ID is 16 bytes. Its text form is the lowercase RFC 9562 layout
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, and Parse accepts exactly that
// layout in either letter case. IDs encode to JSON as strings and to SQL
// as canonical text; Scan also reads 16-byte binary and rejects NULL.
//
// NewV7Generator is the default Generator. It produces RFC 9562 version 7
// identifiers that strictly increase for a given generator, including within
// one millisecond, across goroutines and when the clock moves backwards.
// Components that create records accept any Generator, so a consumer can
// replace it.
//
// Identifiers are not secrets. They embed a timestamp and a partly
// predictable counter, so never use one as a credential, session token or
// link secret. Store creation times in their own columns: a burst above
// 2^25 identifiers in one millisecond borrows future timestamps.
package id
```

`pkg/id/example_test.go`:

```go
package id_test

import (
	"fmt"

	"github.com/kartaladev/scrty/pkg/id"
)

// The default generator uses time.Now and crypto/rand.Reader; WithClock and
// WithRandom replace them. Identifiers are not secrets.
func ExampleNewV7Generator() {
	gen := id.NewV7Generator()

	first, _ := gen.NewID()
	second, _ := gen.NewID()

	fmt.Println(first.String() < second.String())
	fmt.Println(len(first.String()))
	// Output:
	// true
	// 36
}
```

- [ ] **Step 4: Run the fuzz test and the examples**

Run: `go test -run=^$ -fuzz=FuzzParse -fuzztime=30s ./pkg/id`
Expected: PASS, with no new failing inputs.

Run: `go test -run 'ExampleNewV7Generator' -v -count=1 ./pkg/id`
Expected: `--- PASS: ExampleNewV7Generator`.

- [ ] **Step 5: Commit**

```bash
git add pkg/id/doc.go pkg/id/example_test.go pkg/id/id_test.go
git commit -m "docs(id): document identifiers, add a fuzz test and an example"
```

---

### Task 15: Simplify `pkg/id` (tasks.md 3.9)

**Files:**
- Modify: any file under `pkg/id/` that `/simplify` changes

- [ ] **Step 1: Run `/simplify` on `pkg/id`**

Invoke `/simplify`, scoped to `pkg/id/`. Apply only changes that keep behaviour identical.

- [ ] **Step 2: Verify**

Run: `go test -race -count=1 ./pkg/id && gofmt -l pkg/id`
Expected: PASS and no `gofmt` output.

- [ ] **Step 3: Commit (if anything changed)**

```bash
git add pkg/id
git commit -m "refactor(id): simplify after review"
```

---

### Task 16: Sampler core semantics (tasks.md 4.1)

**Files:**
- Create: `pkg/logsample/logsample.go`, `pkg/logsample/logsample_test.go`

**Interfaces:**
- Produces:
  - `type Sampler struct{...}`;
  - `func New(window time.Duration) *Sampler` (options added in Task 18);
  - `func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int)`.

- [ ] **Step 1: Write the failing test**

`pkg/logsample/logsample_test.go`:

```go
package logsample_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/pkg/logsample"
)

var base = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type event struct {
	key string
	at  time.Duration
}

type result struct {
	write      bool
	suppressed int
}

func run(s *logsample.Sampler, events []event) []result {
	out := make([]result, 0, len(events))
	for _, e := range events {
		w, n := s.Allow(e.key, base.Add(e.at))
		out = append(out, result{write: w, suppressed: n})
	}
	return out
}

func TestSampler_Allow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		events []event
		assert func(t *testing.T, got []result)
	}

	cases := []testCase{
		{
			name:   "repeated events for one key",
			events: []event{{"a", 0}, {"a", time.Second}, {"a", 2 * time.Second}, {"a", 3 * time.Second}, {"a", 4 * time.Second}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, []result{{true, 0}, {false, 0}, {false, 0}, {false, 0}, {false, 0}}, got)
			},
		},
		{
			name:   "independent keys",
			events: []event{{"a", 0}, {"b", time.Second}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, []result{{true, 0}, {true, 0}}, got)
			},
		},
		{
			name: "count carried into the next window",
			events: []event{
				{"a", 0}, {"a", 10 * time.Second}, {"a", 20 * time.Second}, {"a", 30 * time.Second}, {"a", 40 * time.Second},
				{"a", 70 * time.Second},
			},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, result{true, 4}, got[5])
			},
		},
		{
			name:   "nothing suppressed",
			events: []event{{"a", 0}, {"a", 70 * time.Second}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, []result{{true, 0}, {true, 0}}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, run(logsample.New(time.Minute), tc.events))
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -run 'TestSampler_Allow' -count=1 ./pkg/logsample`
Expected: FAIL to compile with `undefined: logsample.New`. Create `pkg/logsample/logsample.go` containing only `package logsample` and re-run.
Expected: FAIL with `undefined: logsample.New`.

- [ ] **Step 3: Write the minimal implementation**

`pkg/logsample/logsample.go`:

```go
package logsample

import (
	"sync"
	"time"
)

// Sampler writes at most one record per key per window.
type Sampler struct {
	mu          sync.Mutex
	window      time.Duration
	windowStart time.Time
	current     map[string]int
	previous    map[string]int
}

// New returns a Sampler with fixed windows of the given length.
func New(window time.Duration) *Sampler {
	return &Sampler{window: window}
}

// Allow reports whether the event for key at now should be written, and how many
// events for key were suppressed since its previous written record.
func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch elapsed := now.Sub(s.windowStart); {
	case s.windowStart.IsZero() || elapsed >= 2*s.window:
		s.reset(now)
	case elapsed >= s.window:
		s.windowStart = now
		s.previous = s.current
		s.current = map[string]int{}
	}

	if _, seen := s.current[key]; !seen {
		suppressed = s.previous[key]
		delete(s.previous, key)
		s.current[key] = 0
		return true, suppressed
	}
	s.current[key]++
	return false, 0
}

func (s *Sampler) reset(now time.Time) {
	s.windowStart = now
	s.current = map[string]int{}
	s.previous = map[string]int{}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -run 'TestSampler_Allow' -count=1 ./pkg/logsample`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/logsample
git commit -m "feat(logsample): write one record per key per window"
```

---

### Task 17: Disabled sampling and a backwards clock (tasks.md 4.2)

**Files:**
- Modify: `pkg/logsample/logsample.go`, `pkg/logsample/logsample_test.go`

**Interfaces:**
- Consumes: `New`, `Allow`, `run`, `event`, `result` (Task 16).

- [ ] **Step 1: Write the failing test**

Append to `pkg/logsample/logsample_test.go`:

```go
func TestSampler_DisabledAndBackwardsClock(t *testing.T) {
	t.Parallel()

	fiveOfA := []event{{"a", 0}, {"a", time.Second}, {"a", 2 * time.Second}, {"a", 3 * time.Second}, {"a", 4 * time.Second}}
	allWritten := func(t *testing.T, got []result) {
		for n, r := range got {
			assert.Equal(t, result{true, 0}, r, "event %d", n)
		}
	}

	type testCase struct {
		name    string
		sampler *logsample.Sampler
		events  []event
		assert  func(t *testing.T, got []result)
	}

	cases := []testCase{
		{name: "zero window", sampler: logsample.New(0), events: fiveOfA, assert: allWritten},
		{name: "negative window", sampler: logsample.New(-time.Second), events: fiveOfA, assert: allWritten},
		{name: "nil sampler", sampler: nil, events: fiveOfA, assert: allWritten},
		{
			name:    "backwards clock cannot extend suppression",
			sampler: logsample.New(time.Minute),
			events:  []event{{"a", 30 * time.Second}, {"a", 0}, {"a", time.Minute}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, result{false, 0}, got[1], "second event suppressed")
				assert.True(t, got[2].write, "third event written")
				assert.Equal(t, 1, got[2].suppressed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, run(tc.sampler, tc.events))
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -run 'TestSampler_DisabledAndBackwardsClock' -count=1 ./pkg/logsample`
Expected: FAIL. `zero_window` and `negative_window` fail with `Not equal`: events after the first are suppressed because `elapsed >= 0` resets every call. `nil_sampler` panics with a nil pointer dereference. `backwards_clock_cannot_extend_suppression` fails with `third event written`.

- [ ] **Step 3: Write the minimal implementation**

Replace `Allow` in `pkg/logsample/logsample.go`:

```go
// Allow reports whether the event for key at now should be written, and how many
// events for key were suppressed since its previous written record.
//
// A nil Sampler, or a window of zero or less, writes every event with a count of 0.
// A now earlier than the current window's start moves the start back to now without
// starting a new window, so a backwards clock cannot extend suppression.
func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int) {
	if s == nil || s.window <= 0 {
		return true, 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch elapsed := now.Sub(s.windowStart); {
	case s.windowStart.IsZero():
		s.reset(now)
	case now.Before(s.windowStart):
		s.windowStart = now
	case elapsed >= 2*s.window:
		s.reset(now)
	case elapsed >= s.window:
		s.windowStart = now
		s.previous = s.current
		s.current = map[string]int{}
	}

	if _, seen := s.current[key]; !seen {
		suppressed = s.previous[key]
		delete(s.previous, key)
		s.current[key] = 0
		return true, suppressed
	}
	s.current[key]++
	return false, 0
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./pkg/logsample`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/logsample
git commit -m "feat(logsample): disable sampling for non-positive windows and handle a backwards clock"
```

---

### Task 18: Reporter on rotation (tasks.md 4.3)

**Files:**
- Modify: `pkg/logsample/logsample.go`, `pkg/logsample/logsample_test.go`

**Interfaces:**
- Consumes: `Allow`, `run` (Tasks 16–17).
- Produces:
  - `type Option func(*Sampler)`;
  - `func WithReporter(fn func(key string, suppressed int)) Option`;
  - `func New(window time.Duration, opts ...Option) *Sampler`.

- [ ] **Step 1: Write the failing test**

Append to `pkg/logsample/logsample_test.go` (merge the import `sync`):

```go
type recorder struct {
	mu    sync.Mutex
	got   map[string]int
	calls int
}

func (r *recorder) report(key string, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.got == nil {
		r.got = map[string]int{}
	}
	r.got[key] += suppressed
	r.calls++
}

func TestSampler_ReporterOnRotation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		events []event
		assert func(t *testing.T, got []result, rec *recorder)
	}

	cases := []testCase{
		{
			name: "key goes quiet",
			events: []event{
				{"a", 0}, {"a", 10 * time.Second}, {"a", 20 * time.Second}, {"a", 30 * time.Second},
				{"b", 150 * time.Second},
				{"a", 160 * time.Second},
			},
			assert: func(t *testing.T, got []result, rec *recorder) {
				assert.Equal(t, map[string]int{"a": 3}, rec.got)
				assert.Equal(t, result{true, 0}, got[5], "a later event for a reported key carries 0")
			},
		},
		{
			name: "long silence drops both windows",
			events: []event{
				{"a", 0}, {"a", 10 * time.Second},
				{"b", 70 * time.Second}, {"b", 80 * time.Second},
				{"c", 210 * time.Second},
			},
			assert: func(t *testing.T, _ []result, rec *recorder) {
				assert.Equal(t, map[string]int{"a": 1, "b": 1}, rec.got)
				assert.Equal(t, 2, rec.calls, "each key reported once")
			},
		},
		{
			name:   "keys with nothing suppressed are not reported",
			events: []event{{"a", 0}, {"b", 150 * time.Second}},
			assert: func(t *testing.T, _ []result, rec *recorder) {
				assert.Zero(t, rec.calls)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recorder{}
			s := logsample.New(time.Minute, logsample.WithReporter(rec.report))
			got := run(s, tc.events)
			tc.assert(t, got, rec)
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -run 'TestSampler_ReporterOnRotation' -count=1 ./pkg/logsample`
Expected: FAIL to compile with `undefined: logsample.WithReporter` and `too many arguments in call to logsample.New`.

- [ ] **Step 3: Write the minimal implementation**

In `pkg/logsample/logsample.go`, add `maps` and `slices` to the imports, add `report func(key string, suppressed int)` to `Sampler`, then replace `New` and `Allow` and add `evict`:

```go
// Option configures a Sampler.
type Option func(*Sampler)

// WithReporter receives every suppressed count that would otherwise be discarded.
// Default: no reporter, so counts of keys that do not recur are dropped.
func WithReporter(fn func(key string, suppressed int)) Option {
	return func(s *Sampler) { s.report = fn }
}

// New returns a Sampler with fixed windows of the given length.
func New(window time.Duration, opts ...Option) *Sampler {
	s := &Sampler{window: window}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Allow reports whether the event for key at now should be written, and how many
// events for key were suppressed since its previous written record.
func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int) {
	if s == nil || s.window <= 0 {
		return true, 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch elapsed := now.Sub(s.windowStart); {
	case s.windowStart.IsZero():
		s.reset(now)
	case now.Before(s.windowStart):
		s.windowStart = now
	case elapsed >= 2*s.window:
		s.evict(s.previous)
		s.evict(s.current)
		s.reset(now)
	case elapsed >= s.window:
		s.evict(s.previous)
		s.windowStart = now
		s.previous = s.current
		s.current = map[string]int{}
	}

	if _, seen := s.current[key]; !seen {
		suppressed = s.previous[key]
		delete(s.previous, key)
		s.current[key] = 0
		return true, suppressed
	}
	s.current[key]++
	return false, 0
}

// evict reports every non-zero count in m, in key order.
func (s *Sampler) evict(m map[string]int) {
	if s.report == nil {
		return
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if n := m[k]; n > 0 {
			s.report(k, n)
		}
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./pkg/logsample`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/logsample
git commit -m "feat(logsample): report suppressed counts that age out"
```

---

### Task 19: Flush and the lower-bound default (tasks.md 4.4)

**Files:**
- Modify: `pkg/logsample/logsample.go`, `pkg/logsample/logsample_test.go`

**Interfaces:**
- Consumes: `Sampler`, `evict`, `recorder` (Task 18).
- Produces: `func (s *Sampler) Flush()`.

- [ ] **Step 1: Write the failing test**

Append to `pkg/logsample/logsample_test.go`:

```go
func TestSampler_FlushAndLowerBound(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		reporter bool
		drive    func(s *logsample.Sampler) []result
		assert   func(t *testing.T, got []result, rec *recorder)
	}

	cases := []testCase{
		{
			name:     "flush at shutdown reports pending counts and forgets keys",
			reporter: true,
			drive: func(s *logsample.Sampler) []result {
				got := run(s, []event{{"a", 0}, {"a", 10 * time.Second}, {"a", 20 * time.Second}})
				s.Flush()
				return append(got, run(s, []event{{"a", 30 * time.Second}})...)
			},
			assert: func(t *testing.T, got []result, rec *recorder) {
				assert.Equal(t, map[string]int{"a": 2}, rec.got)
				assert.Equal(t, result{true, 0}, got[3])
			},
		},
		{
			name: "flush without a reporter forgets keys",
			drive: func(s *logsample.Sampler) []result {
				run(s, []event{{"a", 0}, {"a", time.Second}})
				s.Flush()
				return run(s, []event{{"a", 2 * time.Second}})
			},
			assert: func(t *testing.T, got []result, _ *recorder) {
				assert.Equal(t, []result{{true, 0}}, got)
			},
		},
		{
			name: "without a reporter an aged-out count is discarded",
			drive: func(s *logsample.Sampler) []result {
				return run(s, []event{{"a", 0}, {"a", time.Second}, {"a", 2 * time.Second}, {"a", 3 * time.Second}, {"a", 180 * time.Second}})
			},
			assert: func(t *testing.T, got []result, _ *recorder) {
				assert.Equal(t, result{true, 0}, got[4])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recorder{}
			var opts []logsample.Option
			if tc.reporter {
				opts = append(opts, logsample.WithReporter(rec.report))
			}
			s := logsample.New(time.Minute, opts...)
			got := tc.drive(s)
			tc.assert(t, got, rec)
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -run 'TestSampler_FlushAndLowerBound' -count=1 ./pkg/logsample`
Expected: FAIL to compile with `s.Flush undefined`.

- [ ] **Step 3: Write the minimal implementation**

Append to `pkg/logsample/logsample.go`:

```go
// Flush reports every pending suppressed count, then forgets all keys, so the next
// event for any key is written with a count of 0. It is safe on a nil Sampler.
func (s *Sampler) Flush() {
	if s == nil || s.window <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.evict(s.previous)
	s.evict(s.current)
	s.current, s.previous = nil, nil
	s.windowStart = time.Time{}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./pkg/logsample`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/logsample
git commit -m "feat(logsample): flush pending counts"
```

---

### Task 20: Bounded memory and a re-entrant reporter (tasks.md 4.5)

**Files:**
- Create: `pkg/logsample/logsample_internal_test.go`
- Modify: `pkg/logsample/logsample.go`, `pkg/logsample/logsample_test.go`

**Interfaces:**
- Consumes: `Sampler.current`, `Sampler.previous`, `Allow`, `Flush` (Tasks 16–19).
- Produces:
  - unexported `type pending struct{ key string; suppressed int }`;
  - `func collect(dst []pending, m map[string]int) []pending`;
  - `func (s *Sampler) deliver(ps []pending)`.

- [ ] **Step 1: Write the tests**

`pkg/logsample/logsample_internal_test.go` (a white-box check of map sizes; its setup differs from every black-box table):

```go
package logsample

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSampler_MemoryStaysBounded(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s := New(time.Minute)
	for n := range 1_000_000 {
		s.Allow("k"+strconv.Itoa(n), base)
	}

	s.Allow("late", base.Add(3*time.Minute))

	s.mu.Lock()
	defer s.mu.Unlock()
	assert.LessOrEqual(t, len(s.current)+len(s.previous), 1)
}
```

Append to `pkg/logsample/logsample_test.go` (a reporter that calls back into the sampler; its setup differs from the tables):

```go
func TestSampler_ReentrantReporterDoesNotDeadlock(t *testing.T) {
	t.Parallel()

	var s *logsample.Sampler
	s = logsample.New(time.Minute, logsample.WithReporter(func(string, int) {
		s.Allow("summary", base.Add(151*time.Second))
	}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		run(s, []event{{"a", 0}, {"a", 10 * time.Second}, {"b", 150 * time.Second}})
		s.Flush()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reporter calling Allow deadlocked")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestSampler_ReentrantReporterDoesNotDeadlock|TestSampler_MemoryStaysBounded' -count=1 ./pkg/logsample`
Expected:
- **`TestSampler_ReentrantReporterDoesNotDeadlock`:** FAILs with `reporter calling Allow deadlocked`, because `evict` calls the reporter while the mutex is held.
- **`TestSampler_MemoryStaysBounded`:** PASSes already.

To see the memory test fail, temporarily replace the `elapsed >= 2*s.window` branch body with `s.windowStart = now` (keep both maps). Run it and expect `Should be less than or equal`. Then revert.

- [ ] **Step 3: Write the minimal implementation**

In `pkg/logsample/logsample.go`, replace `evict`, `Allow` and `Flush` with the version that collects under the lock and delivers after unlocking:

```go
type pending struct {
	key        string
	suppressed int
}

// collect appends every non-zero count in m, in key order.
func collect(dst []pending, m map[string]int) []pending {
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if n := m[k]; n > 0 {
			dst = append(dst, pending{key: k, suppressed: n})
		}
	}
	return dst
}

// deliver calls the reporter on the calling goroutine. It must run without the lock
// held, so a reporter may itself call Allow or Flush.
func (s *Sampler) deliver(ps []pending) {
	if s.report == nil {
		return
	}
	for _, p := range ps {
		s.report(p.key, p.suppressed)
	}
}

func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int) {
	if s == nil || s.window <= 0 {
		return true, 0
	}

	var evicted []pending
	s.mu.Lock()
	switch elapsed := now.Sub(s.windowStart); {
	case s.windowStart.IsZero():
		s.reset(now)
	case now.Before(s.windowStart):
		s.windowStart = now
	case elapsed >= 2*s.window:
		evicted = collect(collect(evicted, s.previous), s.current)
		s.reset(now)
	case elapsed >= s.window:
		evicted = collect(evicted, s.previous)
		s.windowStart = now
		s.previous = s.current
		s.current = map[string]int{}
	}

	if _, seen := s.current[key]; !seen {
		suppressed = s.previous[key]
		delete(s.previous, key)
		s.current[key] = 0
		write = true
	} else {
		s.current[key]++
	}
	s.mu.Unlock()

	s.deliver(evicted)
	return write, suppressed
}

func (s *Sampler) Flush() {
	if s == nil || s.window <= 0 {
		return
	}
	s.mu.Lock()
	evicted := collect(collect(nil, s.previous), s.current)
	s.current, s.previous = nil, nil
	s.windowStart = time.Time{}
	s.mu.Unlock()

	s.deliver(evicted)
}
```

Keep the godoc comments on `Allow` and `Flush` from Tasks 17 and 19 above these functions.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./pkg/logsample`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/logsample
git commit -m "feat(logsample): bound memory and deliver reports outside the lock"
```

---

### Task 21: Totals balance (tasks.md 4.6)

**Files:**
- Modify: `pkg/logsample/logsample_test.go`

**Interfaces:**
- Consumes: `New`, `WithReporter`, `Allow`, `Flush` (Tasks 16–20).

- [ ] **Step 1: Write the property test**

Append to `pkg/logsample/logsample_test.go` (merge the imports `fmt`, `math/rand/v2`, `sync/atomic`):

```go
func TestSampler_TotalsBalance(t *testing.T) {
	t.Parallel()

	type counts struct {
		suppressedEvents atomic.Int64 // events Allow marked as suppressed
		writtenCounts    atomic.Int64 // suppressed counts returned on written events
	}

	record := func(c *counts, write bool, n int) {
		if write {
			c.writtenCounts.Add(int64(n))
			return
		}
		c.suppressedEvents.Add(1)
	}

	type testCase struct {
		name   string
		drive  func(s *logsample.Sampler, c *counts)
		assert func(t *testing.T, suppressed, written, reported int64)
	}

	balanced := func(t *testing.T, suppressed, written, reported int64) {
		assert.Positive(t, suppressed)
		assert.Equal(t, suppressed, written+reported)
	}

	cases := []testCase{
		{
			name: "sequential random sequence",
			drive: func(s *logsample.Sampler, c *counts) {
				rng := rand.New(rand.NewPCG(42, 99))
				at := base
				for range 200_000 {
					at = at.Add(time.Duration(rng.IntN(20_000)) * time.Millisecond)
					switch rng.IntN(1000) {
					case 0:
						at = at.Add(3 * time.Minute)
					case 1:
						at = at.Add(-30 * time.Second)
					}
					w, n := s.Allow(fmt.Sprintf("k%d", rng.IntN(50)), at)
					record(c, w, n)
				}
			},
			assert: balanced,
		},
		{
			name: "64 concurrent goroutines",
			drive: func(s *logsample.Sampler, c *counts) {
				var clock atomic.Int64
				clock.Store(base.UnixNano())
				var wg sync.WaitGroup
				for worker := range 64 {
					wg.Go(func() {
						rng := rand.New(rand.NewPCG(uint64(worker), 7))
						for range 5_000 {
							at := time.Unix(0, clock.Add(int64(rng.IntN(50))*int64(time.Millisecond)))
							w, n := s.Allow(fmt.Sprintf("k%d", rng.IntN(20)), at)
							record(c, w, n)
						}
					})
				}
				wg.Wait()
			},
			assert: balanced,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var reported atomic.Int64
			s := logsample.New(time.Minute, logsample.WithReporter(func(_ string, n int) { reported.Add(int64(n)) }))
			var c counts
			tc.drive(s, &c)
			s.Flush()
			tc.assert(t, c.suppressedEvents.Load(), c.writtenCounts.Load(), reported.Load())
		})
	}
}
```

- [ ] **Step 2: See it fail against a broken implementation**

Temporarily change the `elapsed >= 2*s.window` branch in `Allow` to `evicted = collect(evicted, s.previous)`, which skips reporting `current` on a two-window rotation.

Run: `go test -race -run 'TestSampler_TotalsBalance' -count=1 ./pkg/logsample`
Expected: FAIL in `sequential_random_sequence` with `Not equal`.

Revert the change.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `go test -race -count=1 ./pkg/logsample`
Expected: PASS, with no race report.

- [ ] **Step 4: Commit**

```bash
git add pkg/logsample/logsample_test.go
git commit -m "test(logsample): prove every suppressed event is accounted for exactly once"
```

---

### Task 22: Sampler docs and example (tasks.md 4.7)

**Files:**
- Create: `pkg/logsample/example_test.go`
- Modify: `pkg/logsample/logsample.go` (package and type docs)

- [ ] **Step 1: Write the example**

`pkg/logsample/example_test.go`:

```go
package logsample_test

import (
	"fmt"
	"time"

	"github.com/kartaladev/scrty/pkg/logsample"
)

func ExampleNew() {
	s := logsample.New(time.Minute, logsample.WithReporter(func(key string, suppressed int) {
		fmt.Printf("%s: %d suppressed\n", key, suppressed)
	}))

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for n := range 3 {
		write, _ := s.Allow("login-refused 203.0.113.7", start.Add(time.Duration(n)*time.Second))
		fmt.Println("write:", write)
	}
	s.Flush()
	// Output:
	// write: true
	// write: false
	// write: false
	// login-refused 203.0.113.7: 2 suppressed
}
```

- [ ] **Step 2: Run the example**

Run: `go test -run 'ExampleNew' -v -count=1 ./pkg/logsample`
Expected: `--- PASS: ExampleNew`. To see it fail first, change the last expected output line to `login-refused 203.0.113.7: 3 suppressed`, run, expect FAIL with `got: ... 2 suppressed`, then restore it.

- [ ] **Step 3: Write the package and type docs**

At the top of `pkg/logsample/logsample.go`, above `package logsample`:

```go
// Package logsample bounds repeated log records, such as refusals driven by an
// attacker or an outage, to one record per key per window.
//
// A Sampler keeps counts only for keys seen in the current window and the one
// before it, so memory stays bounded whatever the key space. The first event for a
// key in a window is written and carries how many events for that key were
// suppressed since its previous written record.
//
// By default there is no reporter, and a key that does not recur before its counts
// age out has them discarded: suppressed counts are then a lower bound. With
// WithReporter, every suppressed event is counted exactly once, either on a later
// written record or in a report. Flush reports everything pending, for example at
// shutdown.
//
// The reporter runs synchronously on the goroutine whose Allow or Flush call
// triggered it, after the Sampler's lock is released, so it may call back into the
// Sampler. It must be fast and must not panic.
```

Replace the `Sampler` doc comment with:

```go
// Sampler writes at most one record per key per fixed window, anchored to the first
// event it sees. A nil *Sampler, or one with a window of zero or less, writes every
// event. It is safe for concurrent use.
```

- [ ] **Step 4: Verify the docs**

Run: `go doc ./pkg/logsample | head -20 && go doc ./pkg/logsample WithReporter`
Expected: the package text above, and `WithReporter`'s doc naming the "no reporter" default.

Run: `go test -race -count=1 ./pkg/logsample`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/logsample
git commit -m "docs(logsample): document the lower-bound default and the reporter contract"
```

---

### Task 23: Simplify `pkg/logsample` (tasks.md 4.8)

**Files:**
- Modify: any file under `pkg/logsample/` that `/simplify` changes

- [ ] **Step 1: Run `/simplify` on `pkg/logsample`**

Invoke `/simplify`, scoped to `pkg/logsample/`. Apply only changes that keep behaviour identical.

- [ ] **Step 2: Verify**

Run: `go test -race -count=1 ./pkg/logsample && gofmt -l pkg/logsample`
Expected: PASS and no `gofmt` output.

- [ ] **Step 3: Commit (if anything changed)**

```bash
git add pkg/logsample
git commit -m "refactor(logsample): simplify after review"
```

---

### Task 24: Tools module (tasks.md 5.1)

**Files:**
- Create: `tools/go.mod`, `tools/go.sum`, `Makefile` (the `tools` target only)
- Modify: `.gitignore`

**Interfaces:**
- Produces: `make tools`, which installs `golangci-lint`, `mockgen` and `govulncheck` into `$(CURDIR)/.bin`.

- [ ] **Step 1: Create the tools module and pin the tools**

```bash
mkdir -p tools
cat > tools/go.mod <<'EOF'
module github.com/kartaladev/scrty/tools

go 1.26
EOF
cd tools
go get -tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
go get -tool go.uber.org/mock/mockgen@v0.6.0
go get -tool golang.org/x/vuln/cmd/govulncheck@latest
cd ..
```

Expected: `tools/go.mod` lists three `tool` directives with exact versions.

- [ ] **Step 2: Ignore the install directory**

Append to `.gitignore`:

```
# Pinned tool binaries installed by `make tools`
.bin/
```

- [ ] **Step 3: Write the `tools` target**

`Makefile` (the full target set is added in Task 26):

```make
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

BIN := $(CURDIR)/.bin
export PATH := $(BIN):$(PATH)

.PHONY: tools
tools:
	cd tools && GOBIN=$(BIN) go install tool
```

- [ ] **Step 4: Verify**

Run: `make tools && .bin/golangci-lint version && .bin/mockgen --version && .bin/govulncheck -version`
Expected: each prints its pinned version.

Run: `grep -c '^tool\|golangci\|go.uber.org/mock\|golang.org/x/vuln' go.mod || true`
Expected: `0`, so the core `go.mod` has no tool requirements.

Run: `go test -run 'TestModuleLayout|TestConsumerModuleGraph' -count=1 .`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/go.mod tools/go.sum Makefile .gitignore
git commit -m "build: pin lint, mock and vulnerability tools in a separate module"
```

---

### Task 25: golangci-lint configuration (tasks.md 5.2)

**Files:**
- Create: `.golangci.yml`

- [ ] **Step 1: Write the configuration**

`.golangci.yml`:

```yaml
version: "2"

linters:
  default: standard
  enable:
    - bodyclose
    - contextcheck
    - errorlint
    - gosec
    - misspell
    - nilerr
    - noctx
    - revive
  exclusions:
    paths:
      - testdata

formatters:
  enable:
    - gofmt
    - goimports
  settings:
    goimports:
      local-prefixes:
        - github.com/kartaladev/scrty
  exclusions:
    paths:
      - testdata
```

- [ ] **Step 2: See it fail on misformatted code**

Temporarily add a misformatted file:

```bash
printf 'package id\nfunc   misformatted( ) {}\n' > pkg/id/zz_misformatted.go
```

Run: `.bin/golangci-lint run ./...`
Expected: FAIL, naming `pkg/id/zz_misformatted.go`, reported by `gofmt`.

Run: `rm pkg/id/zz_misformatted.go`

- [ ] **Step 3: Verify the clean tree**

Run: `.bin/golangci-lint run ./...`
Expected: `0 issues.` Fix any real findings in `pkg/id`, `pkg/logsample` or the guard tests before continuing, re-running their tests after each fix.

- [ ] **Step 4: Commit**

```bash
git add .golangci.yml
git commit -m "build: configure golangci-lint with formatters"
```

---

### Task 26: `make check` (tasks.md 5.3)

**Files:**
- Modify: `Makefile`

**Interfaces:**
- Consumes: `make tools` (Task 24), `.golangci.yml` (Task 25).
- Produces: `make check`, running every gate for every workspace module.

- [ ] **Step 1: Write the gates**

Replace `Makefile`:

```make
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

BIN := $(CURDIR)/.bin
export PATH := $(BIN):$(PATH)

# Every module listed in go.work.
MODULES := $(shell go list -m -f '{{.Dir}}')

.PHONY: tools check fmt-check vet lint test vuln generate-check

tools:
	cd tools && GOBIN=$(BIN) go install tool

check: tools fmt-check vet lint test vuln generate-check

fmt-check:
	@out="$$(gofmt -l $(MODULES))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	@for m in $(MODULES); do (cd "$$m" && go vet ./...); done

lint:
	@for m in $(MODULES); do (cd "$$m" && golangci-lint run ./...); done

test:
	@for m in $(MODULES); do (cd "$$m" && go test -race -count=1 ./...); done

vuln:
	@for m in $(MODULES); do (cd "$$m" && govulncheck ./...); done

generate-check:
	@for m in $(MODULES); do (cd "$$m" && go generate ./...); done
	@git diff --exit-code
```

- [ ] **Step 2: Verify each gate fails on an injected fault**

Formatting:

```bash
printf 'package id\nfunc   misformatted( ) {}\n' > pkg/id/zz_misformatted.go
make fmt-check; echo "exit=$?"
rm pkg/id/zz_misformatted.go
```

Expected: `gofmt needed:` naming `pkg/id/zz_misformatted.go`, and `exit=2`.

Vet:

```bash
printf 'package id\n\nimport "fmt"\n\nfunc vetBad() { fmt.Printf("%%d", "x") }\n' > pkg/id/zz_vet.go
make vet; echo "exit=$?"
rm pkg/id/zz_vet.go
```

Expected: `go vet` reports `fmt.Printf format %d has arg "x" of wrong type`, naming `pkg/id/zz_vet.go`, and `exit=2`.

Stale generated file:

```bash
printf 'package id\n\n//go:generate sh -c "echo // regenerated >> zz_gen.go"\n' > pkg/id/zz_gen.go
git add pkg/id/zz_gen.go
make generate-check; echo "exit=$?"
git rm -f --cached pkg/id/zz_gen.go && rm -f pkg/id/zz_gen.go
```

Expected: `git diff` shows `// regenerated` added to `pkg/id/zz_gen.go`, and `exit=2`.

- [ ] **Step 3: Verify a clean tree passes**

Run: `make check`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "build: run formatting, vet, lint, race tests, vulnerability and generate checks per module"
```

---

### Task 27: Continuous integration (tasks.md 5.4)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  check:
    name: make check (Go ${{ matrix.go }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        go: ["1.26.x", "1.27.x"]
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v6
        with:
          go-version: ${{ matrix.go }}
      - name: Run gates
        run: make check
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run make check on Go 1.26 and 1.27"
```

- [ ] **Step 3: Push and verify (needs the user's confirmation)**

Pushing publishes commits. **Ask the user before pushing.** After they confirm:

Run: `git push` then `gh run watch --exit-status $(gh run list --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')`
Expected: both `make check (Go 1.26.x)` and `make check (Go 1.27.x)` jobs succeed.

---

### Task 28: Helper placement in the testcontainers skill (tasks.md 6.1)

**Files:**
- Modify: `.claude/skills/use-testcontainers/SKILL.md`

- [ ] **Step 1: Add the scrty rule**

Insert this section immediately after the `## Helper file layout` section's bullet list:

```markdown
### scrty: helpers and the tests that use them live in the `test` module

In this repository, the "producer module" rule above is replaced by one rule for every module:

- Shared helpers (`RunTestPostgres`, `RunTestRedis`, …) and conformance suites live in `github.com/kartaladev/scrty/test`.
- No other scrty module imports that module, **not even from a `_test.go` file**. A test-only import still becomes a `go.mod` requirement, so the helpers' drivers and testcontainers would appear in every consumer's `go list -m all`.
- Integration tests and conformance-suite runs against implementations in other modules (core's `database/sql` adapters and in-memory defaults, the `pgx` and `gorm` adapters) live inside the `test` module, which imports the modules under test.
- The layout guard (`layout_test.go`) enforces this.
```

- [ ] **Step 2: Verify**

Run: `grep -n "not even from a \`_test.go\` file" .claude/skills/use-testcontainers/SKILL.md`
Expected: one match inside the helper-layout section.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/use-testcontainers/SKILL.md
git commit -m "docs: place scrty test helpers and their tests in the test module"
```

---

### Task 29: Final gate (tasks.md 6.2)

- [ ] **Step 1: Run the gates locally**

Run: `make check`
Expected: exit 0 on Go 1.27.

- [ ] **Step 2: Validate the OpenSpec change**

Run: `openspec validate project-foundation --strict`
Expected: `Change 'project-foundation' is valid`.

- [ ] **Step 3: Confirm CI**

Confirm the latest `ci` run for the pushed commit succeeded on Go 1.26.x and 1.27.x (Task 27, Step 3).

- [ ] **Step 4: Tick `tasks.md`**

Mark every checkbox in `openspec/changes/project-foundation/tasks.md` complete, matching the finished plan tasks.

---

## Self-Review

- **Spec coverage:**
  - **id-generation:**
    - UUIDv7 layout: Tasks 11 and 13.
    - Strictly increasing order (same millisecond, backwards clock, concurrency, across generators): Tasks 12 and 13.
    - Generation failure reported: Task 13.
    - Zero identifier: Task 7.
    - Canonical text and strict parsing (including v4 unchanged and long input): Task 8.
    - JSON (string, number, empty, null, `omitzero`): Task 9.
    - SQL (text, bytes, binary, NULL, malformed): Task 10. The native PostgreSQL `uuid` round trip is deferred to the persistence change, as tasks.md 3.4 states.
    - Replaceable generator (the `Generator` interface; deterministic clock and random options): Task 11. The component-level override scenarios apply to later changes that create records.
  - **log-sampling:**
    - One record per key per window: Task 16.
    - Carried counts: Task 16.
    - Exactly-once accounting with a reporter: Tasks 18 and 21.
    - Flush: Task 19.
    - Lower-bound default: Task 19.
    - Bounded memory: Task 20.
    - Disabled sampling: Task 17.
    - Backwards clock: Task 17.
    - Concurrency and re-entrant reporter: Tasks 20 and 21.
  - **module-layout:**
    - Core production build excludes test tooling: Tasks 3 and 4.
    - No mock types: Task 4.
    - Integration modules separate (go.mod check and consumer graph): Tasks 5 and 6.
    - Test module never imported or required, and helper drivers stay out of consumers' graphs: Tasks 4, 5 and 6.
    - Supported Go releases: Tasks 1, 2 and 27.
    - Build gates: Tasks 25, 26 and 27.
- **Placeholder scan:** no TBD or TODO. Every code step shows code, and every run step shows the command and the expected output.
- **Type consistency:**
  - `violation{Where, What}`, `checkModule`, `copyFixture`, `goCmd(t, dir, env, args...)`, `hasViolation`, `testModule`, `integrationModules`, `listModules(t, dir, env)` and `realCoreConsumer` keep the same names and signatures across Tasks 3–6.
  - `layout(ms int64, counter uint32, random []byte)`, `counterMax`, `seedMask` and the `V7Generator` fields `mu`, `now`, `random`, `lastMS`, `counter` are consistent across Tasks 11–13.
  - `Sampler` fields, `reset`, `collect`, `deliver`, `pending`, `Option`, `WithReporter`, `New(window, opts...)` and `Flush` are consistent across Tasks 16–20.
