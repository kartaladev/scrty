package scrty_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"go/version"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

// forbiddenProduction lists modules no production build may import.
var forbiddenProduction = []string{
	"go.uber.org/mock",
	"github.com/stretchr/testify",
	"github.com/testcontainers/testcontainers-go",
	"github.com/jonboulle/clockwork",
}

type listedPackage struct {
	ImportPath string
	Imports    []string
	Standard   bool
}

// integrationModules lists modules the core go.mod must never require directly.
var integrationModules = []string{
	"github.com/gin-gonic/gin",
	"github.com/gofiber/fiber",
	"gorm.io/gorm",
	"github.com/jackc/pgx",
	"github.com/go-co-op/gocron",
	"github.com/samber/do",
	"github.com/pressly/goose",
	"github.com/testcontainers/testcontainers-go/modules/postgres",
	"github.com/go-webauthn/webauthn",
	"github.com/fxamacker/cbor",
	"github.com/google/go-tpm",
	"github.com/redis/go-redis",
	"github.com/testcontainers/testcontainers-go/modules/redis",
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
	// The path is built by these tests from the repository root or a copied
	// fixture, never from external input.
	data, err := os.ReadFile(gomod) //nolint:gosec // G304: test-constructed path
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

// requireViolations reports direct requirements on integration modules, and any
// requirement at all on the test module. Other indirect requirements are allowed:
// transitive production imports are already caught by the go list -deps walk.
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

// productionImportViolations reports production imports of any module the core
// must not depend on.
//
// It walks both lists, and the integration one is why: requireViolations skips
// requirements marked indirect, because a transitive production import is
// supposed to be caught here instead. Checking only the test-only modules here
// left a gap between the two halves exactly the width of an indirect
// requirement — and an indirect requirement is the state this project
// deliberately leaves a new dependency in until its first tidy, so a production
// file importing a framework passed the guard named after that guarantee.
func productionImportViolations(pkgs []listedPackage) []violation {
	forbidden := make([]string, 0, len(forbiddenProduction)+len(integrationModules))
	forbidden = append(forbidden, forbiddenProduction...)
	forbidden = append(forbidden, integrationModules...)

	var vs []violation

	for _, p := range pkgs {
		if p.Standard {
			continue
		}

		for _, imp := range p.Imports {
			for _, bad := range forbidden {
				if imp == bad || strings.HasPrefix(imp, bad+"/") {
					vs = append(vs, violation{Where: p.ImportPath, What: "imports " + imp + " (module " + bad + ")"})
				}
			}
		}
	}

	return vs
}

func copyFixture(t *testing.T, root string) string {
	t.Helper()
	dst := t.TempDir()
	require.NoError(t, os.CopyFS(dst, os.DirFS(root)))
	return dst
}

func goCmd(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	// The guard's whole job is asking the go tool about this repository, so the
	// arguments are built by these tests, never by external input.
	cmd := exec.CommandContext(t.Context(), "go", args...) //nolint:gosec // G204: fixed binary, test-supplied args
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

// exportedAPIViolations reports every exported identifier of the module rooted
// at dir whose type reaches a type of a package under forbidden.
//
// It reads the packages' compiled export data, so what it walks is the API the
// compiler sees: exported functions, methods, fields, variables, constants and
// types, aliases resolved, and unexported types followed wherever an exported
// identifier hands them out. Unexported fields and methods are not API and are
// not walked.
func exportedAPIViolations(t *testing.T, dir, forbidden string) []violation {
	t.Helper()
	out := goCmd(t, dir, nil, "list", "-export", "-deps", "-json=ImportPath,Export,DepOnly", "./...")
	exports := map[string]string{}
	var roots []string
	dec := json.NewDecoder(strings.NewReader(out))
	for dec.More() {
		var p struct {
			ImportPath string
			Export     string
			DepOnly    bool
		}
		require.NoError(t, dec.Decode(&p))
		exports[p.ImportPath] = p.Export
		if !p.DepOnly {
			roots = append(roots, p.ImportPath)
		}
	}

	imp := importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exports[path]
		if !ok || file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		// The path comes from go list's own output for this module.
		return os.Open(file) //nolint:gosec // G304: path reported by go list
	})

	var vs []violation
	for _, path := range roots {
		pkg, err := imp.Import(path)
		require.NoError(t, err, "importing %s", path)
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() {
				continue
			}
			w := apiWalker{pkg: pkg, forbidden: forbidden, seen: map[types.Type]bool{}}
			w.walk(obj.Type())
			for _, hit := range w.hits {
				vs = append(vs, violation{Where: path, What: name + " exposes " + hit})
			}
		}
	}
	return vs
}

// apiWalker follows a type through everything a caller outside its package
// can reach, and records each named type found under a forbidden path.
type apiWalker struct {
	pkg       *types.Package
	forbidden string
	seen      map[types.Type]bool
	hits      []string
}

func (w *apiWalker) walk(typ types.Type) {
	if typ == nil || w.seen[typ] {
		return
	}
	w.seen[typ] = true

	switch t := typ.(type) {
	case *types.Alias:
		w.walk(types.Unalias(t))
	case *types.Named:
		w.named(t)
	case *types.Pointer:
		w.walk(t.Elem())
	case *types.Slice:
		w.walk(t.Elem())
	case *types.Array:
		w.walk(t.Elem())
	case *types.Chan:
		w.walk(t.Elem())
	case *types.Map:
		w.walk(t.Key())
		w.walk(t.Elem())
	case *types.Signature:
		for tp := range t.TypeParams().TypeParams() {
			w.walk(tp.Constraint())
		}
		w.walk(t.Params())
		w.walk(t.Results())
	case *types.Tuple:
		for v := range t.Variables() {
			w.walk(v.Type())
		}
	case *types.Struct:
		for f := range t.Fields() {
			// An embedded unexported struct still promotes its exported members.
			if f.Exported() || f.Embedded() {
				w.walk(f.Type())
			}
		}
	case *types.Interface:
		for m := range t.ExplicitMethods() {
			if m.Exported() {
				w.walk(m.Type())
			}
		}
		for e := range t.EmbeddedTypes() {
			w.walk(e)
		}
	case *types.TypeParam:
		w.walk(t.Constraint())
	}
}

// named records a forbidden named type, and follows a named type of the
// package under check into its exported fields and methods. Named types of
// other packages are their own module's API and are not followed.
func (w *apiWalker) named(t *types.Named) {
	for arg := range t.TypeArgs().Types() {
		w.walk(arg)
	}
	for tp := range t.TypeParams().TypeParams() {
		w.walk(tp.Constraint())
	}
	obj := t.Obj()
	if obj.Pkg() == nil {
		return
	}
	path := obj.Pkg().Path()
	if path == w.forbidden || strings.HasPrefix(path, w.forbidden) {
		w.hits = append(w.hits, path+"."+obj.Name())
		return
	}
	if path != w.pkg.Path() {
		return
	}
	w.walk(t.Underlying())
	for m := range t.Methods() {
		if m.Exported() {
			w.walk(m.Type())
		}
	}
}

// redisClient is the module path prefix of the Redis client. Only the modules
// in redisClientOwners may require it, directly or indirectly: an adapter
// module requiring it would put a Redis client into the module graph of every
// consumer of that adapter, whether or not they share a limiter.
const redisClient = "github.com/redis/go-redis"

// redisClientOwners lists the workspace modules, by directory relative to the
// repository root, that may require redisClient: the Redis module itself, and
// the test module that runs it against real servers.
var redisClientOwners = []string{"ratelimit/redisstore", "test"}

// redisClientViolations reports a requirement on redisClient in the go.mod of
// the workspace module at dir, unless dir is one of redisClientOwners.
func redisClientViolations(dir string, reqs []requirement) []violation {
	if slices.Contains(redisClientOwners, filepath.ToSlash(dir)) {
		return nil
	}
	var vs []violation
	for _, r := range reqs {
		if r.Path == redisClient || strings.HasPrefix(r.Path, redisClient+"/") {
			vs = append(vs, violation{Where: filepath.ToSlash(filepath.Join(dir, "go.mod")), What: "requires " + r.Path})
		}
	}
	return vs
}

// workspaceModules returns the directory of every module the go.work file at
// root uses, as the file writes it: relative to root for a relative use entry.
// The go tool parses the file, so both forms of the use directive are read.
func workspaceModules(t *testing.T, root string) []string {
	t.Helper()
	out := goCmd(t, root, nil, "work", "edit", "-json", "go.work")
	var work struct{ Use []struct{ DiskPath string } }
	require.NoError(t, json.Unmarshal([]byte(out), &work))
	dirs := make([]string, 0, len(work.Use))
	for _, u := range work.Use {
		dirs = append(dirs, filepath.Clean(u.DiskPath))
	}
	return dirs
}

// workspaceViolations runs the file checks and the test-module go.mod check on
// every module the go.work file at root lists, except the test module at ./test.
// A nested module may require the integrations it adapts, so the integration
// requirement rule stays with the core module (checkModule). Each violation's
// location is prefixed with its module's directory.
func workspaceViolations(t *testing.T, root string) []violation {
	t.Helper()
	var vs []violation
	for _, dir := range workspaceModules(t, root) {
		if dir == "test" {
			continue
		}
		modDir := filepath.Join(root, dir)
		found := fileViolations(t, modDir)
		for _, r := range readRequires(t, filepath.Join(modDir, "go.mod")) {
			if r.Path == testModule || strings.HasPrefix(r.Path, testModule+"/") {
				found = append(found, violation{Where: "go.mod", What: "requires " + r.Path})
			}
		}
		for _, v := range found {
			if dir != "." {
				v.Where = filepath.ToSlash(filepath.Join(dir, v.Where))
			}
			vs = append(vs, v)
		}
	}
	return vs
}

// discoverModules returns the directory of every module found by walking root
// for go.mod files, relative to root and in lexical order. It skips testdata and
// dot-directories below root, and does not depend on any go.work file.
func discoverModules(t *testing.T, root string) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			rel, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr != nil {
				return relErr
			}
			dirs = append(dirs, rel)
		}
		return nil
	})
	require.NoError(t, err)
	return dirs
}

// integrationEntry describes one integration module: the directory it is
// published under, the package it declares, and a name for its test case.
type integrationEntry struct {
	dir, pkg, name string
}

// integrationTable is the single table of integrations. Every workspace
// module other than the core, test and tools modules must appear here.
var integrationTable = []integrationEntry{
	{"authenticate/passkey/webauthn", "webauthn", "the WebAuthn adapter extends passkey"},
	{"store/pgxstore", "pgxstore", "the pgx backend extends store"},
	{"store/gormstore", "gormstore", "the GORM backend extends store"},
	{"ratelimit/redisstore", "redisstore", "the Redis limiter store extends ratelimit"},
	{"expiry/sweep", "sweep", "the sweeper extends expiry"},
	{"httpsec/ginsec", "ginsec", "the Gin adapter extends httpsec"},
	{"httpsec/fibersec", "fibersec", "the Fiber adapter extends httpsec"},
}

// integrationDirs lists, by directory relative to the repository root, every
// workspace module other than the core, test and tools modules. Each one is an
// integration published under the concept it extends.
var integrationDirs = func() []string {
	dirs := make([]string, 0, len(integrationTable))
	for _, m := range integrationTable {
		dirs = append(dirs, m.dir)
	}
	return dirs
}()

// modulePath returns the path the module line of dir's go.mod declares, or the
// empty string when dir holds no go.mod.
func modulePath(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // G304: test-constructed path
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	require.NoError(t, err)
	for _, raw := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(raw), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

// goDirective returns the version the go directive of dir's go.mod declares,
// as written there.
func goDirective(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // G304: test-constructed path
	require.NoError(t, err)
	for _, raw := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(raw), "go "); ok {
			return strings.TrimSpace(rest)
		}
	}
	require.Failf(t, "no go directive", "%s/go.mod declares no go version", dir)
	return ""
}

// packageClause returns the package name of the first non-test Go file in dir,
// or the empty string when dir holds none.
func packageClause(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	require.NoError(t, err)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.PackageClauseOnly)
		require.NoError(t, parseErr)
		return f.Name.Name
	}
	return ""
}

// unlistedModules returns the modules found under root, by
// directory relative to root, that are neither the core module, the test or
// tools module, nor one of listed.
func unlistedModules(t *testing.T, root string, listed []string) []string {
	t.Helper()
	var unlisted []string
	for _, dir := range discoverModules(t, root) {
		dir = filepath.ToSlash(dir)
		if dir == "." || dir == "test" || dir == "tools" || slices.Contains(listed, dir) {
			continue
		}
		unlisted = append(unlisted, dir)
	}
	return unlisted
}

// offGoMinimum returns the modules under root, by directory relative to root,
// whose go directive is not the supported minimum, each mapped to the version it
// declares.
func offGoMinimum(t *testing.T, root string) map[string]string {
	t.Helper()
	off := map[string]string{}
	for _, dir := range discoverModules(t, root) {
		declared := goDirective(t, filepath.Join(root, dir))
		if version.Lang("go"+declared) != "go1.27" {
			off[filepath.ToSlash(dir)] = declared
		}
	}
	return off
}
