package scrty_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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
}

type listedPackage struct {
	ImportPath string
	Imports    []string
	Standard   bool
}

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
