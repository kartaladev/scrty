package signingkey_test

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// josePath is the import prefix every part of the JOSE stack shares, so one
// check covers jwk, jws, jwa and jwt at whatever major version this module
// happens to be on.
const josePath = "lestrrat-go/jwx"

// TestNoExportedSymbolExposesAJOSEType pins a promise this package's
// documentation makes and nothing at run time can show: a consumer never has
// to name a JOSE type to use this package, or to implement KeySource.
//
// The promise is what makes the port implementable. A consumer's key service
// deals in crypto.Signer and crypto.PublicKey; if the port spoke a JOSE
// library's types instead, every such implementation would import that
// library, at the major version this module is pinned to, and a bump here
// would break code that never touches JOSE at all.
//
// This package uses the stack heavily inside — thumbprints, the public JWK a
// record carries — and that is not what is checked. Only the surface is: what
// a consumer can name.
//
// Only non-test files are scanned. The tests import the stack deliberately, to
// build and verify tokens the way a consumer's JOSE-speaking code would.
func TestNoExportedSymbolExposesAJOSEType(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := gotoken.NewFileSet()
	scanned := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, parseErr, "parsing %s", name)
		scanned++

		// The imports are read before the tree is narrowed, because narrowing
		// it to the exported surface drops the import declarations with
		// everything else that is unexported.
		jose := joseImportNames(t, fset, name, file)
		if len(jose) == 0 {
			continue // nothing from the stack can reach this file's surface
		}

		reportExportedJOSETypes(t, fset, name, file, jose)
	}

	require.NotZero(t, scanned, "no production sources were parsed, so nothing was checked")
}

// joseImportNames returns the local names a file refers to the JOSE stack by,
// mapped to the last element of the imported path, which is how a reader names
// the symbol in a failure message however the file aliased the import.
//
// A dot import or a blank import of any part of the stack fails the test
// outright. A dot import makes every symbol in the package reachable with no
// qualifier, so the walk below has no selector to inspect and would pass a
// file that exposed the whole stack; a blank import binds no name at all and
// only runs the package's initialisers, which nothing here needs.
func joseImportNames(
	t *testing.T, fset *gotoken.FileSet, name string, file *ast.File,
) map[string]string {
	t.Helper()

	names := map[string]string{}

	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if !strings.Contains(path, josePath) {
			continue
		}

		base := path[strings.LastIndex(path, "/")+1:]
		local := base
		if spec.Name != nil {
			local = spec.Name.Name
		}

		switch local {
		case ".":
			t.Errorf("%s:%d: dot-imports %s; every symbol in it is then reachable "+
				"unqualified, so no walk over this file can see what it exposes",
				name, fset.Position(spec.Pos()).Line, path)

			continue
		case "_":
			t.Errorf("%s:%d: blank-imports %s; it binds no name but still runs the "+
				"package's initialisers, and nothing here needs that",
				name, fset.Position(spec.Pos()).Line, path)

			continue
		}

		names[local] = base
	}

	return names
}

// reportExportedJOSETypes fails for every JOSE-qualified type a consumer of
// this package can name.
//
// ast.FileExports does the narrowing: it drops unexported declarations,
// unexported struct fields and unexported interface methods, keeps exported
// embedded fields, and never removes a qualified type from a signature it
// keeps. Function bodies survive it, so they are skipped here — the
// implementation names JOSE types on every key it builds, and that is the
// point of the promise rather than a breach of it.
func reportExportedJOSETypes(
	t *testing.T, fset *gotoken.FileSet, name string, file *ast.File, jose map[string]string,
) {
	t.Helper()

	ast.FileExports(file)

	ast.Inspect(file, func(node ast.Node) bool {
		if _, isBody := node.(*ast.BlockStmt); isBody {
			return false
		}

		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}

		if base, isJOSE := jose[pkg.Name]; isJOSE {
			t.Errorf(
				"%s:%d: exported surface names %s.%s from the JOSE stack (%s); "+
					"keys travel as PublicKey and crypto.Signer, so a consumer "+
					"implementing KeySource never imports the stack and a major "+
					"version bump in it stays inside this package",
				name, fset.Position(selector.Pos()).Line,
				pkg.Name, selector.Sel.Name, base)
		}

		return true
	})
}
