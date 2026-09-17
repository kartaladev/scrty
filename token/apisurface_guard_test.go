package token_test

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// unsafeJOSECalls are the knobs that would make verification accept an
// unsigned, unverified or unpinned token. None has a legitimate use on this
// package's paths.
var unsafeJOSECalls = map[string]string{
	"WithVerify":                "would let a token through without checking its signature",
	"ParseInsecure":             "would skip both verification and validation",
	"WithInsecureNoSignature":   "would produce or accept an unsigned token",
	"WithRequireKid":            "would let a token without a kid match an arbitrary key in the set",
	"WithInferAlgorithmFromKey": "would stop requiring the header algorithm to match the key's",
}

// TestProductionSourceGuards pins two claims the package documentation makes
// that cannot be observed at run time, so both read the package's own source:
// that no exported signature carries a type from the JOSE stack, and that no
// production source reaches for a knob that would accept an unsigned token.
//
// Only non-test files are scanned. The tests import the JOSE packages
// deliberately, to build the tokens a consumer never would.
func TestProductionSourceGuards(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		inspect func(t *testing.T, fset *gotoken.FileSet, name string, file *ast.File, jose map[string]string)
	}

	cases := []testCase{
		{name: "no exported symbol exposes a JOSE type", inspect: reportExportedJOSETypes},
		{name: "no production source reaches for an unsafe JOSE knob", inspect: reportUnsafeJOSECalls},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			eachProductionFile(t, tc.inspect)
		})
	}
}

// eachProductionFile parses every non-test source in this package and hands
// each one to inspect, together with the local names that file refers to the
// JOSE stack by. Each case gets its own parse, so a case may filter the tree
// in place.
func eachProductionFile(
	t *testing.T,
	inspect func(t *testing.T, fset *gotoken.FileSet, name string, file *ast.File, jose map[string]string),
) {
	t.Helper()

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

		// Read the imports before inspect runs: filtering the tree to its
		// exported surface drops the import declarations.
		jose := joseImportNames(file)
		if len(jose) == 0 {
			continue // nothing from the JOSE stack can leak out of this file
		}

		inspect(t, fset, name, file, jose)
	}

	require.NotZero(t, scanned, "no production sources were parsed, so nothing was checked")
}

// joseImportNames returns the local names a file refers to the JOSE stack by.
func joseImportNames(file *ast.File) map[string]string {
	names := map[string]string{}

	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if !strings.Contains(path, "lestrrat-go/jwx") {
			continue
		}

		local := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			local = spec.Name.Name
		}
		names[local] = path
	}

	return names
}

// reportExportedJOSETypes fails for every JOSE-qualified type a consumer of
// this package can name.
//
// ast.FileExports does the narrowing: it drops unexported declarations,
// unexported struct fields and unexported interface methods, keeps exported
// embedded fields, and never removes a qualified type from a signature it
// keeps. Function bodies survive it, so they are skipped here — an
// implementation naturally names JOSE types, and that is not the surface.
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

		if path, isJOSE := jose[pkg.Name]; isJOSE {
			t.Errorf(
				"%s:%d: exported surface names %s.%s from %s; "+
					"tokens must travel as strings and claims through Claims, "+
					"so the JOSE stack stays replaceable",
				name, fset.Position(selector.Pos()).Line,
				pkg.Name, selector.Sel.Name, path)
		}

		return true
	})
}

// reportUnsafeJOSECalls fails for every unsafe knob named anywhere in a
// production source, function bodies included: that is where such a call would
// actually be made.
func reportUnsafeJOSECalls(
	t *testing.T, fset *gotoken.FileSet, name string, file *ast.File, jose map[string]string,
) {
	t.Helper()

	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, isJOSE := jose[pkg.Name]; !isJOSE {
			return true
		}

		if why, unsafe := unsafeJOSECalls[selector.Sel.Name]; unsafe {
			t.Errorf("%s:%d: names %s.%s, which %s",
				name, fset.Position(selector.Pos()).Line,
				pkg.Name, selector.Sel.Name, why)
		}

		return true
	})
}
