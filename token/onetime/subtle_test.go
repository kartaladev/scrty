package onetime_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretAndBindingAreComparedInConstantTime reads the package's own source.
//
// No black-box test can tell a constant-time comparison from a fast one: both
// return the same answers, and timing them is exactly the measurement an
// attacker has to make thousands of times to learn anything. So the guarantee
// is pinned where it is decided — in the comparison the code performs — rather
// than inferred from behaviour that cannot show it.
func TestSecretAndBindingAreComparedInConstantTime(t *testing.T) {
	t.Parallel()

	sources, err := filepath.Glob("*.go")
	require.NoError(t, err)

	fset := token.NewFileSet()

	var parsed []*ast.File
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		parsed = append(parsed, file)
	}
	require.NotEmpty(t, parsed, "the production package did not parse")

	var (
		checkBody     *ast.FuncDecl
		checkFile     *ast.File
		constantTime  int
		shortCircuits []string
	)

	for _, file := range parsed {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "Check" {
				continue
			}
			checkBody, checkFile = fn, file
		}
	}
	require.NotNil(t, checkBody, "no Check method was found to inspect")

	ast.Inspect(checkBody, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		switch {
		case pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare":
			constantTime++
		case pkg.Name == "bytes" && (sel.Sel.Name == "Equal" || sel.Sel.Name == "Compare"),
			pkg.Name == "strings" && (sel.Sel.Name == "EqualFold" || sel.Sel.Name == "Compare"),
			pkg.Name == "reflect" && sel.Sel.Name == "DeepEqual",
			pkg.Name == "slices" && sel.Sel.Name == "Equal":
			shortCircuits = append(shortCircuits, pkg.Name+"."+sel.Sel.Name)
		}

		return true
	})

	var imported bool
	for _, spec := range checkFile.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		require.NoError(t, err)
		if path == "crypto/subtle" {
			imported = true
		}
	}

	assert.True(t, imported, "the file declaring Check does not import crypto/subtle")
	assert.GreaterOrEqual(t, constantTime, 2,
		"Check makes fewer than two constant-time comparisons, so the secret or the binding is compared some other way")
	assert.Empty(t, shortCircuits,
		"Check compares with a primitive that returns as soon as two bytes differ, which times the answer out one byte at a time")
}
