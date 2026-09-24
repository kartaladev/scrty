package identity_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// portMethods maps a method name to the port it would implement. A production
// type in this package declaring any of them means scrty has started shipping an
// identity port implementation.
var portMethods = map[string]string{
	"LoadByUsername": "UserLoader",
	"LoadByUserID":   "UserLoader",
	"LoadPrivileges": "RoleLoader",
	"Provision":      "UserProvisioner",
	"Update":         "UserProvisioner",
	"Required":       "MFARequirementLookup",
}

// TestIdentityShipsNoPortImplementation pins the half of "no silent defaults"
// that this package owns: it defines the ports as contracts and ships no
// implementation of them, so a component given no port cannot quietly fall back
// to one.
//
// Go cannot enumerate a package's types at run time, so this reads the package's
// own source. Only non-test files are scanned: the conformance suite's in-memory
// store is exactly what is allowed to exist, and it lives in the test module.
func TestIdentityShipsNoPortImplementation(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	scanned := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, parseErr, "parsing %s", name)
		scanned++

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue // a plain function implements no interface
			}

			if port, implements := portMethods[fn.Name.Name]; implements {
				t.Errorf(
					"%s declares method %s, which implements %s: identity defines the ports "+
						"and ships no implementation of them, so this belongs in the test module",
					name, fn.Name.Name, port)
			}
		}
	}

	require.Positive(t, scanned, "scanned no production files, so this guard proved nothing")
}
