package factor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllKindsNamesEveryDeclaredKind pins that the enumeration the tests walk is
// the vocabulary the package declares.
//
// Go cannot enumerate a string-const type, so AllKinds is written by hand, and
// every test that checks a property of the whole vocabulary — that each kind's
// channel and exemption are covered, that no first factor arrives on the
// authenticator-app channel — walks that list. A kind added to the const block
// and forgotten there is therefore not merely untested: it is invisible to the
// tests that exist to catch exactly the mistake of adding one, and it could be
// exempt from a second factor or share a channel with one while the suite stays
// green.
//
// Nothing in the type system can enforce the list, so this reads the package's
// own source instead, as the identity package's port guard does.
func TestAllKindsNamesEveryDeclaredKind(t *testing.T) {
	t.Parallel()

	listed := make(map[Kind]bool, len(AllKinds))
	for _, k := range AllKinds {
		listed[k] = true
	}

	require.Len(t, AllKinds, len(listed), "AllKinds names the same kind twice")

	declared := declaredKinds(t, "factor.go")

	require.NotEmpty(t, declared,
		"no Kind constant was found in factor.go, so this guard proved nothing")

	for name, value := range declared {
		assert.True(t, listed[value],
			"factor.go declares kind %s (%q), which AllKinds does not name: every test that "+
				"walks the vocabulary skips it, so neither its channel nor its exemption is "+
				"checked", name, value)
	}

	assert.Len(t, AllKinds, len(declared),
		"AllKinds has %d entries but factor.go declares %d kinds, so the list names something "+
			"the package does not declare", len(AllKinds), len(declared))
}

// declaredKinds returns every Kind-typed constant the named source file
// declares, by constant name.
//
// A constant in a block that declares kinds but that names no type of its own is
// counted too: an untyped string constant converts to a Kind implicitly, so it
// is just as much part of the vocabulary as an explicitly typed one.
func declaredKinds(t *testing.T, filename string) map[string]Kind {
	t.Helper()

	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, filename, nil, 0)
	require.NoError(t, err, "parsing %s", filename)

	kinds := make(map[string]Kind)

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}

		if !declaresKind(gen) {
			continue
		}

		for _, spec := range gen.Specs {
			value, valueOK := spec.(*ast.ValueSpec)
			if !valueOK || !isKindType(value.Type) {
				continue
			}

			for i, name := range value.Names {
				require.Less(t, i, len(value.Values),
					"%s: constant %s has no value, so its kind cannot be read", filename, name.Name)

				lit, litOK := value.Values[i].(*ast.BasicLit)
				require.True(t, litOK && lit.Kind == token.STRING,
					"%s: constant %s is not a string literal, so this guard cannot read the "+
						"vocabulary it declares", filename, name.Name)

				unquoted, unquoteErr := strconv.Unquote(lit.Value)
				require.NoError(t, unquoteErr, "%s: constant %s", filename, name.Name)

				kinds[name.Name] = Kind(unquoted)
			}
		}
	}

	return kinds
}

// declaresKind reports whether the const block names the Kind type at all.
func declaresKind(gen *ast.GenDecl) bool {
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}

		if ident, isIdent := value.Type.(*ast.Ident); isIdent && ident.Name == "Kind" {
			return true
		}
	}

	return false
}

// isKindType reports whether a value spec's type makes it a kind: either Kind
// itself, or no type at all inside a block that declares kinds.
func isKindType(typ ast.Expr) bool {
	if typ == nil {
		return true
	}

	ident, ok := typ.(*ast.Ident)

	return ok && ident.Name == "Kind"
}
