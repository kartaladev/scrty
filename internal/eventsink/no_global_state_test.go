package eventsink_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/eventsink"
)

// GuardRefused returns its abort to the guard rather than reporting it: the
// shape is pinned at compile time.
var _ func(context.Context, error) error = eventsink.GuardRefused

// TestEventsink_HoldsNoProcessState pins that the package keeps no state of
// its own: no package-level variable, and so no reporter or other hook a
// caller could install for the whole process. A guard's aborted walk is
// returned to the guard (GuardRefused), which reports it by the guard's own
// configuration; a process-wide hook could see no guard's configuration.
//
// It reads the package's own source, since the absence of a declaration is
// not something a compiled test can name.
func TestEventsink_HoldsNoProcessState(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	fset := token.NewFileSet()

	var checked int

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		src, err := os.ReadFile(name) //nolint:gosec // G304: the package's own source files
		require.NoError(t, err)

		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		require.NoError(t, err)

		checked++

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok == token.VAR {
					t.Errorf("%s declares a package-level variable at %s", name, fset.Position(d.Pos()))
				}
			case *ast.FuncDecl:
				if d.Recv == nil && strings.HasPrefix(d.Name.Name, "Set") {
					t.Errorf("%s declares %s, a process-wide setter", name, d.Name.Name)
				}
			}
		}
	}

	require.Positive(t, checked, "no source file was read")
}
