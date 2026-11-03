package event_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
)

// packageDoc is the package's documentation, as go doc prints it: the doc
// comment of every non-test file that has one.
func packageDoc(t *testing.T) string {
	t.Helper()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	var doc strings.Builder
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		src, err := os.ReadFile(name) //nolint:gosec // G304: the names are this package's own files, listed above
		require.NoError(t, err)

		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ParseComments|parser.PackageClauseOnly)
		require.NoError(t, err)

		if f.Doc != nil {
			doc.WriteString(f.Doc.Text())
		}
	}

	return doc.String()
}

// TestSecurityEvents_Documented pins that go doc of the package lists every
// event name the library reports, and states the sink's contract, a blocking
// sink included.
func TestSecurityEvents_Documented(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, doc string)
	}

	cases := []testCase{
		{
			name: "every name is listed",
			assert: func(t *testing.T, doc string) {
				for _, name := range event.Names() {
					assert.Contains(t, doc, "  - "+name+":", "%s is not in the package's list", name)
				}
			},
		},
		{
			name: "the sink's contract is stated",
			assert: func(t *testing.T, doc string) {
				for _, clause := range []string{
					"synchronously",
					"cancellation",
					"cannot change the outcome",
					"recovered and logged",
					"A sink that blocks holds the request",
					"consumer's responsibility",
					"whether an account exists",
				} {
					assert.Contains(t, doc, clause)
				}
			},
		},
	}

	doc := packageDoc(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, doc)
		})
	}
}
