package httpsec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enableOptions lists every exported Enable option of the package, read from
// its non-test source files.
func enableOptions(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()

	var found []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err, name)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !strings.HasPrefix(fn.Name.Name, "Enable") {
				continue
			}

			found = append(found, fn.Name.Name)
		}
	}

	slices.Sort(found)

	return found
}

// TestEndpointAnswering_ClassifiesEveryEnableOption is the guard on
// endpointAnswering: the base path is refused on a chain whose built-ins answer
// no path, and a built-in missing from that list is taken as answering none. A
// new Enable option therefore cannot be added without this table saying whether
// it answers a path of its own, and the list agreeing.
func TestEndpointAnswering_ClassifiesEveryEnableOption(t *testing.T) {
	t.Parallel()

	// answersPath classifies each option: true when it answers a request path
	// of its own, which the base path moves, false when it only wraps, reads or
	// checks the requests that reach it.
	answersPath := map[string]bool{
		"EnableFormLogin":          true,
		"EnableLogout":             true,
		"EnableJWKSEndpoint":       true,
		"EnableSessionRenewal":     true,
		"EnablePasswordChangeGate": true,
		"EnableSessionSignals":     true,
		"EnableSessionManagement":  true,
		"EnableMFA":                true,
		"EnableMFAEnrolment":       true,
		"EnablePasskeys":           true,
		"EnableMagicLink":          true,
		"EnableAccountRecovery":    true,
		"EnableReauthentication":   true,
		"EnableOIDCLogin":          true,
		"EnableOIDCProvider":       true,

		"EnableAPIKey":              false,
		"EnableAuthorization":       false,
		"EnableAutomationChallenge": false,
		"EnableBasicAuth":           false,
		"EnableBearerToken":         false,
		"EnableCertificateBinding":  false,
		"EnableCORS":                false,
		"EnableCSRFProtection":      false,
		"EnableDPoP":                false,
		"EnableRecoveryCooldown":    false,
		"EnableSecurityEvents":      false,
		"EnableSecurityHeaders":     false,
		"EnableSessionBearer":       false,
		"EnableSignInNotice":        false,
		"EnableTrustedProxies":      false,
	}

	options := enableOptions(t)
	require.NotEmpty(t, options, "no Enable option was found: the parse is broken")

	t.Run("every Enable option is classified here", func(t *testing.T) {
		for _, name := range options {
			_, ok := answersPath[name]
			assert.True(t, ok, "%s is an Enable option this table does not classify: say whether it answers "+
				"a path of its own, and add it to endpointAnswering when it does", name)
		}
	})

	t.Run("every classification names an Enable option", func(t *testing.T) {
		for name := range answersPath {
			assert.Contains(t, options, name, "%s is classified here but is not an Enable option", name)
		}
	})

	t.Run("endpointAnswering agrees with the classification", func(t *testing.T) {
		for name, answers := range answersPath {
			assert.Equal(t, answers, endpointAnswering[name], "endpointAnswering[%q]", name)
		}

		for name := range endpointAnswering {
			_, ok := answersPath[name]
			assert.True(t, ok, "endpointAnswering names %q, which is not classified here", name)
		}
	})
}
