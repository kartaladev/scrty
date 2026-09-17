package token_test

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// allowedJOSECalls is every symbol from the JOSE stack that this package's
// production sources may name, keyed by "<package>.<Symbol>" where <package>
// is the last element of the import path rather than whatever local name a
// file binds it to.
//
// It is an allow-list, and that is the whole point. A deny-list of the knobs
// known to defeat key pinning cannot hold: the stack offers many of them —
// jwt.WithKeyProvider, jws.WithKeyProvider, jws.WithUseDefault,
// jwt.WithValidate, jwt.WithAcceptableSkew, jwt.ParseInsecure among them — and
// every release may add another, so anything not enumerated would pass. With
// an allow-list, reaching for a new part of the stack on the verification or
// issue path is a visible, reviewable line in this map.
var allowedJOSECalls = map[string]string{
	// Resolving the configured algorithm once, at construction.
	"jwa.LookupSignatureAlgorithm": "resolves the configured algorithm at construction",
	"jwa.SignatureAlgorithm":       "the resolved algorithm, held on the config",

	// Signing: the key identifier goes into the protected header so
	// verification can select the key.
	"jws.NewHeaders":           "builds the protected header",
	"jws.KeyIDKey":             "the kid header parameter",
	"jws.WithProtectedHeaders": "attaches the protected header when signing",
	"jwt.NewBuilder":           "builds the claim set",
	"jwt.Sign":                 "signs the claim set",
	"jwt.WithKey":              "names the signing key and algorithm",

	// Verification: the key set, the caller's context, and the validation
	// rules built once at construction.
	"jwt.Parse":             "the one verification call",
	"jwt.ParseOption":       "the type the validation rules travel as",
	"jwt.WithKeySet":        "pins verification to the key source's current set",
	"jwt.WithContext":       "propagates the caller's context",
	"jwt.WithRequiredClaim": "makes exp mandatory",
	"jwt.ExpirationKey":     "names the exp claim",
	"jwt.WithClock":         "reads time from the configured clock",
	"jwt.ClockFunc":         "adapts the configured clock",
	"jwt.WithTruncation":    "pins time comparisons away from the process-global setting",
	"jwt.WithIssuer":        "enforces a configured issuer",
	"jwt.WithAudience":      "enforces a configured audience",

	// Reading a verified token.
	"jwt.Token":    "the verified token Claims wraps",
	"jwt.Get":      "reads one claim off a verified token",
	"jwt.JwtIDKey": "names the jti claim",
}

// unsafeJOSECalls explains a handful of refusals, so a developer who reaches
// for one of these gets the reason rather than only "not on the allow-list".
// The refusal itself comes from allowedJOSECalls; this map only annotates it,
// and is deliberately not the thing the guard consults to decide.
var unsafeJOSECalls = map[string]string{
	"jwt.WithVerify":                    "would let a token through without checking its signature",
	"jwt.ParseInsecure":                 "would skip both verification and validation",
	"jwt.WithInsecureNoSignature":       "would produce or accept an unsigned token",
	"jws.WithInsecureNoSignature":       "would produce or accept an unsigned token",
	"jws.WithRequireKid":                "would let a token without a kid match an arbitrary key in the set",
	"jws.WithInferAlgorithmFromKey":     "would stop requiring the header algorithm to match the key's",
	"jwt.WithKeyProvider":               "would let something other than the key source choose the key",
	"jws.WithKeyProvider":               "would let something other than the key source choose the key",
	"jws.KeyProviderFunc":               "would let something other than the key source choose the key",
	"jws.WithUseDefault":                "would match a single-key set without a kid",
	"jwt.WithAcceptableSkew":            "would tolerate clock skew, which this package documents as untolerated",
	"jwt.WithValidate":                  "would make validation a parameter rather than a rule",
	"jwt.WithResetValidators":           "would discard the default time validators",
	"jwt.Settings":                      "would reach for process-global state on behalf of the consumer's binary",
	"jwt.WithNumericDateParsePrecision": "would reach for process-global state on behalf of the consumer's binary",
}

// TestProductionSourceGuards pins three claims the package documentation makes
// that cannot be observed at run time, so all three read the package's own
// source: that no exported signature carries a type from the JOSE stack, that
// no production source names a JOSE symbol outside the reviewed allow-list,
// and that no production source imports the stack in a form that hides the
// names it uses.
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
		{name: "no production source names a JOSE symbol outside the allow-list", inspect: reportDisallowedJOSECalls},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			eachProductionFile(t, tc.inspect)
		})
	}

	// The import form is checked on its own, because a dot import binds no
	// local name and a blank import binds none either: neither leaves a
	// qualified selector for the walks above to see, so a file using one would
	// pass them with nothing inspected at all.
	t.Run("no production source dot-imports or blank-imports the JOSE stack", func(t *testing.T) {
		t.Parallel()

		eachProductionFile(t, func(_ *testing.T, _ *gotoken.FileSet, _ string, _ *ast.File, _ map[string]string) {})
	})
}

// eachProductionFile parses every non-test source in this package and hands
// each one to inspect, together with the local names that file refers to the
// JOSE stack by. Each case gets its own parse, so a case may filter the tree
// in place.
//
// The import forms are checked here rather than in a case, because every walk
// over the tree depends on them: a name the walk cannot see is a name it cannot
// judge.
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
		jose := joseImportNames(t, fset, name, file)
		if len(jose) == 0 {
			continue // nothing from the JOSE stack can leak out of this file
		}

		inspect(t, fset, name, file, jose)
	}

	require.NotZero(t, scanned, "no production sources were parsed, so nothing was checked")
}

// joseImportNames returns the local names a file refers to the JOSE stack by,
// mapped to the last element of the imported path — the name the allow-list is
// written in, so aliasing an import cannot rename a symbol out of its reach.
//
// It fails the test for a dot import or a blank import of any part of the
// stack. A dot import makes every one of its symbols reachable with no
// qualifier, so no walk over selector expressions can see them; a blank import
// binds nothing but still runs the package's initialisers. Neither has a use
// on these paths.
func joseImportNames(
	t *testing.T, fset *gotoken.FileSet, name string, file *ast.File,
) map[string]string {
	t.Helper()

	names := map[string]string{}

	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if !strings.Contains(path, "lestrrat-go/jwx") {
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
				"unqualified, so the allow-list cannot see what this file uses",
				name, fset.Position(spec.Pos()).Line, path)

			continue
		case "_":
			t.Errorf("%s:%d: blank-imports %s; it binds no name but still runs the "+
				"package's initialisers, and nothing on these paths needs that",
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

		if base, isJOSE := jose[pkg.Name]; isJOSE {
			t.Errorf(
				"%s:%d: exported surface names %s.%s from the JOSE stack (%s); "+
					"tokens must travel as strings and claims through Claims, "+
					"so the JOSE stack stays replaceable",
				name, fset.Position(selector.Pos()).Line,
				pkg.Name, selector.Sel.Name, base)
		}

		return true
	})
}

// reportDisallowedJOSECalls fails for every JOSE symbol named anywhere in a
// production source that is not in allowedJOSECalls — function bodies and
// closures inside them included, which is where such a call would actually be
// made.
func reportDisallowedJOSECalls(
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
		base, isJOSE := jose[pkg.Name]
		if !isJOSE {
			return true
		}

		symbol := base + "." + selector.Sel.Name
		if _, allowed := allowedJOSECalls[symbol]; allowed {
			return true
		}

		because := "it is not one of the JOSE symbols these paths were reviewed to use"
		if why, known := unsafeJOSECalls[symbol]; known {
			because = why
		}
		t.Errorf("%s:%d: names %s, which %s; "+
			"if this package really needs it, add it to allowedJOSECalls and say why",
			name, fset.Position(selector.Pos()).Line, symbol, because)

		return true
	})
}

// TestJOSEAllowListIsHonest pins that the allow-list is a record of what the
// package uses, not a standing permission. An entry nothing names is a knob
// pre-authorised for whoever adds the call later, with no review left to do.
func TestJOSEAllowListIsHonest(t *testing.T) {
	t.Parallel()

	named := map[string]struct{}{}
	eachProductionFile(t, func(
		_ *testing.T, _ *gotoken.FileSet, _ string, file *ast.File, jose map[string]string,
	) {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if base, isJOSE := jose[pkg.Name]; isJOSE {
				named[base+"."+selector.Sel.Name] = struct{}{}
			}

			return true
		})
	})
	require.NotEmpty(t, named, "no JOSE symbols were found, so the comparison proves nothing")

	var unused []string
	for symbol := range allowedJOSECalls {
		if _, ok := named[symbol]; !ok {
			unused = append(unused, symbol)
		}
	}
	sort.Strings(unused)

	require.Empty(t, unused,
		"these entries are allowed but never named; remove them rather than leaving "+
			"the JOSE symbols they cover pre-authorised")
}
