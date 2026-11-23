package pgschema_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unprefixedTables holds the names the tables had before the scrty_ prefix.
// The guard keeps its own copy because the relation inventory lives in the
// test module, which this module cannot import.
var unprefixedTables = []string{
	// security-state set
	"account_recoveries", "api_keys", "login_attempts", "login_failure_streaks",
	"mfa_enrolments", "oidc_flows", "oidc_handoffs", "oidc_links",
	"one_time_tokens", "op_access_tokens", "op_authorization_codes",
	"op_browser_sessions", "op_client_assertions", "op_clients", "op_consents",
	"op_device_authorizations", "op_grants", "op_pending_requests",
	"op_refresh_tokens", "passkey_credentials", "passkey_user_handles",
	"rate_limit_buckets", "recovery_codes", "sessions", "signing_keys",
	// identity set
	"assigned_roles", "groups", "organizations", "password_history",
	"resource_privileges", "roles", "users",
}

// stringConstants evaluates every string constant the package's own (non-test)
// source files declare, including constants built from other constants.
func stringConstants(t *testing.T) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	require.NoError(t, err)

	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		require.NoError(t, err)
		files = append(files, f)
	}
	require.NotEmpty(t, files)

	// Imports that fail to resolve only leave unrelated expressions untyped;
	// constants are still evaluated, so type errors are tolerated here.
	conf := types.Config{Importer: importer.Default(), Error: func(error) {}}
	pkg, _ := conf.Check("pgschema", fset, files, nil)
	require.NotNil(t, pkg)

	out := map[string]string{}
	for _, name := range pkg.Scope().Names() {
		c, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || c.Val().Kind() != constant.String {
			continue
		}
		out[name] = constant.StringVal(c.Val())
	}
	return out
}

// literalsIn returns every string literal, constant or not, in the non-test Go
// files of dir, keyed by "file:line".
func literalsIn(t *testing.T, dir string) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)

	out := map[string]string{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		require.NoError(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			out[fmt.Sprintf("%s:%d", p, fset.Position(lit.Pos()).Line)] = val
			return true
		})
	}
	return out
}

func TestStatementsUsePrefixedTables(t *testing.T) {
	t.Parallel()

	names := strings.Join(unprefixedTables, "|")
	// A statement names a table after one of these keywords...
	keyword := regexp.MustCompile(`(?i)\b(FROM|INTO|UPDATE|JOIN|ON|REFERENCES|LOCK TABLE|TABLE|to_regclass\('(?:[a-z_]+\.)?)\s*(` + names + `)\b`)
	// ...or qualifies a column with it. The anchor keeps operation and metric
	// names such as scrty.sessions.load, which a dot or word character precedes, out.
	qualified := regexp.MustCompile(`(^|[^.\w])(` + names + `)\.[a-z_]+\b`)

	type testCase struct {
		name   string
		dir    string
		assert func(t *testing.T, offenders []string)
	}
	empty := func(t *testing.T, offenders []string) {
		assert.Empty(t, offenders, "statements must name scrty_-prefixed tables")
	}

	cases := []testCase{
		{name: "pgschema", dir: ".", assert: empty},
		{name: "storekit", dir: "../storekit", assert: empty},
		{name: "sqlstore", dir: "../../store/sqlstore", assert: empty},
		{name: "pgxstore", dir: "../../store/pgxstore", assert: empty},
		{name: "gormstore", dir: "../../store/gormstore", assert: empty},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lits := literalsIn(t, tc.dir)
			require.NotEmpty(t, lits)

			var offenders []string
			for where, val := range lits {
				if m := keyword.FindStringSubmatch(val); m != nil {
					offenders = append(offenders, where+": "+m[0])
				}
				if m := qualified.FindStringSubmatch(val); m != nil {
					offenders = append(offenders, where+": qualified column "+strings.TrimSpace(m[0]))
				}
			}
			sort.Strings(offenders)
			tc.assert(t, offenders)
		})
	}

	t.Run("pgschema constants are never a bare table name", func(t *testing.T) {
		t.Parallel()

		consts := stringConstants(t)
		require.NotEmpty(t, consts)

		var offenders []string
		for name, val := range consts {
			for _, tbl := range unprefixedTables {
				if val == tbl {
					offenders = append(offenders, name+": bare table name "+tbl)
				}
			}
		}
		sort.Strings(offenders)
		assert.Empty(t, offenders)
	})
}
