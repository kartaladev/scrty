package scrty_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleLayout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		fixture string // empty means the real repository tree
		assert  func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name: "real tree has no violations",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:    "production file imports testify",
			fixture: "testdata/layout/prodtestify",
			assert:  hasViolation("example.com/fixture/app", "github.com/stretchr/testify"),
		},
		{
			name:    "production file imports clockwork",
			fixture: "testdata/layout/prodclockwork",
			assert:  hasViolation("example.com/fixture/app", "github.com/jonboulle/clockwork"),
		},
		{
			name:    "test file imports testify is allowed",
			fixture: "testdata/layout/testtestify",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:    "production file declares an exported mock",
			fixture: "testdata/layout/prodmock",
			assert:  hasViolation("app/app.go", "MockStore"),
		},
		{
			name:    "production file imports the test module",
			fixture: "testdata/layout/prodtestmodule",
			assert:  hasViolation("app/app.go", testModule),
		},
		{
			name:    "test file imports the test module",
			fixture: "testdata/layout/testfiletestmodule",
			assert:  hasViolation("app/app_test.go", testModule),
		},
		{
			name:    "go.mod requires an integration module",
			fixture: "testdata/layout/requiresgin",
			assert:  hasViolation("go.mod", "github.com/gin-gonic/gin"),
		},
		{
			// The requirement is marked indirect, which is the state this project
			// deliberately leaves a new dependency in until its first tidy. The
			// go.mod half of the guard skips indirect requirements, so only the
			// import walk can catch this — and it used to check just the
			// test-only modules, never the integration ones.
			name:    "production file imports an integration module",
			fixture: "testdata/layout/prodgin",
			assert:  hasViolation("example.com/fixture/app", "github.com/gin-gonic/gin"),
		},
		{
			name:    "go.mod requires the test module indirectly",
			fixture: "testdata/layout/requirestestmodule",
			assert:  hasViolation("go.mod", testModule),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := "."
			if tc.fixture != "" {
				dir = copyFixture(t, tc.fixture)
			}

			tc.assert(t, checkModule(t, dir))
		})
	}
}

func TestModuleLayoutEveryWorkspaceModule(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		fixture string // empty means the real repository tree
		assert  func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name: "real workspace has no violations",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:    "nested module production file declares an exported mock",
			fixture: "testdata/layout/wsmock",
			assert:  hasViolation("nested/app/app.go", "MockStore"),
		},
		{
			name:    "nested module imports the test module",
			fixture: "testdata/layout/wstestimport",
			assert:  hasViolation("nested/app/app_test.go", testModule),
		},
		{
			name:    "nested module go.mod requires the test module",
			fixture: "testdata/layout/wstestimport",
			assert:  hasViolation("nested/go.mod", testModule),
		},
		{
			name:    "the test module itself is not scanned",
			fixture: "testdata/layout/wsskiptest",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			root := "."
			if tc.fixture != "" {
				root = copyFixture(t, tc.fixture)
			}

			tc.assert(t, workspaceViolations(t, root))
		})
	}
}

func TestConsumerModuleGraph(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		consumer func(t *testing.T) (dir string, env []string)
		assert   func(t *testing.T, modules []string)
	}

	fixtureConsumer := func(graph string) func(t *testing.T) (string, []string) {
		return func(t *testing.T) (string, []string) {
			return filepath.Join(copyFixture(t, graph), "consumer"), nil
		}
	}

	cases := []testCase{
		{
			name:     "helper used only inside its own module keeps the driver out",
			consumer: fixtureConsumer("testdata/graph/clean"),
			assert: func(t *testing.T, modules []string) {
				assert.NotContains(t, modules, "example.com/driver")
				assert.NotContains(t, modules, "example.com/core/test")
			},
		},
		{
			name:     "control: a core test file importing the helper leaks the driver",
			consumer: fixtureConsumer("testdata/graph/leaky"),
			assert: func(t *testing.T, modules []string) {
				assert.Contains(t, modules, "example.com/driver")
			},
		},
		{
			name:     "consumer of the real core sees no integration module",
			consumer: realCoreConsumer,
			assert: func(t *testing.T, modules []string) {
				for _, m := range modules {
					for _, bad := range append(slices.Clone(integrationModules), testModule) {
						assert.False(t, m == bad || strings.HasPrefix(m, bad+"/"), "consumer graph contains %s", m)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir, env := tc.consumer(t)
			tc.assert(t, listModules(t, dir, env))
		})
	}
}

func TestCoreDependencies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		reqs   []requirement
		assert func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name:   "the WebAuthn library is an integration module",
			reqs:   []requirement{{Path: "github.com/go-webauthn/webauthn"}},
			assert: hasViolation("go.mod", "github.com/go-webauthn/webauthn"),
		},
		{
			name:   "the CBOR library is an integration module",
			reqs:   []requirement{{Path: "github.com/fxamacker/cbor/v2"}},
			assert: hasViolation("go.mod", "github.com/fxamacker/cbor/v2"),
		},
		{
			name:   "the TPM library is an integration module",
			reqs:   []requirement{{Path: "github.com/google/go-tpm"}},
			assert: hasViolation("go.mod", "github.com/google/go-tpm"),
		},
		{
			name:   "the Redis client is an integration module",
			reqs:   []requirement{{Path: "github.com/redis/go-redis/v9"}},
			assert: hasViolation("go.mod", "github.com/redis/go-redis/v9"),
		},
		{
			name:   "the Redis test container module is an integration module",
			reqs:   []requirement{{Path: "github.com/testcontainers/testcontainers-go/modules/redis"}},
			assert: hasViolation("go.mod", "github.com/testcontainers/testcontainers-go/modules/redis"),
		},
		{
			name:   "the gocron scheduler is an integration module",
			reqs:   []requirement{{Path: "github.com/go-co-op/gocron/v2"}},
			assert: hasViolation("go.mod", "github.com/go-co-op/gocron/v2"),
		},
		{
			name:   "the Fiber framework is an integration module",
			reqs:   []requirement{{Path: "github.com/gofiber/fiber/v3"}},
			assert: hasViolation("go.mod", "github.com/gofiber/fiber/v3"),
		},
		{
			name:   "the GORM ORM is an integration module",
			reqs:   []requirement{{Path: "gorm.io/gorm"}},
			assert: hasViolation("go.mod", "gorm.io/gorm"),
		},
		{
			name:   "the samber do container is an integration module",
			reqs:   []requirement{{Path: "github.com/samber/do/v2"}},
			assert: hasViolation("go.mod", "github.com/samber/do/v2"),
		},
		{
			name:   "the goose migrator is an integration module",
			reqs:   []requirement{{Path: "github.com/pressly/goose/v3"}},
			assert: hasViolation("go.mod", "github.com/pressly/goose/v3"),
		},
		{
			name:   "the PostgreSQL test container module is an integration module",
			reqs:   []requirement{{Path: "github.com/testcontainers/testcontainers-go/modules/postgres"}},
			assert: hasViolation("go.mod", "github.com/testcontainers/testcontainers-go/modules/postgres"),
		},
		{
			name:   "a major-version path of a listed driver is refused",
			reqs:   []requirement{{Path: "github.com/jackc/pgx/v5"}},
			assert: hasViolation("go.mod", "github.com/jackc/pgx/v5"),
		},
		{
			name: "an indirect requirement is left to the import walk",
			reqs: []requirement{{Path: "github.com/go-webauthn/webauthn", Indirect: true}},
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, requireViolations(tc.reqs))
		})
	}
}

func TestWebAuthnTypesStayInsideTheAdapter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		dir       string
		fixture   string
		forbidden string
		assert    func(t *testing.T, vs []violation)
	}

	const fixturePkg = "example.com/fixture/adapter"

	cases := []testCase{
		{
			name:      "the adapter module exposes no WebAuthn library type",
			dir:       "authenticate/passkey/webauthn",
			forbidden: "github.com/go-webauthn/",
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:      "control: every exported route to a library type is caught",
			fixture:   "testdata/layout/apileak",
			forbidden: "example.com/forbidden",
			assert: func(t *testing.T, vs []violation) {
				for _, name := range []string{"Leak", "Options", "Verifier", "Embedded", "Alias", "Default", "Hidden", "Generic", "Box", "Outer"} {
					hasViolation(fixturePkg, name+" exposes ")(t, vs)
				}
				for _, v := range vs {
					for _, name := range []string{"Source", "Wrapped", "Clean"} {
						assert.NotContains(t, v.What, name+" exposes ", "unexpected violation %v", v)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := tc.dir
			if tc.fixture != "" {
				dir = copyFixture(t, tc.fixture)
			}

			tc.assert(t, exportedAPIViolations(t, dir, tc.forbidden))
		})
	}
}

func TestSoftwareAuthenticatorStaysOutOfProduction(t *testing.T) {
	t.Parallel()

	const helper = "github.com/kartaladev/scrty/authenticate/passkey/webauthn/webauthntest"

	for _, dir := range []string{".", "authenticate/passkey/webauthn"} {
		for _, p := range listDeps(t, dir) {
			if p.ImportPath == helper {
				continue
			}
			assert.NotContains(t, p.Imports, helper, "%s imports the software authenticator in its production build", p.ImportPath)
		}
	}
}

func TestRedisClientStaysInItsModules(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		check  func(t *testing.T) []violation
		assert func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name: "no workspace module outside redisstore and test requires the client",
			check: func(t *testing.T) []violation {
				var vs []violation
				for _, dir := range workspaceModules(t, ".") {
					vs = append(vs, redisClientViolations(dir, readRequires(t, filepath.Join(dir, "go.mod")))...)
				}
				return vs
			},
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name: "control: an adapter module requiring the client indirectly is caught",
			check: func(*testing.T) []violation {
				return redisClientViolations("httpsec/ginsec", []requirement{{Path: "github.com/redis/go-redis/v9", Indirect: true}})
			},
			assert: hasViolation("httpsec/ginsec/go.mod", "github.com/redis/go-redis/v9"),
		},
		{
			name: "the redisstore and test modules may require the client",
			check: func(*testing.T) []violation {
				reqs := []requirement{{Path: "github.com/redis/go-redis/v9"}}
				return append(redisClientViolations("ratelimit/redisstore", reqs), redisClientViolations("test", reqs)...)
			},
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.check(t))
		})
	}
}

// underConcept asserts that the module at dir is used by the workspace, is
// published at the path its directory names, and declares package pkg.
func underConcept(dir, pkg string) func(t *testing.T, inWorkspace bool, path, name string) {
	return func(t *testing.T, inWorkspace bool, path, name string) {
		t.Helper()
		assert.True(t, inWorkspace, "go.work does not use %s", dir)
		assert.Equal(t, "github.com/kartaladev/scrty/"+dir, path, "module path of %s", dir)
		assert.Equal(t, pkg, name, "package clause of %s", dir)
	}
}

func TestIntegrationModulesUnderTheirConcept(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		dir    string
		assert func(t *testing.T, inWorkspace bool, path, name string)
	}

	cases := make([]testCase, 0, len(integrationTable))
	for _, m := range integrationTable {
		cases = append(cases, testCase{name: m.name, dir: m.dir, assert: underConcept(m.dir, m.pkg)})
	}

	modules := workspaceModules(t, ".")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, slices.Contains(modules, filepath.FromSlash(tc.dir)), modulePath(t, tc.dir), packageClause(t, tc.dir))
		})
	}
}

func TestNoUnlistedIntegrationModule(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		root   string
		assert func(t *testing.T, unlisted []string)
	}

	cases := []testCase{
		{
			name: "every workspace module is a listed integration, the core, test or tools",
			root: ".",
			assert: func(t *testing.T, unlisted []string) {
				assert.Empty(t, unlisted)
			},
		},
		{
			name: "control: a module outside the list is named by its directory",
			root: "testdata/layout/wsunlisted",
			assert: func(t *testing.T, unlisted []string) {
				assert.Equal(t, []string{"pgx"}, unlisted)
			},
		},
		{
			name: "control: a module no go.work lists is named by its directory",
			root: "testdata/layout/wsstray",
			assert: func(t *testing.T, unlisted []string) {
				assert.Equal(t, []string{"pgx"}, unlisted)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, unlistedModules(t, tc.root, integrationDirs))
		})
	}
}

func TestGoWorkListsEveryModule(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		root   string
		assert func(t *testing.T, found, listed []string)
	}

	cases := []testCase{
		{
			name: "go.work uses every module in the tree except tools",
			root: ".",
			assert: func(t *testing.T, found, listed []string) {
				assert.ElementsMatch(t, listed, slices.DeleteFunc(found, func(dir string) bool { return dir == "tools" }))
			},
		},
		{
			name: "control: a module in the tree but not in go.work is detected",
			root: "testdata/layout/wsstray",
			assert: func(t *testing.T, found, listed []string) {
				assert.Equal(t, []string{"."}, listed)
				assert.ElementsMatch(t, []string{".", "pgx"}, found)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, discoverModules(t, tc.root), workspaceModules(t, tc.root))
		})
	}
}

// TestWorkspaceModulesReadsSingleLineUse pins that workspaceModules reads both
// forms of the go.work use directive.
func TestWorkspaceModulesReadsSingleLineUse(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	work := "go 1.27\n\nuse ./a\n\nuse (\n\t./b\n)\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.work"), []byte(work), 0o600))
	for _, dir := range []string{"a", "b"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o750))
		mod := "module example.com/" + dir + "\n\ngo 1.27\n"
		require.NoError(t, os.WriteFile(filepath.Join(root, dir, "go.mod"), []byte(mod), 0o600))
	}

	assert.ElementsMatch(t, []string{"a", "b"}, workspaceModules(t, root))
}

// TestBackendDoesNotShadowDriver pins that each backend's package name differs
// from the name of the driver package it wraps. The names differ exactly when a
// file can import both without an import alias.
func TestBackendDoesNotShadowDriver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		dir    string
		driver string
	}

	cases := []testCase{
		{name: "pgxstore beside pgx", dir: "store/pgxstore", driver: "github.com/jackc/pgx/v5"},
		{name: "gormstore beside gorm", dir: "store/gormstore", driver: "gorm.io/gorm"},
		{name: "redisstore beside go-redis", dir: "ratelimit/redisstore", driver: "github.com/redis/go-redis/v9"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			driverName := strings.TrimSpace(goCmd(t, tc.dir, nil, "list", "-f", "{{.Name}}", tc.driver))
			clause := packageClause(t, tc.dir)
			require.NotEmpty(t, clause, "no package clause in %s", tc.dir)
			assert.NotEqual(t, driverName, clause)
		})
	}
}

func TestModulesDeclareGoMinimum(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		root   string
		assert func(t *testing.T, off map[string]string)
	}

	cases := []testCase{
		{
			name: "every module declares the minimum",
			root: ".",
			assert: func(t *testing.T, off map[string]string) {
				assert.Empty(t, off, "modules declaring another go version: %v", off)
			},
		},
		{
			name: "control: a module no go.work lists is named when it declares less",
			root: "testdata/layout/wsstray",
			assert: func(t *testing.T, off map[string]string) {
				assert.Equal(t, map[string]string{"pgx": "1.21"}, off)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, offGoMinimum(t, tc.root))
		})
	}
}

func TestParseModEdit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		out    string
		assert func(t *testing.T, mf modEdit, err error)
	}

	cases := []testCase{
		{
			name: "requirements and replaces are read",
			out: `{"Module":{"Path":"m"},"Require":[{"Path":"github.com/kartaladev/scrty","Version":"v0.0.0"},` +
				`{"Path":"example.com/x","Version":"v1.0.0","Indirect":true}],` +
				`"Replace":[{"Old":{"Path":"github.com/kartaladev/scrty"},"New":{"Path":"../../"}},` +
				`{"Old":{"Path":"a"},"New":{"Path":"b","Version":"v1.0.0"}}]}`,
			assert: func(t *testing.T, mf modEdit, err error) {
				require.NoError(t, err)
				assert.Equal(t, []scrtyRequirement{{Module: "d", Path: "github.com/kartaladev/scrty", Version: "v0.0.0"}}, readScrtyRequirements("d", mf))
				assert.Equal(t, []string{"../../"}, readReplaces(mf))
			},
		},
		{
			name: "an indirect scrty requirement is read",
			out:  `{"Require":[{"Path":"github.com/kartaladev/scrty/store/pgxstore","Version":"v0.0.0","Indirect":true}]}`,
			assert: func(t *testing.T, mf modEdit, err error) {
				require.NoError(t, err)
				assert.Equal(t, []scrtyRequirement{{Module: "d", Path: "github.com/kartaladev/scrty/store/pgxstore", Version: "v0.0.0", Indirect: true}}, readScrtyRequirements("d", mf))
			},
		},
		{
			name: "a module whose path only shares a prefix is not a scrty module",
			out:  `{"Require":[{"Path":"github.com/kartaladev/scrtyfoo","Version":"v0.0.0"}]}`,
			assert: func(t *testing.T, mf modEdit, err error) {
				require.NoError(t, err)
				assert.Empty(t, readScrtyRequirements("d", mf))
			},
		},
		{
			name: "empty output is an error, not an empty module",
			out:  "",
			assert: func(t *testing.T, _ modEdit, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "output that is not json is an error",
			out:  "go: errors parsing go.mod",
			assert: func(t *testing.T, _ modEdit, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "json of the wrong shape is an error",
			out:  `["Require"]`,
			assert: func(t *testing.T, _ modEdit, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mf, err := parseModEdit([]byte(tc.out))
			tc.assert(t, mf, err)
		})
	}
}

func TestNestedModulesRequireReleasedVersions(t *testing.T) {
	t.Parallel()

	const (
		root    = "github.com/kartaladev/scrty"
		sibling = "github.com/kartaladev/scrty/store/pgxstore"
		zeroPV  = "v0.0.0-00010101000000-000000000000"
	)

	type testCase struct {
		name     string
		reqs     []scrtyRequirement
		replaces map[string][]string
		want     string
		assert   func(t *testing.T, vs []violation)
	}

	clean := func(t *testing.T, vs []violation) {
		t.Helper()
		assert.Empty(t, vs)
	}

	cases := []testCase{
		{
			name:   "v0.0.0 direct is reported",
			reqs:   []scrtyRequirement{{Module: "store/pgxstore", Path: root, Version: "v0.0.0"}},
			assert: hasViolation("store/pgxstore", root+" v0.0.0"),
		},
		{
			name:   "the zero pseudo-version is reported",
			reqs:   []scrtyRequirement{{Module: "httpsec/ginsec", Path: root, Version: zeroPV}},
			assert: hasViolation("httpsec/ginsec", root+" "+zeroPV),
		},
		{
			name:   "an indirect v0.0.0 is reported",
			reqs:   []scrtyRequirement{{Module: "test", Path: sibling, Version: "v0.0.0", Indirect: true}},
			assert: hasViolation("test", "indirectly requires "+sibling+" v0.0.0"),
		},
		{
			name:   "v0.1.0 with no release version is clean",
			reqs:   []scrtyRequirement{{Module: "store/pgxstore", Path: root, Version: "v0.1.0"}},
			assert: clean,
		},
		{
			name:   "v0.1.0 against release version v0.1.0 is clean",
			reqs:   []scrtyRequirement{{Module: "store/pgxstore", Path: root, Version: "v0.1.0"}},
			want:   "v0.1.0",
			assert: clean,
		},
		{
			name:   "v0.1.0 against release version v0.2.0 is reported",
			reqs:   []scrtyRequirement{{Module: "store/pgxstore", Path: root, Version: "v0.1.0"}},
			want:   "v0.2.0",
			assert: hasViolation("store/pgxstore", root+" v0.1.0, not the release version v0.2.0"),
		},
		{
			name:   "an indirect requirement is held to the release version",
			reqs:   []scrtyRequirement{{Module: "test", Path: sibling, Version: "v0.1.0", Indirect: true}},
			want:   "v0.2.0",
			assert: hasViolation("test", sibling+" v0.1.0, not the release version v0.2.0"),
		},
		{
			name:     "a replace two levels up is clean",
			replaces: map[string][]string{"store/pgxstore": {"../../"}},
			assert:   clean,
		},
		{
			name:     "a sibling replace inside the repository is clean",
			replaces: map[string][]string{"test": {"../store/pgxstore"}},
			assert:   clean,
		},
		{
			name:     "an absolute replace target is reported",
			replaces: map[string][]string{"store/pgxstore": {"/tmp/x"}},
			assert:   hasViolation("store/pgxstore", "/tmp/x is an absolute path"),
		},
		{
			name:     "a replace climbing out of the repository is reported",
			replaces: map[string][]string{"store/pgxstore": {"../../../outside"}},
			assert:   hasViolation("store/pgxstore", "../../../outside climbs out of the repository"),
		},
		{
			name:     "a replace of a top-level module climbing one level is reported",
			replaces: map[string][]string{"test": {"../../x"}},
			assert:   hasViolation("test", "../../x climbs out of the repository"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, releaseRequirementViolations(tc.reqs, tc.replaces, tc.want))
		})
	}

	t.Run("every nested module in the real tree", func(t *testing.T) {
		t.Parallel()

		var reqs []scrtyRequirement
		replaces := map[string][]string{}
		for _, dir := range workspaceModules(t, ".") {
			if dir == "." {
				continue
			}
			mf := readModEdit(t, ".", dir)
			reqs = append(reqs, readScrtyRequirements(filepath.ToSlash(dir), mf)...)
			replaces[filepath.ToSlash(dir)] = readReplaces(mf)
		}
		require.NotEmpty(t, reqs, "no nested module requires a scrty module: the reader found nothing")

		assert.Empty(t, releaseRequirementViolations(reqs, replaces, os.Getenv("SCRTY_RELEASE_VERSION")))
	})
}

func TestParseReleaseModules(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		data   string
		assert func(t *testing.T, entries []releaseEntry, err error)
	}

	cases := []testCase{
		{
			name: "dir and package per line, blank lines ignored",
			data: "store/pgxstore github.com/kartaladev/scrty/store/pgxstore\n\ntest github.com/kartaladev/scrty/test/storetest\n",
			assert: func(t *testing.T, entries []releaseEntry, err error) {
				require.NoError(t, err)
				assert.Equal(t, []releaseEntry{
					{Dir: "store/pgxstore", Pkg: "github.com/kartaladev/scrty/store/pgxstore"},
					{Dir: "test", Pkg: "github.com/kartaladev/scrty/test/storetest"},
				}, entries)
			},
		},
		{
			name: "a line with one field is an error",
			data: "store/pgxstore\n",
			assert: func(t *testing.T, _ []releaseEntry, err error) {
				require.ErrorContains(t, err, "line 1")
			},
		},
		{
			name: "a line with three fields is an error",
			data: "a b c\n",
			assert: func(t *testing.T, _ []releaseEntry, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			entries, err := parseReleaseModules([]byte(tc.data))
			tc.assert(t, entries, err)
		})
	}
}

func TestReleaseModuleListsAgree(t *testing.T) {
	t.Parallel()

	workspace := []string{"httpsec/ginsec", "store/pgxstore", "test"}

	type testCase struct {
		name   string
		listed []string
		assert func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name:   "equal sets are clean",
			listed: []string{"test", "httpsec/ginsec", "store/pgxstore"},
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:   "a workspace module missing from the list is reported",
			listed: []string{"httpsec/ginsec", "store/pgxstore"},
			assert: hasViolation("release-modules.txt", "does not list test"),
		},
		{
			name:   "an extra entry is reported",
			listed: []string{"httpsec/ginsec", "store/pgxstore", "test", "store/gormstore"},
			assert: hasViolation("release-modules.txt", "lists store/gormstore, which go.work does not use"),
		},
		{
			name:   "tools is reported",
			listed: []string{"httpsec/ginsec", "store/pgxstore", "test", "tools"},
			assert: hasViolation("release-modules.txt", "lists tools, which is never released"),
		},
		{
			name:   "the root is reported",
			listed: []string{"httpsec/ginsec", "store/pgxstore", "test", "."},
			assert: hasViolation("release-modules.txt", "lists ., which is never released"),
		},
		{
			name:   "a duplicate entry is reported",
			listed: []string{"httpsec/ginsec", "store/pgxstore", "test", "test"},
			assert: hasViolation("release-modules.txt", "lists test more than once"),
		},
		{
			name:   "an empty list reports every module",
			listed: nil,
			assert: hasViolation("release-modules.txt", "does not list httpsec/ginsec"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, releaseListViolations(tc.listed, workspace))
		})
	}

	t.Run("release-modules.txt in the real tree", func(t *testing.T) {
		t.Parallel()

		data, err := os.ReadFile("release-modules.txt")
		require.NoError(t, err, "the release gate, the probe and the tag helper read this file")
		entries, err := parseReleaseModules(data)
		require.NoError(t, err)

		var nested []string
		for _, dir := range workspaceModules(t, ".") {
			if dir != "." {
				nested = append(nested, filepath.ToSlash(dir))
			}
		}
		listed := make([]string, 0, len(entries))
		for _, e := range entries {
			listed = append(listed, e.Dir)
		}
		assert.Empty(t, releaseListViolations(listed, nested))

		abs, err := filepath.Abs("go.work")
		require.NoError(t, err)
		for _, e := range entries {
			// The import path must name a package the workspace builds.
			out := goCmd(t, ".", []string{"GOWORK=" + abs}, "list", e.Pkg)
			assert.Equal(t, e.Pkg, strings.TrimSpace(out), "entry for %s", e.Dir)
		}
	})
}

func TestModulesDeclareGoFloor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		directives map[string]string
		assert     func(t *testing.T, vs []violation)
	}

	cases := []testCase{
		{
			name:       "1.27 and 1.27 patch releases are clean",
			directives: map[string]string{".": "1.27", "test": "1.27.3", "store/pgxstore": "1.27.0"},
			assert: func(t *testing.T, vs []violation) {
				assert.Empty(t, vs)
			},
		},
		{
			name:       "1.26 is reported",
			directives: map[string]string{".": "1.27", "expiry/sweep": "1.26"},
			assert:     hasViolation("expiry/sweep", `"1.26"`),
		},
		{
			name:       "1.28 is reported",
			directives: map[string]string{"test": "1.28"},
			assert:     hasViolation("test", `"1.28"`),
		},
		{
			name:       "1.270 is not a 1.27 patch release",
			directives: map[string]string{"test": "1.270"},
			assert:     hasViolation("test", `"1.270"`),
		},
		{
			name:       "a pre-release suffix is reported",
			directives: map[string]string{"test": "1.27rc1"},
			assert:     hasViolation("test", `"1.27rc1"`),
		},
		{
			name:       "an empty directive is reported",
			directives: map[string]string{"test": ""},
			assert:     hasViolation("test", `""`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, goFloorViolations(tc.directives))
		})
	}

	t.Run("every workspace module in the real tree", func(t *testing.T) {
		t.Parallel()

		directives := map[string]string{}
		for _, dir := range workspaceModules(t, ".") {
			directives[filepath.ToSlash(dir)] = goDirective(t, dir)
		}
		require.Greater(t, len(directives), 1)

		assert.Empty(t, goFloorViolations(directives))
	})
}
