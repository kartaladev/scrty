package scrty_test

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestBackendDoesNotShadowDriver builds, per backend, a consumer that imports
// the backend beside the driver it wraps, with no import alias. It compiles only
// while the backend's package name differs from its driver's. The build is
// read-only, so a fixture whose go.mod or go.sum has drifted fails instead of
// being rewritten.
func TestBackendDoesNotShadowDriver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		fixture string
	}

	cases := []testCase{
		{name: "pgxstore beside github.com/jackc/pgx/v5", fixture: "testdata/layout/noaliaspgx"},
		{name: "gormstore beside gorm.io/gorm", fixture: "testdata/layout/noaliasgorm"},
		{name: "redisstore beside github.com/redis/go-redis/v9", fixture: "testdata/layout/noaliasredis"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			goCmd(t, tc.fixture, []string{"GOFLAGS=-mod=readonly"}, "build", "./...")
		})
	}
}

func TestModulesDeclareGoMinimum(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		root   string
		assert func(t *testing.T, below []string)
	}

	cases := []testCase{
		{
			name: "every module declares the minimum",
			root: ".",
			assert: func(t *testing.T, below []string) {
				assert.Empty(t, below)
			},
		},
		{
			name: "control: a module no go.work lists is named when it declares less",
			root: "testdata/layout/wsstray",
			assert: func(t *testing.T, below []string) {
				assert.Equal(t, []string{"pgx"}, below)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, belowGoMinimum(t, tc.root))
		})
	}
}
