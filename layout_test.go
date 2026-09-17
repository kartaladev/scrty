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
