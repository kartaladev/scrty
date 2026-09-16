package scrty_test

import (
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
