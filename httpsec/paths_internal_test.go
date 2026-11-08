package httpsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Internal, because checkEndpointPath is unexported; the New-level rows are in
// TestEndpointPathShape.
func TestCheckEndpointPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, err error)
	}

	accepted := func(t *testing.T, err error) {
		t.Helper()

		assert.NoError(t, err)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, ErrConfig)
		assert.ErrorContains(t, err, "TheSetting", "the error names the setting")
	}

	cases := []testCase{
		{name: "a clean absolute path", path: "/auth/sign-in", assert: accepted},
		{name: "every allowed character", path: "/Az09-._~/x", assert: accepted},
		{name: "one trailing slash", path: "/federation/callback/", assert: accepted},
		{name: "a single segment", path: "/a", assert: accepted},
		{name: "empty", path: "", assert: refused},
		{name: "relative", path: "signin", assert: refused},
		{name: "the root", path: "/", assert: refused},
		{name: "the root written twice", path: "//", assert: refused},
		{name: "the root written three times", path: "///", assert: refused},
		{name: "a dot segment", path: "/a/./b", assert: refused},
		{name: "a dot-dot segment", path: "/a/../b", assert: refused},
		{name: "a trailing dot-dot", path: "/a/..", assert: refused},
		{name: "a double slash", path: "/a//b", assert: refused},
		{name: "two trailing slashes", path: "/a//", assert: refused},
		{name: "a leading double slash", path: "//a", assert: refused},
		{name: "a space", path: "/a b", assert: refused},
		{name: "a percent escape", path: "/a%20b", assert: refused},
		{name: "a query", path: "/a?b", assert: refused},
		{name: "a fragment", path: "/a#b", assert: refused},
		{name: "a colon", path: "/a:b", assert: refused},
		{name: "an at sign", path: "/a@b", assert: refused},
		{name: "a plus", path: "/a+b", assert: refused},
		{name: "a comma", path: "/a,b", assert: refused},
		{name: "a semicolon", path: "/a;b", assert: refused},
		{name: "an equals sign", path: "/a=b", assert: refused},
		{name: "an exclamation mark", path: "/a!b", assert: refused},
		{name: "a wildcard", path: "/a/*", assert: refused},
		{name: "a backslash", path: `/a\b`, assert: refused},
		{name: "a non-ASCII letter", path: "/déconnexion", assert: refused},
		{name: "a newline", path: "/a\nb", assert: refused},
		{name: "a NUL byte", path: "/a\x00b", assert: refused},
		{name: "a tab", path: "/a\tb", assert: refused},
		{name: "a carriage return", path: "/a\rb", assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, checkEndpointPath("TheSetting", tc.path))
		})
	}
}
