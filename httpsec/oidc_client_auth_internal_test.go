package httpsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueryNamesCredential(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		raw    string
		assert func(t *testing.T, named bool)
	}

	names := func(raw string) testCase {
		return testCase{name: "names: " + raw, raw: raw, assert: func(t *testing.T, named bool) {
			t.Helper()
			assert.True(t, named)
		}}
	}
	passes := func(raw string) testCase {
		return testCase{name: "passes: " + raw, raw: raw, assert: func(t *testing.T, named bool) {
			t.Helper()
			assert.False(t, named)
		}}
	}

	cases := []testCase{
		names("client_secret=abc"),
		names("client_assertion=x"),
		names("client_assertion_type=x"),
		names("client_secret=%zz"),
		names("client_secret=abc;x=1"),
		names("client%5Fsecret=%zz"),
		names("client%5fsecret=abc"),
		names("a=1;client_secret=abc"),
		names("a=1&client_secret"),
		names("client_secret"),
		names("client_secret="),
		names("a=1&b=2&client_assertion=x"),
		names("%zz=1&client_secret=abc"),
		passes(""),
		passes("a=1"),
		passes("a=client_secret"),
		passes("a=1;b=client_assertion"),
		passes("client_id=web"),
		passes("client_secrets=abc"),
		passes("xclient_secret=abc"),
		passes("%zz=1"),
		passes("&&;;"),
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, queryNamesCredential(tc.raw))
		})
	}
}
