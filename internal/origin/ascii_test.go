package origin_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/origin"
)

func TestEqualFoldASCII(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		a, b   string
		assert func(t *testing.T, equal bool)
	}

	equal := func(t *testing.T, got bool) { t.Helper(); assert.True(t, got) }
	different := func(t *testing.T, got bool) { t.Helper(); assert.False(t, got) }

	cases := []testCase{
		{name: "same case", a: "localhost", b: "localhost", assert: equal},
		{name: "ASCII case differs", a: "LocalHost", b: "lOCALhOST", assert: equal},
		{name: "both empty", a: "", b: "", assert: equal},
		{name: "different lengths", a: "ab", b: "abc", assert: different},
		{name: "different letters", a: "abc", b: "abd", assert: different},
		{name: "Kelvin sign is not k", a: "K", b: "k", assert: different},
		{name: "Kelvin sign inside a word", a: "marKet", b: "market", assert: different},
		{name: "long s is not s", a: "ſ", b: "s", assert: different},
		{name: "non-ASCII must match exactly", a: "café", b: "CAFÉ", assert: different},
		{name: "non-ASCII identical", a: "CAFé", b: "café", assert: equal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, origin.EqualFoldASCII(tc.a, tc.b))
		})
	}
}

func TestTrimSpaceASCII(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string)
	}

	cases := []testCase{
		{name: "nothing to trim", in: "write", assert: func(t *testing.T, got string) { assert.Equal(t, "write", got) }},
		{name: "surrounding ASCII space", in: " \t\r\nwrite\v\f ", assert: func(t *testing.T, got string) { assert.Equal(t, "write", got) }},
		{name: "inner space stays", in: " a b ", assert: func(t *testing.T, got string) { assert.Equal(t, "a b", got) }},
		{name: "no-break space stays", in: " write", assert: func(t *testing.T, got string) { assert.Equal(t, " write", got) }},
		{name: "only space", in: "  ", assert: func(t *testing.T, got string) { assert.Empty(t, got) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, origin.TrimSpaceASCII(tc.in))
		})
	}
}
