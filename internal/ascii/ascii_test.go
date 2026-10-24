package ascii_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/ascii"
)

func TestEqualFold(t *testing.T) {
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

			tc.assert(t, ascii.EqualFold(tc.a, tc.b))
		})
	}
}

func TestTrimSpace(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) { t.Helper(); assert.Equal(t, want, got) }
	}

	cases := []testCase{
		{name: "nothing to trim", in: "write", assert: is("write")},
		{name: "surrounding ASCII space", in: " \t\r\nwrite\v\f ", assert: is("write")},
		{name: "inner space stays", in: " a b ", assert: is("a b")},
		{name: "no-break space stays", in: " write", assert: is(" write")},
		{name: "only space", in: "  ", assert: is("")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, ascii.TrimSpace(tc.in))
		})
	}
}

func TestCaseFold(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		fold func(string) string
		in   string
		want string
	}

	cases := []testCase{
		{name: "lower folds A-Z", fold: ascii.ToLower, in: "GeT /Path", want: "get /path"},
		{name: "lower keeps Kelvin sign", fold: ascii.ToLower, in: "Kİ", want: "Kİ"},
		{name: "lower keeps non-letters", fold: ascii.ToLower, in: "@[`{1", want: "@[`{1"},
		{name: "lower of empty", fold: ascii.ToLower, in: "", want: ""},
		{name: "lower keeps accented capital", fold: ascii.ToLower, in: "CAFÉ", want: "cafÉ"},
		{name: "upper folds a-z", fold: ascii.ToUpper, in: "get /Path", want: "GET /PATH"},
		{name: "upper keeps long s", fold: ascii.ToUpper, in: "ſ", want: "ſ"},
		{name: "upper keeps non-letters", fold: ascii.ToUpper, in: "@[`{1", want: "@[`{1"},
		{name: "upper keeps accented small", fold: ascii.ToUpper, in: "café", want: "CAFé"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, tc.fold(tc.in))
		})
	}
}
