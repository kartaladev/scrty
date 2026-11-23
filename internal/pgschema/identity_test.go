package pgschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTextArray(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		values []string
		assert func(t *testing.T, got string)
	}

	cases := []testCase{
		{
			name: "no values is the empty array",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "{}", got)
			},
		},
		{
			name:   "every element is quoted, so commas, braces and spaces stay inside it",
			values: []string{"a,b", "{c}", " d "},
			assert: func(t *testing.T, got string) {
				assert.Equal(t, `{"a,b","{c}"," d "}`, got)
			},
		},
		{
			name:   "quotes and backslashes are escaped",
			values: []string{`say "hi"`, `back\slash`},
			assert: func(t *testing.T, got string) {
				assert.Equal(t, `{"say \"hi\"","back\\slash"}`, got)
			},
		},
		{
			name:   "an element spelled NULL stays text, not a NULL",
			values: []string{"NULL", ""},
			assert: func(t *testing.T, got string) {
				assert.Equal(t, `{"NULL",""}`, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, TextArray(tc.values))
		})
	}
}
