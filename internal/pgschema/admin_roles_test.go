package pgschema_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
)

func TestParseLabels(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		raw    string
		assert func(t *testing.T, got []string, err error)
	}

	cases := []testCase{
		{
			name: "labels keep their order and text",
			raw:  `["Partner","a \"quoted\", label","{}"]`,
			assert: func(t *testing.T, got []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Partner", `a "quoted", label`, "{}"}, got)
			},
		},
		{
			name: "an empty array is no labels",
			raw:  `[]`,
			assert: func(t *testing.T, got []string, err error) {
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			name: "null is no labels",
			raw:  `null`,
			assert: func(t *testing.T, got []string, err error) {
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			name: "text that is not a JSON array fails",
			raw:  `{a,b}`,
			assert: func(t *testing.T, got []string, err error) {
				require.Error(t, err)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := pgschema.ParseLabels(tc.raw)
			tc.assert(t, got, err)
		})
	}
}
