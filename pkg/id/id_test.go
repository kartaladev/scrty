package id_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

func TestID_IsZero(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  id.ID
		assert func(t *testing.T, zero bool)
	}

	cases := []testCase{
		{
			name:   "unassigned value",
			value:  id.ID{},
			assert: func(t *testing.T, zero bool) { assert.True(t, zero) },
		},
		{
			name:   "Nil",
			value:  id.Nil,
			assert: func(t *testing.T, zero bool) { assert.True(t, zero) },
		},
		{
			name:   "any non-zero byte",
			value:  id.ID{15: 1},
			assert: func(t *testing.T, zero bool) { assert.False(t, zero) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.value.IsZero())
		})
	}
}

const vector = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" // RFC 9562 Appendix A.6

func TestParse(t *testing.T) {
	t.Parallel()

	sample := id.ID{0: 0xde, 7: 0x42, 15: 0xad}

	type testCase struct {
		name   string
		input  string
		assert func(t *testing.T, got id.ID, err error)
	}

	invalid := func(t *testing.T, got id.ID, err error) {
		require.ErrorIs(t, err, id.ErrInvalid)
		assert.Contains(t, err.Error(), "invalid identifier")
		assert.Equal(t, id.Nil, got)
	}

	cases := []testCase{
		{
			name:  "canonical vector",
			input: vector,
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vector, got.String())
			},
		},
		{
			name:  "uppercase input formats lowercase",
			input: strings.ToUpper(vector),
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vector, got.String())
			},
		},
		{
			name:  "formatted identifier round trips",
			input: sample.String(),
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, sample, got)
			},
		},
		{
			name:  "version 4 identifier parses unchanged",
			input: "9b2f8c1e-4a5d-4c3b-8e2f-1a2b3c4d5e6f",
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, "9b2f8c1e-4a5d-4c3b-8e2f-1a2b3c4d5e6f", got.String())
			},
		},
		{name: "empty string", input: "", assert: invalid},
		{name: "braces", input: "{" + vector + "}", assert: invalid},
		{name: "urn prefix", input: "urn:uuid:" + vector, assert: invalid},
		{name: "no hyphens", input: strings.ReplaceAll(vector, "-", ""), assert: invalid},
		{name: "non-hex character", input: vector[:35] + "g", assert: invalid},
		{name: "hyphen in the wrong place", input: vector[:7] + "-" + vector[8:], assert: invalid},
		{
			name:  "long input is not echoed in full",
			input: strings.Repeat("a", 10_000),
			assert: func(t *testing.T, got id.ID, err error) {
				invalid(t, got, err)
				assert.Less(t, len(err.Error()), 200)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := id.Parse(tc.input)
			tc.assert(t, got, err)
		})
	}
}
