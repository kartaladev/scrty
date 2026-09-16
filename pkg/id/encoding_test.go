package id_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

type record struct {
	ID       id.ID `json:"id"`
	Optional id.ID `json:"optional,omitzero"`
}

func TestID_MarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		input  record
		assert func(t *testing.T, got []byte, err error)
	}

	cases := []testCase{
		{
			name:  "identifier encodes as a JSON string and a zero optional is omitted",
			input: record{ID: id.MustParse(vector)},
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"id":"`+vector+`"}`, string(got))
			},
		},
		{
			name:  "non-zero optional is present",
			input: record{ID: id.MustParse(vector), Optional: id.MustParse(vector)},
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"id":"`+vector+`","optional":"`+vector+`"}`, string(got))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.input)
			tc.assert(t, got, err)
		})
	}
}

func TestID_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		input  string
		assert func(t *testing.T, got id.ID, err error)
	}

	cases := []testCase{
		{
			name:  "JSON string",
			input: `"` + vector + `"`,
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, id.MustParse(vector), got)
			},
		},
		{
			name:  "JSON number",
			input: `42`,
			assert: func(t *testing.T, _ id.ID, err error) {
				require.ErrorIs(t, err, id.ErrInvalid)
			},
		},
		{
			name:  "empty JSON string",
			input: `""`,
			assert: func(t *testing.T, _ id.ID, err error) {
				require.ErrorIs(t, err, id.ErrInvalid)
			},
		},
		{
			name:  "JSON null into a non-pointer identifier",
			input: `null`,
			assert: func(t *testing.T, _ id.ID, err error) {
				require.ErrorIs(t, err, id.ErrInvalid)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got id.ID
			err := json.Unmarshal([]byte(tc.input), &got)
			tc.assert(t, got, err)
		})
	}
}
