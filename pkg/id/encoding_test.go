package id_test

import (
	"database/sql/driver"
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
			input: record{ID: vectorID},
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"id":"`+vector+`"}`, string(got))
			},
		},
		{
			name:  "non-zero optional is present",
			input: record{ID: vectorID, Optional: vectorID},
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
				assert.Equal(t, vectorID, got)
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

func TestID_Scan(t *testing.T) {
	t.Parallel()

	sentinel := id.ID{0: 0xff, 15: 0xff}

	type testCase struct {
		name   string
		src    any
		assert func(t *testing.T, got id.ID, err error)
	}

	rejected := func(t *testing.T, got id.ID, err error) {
		require.ErrorIs(t, err, id.ErrInvalid)
		assert.Equal(t, sentinel, got, "a failed scan leaves the value unchanged")
	}

	cases := []testCase{
		{
			name: "canonical string",
			src:  vector,
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vectorID, got)
			},
		},
		{
			name: "canonical text as bytes",
			src:  []byte(vector),
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vectorID, got)
			},
		},
		{
			name: "16-byte binary keeps byte order",
			src:  vectorID[:],
			assert: func(t *testing.T, got id.ID, err error) {
				require.NoError(t, err)
				assert.Equal(t, vectorID, got)
			},
		},
		{name: "SQL NULL", src: nil, assert: rejected},
		{name: "15-byte value", src: make([]byte, 15), assert: rejected},
		{name: "malformed string", src: "not-an-id", assert: rejected},
		{name: "unsupported type", src: int64(7), assert: rejected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sentinel
			err := got.Scan(tc.src)
			tc.assert(t, got, err)
		})
	}
}

func TestID_Value(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  id.ID
		assert func(t *testing.T, got driver.Value, err error)
	}

	cases := []testCase{
		{
			name:  "canonical text",
			value: vectorID,
			assert: func(t *testing.T, got driver.Value, err error) {
				require.NoError(t, err)
				assert.Equal(t, vector, got)
			},
		},
		{
			name:  "zero identifier is canonical zero text",
			value: id.Nil,
			assert: func(t *testing.T, got driver.Value, err error) {
				require.NoError(t, err)
				assert.Equal(t, "00000000-0000-0000-0000-000000000000", got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.value.Value()
			tc.assert(t, got, err)
		})
	}
}
