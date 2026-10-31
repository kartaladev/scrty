package id_test

import (
	"database/sql/driver"
	"encoding/json"
	"strings"
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

var vectorID = id.MustParse(vector)

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

func FuzzParse(f *testing.F) {
	f.Add(vector)
	f.Add(strings.ToUpper(vector))
	f.Add("")
	f.Add("{" + vector + "}")
	f.Add(strings.ReplaceAll(vector, "-", ""))

	f.Fuzz(func(t *testing.T, s string) {
		got, err := id.Parse(s)
		if err != nil {
			require.ErrorIs(t, err, id.ErrInvalid)
			return
		}
		require.Equal(t, strings.ToLower(s), got.String())

		again, err := id.Parse(got.String())
		require.NoError(t, err)
		require.Equal(t, got, again)
	})
}
