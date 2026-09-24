package notify

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNormalizeCRLF pins the function itself rather than the delivered
// message.
//
// The end-to-end encoding table cannot tell normalizeCRLF apart from doing
// nothing, because net/textproto's dot-writer converts a bare LF to CRLF on
// its way out as well. What build produces has to be a correct RFC 5322
// message whatever writes it, so the normalisation is asserted here.
func TestNormalizeCRLF(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string)
	}

	cases := []testCase{
		{
			name: "a bare line feed becomes a CRLF pair",
			in:   "line one\nline two",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "line one\r\nline two", got)
			},
		},
		{
			name: "an existing CRLF pair is not doubled",
			in:   "line one\r\nline two",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "line one\r\nline two", got)
			},
		},
		{
			name: "a body mixing both ends up consistent",
			in:   "one\r\ntwo\nthree",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "one\r\ntwo\r\nthree", got)
			},
		},
		{
			name: "a body with no line break is untouched",
			in:   "here is your link",
			assert: func(t *testing.T, got string) {
				assert.Equal(t, "here is your link", got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, normalizeCRLF(tc.in))
		})
	}
}
