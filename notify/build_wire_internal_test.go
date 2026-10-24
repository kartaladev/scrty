package notify

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBuild_WireCarriesNoBareCarriageReturn pins what reaches DATA: whatever
// mix of CR, LF and CRLF a body holds, every line ends in CRLF and no CR stands
// alone. A bare CR is dangerous because some servers treat it as a line end,
// so a body like "\r.\r" can smuggle the end-of-data marker or a command.
func TestBuild_WireCarriesNoBareCarriageReturn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		body   string
		assert func(t *testing.T, body string)
	}

	cases := []testCase{
		{
			name: "a bare carriage return becomes CRLF",
			body: "hello\r.\r\nMAIL FROM",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "hello\r\n.\r\nMAIL FROM", body)
			},
		},
		{
			name: "a bare line feed becomes CRLF",
			body: "one\ntwo",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "one\r\ntwo", body)
			},
		},
		{
			name: "a CRLF stays one CRLF",
			body: "one\r\ntwo",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "one\r\ntwo", body)
			},
		},
		{
			name: "all three mixed",
			body: "a\rb\nc\r\nd\r\r\ne",
			assert: func(t *testing.T, body string) {
				assert.Equal(t, "a\r\nb\r\nc\r\nd\r\n\r\ne", body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wire := string(build("noreply@example.com", Message{To: "a@example.com", Subject: "s", TextBody: tc.body}))
			_, body, found := strings.Cut(wire, "\r\n\r\n")

			assert.True(t, found, "the header block ends in a blank line")
			assert.NotRegexp(t, "\r[^\n]|\r$", wire, "a carriage return stands alone")
			tc.assert(t, body)
		})
	}
}
