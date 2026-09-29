package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
)

// jsonDocument is a valid JSON document of exactly size bytes.
func jsonDocument(size int) string {
	const open, closing = `{"assertion":"`, `"}`

	return open + strings.Repeat("a", size-len(open)-len(closing)) + closing
}

// TestReadResponse pins the two library readers a method's response is read
// with: each reads the body only, requires the content type its format
// declares and bounds the body at the method's limit. What it cannot read is
// missing credentials, and what is too large is too large; the method never
// sees either.
func TestReadResponse(t *testing.T) {
	t.Parallel()

	const (
		form = "application/x-www-form-urlencoded"
		json = "application/json"
	)

	type testCase struct {
		name        string
		format      mfa.ResponseFormat
		target      string
		contentType string
		body        string
		assert      func(t *testing.T, response []byte, err error)
	}

	gives := func(want string) func(t *testing.T, response []byte, err error) {
		return func(t *testing.T, response []byte, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, []byte(want), response, "the method receives exactly these bytes")
		}
	}

	refusedAs := func(sentinel error) func(t *testing.T, response []byte, err error) {
		return func(t *testing.T, response []byte, err error) {
			t.Helper()

			require.ErrorIs(t, err, sentinel)
			assert.Empty(t, response, "nothing is handed on from a response that was refused")
		}
	}

	sixKiB := jsonDocument(6 << 10)
	longCode := strings.Repeat("7", 6<<10)

	cases := []testCase{
		{
			name:        "a form field",
			format:      mfa.FormField("code", 4<<10),
			contentType: form,
			body:        "code=123456",
			assert:      gives("123456"),
		},
		{
			name:        "a form field under a larger declared limit",
			format:      mfa.FormField("code", 16<<10),
			contentType: form,
			body:        "code=" + longCode,
			assert:      gives(longCode),
		},
		{
			name:        "a form field of the declared name only",
			format:      mfa.FormField("otp", 4<<10),
			contentType: form,
			body:        "code=123456",
			assert:      refusedAs(httpsec.ErrCredentialsMissing),
		},
		{
			name:        "a JSON document under its limit",
			format:      mfa.JSONBody(16 << 10),
			contentType: json,
			body:        sixKiB,
			assert:      gives(sixKiB),
		},
		{
			name:        "a structured-syntax JSON media type",
			format:      mfa.JSONBody(16 << 10),
			contentType: "application/vnd.x+json",
			body:        `{"a":1}`,
			assert:      gives(`{"a":1}`),
		},
		{
			name:        "a JSON media type with a charset",
			format:      mfa.JSONBody(16 << 10),
			contentType: json + "; charset=utf-8",
			body:        `{"a":1}`,
			assert:      gives(`{"a":1}`),
		},
		{
			name:        "a URL-encoded body to a JSON method",
			format:      mfa.JSONBody(16 << 10),
			contentType: form,
			body:        "code=123456",
			assert:      refusedAs(httpsec.ErrCredentialsMissing),
		},
		{
			name:   "a JSON body with no content type",
			format: mfa.JSONBody(16 << 10),
			body:   `{"a":1}`,
			assert: refusedAs(httpsec.ErrCredentialsMissing),
		},
		{
			name:        "an empty JSON body",
			format:      mfa.JSONBody(16 << 10),
			contentType: json,
			assert:      refusedAs(httpsec.ErrCredentialsMissing),
		},
		{
			name:        "invalid JSON",
			format:      mfa.JSONBody(16 << 10),
			contentType: json,
			body:        "{",
			assert:      refusedAs(httpsec.ErrCredentialsMissing),
		},
		{
			name:        "a JSON document in the query and none in the body",
			format:      mfa.JSONBody(16 << 10),
			target:      `/?response={"a":1}`,
			contentType: json,
			assert:      refusedAs(httpsec.ErrCredentialsMissing),
		},
		{
			name:        "a 5 KiB form to a 4 KiB field",
			format:      mfa.FormField("code", 4<<10),
			contentType: form,
			body:        "code=" + strings.Repeat("1", 5<<10),
			assert:      refusedAs(httpsec.ErrRequestTooLarge),
		},
		{
			name:        "a JSON body over its limit",
			format:      mfa.JSONBody(1 << 10),
			contentType: json,
			body:        jsonDocument(2 << 10),
			assert:      refusedAs(httpsec.ErrRequestTooLarge),
		},
		{
			name:        "a code only in the query",
			format:      mfa.FormField("code", 4<<10),
			target:      "/?code=123456",
			contentType: form,
			assert:      refusedAs(httpsec.ErrCredentialsMissing),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := tc.target
			if target == "" {
				target = "/"
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			response, err := httpsec.ReadResponse(httpsec.NewHTTPRequest(req), tc.format)
			tc.assert(t, response, err)
		})
	}
}
