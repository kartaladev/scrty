package mfa_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/mfa"
)

func TestResponseFormat(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		format mfa.ResponseFormat
		assert func(t *testing.T, f mfa.ResponseFormat)
	}

	cases := []testCase{
		{
			name:   "a form field reports its kind, field and limit",
			format: mfa.FormField("code", 4096),
			assert: func(t *testing.T, f mfa.ResponseFormat) {
				assert.Equal(t, mfa.ResponseFormField, f.Kind())
				assert.Equal(t, "code", f.Field())
				assert.Equal(t, int64(4096), f.Limit())
			},
		},
		{
			name:   "a JSON body reports its kind and limit, and no field",
			format: mfa.JSONBody(16 << 10),
			assert: func(t *testing.T, f mfa.ResponseFormat) {
				assert.Equal(t, mfa.ResponseJSONBody, f.Kind())
				assert.Empty(t, f.Field())
				assert.Equal(t, int64(16384), f.Limit())
			},
		},
		{
			name:   "the zero format is neither kind",
			format: mfa.ResponseFormat{},
			assert: func(t *testing.T, f mfa.ResponseFormat) {
				assert.NotEqual(t, mfa.ResponseFormField, f.Kind())
				assert.NotEqual(t, mfa.ResponseJSONBody, f.Kind())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.format)
		})
	}
}
