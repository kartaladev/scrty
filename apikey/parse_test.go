package apikey_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
)

// TestManagerParsePresented pins that a key whose shape is wrong costs one
// string comparison rather than a store query. A scanner firing malformed
// strings at an endpoint must not be able to turn that endpoint into load on
// the database behind it.
func TestManagerParsePresented(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		presented func(valid string) string
	}

	cases := []testCase{
		{name: "empty", presented: func(string) string { return "" }},
		{name: "no prefix", presented: func(v string) string { return strings.TrimPrefix(v, "sk_") }},
		{name: "wrong prefix", presented: func(v string) string { return "acme_" + strings.TrimPrefix(v, "sk_") }},
		{name: "prefix only", presented: func(string) string { return "sk_" }},
		{name: "no dot", presented: func(v string) string { return strings.ReplaceAll(v, ".", "") }},
		{name: "unparsable id", presented: func(string) string { return "sk_not-an-id.c2VjcmV0" }},
		{name: "empty secret", presented: func(v string) string { return v[:strings.Index(v, ".")+1] }},
		{name: "prefix of the prefix", presented: func(v string) string { return "s_" + strings.TrimPrefix(v, "sk_") }},
		{
			name: "a secret that is not base64url",
			presented: func(v string) string {
				return v[:strings.Index(v, ".")+1] + "not a secret!!"
			},
		},
		{
			name:      "the separator is the underscore, not a bare prefix",
			presented: func(v string) string { return "sk" + strings.TrimPrefix(v, "sk_") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			store := &countingKeyStore{Store: apikey.NewMemoryStore()}

			m, err := apikey.NewManager(apikey.WithStore(store))
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			before := store.Reads()

			_, _, verifyErr := m.Verify(ctx, tc.presented(valid))
			assert.ErrorIs(t, verifyErr, apikey.ErrVerificationFailed)
			assert.Equal(t, before, store.Reads(), "a malformed key must not reach the store")
		})
	}
}
