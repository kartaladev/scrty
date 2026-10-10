package pgschema_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/pgschema"
)

func TestLimiterKey(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 513)
	type testCase struct {
		name   string
		in     string
		assert func(t *testing.T, got string)
	}
	cases := []testCase{
		{
			name: "short key stored as given", in: "203.0.113.7",
			assert: func(t *testing.T, got string) { assert.Equal(t, "203.0.113.7", got) },
		},
		{
			name: "512 bytes stored as given", in: strings.Repeat("a", 512),
			assert: func(t *testing.T, got string) { assert.Len(t, got, 512) },
		},
		{
			name: "513 bytes stored as digest", in: long,
			assert: func(t *testing.T, got string) {
				sum := sha256.Sum256([]byte(long))
				assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), got)
			},
		},
		{
			name: "digest-shaped key is hashed too", in: "sha256:abc",
			assert: func(t *testing.T, got string) {
				sum := sha256.Sum256([]byte("sha256:abc"))
				assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), got)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, pgschema.LimiterKey(tc.in))
		})
	}
}
