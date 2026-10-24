package password

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// hostileScryptRecord builds a record whose salt and key are well formed, so the
// only thing a parser can object to is the cost parameters.
func hostileScryptRecord(n, r, p int) []byte {
	salt := make([]byte, 16)
	key := make([]byte, 32)

	return fmt.Appendf(nil, "scrypt$%d$%d$%d$%s$%s", n, r, p, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func TestParseScrypt_RefusesParallelismBeyondFootprintCeiling(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		record []byte
		assert func(t *testing.T, ok bool)
	}

	refused := func(t *testing.T, ok bool) {
		t.Helper()
		assert.False(t, ok, "the record's demand is above a ceiling, so no key may be derived for it")
	}

	read := func(t *testing.T, ok bool) {
		t.Helper()
		assert.True(t, ok, "a record at the ceiling is still read")
	}

	cases := []testCase{
		{
			name:   "parallelism of 2^30-1 multiplies the work and the footprint",
			record: hostileScryptRecord(32768, 8, 1073741823),
			assert: refused,
		},
		{
			name:   "parallelism just above the ceiling",
			record: hostileScryptRecord(32768, 8, 17),
			assert: refused,
		},
		{
			name:   "N and r whose working memory is above 1 GiB",
			record: hostileScryptRecord(1<<20, 8, 1),
			assert: refused,
		},
		{
			name:   "parallelism counts towards the working memory",
			record: hostileScryptRecord(1<<20-15, 8, 16),
			assert: refused,
		},
		{
			name:   "parallelism at the ceiling",
			record: hostileScryptRecord(32768, 8, 16),
			assert: read,
		},
		{
			name:   "working memory just under 1 GiB",
			record: hostileScryptRecord(1<<19, 15, 16),
			assert: read,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, _, _, _, ok := parseScrypt(tc.record)
			tc.assert(t, ok)
		})
	}
}
