package passkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/passkey"
)

func TestManager_LogInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		assert func(t *testing.T, d time.Duration)
	}

	cases := []testCase{
		{
			name: "defaults to one minute",
			assert: func(t *testing.T, d time.Duration) {
				assert.Equal(t, time.Minute, d)
			},
		},
		{
			name: "reports the interval WithLogInterval set",
			opts: []passkey.Option{passkey.WithLogInterval(5 * time.Second)},
			assert: func(t *testing.T, d time.Duration) {
				assert.Equal(t, 5*time.Second, d)
			},
		},
		{
			name: "reports an interval that writes every record",
			opts: []passkey.Option{passkey.WithLogInterval(-1)},
			assert: func(t *testing.T, d time.Duration) {
				assert.Equal(t, time.Duration(-1), d)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := newFixture(t).manager(t, tc.opts...)
			tc.assert(t, m.LogInterval())
		})
	}
}
