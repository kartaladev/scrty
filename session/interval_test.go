package session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

func TestManagerTouchInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.ManagerOption
		assert func(t *testing.T, got time.Duration)
	}

	cases := []testCase{
		{
			name:   "default is zero, every touch writes",
			assert: func(t *testing.T, got time.Duration) { assert.Zero(t, got) },
		},
		{
			name:   "reports what WithTouchInterval configured",
			opts:   []session.ManagerOption{session.WithTouchInterval(time.Minute)},
			assert: func(t *testing.T, got time.Duration) { assert.Equal(t, time.Minute, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.NewManager(append([]session.ManagerOption{session.WithStore(session.NewMemoryStore())}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, m.TouchInterval())
		})
	}
}
