package must_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/must"
)

var errBoom = errors.New("boom")

func TestMust(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		err    error
		assert func(*testing.T, func() string)
	}{
		{
			name:  "value passes through",
			value: "ready",
			assert: func(t *testing.T, call func() string) {
				t.Helper()

				assert.Equal(t, "ready", call())
			},
		},
		{
			name:  "error panics with that error",
			value: "ignored",
			err:   errBoom,
			assert: func(t *testing.T, call func() string) {
				t.Helper()

				assert.PanicsWithValue(t, errBoom, func() { call() })
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, func() string { return must.Must(tc.value, tc.err) })
		})
	}
}
