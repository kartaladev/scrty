package notify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/notify"
)

func TestNotifySentinels(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		notify.ErrUnsafeHeaderValue,
		notify.ErrQueueFull,
		notify.ErrSenderClosed,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}

			assert.NotErrorIs(t, a, b, "sentinels must be distinguishable")
		}
	}

	for _, err := range sentinels {
		assert.NotContains(t, err.Error(), "scrty: ", "each names its own package")
		assert.Contains(t, err.Error(), "notify: ")
	}
}
