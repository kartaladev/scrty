package logsample

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSampler_MemoryStaysBounded(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s := New(time.Minute)
	for n := range 1_000_000 {
		s.Allow("k"+strconv.Itoa(n), base)
	}

	s.Allow("late", base.Add(3*time.Minute))

	s.mu.Lock()
	defer s.mu.Unlock()
	assert.LessOrEqual(t, len(s.current)+len(s.previous), 1)
}
