package httpsec

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/session"
)

// TestSessionCookie_MaxAgeOf pins the Max-Age a persistent sign-in's cookie is
// set with, at the edges of what it can hold: rounded up, at least 1, and
// capped at math.MaxInt32 for a deadline too far away to count in seconds
// without overflowing.
func TestSessionCookie_MaxAgeOf(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	type testCase struct {
		name       string
		persistent bool
		deadline   time.Time
		assert     func(t *testing.T, maxAge int)
	}

	equal := func(want int) func(*testing.T, int) {
		return func(t *testing.T, got int) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	cases := []testCase{
		{name: "twelve hours", persistent: true, deadline: now.Add(12 * time.Hour), assert: equal(43200)},
		{name: "rounded up", persistent: true, deadline: now.Add(1500 * time.Millisecond), assert: equal(2)},
		{name: "close to the deadline is one", persistent: true, deadline: now.Add(400 * time.Millisecond), assert: equal(1)},
		{name: "past the deadline is one", persistent: true, deadline: now.Add(-time.Hour), assert: equal(1)},
		{name: "not persistent is none", deadline: now.Add(time.Hour), assert: equal(0)},
		{name: "300 years away is the cap", persistent: true, deadline: now.AddDate(300, 0, 0), assert: equal(math.MaxInt32)},
		{
			name: "just past the cap is the cap", persistent: true,
			deadline: now.Add((time.Duration(math.MaxInt32) + 1) * time.Second), assert: equal(math.MaxInt32),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &sessionCookie{}
			s.ref.now = func() time.Time { return now }

			tc.assert(t, s.maxAgeOf(&session.Session{PersistentCookie: tc.persistent, AbsoluteExpiresAt: tc.deadline}))
		})
	}
}
