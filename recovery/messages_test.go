package recovery_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/recovery"
)

func TestDefaultMessages_HoldNotices(t *testing.T) {
	t.Parallel()

	const (
		link      = "https://app.example.com/recovery/cancel?cancel_token=tok.secret"
		voidedMsg = "saved recovery codes"
	)

	until := monday1000.Add(72 * time.Hour)
	held := func(n recovery.Notice) (string, string) { return recovery.DefaultMessages().Held(n, link, until) }
	cancelled := func(n recovery.Notice) (string, string) { return recovery.DefaultMessages().Cancelled(n) }

	type testCase struct {
		name   string
		build  func(n recovery.Notice) (string, string)
		notice recovery.Notice
		assert func(t *testing.T, subject, body string)
	}

	cases := []testCase{
		{
			name:   "a held notice for a voided set says the saved codes no longer work",
			build:  held,
			notice: recovery.Notice{At: monday1000, CodesVoided: true, Repudiation: repudiation},
			assert: func(t *testing.T, _, body string) {
				assert.Contains(t, body, voidedMsg)
				assert.Contains(t, body, "no longer work")
				assert.Contains(t, body, link)
			},
		},
		{
			name:   "a held notice with the set untouched says nothing of saved codes",
			build:  held,
			notice: recovery.Notice{At: monday1000, Repudiation: repudiation},
			assert: func(t *testing.T, _, body string) {
				assert.NotContains(t, body, voidedMsg)
			},
		},
		{
			name:   "a cancelled notice for a voided set says the old codes no longer work",
			build:  cancelled,
			notice: recovery.Notice{At: monday1000, CodesVoided: true, Repudiation: repudiation},
			assert: func(t *testing.T, _, body string) {
				assert.Contains(t, body, voidedMsg)
				assert.Contains(t, body, "no longer work")
				assert.Contains(t, body, "generate a new set")
			},
		},
		{
			name:   "a cancelled notice with the set untouched says nothing of saved codes",
			build:  cancelled,
			notice: recovery.Notice{At: monday1000, Repudiation: repudiation},
			assert: func(t *testing.T, _, body string) {
				assert.NotContains(t, body, voidedMsg)
				assert.Contains(t, body, "Nothing was removed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			subject, body := tc.build(tc.notice)

			assert.NotEmpty(t, subject)
			assert.Contains(t, body, repudiation)
			assert.Contains(t, body, "28 September 2026 10:00 UTC")
			assert.NotContains(t, strings.ToLower(body+subject), "scrty", "no brand is named")
			tc.assert(t, subject, body)
		})
	}
}

// TestDefaultMessages_RecoveredNotice pins that the default Recovered notice's
// body says the saved codes were replaced exactly when Notice.CodesReplaced is
// true, and says nothing about them otherwise.
func TestDefaultMessages_RecoveredNotice(t *testing.T) {
	t.Parallel()

	const replacedMsg = "saved recovery codes were replaced"

	type testCase struct {
		name   string
		notice recovery.Notice
		assert func(t *testing.T, body string)
	}

	cases := []testCase{
		{
			name:   "codes replaced says so, and that the previous codes no longer work",
			notice: recovery.Notice{At: monday1000, CodesReplaced: true, Repudiation: repudiation},
			assert: func(t *testing.T, body string) {
				assert.Contains(t, body, replacedMsg)
				assert.Contains(t, body, "previous codes no longer work")
			},
		},
		{
			name:   "codes not replaced says nothing about them",
			notice: recovery.Notice{At: monday1000, Repudiation: repudiation},
			assert: func(t *testing.T, body string) {
				assert.NotContains(t, body, replacedMsg)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			subject, body := recovery.DefaultMessages().Recovered(tc.notice)

			assert.NotEmpty(t, subject)
			assert.Contains(t, body, repudiation)
			assert.Contains(t, body, "28 September 2026 10:00 UTC")
			tc.assert(t, body)
		})
	}
}
