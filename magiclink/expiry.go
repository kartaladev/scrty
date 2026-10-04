package magiclink

import (
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
)

// ExpiryTask returns the task that deletes m's expired magic-link tokens by
// purging the token manager m wraps, exactly as m.PurgeExpired does.
//
// The task is named "magiclink-tokens". It sets no Interval, because only the
// deployment knows its cadence, and it accepts no cutoff: the token manager
// derives its own from its issuance window. It never deletes a token still
// inside that window, expired or not, so a sweep cannot free issuance quota.
// A store that cannot purge yields an error matching
// expiry.ErrPurgeUnsupported.
func ExpiryTask(m *Manager) expiry.Task {
	return onetime.ExpiryTaskNamed("magiclink-tokens", m.tokens)
}
