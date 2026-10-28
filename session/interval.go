package session

import "time"

// TouchInterval reports how stale recorded activity may be before Touch writes
// it again, which is what WithTouchInterval configured. Zero, the default,
// means every Touch writes.
func (m *Sessions) TouchInterval() time.Duration { return m.touchInterval }
