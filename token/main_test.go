package token_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain pins that issuing and verifying start nothing in the background.
// This package holds no loop of its own — the key source owns rotation and
// reload — so any goroutine still running when the suite ends is a leak.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
