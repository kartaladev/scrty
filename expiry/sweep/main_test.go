package sweep_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain pins that a sweeper shut down by its test leaves nothing running:
// gocron starts a goroutine as soon as a scheduler is built, and Shutdown is
// what releases it, so any goroutine left when the suite ends is a leak.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
