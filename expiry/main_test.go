package expiry_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package when any test leaves a goroutine running, which
// pins that a run starts none of its own: not to enforce a timeout, and not to
// run a task.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
