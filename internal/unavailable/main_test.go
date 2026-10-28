package unavailable_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if any test leaves a goroutine behind. The
// decorator starts none of its own; this is what shows it.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
