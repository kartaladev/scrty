package errwalk

import "testing"

// CountArms counts the deferred recovers armed until the test ends. The hook
// is process-wide, so a test that uses it must not run in parallel.
func CountArms(t *testing.T) *int {
	t.Helper()

	n := new(int)
	restore := SetArmHook(func() { *n++ })

	t.Cleanup(restore)

	return n
}
