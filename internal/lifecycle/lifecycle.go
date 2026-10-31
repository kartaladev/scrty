// Package lifecycle holds the wait every component's Shutdown shares, so the
// rule it follows is written once and cannot drift between copies.
package lifecycle

import "context"

// Await waits for done to close, for no longer than ctx allows. It returns nil
// once done is closed, or ctx's error if ctx ends first.
//
// Completion wins a tie: when done is already closed, Await returns nil even
// if ctx is already done too. It checks done on its own before waiting, so the
// result does not depend on which ready case a select happens to pick.
func Await(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
