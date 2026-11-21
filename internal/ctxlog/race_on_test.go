//go:build race

package ctxlog_test

// raceEnabled reports whether the race detector instruments this test binary.
// The detector adds allocations of its own, so allocation counts are only
// pinned without it.
const raceEnabled = true
