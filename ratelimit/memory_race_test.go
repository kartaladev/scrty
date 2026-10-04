//go:build race

package ratelimit_test

// raceEnabled reports that the race detector is on. Its instrumentation slows
// concurrent sweeps far more than the single-threaded reference they are judged
// against, so a latency ratio measured under it says nothing about the limiter.
const raceEnabled = true
