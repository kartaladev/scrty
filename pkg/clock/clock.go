// Package clock is the time source every scrty component reads and waits on.
//
// A component that only reads the time takes a Clock; one that runs background
// loops takes a Timed, and waits between runs on its After, so advancing a
// controlled clock runs those loops without real waiting. Both default to
// System.
//
// The method signatures match github.com/jonboulle/clockwork's Clock exactly,
// so a clockwork fake or real clock, or any type of the consumer's with these
// methods, satisfies both interfaces with no adapter. scrty itself never
// imports clockwork outside its tests.
package clock

import "time"

// Clock is the time source of a component that only reads the time.
type Clock interface {
	Now() time.Time
}

// Timed is the time source of a component that also waits.
//
// After must deliver once Now has advanced by at least d, whether Now is the
// system time or a controlled one; a Timed whose After runs on real time while
// its Now is controlled would fire the component's loops at the wrong moments.
// clockwork's fake clock is a conforming implementation.
type Timed interface {
	Clock
	After(d time.Duration) <-chan time.Time
}

// System returns the clock backed by package time. It is every component's
// default.
func System() Timed { return system{} }

type system struct{}

func (system) Now() time.Time { return time.Now() }

func (system) After(d time.Duration) <-chan time.Time { return time.After(d) }
