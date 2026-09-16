package logsample_test

import (
	"fmt"
	"time"

	"github.com/kartaladev/scrty/pkg/logsample"
)

func ExampleNew() {
	s := logsample.New(time.Minute, logsample.WithReporter(func(key string, suppressed int) {
		fmt.Printf("%s: %d suppressed\n", key, suppressed)
	}))

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for n := range 3 {
		write, _ := s.Allow("login-refused 203.0.113.7", start.Add(time.Duration(n)*time.Second))
		fmt.Println("write:", write)
	}
	s.Flush()
	// Output:
	// write: true
	// write: false
	// write: false
	// login-refused 203.0.113.7: 2 suppressed
}
