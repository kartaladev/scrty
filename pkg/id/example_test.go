package id_test

import (
	"fmt"

	"github.com/kartaladev/scrty/pkg/id"
)

// The default generator uses clock.System() and crypto/rand.Reader; WithClock
// and WithRandom replace them. Identifiers are not secrets.
func ExampleNewV7Generator() {
	ids := id.NewV7Generator()

	first, _ := ids.NewID()
	second, _ := ids.NewID()

	fmt.Println(first.String() < second.String())
	fmt.Println(len(first.String()))
	// Output:
	// true
	// 36
}
