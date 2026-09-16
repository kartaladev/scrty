package id_test

import (
	"fmt"

	"github.com/kartaladev/scrty/pkg/id"
)

// The default generator uses time.Now and crypto/rand.Reader; WithClock and
// WithRandom replace them. Identifiers are not secrets.
func ExampleNewV7Generator() {
	gen := id.NewV7Generator()

	first, _ := gen.NewID()
	second, _ := gen.NewID()

	fmt.Println(first.String() < second.String())
	fmt.Println(len(first.String()))
	// Output:
	// true
	// 36
}
