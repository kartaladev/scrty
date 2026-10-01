// Package forbidden is a stand-in for a library whose types must stay out of
// an adapter's exported API. It is used only by guard fixtures.
package forbidden

// Config is a stand-in library type.
type Config struct{ Name string }
