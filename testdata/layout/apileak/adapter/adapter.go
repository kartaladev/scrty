// Package adapter leaks a forbidden library's types through its exported API in
// every way the guard must notice, and hides them in the ways it must allow.
package adapter

import "example.com/forbidden"

// Leak returns a library type.
func Leak() forbidden.Config { return forbidden.Config{} }

// Options exposes a library type through an exported field.
type Options struct {
	Public  *forbidden.Config
	private forbidden.Config //nolint:unused // fixture: an unexported field is not API
}

// Verifier exposes a library type through an exported method.
type Verifier struct{}

// Use takes a library type.
func (Verifier) Use(_ []forbidden.Config) {}

// Embedded promotes a library type through an embedded field.
type Embedded struct{ forbidden.Config }

// Alias names a library type.
type Alias = forbidden.Config

// Default is a variable of a library type.
var Default = map[string]forbidden.Config{}

type hidden struct{ Exposed forbidden.Config }

// Hidden returns an unexported type whose exported field is a library type.
func Hidden() hidden { return hidden{} } //nolint:revive // fixture: unexported return on purpose

// Source keeps the library type behind an unexported method.
type Source interface {
	provider() forbidden.Config
}

type wrapped struct{ cfg forbidden.Config }

// Wrapped returns an unexported type that keeps the library type unexported.
func Wrapped() *wrapped { return &wrapped{} } //nolint:revive // fixture: unexported return on purpose

func (w *wrapped) config() forbidden.Config { return w.cfg } //nolint:unused // fixture: not API

// Clean exposes nothing of the library.
func Clean() int { return 0 }

// Generic constrains a type parameter by an interface returning a library type.
func Generic[T interface{ Get() forbidden.Config }]() {}

// Box constrains its type parameter by an interface returning a library type.
type Box[T interface{ Get() forbidden.Config }] struct{}

type inner struct{ Exposed forbidden.Config }

// Outer promotes an exported library-typed field from an embedded unexported struct.
type Outer struct{ inner }
