// Package app imports test tooling from a production file.
package app

import "github.com/jonboulle/clockwork"

var _ = clockwork.NewFakeClock()
