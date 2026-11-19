//go:debug panicnil=1

package errwalk_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
)

type panicNilUnwrap struct{}

func (panicNilUnwrap) Error() string { return "panic nil unwrap" }
func (panicNilUnwrap) Unwrap() error { panic(nil) }

// TestFlatten_PanicNilAborts pins that panic(nil), which recover reports as
// nil under GODEBUG=panicnil=1, is still a panic abort.
func TestFlatten_PanicNilAborts(t *testing.T) {
	c, abort := errwalk.Flatten(panicNilUnwrap{})

	var pe *errwalk.PanicError
	require.ErrorAs(t, abort, &pe)
	assert.Nil(t, pe.Value)
	assert.Equal(t, "panic", errwalk.Reason(abort))
	assert.Nil(t, c)
}
