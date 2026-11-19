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

	// The done-flag path captures the frames as a non-nil panic's does.
	functions := frameFunctions(pe.Frames)
	require.GreaterOrEqual(t, len(functions), 2, "frames: %v", functions)
	assert.Equal(t, "runtime.gopanic", functions[0])
	assert.Contains(t, functions[1], "errwalk_test.panicNilUnwrap.Unwrap")

	// A walk into a caller's buffer aborts the same way, with no chain.
	var buf [16]error

	into, intoAbort := errwalk.FlattenInto(buf[:], panicNilUnwrap{})
	require.ErrorAs(t, intoAbort, &pe)
	assert.Nil(t, pe.Value)
	assert.Equal(t, "panic", errwalk.Reason(intoAbort))
	assert.Nil(t, into)
}
