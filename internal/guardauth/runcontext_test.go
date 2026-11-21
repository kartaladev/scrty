package guardauth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/guardauth"
)

// This package's tests do not import the chain's package, so nothing has
// installed a reader: RunContext answers nil rather than panicking, and the
// adapters fall back to the exchange's own context.
func TestRunContext_NothingInstalled(t *testing.T) {
	t.Parallel()

	assert.Nil(t, guardauth.RunContext(struct{}{}))
	assert.Nil(t, guardauth.RunContext(nil))
}

// A nil reader is a wiring mistake, refused where it is made rather than
// passing for "no run" on every request.
func TestSetRunContext_RefusesNil(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "guardauth: SetRunContext needs a function", func() {
		guardauth.SetRunContext(nil)
	})
}
