package id

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Layout reproduces the RFC 9562 Appendix A.6 vector from its fields. The 26-bit
// counter is rand_a (12 bits) followed by the top 14 bits of rand_b.
func TestLayout_RFC9562Vector(t *testing.T) {
	t.Parallel()

	tail, err := hex.DecodeString("dc0c0c07398f")
	require.NoError(t, err)

	got := layout(0x017F22E279B0, 0xCC3<<14|0x18C4, tail)

	assert.Equal(t, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f", got.String())
}
