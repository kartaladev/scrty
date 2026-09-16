package id

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"testing"
	"time"

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

// Overflow is forced by setting the counter directly: a seed never starts within
// 2^25 of the limit, so reaching it through NewID would take 33 million calls.
func TestV7Generator_CounterOverflowBorrowsNextMillisecond(t *testing.T) {
	t.Parallel()

	at := time.UnixMilli(1_700_000_000_000)
	g := NewV7Generator(WithClock(func() time.Time { return at }), WithRandom(rand.NewChaCha8([32]byte{7})))

	first, err := g.NewID()
	require.NoError(t, err)
	g.mu.Lock()
	g.counter = counterMax
	g.mu.Unlock()

	next, err := g.NewID()
	require.NoError(t, err)

	var ms [8]byte
	copy(ms[2:], next[:6])
	assert.Equal(t, at.UnixMilli()+1, int64(binary.BigEndian.Uint64(ms[:])))
	assert.Positive(t, bytes.Compare(next[:], first[:]))
}
