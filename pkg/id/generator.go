package id

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"
)

// Generator creates identifiers for library-owned records. Components accept a
// Generator option and use NewV7Generator when none is configured.
type Generator interface {
	NewID() (ID, error)
}

const (
	counterBits = 26
	seedBits    = 25
	counterMax  = 1<<counterBits - 1
	seedMask    = 1<<seedBits - 1
)

// V7Generator produces RFC 9562 version 7 identifiers.
type V7Generator struct {
	now    func() time.Time
	random io.Reader
}

// V7Option configures a V7Generator.
type V7Option func(*V7Generator)

// WithClock replaces the time source. Default: time.Now. A nil function keeps the default.
func WithClock(now func() time.Time) V7Option {
	return func(g *V7Generator) {
		if now != nil {
			g.now = now
		}
	}
}

// WithRandom replaces the random source. Default: crypto/rand.Reader. A nil reader keeps the default.
func WithRandom(r io.Reader) V7Option {
	return func(g *V7Generator) {
		if r != nil {
			g.random = r
		}
	}
}

// NewV7Generator returns the default generator.
func NewV7Generator(opts ...V7Option) *V7Generator {
	g := &V7Generator{now: time.Now, random: rand.Reader}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g
}

// NewID returns the next identifier.
func (g *V7Generator) NewID() (ID, error) {
	var rnd [10]byte
	_, _ = io.ReadFull(g.random, rnd[:])
	seed := binary.BigEndian.Uint32(rnd[0:4]) & seedMask
	return layout(g.now().UnixMilli(), seed, rnd[4:10]), nil
}

// layout places a 48-bit millisecond timestamp, the version, a 26-bit counter
// (12 bits in rand_a, 14 bits at the top of rand_b), the variant and 48 random bits.
func layout(ms int64, counter uint32, random []byte) ID {
	var i ID
	i[0] = byte(ms >> 40)
	i[1] = byte(ms >> 32)
	i[2] = byte(ms >> 24)
	i[3] = byte(ms >> 16)
	i[4] = byte(ms >> 8)
	i[5] = byte(ms)
	hi := uint16(counter >> 14)
	lo := uint16(counter & 0x3FFF)
	i[6] = 0x70 | byte(hi>>8)
	i[7] = byte(hi)
	i[8] = 0x80 | byte(lo>>8)
	i[9] = byte(lo)
	copy(i[10:], random)
	return i
}
