package id

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// Generator creates identifiers for library-owned records. Components accept a
// Generator option and use NewV7Generator when none is configured.
type Generator interface {
	NewID() (ID, error)
}

const (
	counterBits    = 26
	counterLowBits = 14 // the counter bits carried at the top of rand_b
	counterLowMask = 1<<counterLowBits - 1
	seedBits       = 25
	counterMax     = 1<<counterBits - 1
	seedMask       = 1<<seedBits - 1
)

// V7Generator produces RFC 9562 version 7 identifiers that strictly increase.
// It is safe for concurrent use.
type V7Generator struct {
	mu      sync.Mutex
	now     func() time.Time
	random  io.Reader
	lastMS  int64
	counter uint32
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

// NewID returns the next identifier. It is safe for concurrent use.
//
// In a new millisecond the 26-bit counter is re-seeded with 25 random bits. In the
// same millisecond, or when the clock moved backwards, the last timestamp is kept
// and the counter increments. On overflow the timestamp advances by 1 ms. When the
// random source fails, NewID returns an error wrapping it and no identifier.
func (g *V7Generator) NewID() (ID, error) {
	var rnd [10]byte
	if _, err := io.ReadFull(g.random, rnd[:]); err != nil {
		return Nil, fmt.Errorf("id: read random source: %w", err)
	}
	seed := binary.BigEndian.Uint32(rnd[0:4]) & seedMask

	g.mu.Lock()
	ms := g.now().UnixMilli()
	switch {
	case ms > g.lastMS:
		g.lastMS = ms
		g.counter = seed
	case g.counter < counterMax:
		g.counter++
	default:
		g.lastMS++
		g.counter = seed
	}
	ts, ctr := g.lastMS, g.counter
	g.mu.Unlock()

	return layout(ts, ctr, rnd[4:10]), nil
}

// layout places a 48-bit millisecond timestamp, the version, a 26-bit counter
// (12 bits in rand_a, 14 bits at the top of rand_b), the variant and 48 random bits.
func layout(ms int64, counter uint32, random []byte) ID {
	var i ID
	if ms < 0 {
		// Before 1970 there is no version 7 layout to write: the timestamp field is
		// unsigned. Clamp rather than wrap a negative clock into the far future.
		ms = 0
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(ms))
	copy(i[:6], ts[2:])
	// counter is 26 bits, so each half fits its uint16 by construction.
	binary.BigEndian.PutUint16(i[6:8], 0x7000|uint16(counter>>counterLowBits)) //nolint:gosec // 12 bits
	binary.BigEndian.PutUint16(i[8:10], 0x8000|uint16(counter&counterLowMask)) //nolint:gosec // 14 bits
	copy(i[10:], random)
	return i
}
