package id_test

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

var t0 = time.Date(2022, 2, 22, 19, 22, 22, 0, time.UTC)

func frozen(at time.Time) func() time.Time { return func() time.Time { return at } }

func seeded(seed byte) *rand.ChaCha8 { return rand.NewChaCha8([32]byte{seed}) }

func TestV7Generator_Layout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, newGen func() *id.V7Generator)
	}

	cases := []testCase{
		{
			name: "version, variant and millisecond timestamp",
			assert: func(t *testing.T, newGen func() *id.V7Generator) {
				got, err := newGen().NewID()
				require.NoError(t, err)
				assert.Equal(t, byte(7), got[6]>>4, "version")
				assert.Equal(t, byte(0b10), got[8]>>6, "variant")
				var ms [8]byte
				copy(ms[2:], got[:6])
				assert.Equal(t, uint64(1645557742000), binary.BigEndian.Uint64(ms[:]))
				assert.False(t, got.IsZero())
			},
		},
		{
			name: "identically configured generators produce the same sequence",
			assert: func(t *testing.T, newGen func() *id.V7Generator) {
				a, b := newGen(), newGen()
				for range 10 {
					x, errA := a.NewID()
					y, errB := b.NewID()
					require.NoError(t, errA)
					require.NoError(t, errB)
					assert.Equal(t, x, y)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, func() *id.V7Generator {
				return id.NewV7Generator(id.WithClock(frozen(t0)), id.WithRandom(seeded(1)))
			})
		})
	}
}
