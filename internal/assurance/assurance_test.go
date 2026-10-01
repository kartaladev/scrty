package assurance_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/internal/assurance"
)

func TestProof(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		proof  func() assurance.Proof
		assert func(t *testing.T, p assurance.Proof)
	}

	cases := []testCase{
		{
			name:  "the zero value proves nothing",
			proof: func() assurance.Proof { return assurance.Proof{} },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.False(t, p.Holds())
				assert.Empty(t, p.Kind())
				assert.True(t, p.At().IsZero())
			},
		},
		{
			name:  "an empty kind proves nothing",
			proof: func() assurance.Proof { return assurance.New("", at) },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.False(t, p.Holds())
				assert.Equal(t, assurance.Proof{}, p, "an invalid proof is the zero proof")
			},
		},
		{
			name:  "a zero instant proves nothing",
			proof: func() assurance.Proof { return assurance.New(factor.Passkey, time.Time{}) },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.False(t, p.Holds())
				assert.Equal(t, assurance.Proof{}, p, "an invalid proof is the zero proof")
			},
		},
		{
			name:  "a kind and an instant hold",
			proof: func() assurance.Proof { return assurance.New(factor.Passkey, at) },
			assert: func(t *testing.T, p assurance.Proof) {
				assert.True(t, p.Holds())
				assert.Equal(t, factor.Passkey, p.Kind())
				assert.Equal(t, at, p.At())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.proof())
		})
	}
}
