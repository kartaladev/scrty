package password

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// emptyHistory is a History with nothing in it; these tests only build guards.
type emptyHistory struct{}

func (emptyHistory) RecentPasswords(context.Context, identity.UserID, int) ([][]byte, error) {
	return nil, nil
}

func (emptyHistory) RetirePassword(context.Context, identity.UserID, []byte, int) error { return nil }

func (emptyHistory) ForgetPasswords(context.Context, identity.UserID) error { return nil }

// pepperedEncoder stands for a consumer encoder whose Match depends on its own
// configuration, so a second one of the same type is not interchangeable.
type pepperedEncoder struct{ pepper string }

func (e *pepperedEncoder) Encode(input string) ([]byte, error) {
	return []byte(e.pepper + ":" + input), nil
}

func (e *pepperedEncoder) Match(input string, encoded []byte) bool {
	return string(encoded) == e.pepper+":"+input
}

// countOfType reports how many matchers share enc's concrete type.
func countOfType(matchers []Encoder, enc Encoder) int {
	n := 0
	for _, m := range matchers {
		if reflect.TypeOf(m) == reflect.TypeOf(enc) {
			n++
		}
	}

	return n
}

func TestNewReuseGuard_DerivesOncePerStoredHash(t *testing.T) {
	t.Parallel()

	mustEnc := func(enc Encoder, err error) Encoder {
		require.NoError(t, err)
		return enc
	}

	argon := mustEnc(NewArgon2idEncoder())
	bc := mustEnc(NewBcryptEncoder())
	sc := mustEnc(NewScryptEncoder())
	consumer := &pepperedEncoder{pepper: "a"}

	type testCase struct {
		name   string
		enc    Encoder
		opts   []ReuseOption
		assert func(t *testing.T, g *ReuseGuard)
	}

	// onlyOwn asserts the guard's own algorithm is derived by exactly one
	// matcher, and that the other built-in algorithms are still matched.
	onlyOwn := func(total int) func(t *testing.T, g *ReuseGuard) {
		return func(t *testing.T, g *ReuseGuard) {
			assert.Same(t, g.enc, g.matchers[0], "the guard's own encoder comes first")
			assert.Equalf(t, 1, countOfType(g.matchers, g.enc),
				"a stored hash of the guard's own algorithm is derived by %d matchers, want 1",
				countOfType(g.matchers, g.enc))

			for _, builtin := range []Encoder{argon, bc, sc} {
				assert.Positivef(t, countOfType(g.matchers, builtin), "no matcher for %T", builtin)
			}

			assert.Len(t, g.matchers, total)
		}
	}

	cases := []testCase{
		{name: "an Argon2id guard", enc: argon, assert: onlyOwn(3)},
		{name: "a bcrypt guard", enc: bc, assert: onlyOwn(3)},
		{name: "a scrypt guard", enc: sc, assert: onlyOwn(3)},
		{name: "a consumer encoder guard keeps every built-in", enc: consumer, assert: onlyOwn(4)},
		{
			name: "consumer-supplied matchers of the guard's type are never left out",
			enc:  consumer,
			opts: []ReuseOption{WithReuseMatchers(&pepperedEncoder{pepper: "b"}, argon)},
			assert: func(t *testing.T, g *ReuseGuard) {
				assert.Equal(t, 2, countOfType(g.matchers, consumer))
				assert.Len(t, g.matchers, 3)
			},
		},
		{
			name: "a consumer-supplied built-in of the guard's type is kept",
			enc:  argon,
			opts: []ReuseOption{WithReuseMatchers(argon)},
			assert: func(t *testing.T, g *ReuseGuard) {
				assert.Equal(t, 2, countOfType(g.matchers, argon))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g, err := NewReuseGuard(emptyHistory{}, tc.enc, 3, tc.opts...)
			require.NoError(t, err)

			tc.assert(t, g)
		})
	}
}

// BenchmarkReuseGuard_CheckOwnAlgorithmMiss is a check against one stored hash
// of the guard's own algorithm that does not match, at default Argon2id
// parameters: it costs one derivation, not one per matcher of that algorithm.
func BenchmarkReuseGuard_CheckOwnAlgorithmMiss(b *testing.B) {
	enc, err := NewArgon2idEncoder()
	require.NoError(b, err)

	stored, err := enc.Encode("current")
	require.NoError(b, err)

	g, err := NewReuseGuard(emptyHistory{}, enc, 1)
	require.NoError(b, err)

	user := &identity.Details{ID: "u-1", Password: stored}

	for b.Loop() {
		_ = g.Check(b.Context(), user, "candidate")
	}
}
