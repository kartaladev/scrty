package idgen_test

//go:generate mockgen -source=../../pkg/id/generator.go -destination=generator_mock_test.go -package=idgen_test -typed

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/pkg/id"
)

// outcome is what one call to idgen.New did, including a panic it let through.
type outcome struct {
	id       id.ID
	err      error
	panicked bool
	panicVal any
}

// derefGenerator reads its receiver, so calling NewID on a nil *derefGenerator
// panics.
type derefGenerator struct{ next id.ID }

func (g *derefGenerator) NewID() (id.ID, error) { return g.next, nil }

func TestNew(t *testing.T) {
	t.Parallel()

	var (
		goodID   = id.ID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
		genError = errors.New("the generator is out of entropy")
	)

	type testCase struct {
		name      string
		generator func(t *testing.T) id.Generator
		assert    func(t *testing.T, got outcome)
	}

	cases := []testCase{
		{
			name: "nil id",
			generator: mockReturning(func(g *MockGenerator) {
				g.EXPECT().NewID().Return(id.Nil, nil)
			}),
			assert: func(t *testing.T, got outcome) {
				require.ErrorIs(t, got.err, idgen.ErrNil)
				assert.Equal(t, id.Nil, got.id)
			},
		},
		{
			name: "good id",
			generator: mockReturning(func(g *MockGenerator) {
				g.EXPECT().NewID().Return(goodID, nil)
			}),
			assert: func(t *testing.T, got outcome) {
				require.NoError(t, got.err)
				assert.Equal(t, goodID, got.id)
			},
		},
		{
			name: "error with nil id",
			generator: mockReturning(func(g *MockGenerator) {
				g.EXPECT().NewID().Return(id.Nil, genError)
			}),
			assert: func(t *testing.T, got outcome) {
				require.ErrorIs(t, got.err, genError)
				assert.NotErrorIs(t, got.err, idgen.ErrNil)
				assert.Equal(t, genError, got.err, "the generator's own error comes back unchanged")
			},
		},
		{
			name: "error with good id",
			generator: mockReturning(func(g *MockGenerator) {
				g.EXPECT().NewID().Return(goodID, genError)
			}),
			assert: func(t *testing.T, got outcome) {
				require.ErrorIs(t, got.err, genError)
				assert.NotErrorIs(t, got.err, idgen.ErrNil)
				assert.Equal(t, genError, got.err, "the generator's own error comes back unchanged")
			},
		},
		{
			name: "nil generator",
			generator: func(*testing.T) id.Generator {
				return nil
			},
			assert: func(t *testing.T, got outcome) {
				require.False(t, got.panicked, "a nil generator is refused with an error, not a panic")
				require.ErrorIs(t, got.err, idgen.ErrNoGenerator)
				assert.NotErrorIs(t, got.err, idgen.ErrNil)
				assert.Equal(t, id.Nil, got.id)
			},
		},
		{
			name: "typed-nil generator",
			generator: func(*testing.T) id.Generator {
				var g *derefGenerator
				return g
			},
			assert: func(t *testing.T, got outcome) {
				require.False(t, got.panicked, "a typed-nil generator is refused with an error, not a panic: %v", got.panicVal)
				require.ErrorIs(t, got.err, idgen.ErrNoGenerator)
				assert.NotErrorIs(t, got.err, idgen.ErrNil)
				assert.Equal(t, id.Nil, got.id)
			},
		},
		{
			name: "generator panics",
			generator: mockReturning(func(g *MockGenerator) {
				g.EXPECT().NewID().DoAndReturn(func() (id.ID, error) {
					panic("the generator blew up")
				})
			}),
			assert: func(t *testing.T, got outcome) {
				require.True(t, got.panicked, "idgen recovers no panic")
				assert.Equal(t, "the generator blew up", got.panicVal)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, call(tc.generator(t)))
		})
	}
}

// mockReturning builds a generator double and lets expect script its answers.
func mockReturning(expect func(g *MockGenerator)) func(t *testing.T) id.Generator {
	return func(t *testing.T) id.Generator {
		g := NewMockGenerator(gomock.NewController(t))
		expect(g)
		return g
	}
}

// call runs idgen.New and records a panic instead of propagating it, so a row
// can assert that the panic was not recovered inside idgen.
func call(g id.Generator) (got outcome) {
	defer func() {
		if r := recover(); r != nil {
			got.panicked = true
			got.panicVal = r
		}
	}()
	got.id, got.err = idgen.New(g)
	return got
}
