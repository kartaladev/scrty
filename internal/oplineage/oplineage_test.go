package oplineage_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/session"
)

func TestNew(t *testing.T) {
	t.Parallel()

	memory, err := session.NewMemoryStore()
	require.NoError(t, err)
	var typedNil *session.MemoryStore

	cases := []struct {
		name   string
		inner  session.Store
		assert func(t *testing.T, got session.Store)
	}{
		{
			name:   "a session store is what the store holds",
			inner:  memory,
			assert: func(t *testing.T, got session.Store) { assert.Same(t, memory, got) },
		},
		{
			name:   "no session store builds the zero store",
			inner:  nil,
			assert: func(t *testing.T, got session.Store) { assert.Nil(t, got) },
		},
		{
			name:   "a typed nil session store builds the zero store too, so nobody has to look inside",
			inner:  typedNil,
			assert: func(t *testing.T, got session.Store) { assert.True(t, got == nil, "got %T", got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, oplineage.Sessions(oplineage.New(tc.inner)))
		})
	}
}

// The guarantee is the shape: one unexported field and no method, so nothing outside
// this package can fill a Store, and nothing holding one can get a session.Store back
// out of it and hand it to a sign-in path.
func TestStore_ShapeGivesNoWayInOrOut(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[oplineage.Store]()
	require.Equal(t, 1, typ.NumField())
	assert.False(t, typ.Field(0).IsExported(), "the field must be unexported")
	assert.Equal(t, 0, typ.NumMethod(), "a method would reach consumers through the alias")
	assert.Equal(t, 0, reflect.PointerTo(typ).NumMethod(), "so would one on the pointer")
}
