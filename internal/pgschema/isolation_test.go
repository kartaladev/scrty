package pgschema_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/pgschema"
)

func TestReadCommittedOrWeaker(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		level  string
		assert func(t *testing.T, ok bool)
	}

	accepted := func(t *testing.T, ok bool) { assert.True(t, ok) }
	refused := func(t *testing.T, ok bool) { assert.False(t, ok) }

	cases := []testCase{
		{name: "read committed", level: "read committed", assert: accepted},
		{name: "read uncommitted runs as read committed", level: "read uncommitted", assert: accepted},
		{name: "repeatable read", level: "repeatable read", assert: refused},
		{name: "serializable", level: "serializable", assert: refused},
		{name: "an unknown spelling", level: "READ COMMITTED", assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, pgschema.ReadCommittedOrWeaker(tc.level))
		})
	}
}
