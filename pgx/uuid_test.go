package pgx

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

func TestUUIDHelpers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		in     id.ID
		assert func(t *testing.T, arg any, got id.ID, err error)
	}

	roundTrips := func(want id.ID) func(t *testing.T, arg any, got id.ID, err error) {
		return func(t *testing.T, arg any, got id.ID, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want.String(), arg, "the argument is the canonical text")
			assert.Equal(t, want, got)
		}
	}

	v7 := id.MustParse("01926a4e-7b3c-7def-8123-456789abcdef")
	cases := []testCase{
		{name: "a version 7 identifier round-trips", in: v7, assert: roundTrips(v7)},
		{name: "the zero identifier round-trips", in: id.Nil, assert: roundTrips(id.Nil)},
		{
			name:   "a consumer's version 4 identifier round-trips",
			in:     id.MustParse("00000000-0000-4000-8000-000000000001"),
			assert: roundTrips(id.MustParse("00000000-0000-4000-8000-000000000001")),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			arg := uuidArg(tc.in)

			// What PostgreSQL hands back for a uuid column holding arg.
			var u pgtype.UUID
			require.NoError(t, u.Scan(arg))

			got, err := scanID(u)
			tc.assert(t, arg, got, err)
		})
	}
}

func TestScanIDRefusesNull(t *testing.T) {
	t.Parallel()

	got, err := scanID(pgtype.UUID{})
	require.Error(t, err, "a NULL uuid is not an identifier")
	assert.Equal(t, id.Nil, got)
}
