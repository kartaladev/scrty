package session_test

import (
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// fixedGenerator is a consumer's generator that always hands out one
// identifier.
type fixedGenerator struct{ value id.ID }

func (g fixedGenerator) NewID() (id.ID, error) { return g.value, nil }

func TestWithFamilyIDGenerator(t *testing.T) {
	t.Parallel()

	chosen := id.MustParse("01926a4e-0000-7000-8000-0000000000aa")

	type testCase struct {
		name   string
		opt    session.Option
		assert func(t *testing.T, m *session.Sessions, err error)
	}

	cases := []testCase{
		{
			name: "the consumer's generator mints the family identifier",
			opt:  session.WithFamilyIDGenerator(fixedGenerator{value: chosen}),
			assert: func(t *testing.T, m *session.Sessions, err error) {
				require.NoError(t, err)

				got, err := m.Create(t.Context(), testUser)

				require.NoError(t, err)
				assert.Equal(t, chosen, got.FamilyID)
			},
		},
		{
			name: "a nil generator is a configuration error",
			opt:  session.WithFamilyIDGenerator(nil),
			assert: func(t *testing.T, _ *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
			},
		},
		{
			name: "a typed-nil generator is a configuration error",
			opt:  session.WithFamilyIDGenerator((*id.V7Generator)(nil)),
			assert: func(t *testing.T, _ *session.Sessions, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(tc.opt)

			tc.assert(t, m, err)
		})
	}
}

// The default generator reads the manager's clock whichever order the options
// come in, so a family identifier's time prefix is the manager's time.
func TestDefaultFamilyIDsFollowTheClockInAnyOptionOrder(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := session.NewMemoryStore(session.WithMemoryStoreClock(clk))

	for name, opts := range map[string][]session.Option{
		"clock first": {session.WithClock(clk), session.WithStore(store)},
		"clock last":  {session.WithStore(store), session.WithClock(clk)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(opts...)
			require.NoError(t, err)

			got, err := m.Create(t.Context(), testUser)

			require.NoError(t, err)
			wantMillis := createdAt.UnixMilli()
			assert.Equal(t, wantMillis, idMillis(got.FamilyID), "the family identifier carries the manager clock's time")
		})
	}
}

// idMillis reads the 48-bit millisecond prefix of a version 7 identifier.
func idMillis(v id.ID) int64 {
	var ms int64
	for _, b := range v[:6] {
		ms = ms<<8 | int64(b)
	}

	return ms
}
