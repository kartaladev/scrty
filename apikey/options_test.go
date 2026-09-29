package apikey_test

import (
	"crypto/rand"
	"crypto/sha512"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestNewAPIKeyManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []apikey.Option
		assert func(t *testing.T, m *apikey.Manager, err error)
	}

	configError := func(t *testing.T, m *apikey.Manager, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, apikey.ErrConfig)
		assert.Nil(t, m)
	}

	// consumerClockAt is what a consumer's own read-only clock reports, for
	// the "consumer clock" row below.
	consumerClockAt := time.Date(2035, time.July, 7, 7, 7, 7, 0, time.UTC)

	cases := []testCase{
		{
			name: "defaults",
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "sk", m.Prefix())
			},
		},
		{name: "uppercase prefix", opts: []apikey.Option{apikey.WithPrefix("Bad-Prefix")}, assert: configError},
		{name: "prefix with a hyphen", opts: []apikey.Option{apikey.WithPrefix("acme-co")}, assert: configError},
		{name: "prefix with an underscore", opts: []apikey.Option{apikey.WithPrefix("ac_me")}, assert: configError},
		{name: "empty prefix", opts: []apikey.Option{apikey.WithPrefix("")}, assert: configError},
		{name: "prefix too long", opts: []apikey.Option{apikey.WithPrefix("abcdefghijklmnopq")}, assert: configError},
		{name: "nil digest", opts: []apikey.Option{apikey.WithDigest(nil)}, assert: configError},
		{name: "nil id generator", opts: []apikey.Option{apikey.WithIDGenerator(nil)}, assert: configError},
		{name: "nil clock", opts: []apikey.Option{apikey.WithClock(nil)}, assert: configError},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first issued key reads from a nil
			// receiver.
			name:   "typed-nil clock",
			opts:   []apikey.Option{apikey.WithClock((*clockwork.FakeClock)(nil))},
			assert: configError,
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and Issue reads
			// the issued key's created-at from the consumer's clock.
			name: "a consumer's own read-only clock is the manager's time source",
			opts: []apikey.Option{apikey.WithClock(fixedClock{at: consumerClockAt})},
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, m)

				_, rec, issueErr := m.Issue(t.Context(), "u-consumer-clock", "consumer clock key", nil, 0)
				require.NoError(t, issueErr)
				assert.True(t, consumerClockAt.Equal(rec.CreatedAt),
					"the issued key's created-at did not come from the consumer's clock")
			},
		},
		{name: "nil random", opts: []apikey.Option{apikey.WithRandom(nil)}, assert: configError},
		{name: "nil store", opts: []apikey.Option{apikey.WithStore(nil)}, assert: configError},
		{name: "typed-nil store", opts: []apikey.Option{apikey.WithStore((*apikey.MemoryStore)(nil))}, assert: configError},
		{
			name: "a sixteen-character alphanumeric prefix",
			opts: []apikey.Option{apikey.WithPrefix("acme0123456789ab")},
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "acme0123456789ab", m.Prefix())
			},
		},
		{
			name: "a single-character prefix",
			opts: []apikey.Option{apikey.WithPrefix("k")},
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k", m.Prefix())
			},
		},
		{
			name: "every port replaced at once",
			opts: []apikey.Option{
				apikey.WithStore(apikey.NewMemoryStore()),
				apikey.WithPrefix("acme"),
				apikey.WithDigest(func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] }),
				apikey.WithIDGenerator(id.NewV7Generator()),
				apikey.WithClock(clock.System()),
				apikey.WithRandom(rand.Reader),
			},
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "acme", m.Prefix())
			},
		},
		{
			// A nil logger has an obvious reading — "do not log from this
			// component" — so it is ignored rather than refused.
			name: "a nil logger is accepted",
			opts: []apikey.Option{apikey.WithLogger(nil)},
			assert: func(t *testing.T, m *apikey.Manager, err error) {
				require.NoError(t, err)
				assert.Equal(t, "sk", m.Prefix())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := apikey.NewManager(tc.opts...)
			tc.assert(t, m, err)
		})
	}
}
