package oidcprovider_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// The contract the store shares with every other is held by the conformance suite in the
// test module. These cases hold what is the memory store's own: the sweep a Create runs,
// by the time it is given, and a usable zero value.
func TestMemoryDeviceAuthorizationStore(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	// record returns record n, expiring at expires, in state.
	record := func(n byte, state oidcprovider.DeviceState, expires time.Time) *oidcprovider.DeviceAuthorization {
		return &oidcprovider.DeviceAuthorization{
			ID:               id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n)),
			DeviceCodeDigest: bytes.Repeat([]byte{n}, 32),
			UserCodeDigest:   bytes.Repeat([]byte{n + 100}, 32),
			ClientID:         "tv",
			ExpiresAt:        expires,
			State:            state,
		}
	}
	held := func(t *testing.T, s *oidcprovider.MemoryDeviceAuthorizationStore, n byte) bool {
		t.Helper()
		_, err := s.LoadByDeviceCode(t.Context(), bytes.Repeat([]byte{n}, 32))
		if err != nil {
			require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			return false
		}

		return true
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, s *oidcprovider.MemoryDeviceAuthorizationStore)
	}

	cases := []testCase{
		{
			name: "a create forgets what has expired at its time",
			assert: func(t *testing.T, s *oidcprovider.MemoryDeviceAuthorizationStore) {
				require.NoError(t, s.Create(t.Context(), record(1, oidcprovider.DeviceApproved, start.Add(time.Second)), start))
				require.NoError(t, s.Create(t.Context(), record(2, oidcprovider.DeviceIssued, start.Add(time.Hour)), start))

				require.NoError(t, s.Create(t.Context(), record(3, oidcprovider.DeviceIssued, start.Add(time.Hour)), start.Add(2*time.Minute)))
				assert.False(t, held(t, s, 1), "expired at the create's time, so forgotten")
				assert.True(t, held(t, s, 2), "not expired, so kept")
			},
		},
		{
			name: "a create keeps a spent record until a minute past its expiry",
			assert: func(t *testing.T, s *oidcprovider.MemoryDeviceAuthorizationStore) {
				require.NoError(t, s.Create(t.Context(), record(1, oidcprovider.DeviceSpent, start.Add(time.Second)), start))

				require.NoError(t, s.Create(t.Context(), record(2, oidcprovider.DeviceIssued, start.Add(time.Hour)), start.Add(time.Minute)))
				assert.True(t, held(t, s, 1), "within its replay window")

				require.NoError(t, s.Create(t.Context(), record(3, oidcprovider.DeviceIssued, start.Add(time.Hour)), start.Add(2*time.Minute+time.Second)))
				assert.False(t, held(t, s, 1), "past its replay window")
			},
		},
		{
			name: "a create sweeps at most once a minute of its time",
			assert: func(t *testing.T, s *oidcprovider.MemoryDeviceAuthorizationStore) {
				require.NoError(t, s.Create(t.Context(), record(1, oidcprovider.DeviceIssued, start.Add(time.Second)), start))

				require.NoError(t, s.Create(t.Context(), record(2, oidcprovider.DeviceIssued, start.Add(time.Hour)), start.Add(30*time.Second)))
				assert.True(t, held(t, s, 1), "expired, but the sweep is not due")
			},
		},
		{
			name: "a create at a time before the last sweep sweeps again, so a clock stepping back does not stop the sweep",
			assert: func(t *testing.T, s *oidcprovider.MemoryDeviceAuthorizationStore) {
				far := time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)
				require.NoError(t, s.Create(t.Context(), record(1, oidcprovider.DeviceIssued, far.Add(time.Hour)), far))
				require.NoError(t, s.Create(t.Context(), record(2, oidcprovider.DeviceIssued, start.Add(time.Second)), start))

				require.NoError(t, s.Create(t.Context(), record(3, oidcprovider.DeviceIssued, start.Add(time.Hour)), start.Add(2*time.Minute)))
				assert.False(t, held(t, s, 2), "the sweep runs by the time it is given again")
			},
		},
		{
			name: "the zero value is an empty store, ready to use",
			assert: func(t *testing.T, _ *oidcprovider.MemoryDeviceAuthorizationStore) {
				var s oidcprovider.MemoryDeviceAuthorizationStore
				assert.False(t, held(t, &s, 1))
				require.ErrorIs(t, s.Claim(t.Context(), id.MustParse("01926a4e-0000-7000-8000-000000000001"), []byte{1}, start),
					oidcprovider.ErrNotFound, "nothing to claim")
				require.NoError(t, s.Create(t.Context(), record(1, oidcprovider.DeviceIssued, start.Add(time.Hour)), start))
				assert.True(t, held(t, &s, 1))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, oidcprovider.NewMemoryDeviceAuthorizationStore())
		})
	}
}
