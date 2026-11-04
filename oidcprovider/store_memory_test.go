package oidcprovider_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

func memoryID(n int) id.ID {
	return id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n))
}

// Nothing runs a timer in these stores, so a write is what keeps them bounded when no
// expiry task is wired. Behaviour every durable store shares runs through
// storetest; only what the in-memory stores do on their own clock is here.
func TestMemoryStores_ForgetWhatExpired(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	future := start.Add(time.Hour)

	// load reports whether record n is still held, and add stores it with a lifetime.
	type store struct {
		add  func(t *testing.T, n int, expires time.Time)
		held func(t *testing.T, n int) bool
	}

	cases := []struct {
		name    string
		newCase func(t *testing.T, clk *clockwork.FakeClock) store
	}{
		{
			name: "pending requests",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				s, err := oidcprovider.NewMemoryPendingRequestStore(oidcprovider.WithMemoryStoreClock(clk))
				require.NoError(t, err)

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Create(t.Context(), &oidcprovider.PendingRequest{HandleDigest: fmt.Append(nil, n), ExpiresAt: expires}))
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						_, err := s.Load(t.Context(), fmt.Append(nil, n))
						return err == nil
					},
				}
			},
		},
		{
			name: "code records",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				s, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(clk))
				require.NoError(t, err)

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Create(t.Context(), &oidcprovider.CodeRecord{TokenID: memoryID(n), ExpiresAt: expires}))
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						_, err := s.Load(t.Context(), memoryID(n))
						return err == nil
					},
				}
			},
		},
		{
			name: "grants",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				s, err := oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(clk))
				require.NoError(t, err)

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Create(t.Context(), &oidcprovider.Grant{Family: memoryID(n), ExpiresAt: expires}))
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						_, err := s.Load(t.Context(), memoryID(n))
						return err == nil
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(start)
			s := tc.newCase(t, clk)

			s.add(t, 1, start.Add(time.Second))
			s.add(t, 2, future)

			clk.Advance(2 * time.Minute)
			s.add(t, 3, future)

			assert.False(t, s.held(t, 1), "a write forgets what the store's clock says has expired")
			assert.True(t, s.held(t, 2), "and keeps what has not")
			assert.True(t, s.held(t, 3), "and stores what it was given")
		})
	}
}

// A revocation has no deadline of its own. It must outlive every code that could
// name it, and it must still go, or a store of the default kind grows without bound.
func TestMemoryGrantStore_ForgetsRevocations(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	const longestCode = 10 * time.Minute

	// writes, each adding a record, so the sweep runs.
	writes := []struct {
		name  string
		write func(t *testing.T, s *oidcprovider.MemoryGrantStore, n int)
	}{
		{
			name: "create",
			write: func(t *testing.T, s *oidcprovider.MemoryGrantStore, n int) {
				t.Helper()
				require.NoError(t, s.Create(t.Context(), &oidcprovider.Grant{Family: memoryID(n), ExpiresAt: start.Add(time.Hour)}))
			},
		},
		{
			name: "a revocation recorded first",
			write: func(t *testing.T, s *oidcprovider.MemoryGrantStore, n int) {
				t.Helper()
				require.NoError(t, s.Revoke(t.Context(), memoryID(n), oidcprovider.CauseCodeReplay, start))
			},
		},
	}

	for _, w := range writes {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			clk := clockwork.NewFakeClockAt(start)
			s, err := oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)
			require.NoError(t, s.Revoke(ctx, memoryID(1), oidcprovider.CauseCodeReplay, start))

			clk.Advance(longestCode)
			w.write(t, s, 2)
			got, err := s.Load(ctx, memoryID(1))
			require.NoError(t, err, "kept while any code that could name it may live")
			assert.True(t, got.Revoked)

			clk.Advance(2 * time.Minute)
			w.write(t, s, 3)
			_, err = s.Load(ctx, memoryID(1))
			require.ErrorIs(t, err, oidcprovider.ErrNotFound, "then forgotten, or revocations grow without bound")
		})
	}
}

func TestMemoryStores_RefuseNilClock(t *testing.T) {
	t.Parallel()

	var typedNil *clockwork.FakeClock

	cases := []struct {
		name  string
		build func(opt oidcprovider.MemoryStoreOption) error
	}{
		{name: "pending requests", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryPendingRequestStore(opt)
			return err
		}},
		{name: "code records", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryCodeStore(opt)
			return err
		}},
		{name: "consents", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryConsentStore(opt)
			return err
		}},
		{name: "grants", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryGrantStore(opt)
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.ErrorIs(t, tc.build(oidcprovider.WithMemoryStoreClock(nil)), oidcprovider.ErrConfig)
			require.ErrorIs(t, tc.build(oidcprovider.WithMemoryStoreClock(typedNil)), oidcprovider.ErrConfig)
			require.NoError(t, tc.build(nil), "a nil option is skipped")
		})
	}
}
