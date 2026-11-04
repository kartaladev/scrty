package storetest_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
	"github.com/kartaladev/scrty/token/onetime"
)

// TestMemory runs the provider's in-memory defaults through their suites.
func TestMemory(t *testing.T) {
	t.Parallel()

	t.Run("PendingRequests", func(t *testing.T) {
		t.Parallel()
		storetest.PendingRequestSuite(t, func(*testing.T) oidcprovider.PendingRequestStore {
			return must.Must(oidcprovider.NewMemoryPendingRequestStore())
		})
	})

	t.Run("CodeRecords", func(t *testing.T) {
		t.Parallel()
		storetest.CodeRecordSuite(t, func(*testing.T) oidcprovider.CodeStore {
			return must.Must(oidcprovider.NewMemoryCodeStore())
		})
	})

	t.Run("Consents", func(t *testing.T) {
		t.Parallel()
		storetest.ConsentSuite(t, func(*testing.T) oidcprovider.ConsentStore {
			return must.Must(oidcprovider.NewMemoryConsentStore())
		})
	})

	t.Run("Grants", func(t *testing.T) {
		t.Parallel()
		storetest.GrantSuite(t, func(*testing.T) oidcprovider.GrantStore {
			return must.Must(oidcprovider.NewMemoryGrantStore())
		})
	})

	t.Run("AccessTokens", func(t *testing.T) {
		t.Parallel()
		storetest.AccessTokenSuite(t, func(*testing.T) oidcprovider.AccessTokenStore {
			return must.Must(oidcprovider.NewMemoryAccessTokenStore())
		})
	})

	t.Run("AssertionIDs", func(t *testing.T) {
		t.Parallel()
		storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
			return must.Must(oidcprovider.NewMemoryAssertionIDStore())
		})
	})

	t.Run("BrowserSessions", func(t *testing.T) {
		t.Parallel()
		storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore {
			return must.Must(oidcprovider.NewMemoryBrowserSessionStore())
		})
	})

	t.Run("Races", func(t *testing.T) {
		t.Parallel()

		t.Run("BrowserSessions", func(t *testing.T) {
			t.Parallel()
			storetest.RunTouchRace(t, providerHarness(func() oidcprovider.BrowserSessionStore {
				return must.Must(oidcprovider.NewMemoryBrowserSessionStore())
			}))
		})

		t.Run("PendingRequests", func(t *testing.T) {
			t.Parallel()
			storetest.RunAdvanceRace(t, providerHarness(func() oidcprovider.PendingRequestStore {
				return must.Must(oidcprovider.NewMemoryPendingRequestStore())
			}))
		})
		t.Run("CodeTokens", func(t *testing.T) {
			t.Parallel()
			storetest.RunCodeSpendRace(t, providerHarness(func() onetime.Store {
				return must.Must(onetime.NewMemoryStore())
			}))
		})
		t.Run("AssertionIDs", func(t *testing.T) {
			t.Parallel()
			storetest.RunAssertionRecordRace(t, providerHarness(func() oidcprovider.AssertionIDStore {
				return must.Must(oidcprovider.NewMemoryAssertionIDStore())
			}))
		})
		t.Run("Grants", func(t *testing.T) {
			t.Parallel()
			storetest.RunGrantRaces(t, providerHarness(func() oidcprovider.GrantStore {
				return must.Must(oidcprovider.NewMemoryGrantStore())
			}))
		})
	})
}

// TestMemoryAtAnyClock runs the provider's in-memory defaults through their suites on a
// store clock long before the suites' fixture dates, and on ones past them, which is
// where the wall clock will be. A store's clock decides only what it forgets of its own
// accord, so no suite may turn on which side of its fixtures that clock is. No suite moves
// that clock, so a sweep there finds nothing held, and sweepers holds each store to a sweep
// that does.
func TestMemoryAtAnyClock(t *testing.T) {
	t.Parallel()

	for _, at := range []time.Time{
		time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		clk := oidcprovider.WithMemoryStoreClock(clockwork.NewFakeClockAt(at))

		suites := map[string]func(t *testing.T){
			"PendingRequests": func(t *testing.T) {
				storetest.PendingRequestSuite(t, func(*testing.T) oidcprovider.PendingRequestStore {
					return must.Must(oidcprovider.NewMemoryPendingRequestStore(clk))
				})
			},
			"CodeRecords": func(t *testing.T) {
				storetest.CodeRecordSuite(t, func(*testing.T) oidcprovider.CodeStore {
					return must.Must(oidcprovider.NewMemoryCodeStore(clk))
				})
			},
			"Grants": func(t *testing.T) {
				storetest.GrantSuite(t, func(*testing.T) oidcprovider.GrantStore {
					return must.Must(oidcprovider.NewMemoryGrantStore(clk))
				})
			},
			"AccessTokens": func(t *testing.T) {
				storetest.AccessTokenSuite(t, func(*testing.T) oidcprovider.AccessTokenStore {
					return must.Must(oidcprovider.NewMemoryAccessTokenStore(clk))
				})
			},
			"AssertionIDs": func(t *testing.T) {
				storetest.AssertionIDSuite(t, func(*testing.T) oidcprovider.AssertionIDStore {
					return must.Must(oidcprovider.NewMemoryAssertionIDStore(clk))
				})
			},
			"BrowserSessions": func(t *testing.T) {
				storetest.BrowserSessionSuite(t, func(*testing.T) oidcprovider.BrowserSessionStore {
					return must.Must(oidcprovider.NewMemoryBrowserSessionStore(clk))
				})
			},
		}
		for name, run := range suites {
			t.Run(at.Format("2006")+"/"+name, func(t *testing.T) {
				t.Parallel()
				run(t)
			})
		}

		for name, newStore := range sweepers() {
			t.Run(at.Format("2006")+"/a sweep keeps what has not expired/"+name, func(t *testing.T) {
				t.Parallel()

				clk := clockwork.NewFakeClockAt(at)
				s := newStore(clk)

				s.put(t, 1, at.Add(time.Hour))
				s.put(t, 2, at.Add(time.Second))

				// Past the sweep's minute, so this write sweeps with both of them held.
				clk.Advance(2 * time.Minute)
				s.put(t, 3, at.Add(time.Hour))

				assert.False(t, s.held(t, 2, at), "the sweep ran, and forgot what its clock says has expired")
				assert.True(t, s.held(t, 1, at), "and kept what has not")
				assert.True(t, s.held(t, 3, at), "and stored what it was given")
			})
		}
	}
}

// sweeper is a store that forgets by its own clock on a write: put stores record n to
// expire at expires, and held asks for it at the time given.
type sweeper struct {
	put  func(t *testing.T, n byte, expires time.Time)
	held func(t *testing.T, n byte, at time.Time) bool
}

// sweepDigest and sweepID name record n of a sweeper.
func sweepDigest(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }

func sweepID(n byte) id.ID { return id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n)) }

// found reports whether a load found its record, failing for anything but not found.
func found(t *testing.T, err error) bool {
	t.Helper()

	if errors.Is(err, oidcprovider.ErrNotFound) {
		return false
	}
	require.NoError(t, err)

	return true
}

// sweepers returns the provider's in-memory stores with a sweep of their own, each over
// the clock it is given.
func sweepers() map[string]func(clock.Clock) sweeper {
	return map[string]func(clock.Clock) sweeper{
		"PendingRequests": func(clk clock.Clock) sweeper {
			s := must.Must(oidcprovider.NewMemoryPendingRequestStore(oidcprovider.WithMemoryStoreClock(clk)))

			return sweeper{
				put: func(t *testing.T, n byte, expires time.Time) {
					t.Helper()
					require.NoError(t, s.Create(t.Context(), &oidcprovider.PendingRequest{
						ID: sweepID(n), HandleDigest: sweepDigest(n), ExpiresAt: expires,
					}))
				},
				held: func(t *testing.T, n byte, _ time.Time) bool {
					t.Helper()
					_, err := s.Load(t.Context(), sweepDigest(n))

					return found(t, err)
				},
			}
		},
		"CodeRecords": func(clk clock.Clock) sweeper {
			s := must.Must(oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(clk)))

			return sweeper{
				put: func(t *testing.T, n byte, expires time.Time) {
					t.Helper()
					require.NoError(t, s.Create(t.Context(), &oidcprovider.CodeRecord{TokenID: sweepID(n), ExpiresAt: expires}))
				},
				held: func(t *testing.T, n byte, _ time.Time) bool {
					t.Helper()
					_, err := s.Load(t.Context(), sweepID(n))

					return found(t, err)
				},
			}
		},
		"Grants": func(clk clock.Clock) sweeper {
			s := must.Must(oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(clk)))

			return sweeper{
				put: func(t *testing.T, n byte, expires time.Time) {
					t.Helper()
					require.NoError(t, s.Create(t.Context(), &oidcprovider.Grant{Family: sweepID(n), ExpiresAt: expires}))
				},
				held: func(t *testing.T, n byte, _ time.Time) bool {
					t.Helper()
					_, err := s.Load(t.Context(), sweepID(n))

					return found(t, err)
				},
			}
		},
		"AccessTokens": func(clk clock.Clock) sweeper {
			s := must.Must(oidcprovider.NewMemoryAccessTokenStore(oidcprovider.WithMemoryStoreClock(clk)))

			return sweeper{
				put: func(t *testing.T, n byte, expires time.Time) {
					t.Helper()
					require.NoError(t, s.Create(t.Context(), &oidcprovider.AccessTokenRecord{
						ID: sweepID(n), Digest: sweepDigest(n), ExpiresAt: expires,
					}))
				},
				held: func(t *testing.T, n byte, _ time.Time) bool {
					t.Helper()
					_, err := s.Load(t.Context(), sweepID(n))

					return found(t, err)
				},
			}
		},
		"BrowserSessions": func(clk clock.Clock) sweeper {
			s := must.Must(oidcprovider.NewMemoryBrowserSessionStore(oidcprovider.WithMemoryStoreClock(clk)))

			return sweeper{
				put: func(t *testing.T, n byte, expires time.Time) {
					t.Helper()
					require.NoError(t, s.Put(t.Context(), &oidcprovider.BrowserSession{
						Digest: sweepDigest(n), IdleExpiresAt: expires, AbsoluteExpiresAt: expires,
					}))
				},
				// at is the caller's time, before every record's end, so only a sweep
				// can have made a record not found.
				held: func(t *testing.T, n byte, at time.Time) bool {
					t.Helper()
					_, err := s.Load(t.Context(), sweepDigest(n), at)

					return found(t, err)
				},
			}
		},
	}
}
