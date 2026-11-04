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
	"github.com/kartaladev/scrty/token/onetime"
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
		{
			name: "access tokens",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				s, err := oidcprovider.NewMemoryAccessTokenStore(oidcprovider.WithMemoryStoreClock(clk))
				require.NoError(t, err)

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Create(t.Context(), &oidcprovider.AccessTokenRecord{ID: memoryID(n), ExpiresAt: expires}))
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
			name: "browser sessions",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				s, err := oidcprovider.NewMemoryBrowserSessionStore(oidcprovider.WithMemoryStoreClock(clk))
				require.NoError(t, err)

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Put(t.Context(), &oidcprovider.BrowserSession{
							Digest:            fmt.Append(nil, n),
							IdleExpiresAt:     expires,
							AbsoluteExpiresAt: future,
						}))
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						// A deletion cannot be told from expiry by a load at the clock's
						// time, so this asks at the start, when everything was live. It
						// is the sweep, and not the judgement, that this table is about.
						_, err := s.Load(t.Context(), fmt.Append(nil, n), start)
						return err == nil
					},
				}
			},
		},
		{
			name: "the provider's default assertion identifiers",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				p, err := oidcprovider.New(validDeps(t), oidcprovider.WithClock(clk))
				require.NoError(t, err)
				s, ok := p.AssertionIDsForTest().(*oidcprovider.MemoryAssertionIDStore)
				require.True(t, ok)

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						fresh, err := s.Record(t.Context(), "c", fmt.Sprint(n), expires)
						require.NoError(t, err)
						require.True(t, fresh)
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						// Only DeleteExpired can be asked what it finds without adding
						// the pair, and it would forget the record it is asked about.
						return s.HeldForTest("c", fmt.Sprint(n))
					},
				}
			},
		},
		{
			name: "the provider's default code tokens",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				p, err := oidcprovider.New(validDeps(t), oidcprovider.WithClock(clk))
				require.NoError(t, err)
				s := p.CodeTokensForTest()

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Insert(t.Context(), codeToken(n, clk.Now(), expires)))
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						_, err := s.FindByID(t.Context(), memoryID(n))
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

			s.add(t, 4, clk.Now().Add(time.Second))
			clk.Advance(30 * time.Second)
			s.add(t, 5, future)
			assert.True(t, s.held(t, 4), "a sweep runs at most once per minute")

			// Past the sweep's minute, and past the minute the default assertion store
			// keeps a pair beyond its expiry.
			clk.Advance(32 * time.Second)
			s.add(t, 6, future)
			assert.False(t, s.held(t, 4), "and the next one, once due, forgets it")
		})
	}
}

// A code's record and token outlive its expiry by a minute, so that a replay is told from a
// code long gone, and an end of the sign-in reaches an exchange still in flight. They still
// go, with no consumer doing anything.
func TestMemoryCodeStores_KeepACodeAMinutePastItsExpiry(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	type store struct {
		add  func(t *testing.T, n int, expires time.Time)
		held func(t *testing.T, n int) bool
	}

	cases := []struct {
		name    string
		newCase func(t *testing.T, clk *clockwork.FakeClock) store
	}{
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
			name: "the provider's default code tokens",
			newCase: func(t *testing.T, clk *clockwork.FakeClock) store {
				t.Helper()
				p, err := oidcprovider.New(validDeps(t), oidcprovider.WithClock(clk))
				require.NoError(t, err)
				s := p.CodeTokensForTest()

				return store{
					add: func(t *testing.T, n int, expires time.Time) {
						t.Helper()
						require.NoError(t, s.Insert(t.Context(), codeToken(n, clk.Now(), expires)))
					},
					held: func(t *testing.T, n int) bool {
						t.Helper()
						_, err := s.FindByID(t.Context(), memoryID(n))

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

			expires := start.Add(time.Minute)
			s.add(t, 1, expires)
			s.add(t, 2, expires.Add(time.Hour))

			// 59 seconds past its expiry, on a write whose sweep is due.
			clk.Advance(time.Minute + 59*time.Second)
			s.add(t, 3, clk.Now().Add(time.Hour))
			assert.True(t, s.held(t, 1), "forgotten within the minute past its expiry")

			// Past the minute, on the next sweep due.
			clk.Advance(time.Minute)
			s.add(t, 4, clk.Now().Add(time.Hour))
			assert.False(t, s.held(t, 1), "kept past the minute")
			assert.True(t, s.held(t, 2), "and what has not expired stays")
		})
	}
}

// codeToken is a token of the purpose a provider's codes are spent under.
func codeToken(n int, issued, expires time.Time) onetime.Token {
	return onetime.Token{
		ID: memoryID(n), Purpose: "oidc-provider.code", Subject: "c", SecretHash: fmt.Append(nil, n),
		IssuedAt: issued, ExpiresAt: expires,
	}
}

// No consumer can reach the default code-token store to purge it, so whichever write
// brings a code in is what keeps it bounded.
func TestNew_DefaultCodeTokenStore_BoundedWithNoConsumerAction(t *testing.T) {
	t.Parallel()

	start := time.Date(2001, 1, 1, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		write func(t *testing.T, s onetime.Store, tok onetime.Token)
	}{
		{
			name: "insert",
			write: func(t *testing.T, s onetime.Store, tok onetime.Token) {
				t.Helper()
				require.NoError(t, s.Insert(t.Context(), tok))
			},
		},
		{
			name: "insert within a limit",
			write: func(t *testing.T, s onetime.Store, tok onetime.Token) {
				t.Helper()
				stored, err := s.InsertWithin(t.Context(), tok, tok.IssuedAt, 1000)
				require.NoError(t, err)
				require.True(t, stored)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(start)
			p, err := oidcprovider.New(validDeps(t), oidcprovider.WithClock(clk))
			require.NoError(t, err)
			tokens := p.CodeTokensForTest()

			for n := range 100 {
				tc.write(t, tokens, codeToken(n+1, clk.Now(), clk.Now().Add(time.Minute)))
			}
			clk.Advance(24 * time.Hour)
			tc.write(t, tokens, codeToken(1000, clk.Now(), clk.Now().Add(time.Minute)))

			held, ok := tokens.(interface{ Len() int })
			require.True(t, ok)
			assert.Equal(t, 1, held.Len(), "a day past their expiry, the tokens were kept")
		})
	}
}

// Whether a pair is held is never judged by a clock: not the system clock, and not one
// the store was given, whichever side of the pair's expiry it is on. A pair goes only
// when DeleteExpired removes it, and then at the caller's time alone.
func TestMemoryAssertionIDStore_HeldUntilDeleteExpiredRemovesIt(t *testing.T) {
	t.Parallel()

	callerNow := time.Date(2001, 1, 1, 10, 0, 0, 0, time.UTC)
	until := callerNow.Add(5 * time.Minute)

	cases := []struct {
		name string
		// clock is the store's, and nil leaves it on the system clock.
		clock *clockwork.FakeClock
	}{
		{name: "the system clock, long past the pair's expiry"},
		{name: "a clock long past the pair's expiry", clock: clockwork.NewFakeClockAt(until.AddDate(30, 0, 0))},
		{name: "a clock before the pair's expiry", clock: clockwork.NewFakeClockAt(callerNow)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []oidcprovider.MemoryStoreOption
			if tc.clock != nil {
				opts = append(opts, oidcprovider.WithMemoryStoreClock(tc.clock))
			}
			s, err := oidcprovider.NewMemoryAssertionIDStore(opts...)
			require.NoError(t, err)

			record := func(jti string) bool {
				t.Helper()
				fresh, err := s.Record(t.Context(), "c", jti, until)
				require.NoError(t, err)

				return fresh
			}

			require.True(t, record("jti-1"))
			assert.False(t, record("jti-1"), "one identifier was recorded as new twice")

			if tc.clock != nil {
				tc.clock.Advance(24 * time.Hour)
			}
			require.True(t, record("jti-2"), "a write, on a clock a day on")
			assert.False(t, record("jti-1"), "a write forgets nothing of its own accord")

			removed, err := s.DeleteExpired(t.Context(), until)
			require.NoError(t, err)
			assert.Zero(t, removed, "a pair expiring at the time given is not strictly before it")

			removed, err = s.DeleteExpired(t.Context(), until.Add(time.Second))
			require.NoError(t, err)
			assert.Equal(t, 2, removed)
			assert.True(t, record("jti-1"), "removed, it is new again")
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
		{name: "access tokens", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryAccessTokenStore(opt)
			return err
		}},
		{name: "assertion identifiers", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryAssertionIDStore(opt)
			return err
		}},
		{name: "browser sessions", build: func(opt oidcprovider.MemoryStoreOption) error {
			_, err := oidcprovider.NewMemoryBrowserSessionStore(opt)
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
