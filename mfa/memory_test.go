package mfa_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// confirmed puts a pending enrolment for user and confirms it at step, so a
// case that is about AcceptStep does not restate the two calls that get there.
func confirmed(
	t *testing.T, s mfa.EnrolmentStore, user identity.UserID, step int64, at time.Time,
) mfa.EnrolmentStore {
	t.Helper()

	require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
		User: user, Secret: []byte("secret"), CreatedAt: at,
	}))

	ok, err := s.Confirm(t.Context(), user, step, at)
	require.NoError(t, err)
	require.True(t, ok)

	return s
}

func TestMemoryEnrolmentStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		run    func(t *testing.T, s mfa.EnrolmentStore) (any, error)
		assert func(t *testing.T, got any, err error)
	}

	cases := []testCase{
		{
			name: "an unknown user holds no enrolment and is not an error",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				_, ok, err := s.Get(t.Context(), "nobody")

				return ok, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool))
			},
		},
		{
			name: "a pending enrolment is stored and readable",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte("secret"), CreatedAt: now,
				}))

				e, ok, err := s.Get(t.Context(), "u-1")
				require.True(t, ok)

				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)

				e := got.(mfa.Enrolment)
				assert.Equal(t, []byte("secret"), e.Secret)
				assert.Equal(t, now, e.CreatedAt)
				assert.True(t, e.ConfirmedAt.IsZero(), "a stored pending enrolment is not confirmed")
			},
		},
		{
			name: "a pending enrolment is replaced by a later begin",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(),
					mfa.Enrolment{User: "u-1", Secret: []byte("first")}))
				require.NoError(t, s.PutPending(t.Context(),
					mfa.Enrolment{User: "u-1", Secret: []byte("second")}))

				e, _, err := s.Get(t.Context(), "u-1")

				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("second"), got.(mfa.Enrolment).Secret)
			},
		},
		{
			name: "a confirmed enrolment refuses a new pending one",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				confirmed(t, s, "u-1", 100, now)

				return nil, s.PutPending(t.Context(),
					mfa.Enrolment{User: "u-1", Secret: []byte("second")})
			},
			assert: func(t *testing.T, _ any, err error) {
				assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)
			},
		},
		{
			name: "a refused begin leaves the confirmed secret untouched",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				confirmed(t, s, "u-1", 100, now)
				require.ErrorIs(t,
					s.PutPending(t.Context(), mfa.Enrolment{User: "u-1", Secret: []byte("second")}),
					mfa.ErrAlreadyEnrolled)

				e, _, err := s.Get(t.Context(), "u-1")

				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)

				e := got.(mfa.Enrolment)
				assert.Equal(t, []byte("secret"), e.Secret)
				assert.False(t, e.ConfirmedAt.IsZero())
			},
		},
		{
			name: "confirming an absent enrolment reports false",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				return s.Confirm(t.Context(), "nobody", 1, now)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool))
			},
		},
		{
			name: "confirming an already confirmed enrolment reports false",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				confirmed(t, s, "u-1", 100, now)

				return s.Confirm(t.Context(), "u-1", 101, now)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool), "there was no pending enrolment to confirm")
			},
		},
		{
			name: "AcceptStep refuses a pending enrolment",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(),
					mfa.Enrolment{User: "u-1", Secret: []byte("s")}))

				return s.AcceptStep(t.Context(), "u-1", 100)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool), "an unconfirmed enrolment accepts no step")
			},
		},
		{
			name: "AcceptStep refuses an unknown user",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				return s.AcceptStep(t.Context(), "nobody", 100)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool))
			},
		},
		{
			name: "AcceptStep refuses a step at or below the recorded one",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				s2 := confirmed(t, s, "u-1", 100, now)

				first, err := s2.AcceptStep(t.Context(), "u-1", 101)
				require.NoError(t, err)
				require.True(t, first)

				same, err := s2.AcceptStep(t.Context(), "u-1", 101)
				require.NoError(t, err)

				older, err := s2.AcceptStep(t.Context(), "u-1", 100)
				require.NoError(t, err)

				return []bool{same, older}, nil
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []bool{false, false}, got)
			},
		},
		{
			name: "a returned enrolment shares no memory with the stored one",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(),
					mfa.Enrolment{User: "u-1", Secret: []byte("secret")}))

				e, _, err := s.Get(t.Context(), "u-1")
				require.NoError(t, err)
				e.Secret[0] = 'X'

				again, _, err := s.Get(t.Context(), "u-1")

				return again, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("secret"), got.(mfa.Enrolment).Secret)
			},
		},
		{
			name: "the caller's own slice cannot be written through after storing",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				secret := []byte("secret")
				require.NoError(t, s.PutPending(t.Context(),
					mfa.Enrolment{User: "u-1", Secret: secret}))
				secret[0] = 'X'

				e, _, err := s.Get(t.Context(), "u-1")

				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("secret"), got.(mfa.Enrolment).Secret)
			},
		},
		{
			name: "deleting an absent enrolment is not an error",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				return nil, s.Delete(t.Context(), "nobody")
			},
			assert: func(t *testing.T, _ any, err error) { require.NoError(t, err) },
		},
		{
			name: "a deleted enrolment is gone",
			run: func(t *testing.T, s mfa.EnrolmentStore) (any, error) {
				confirmed(t, s, "u-1", 100, now)
				require.NoError(t, s.Delete(t.Context(), "u-1"))

				_, ok, err := s.Get(t.Context(), "u-1")

				return ok, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.False(t, got.(bool))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.run(t, mfa.NewMemoryEnrolmentStore())
			tc.assert(t, got, err)
		})
	}
}

func TestMemoryEnrolmentStoreAcceptStepRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	s := confirmed(t, mfa.NewMemoryEnrolmentStore(), "u-1", 100, time.Now())

	const goroutines = 16

	var (
		wg       sync.WaitGroup
		accepted atomic.Int64
		start    = make(chan struct{})
	)

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if got, stepErr := s.AcceptStep(ctx, "u-1", 101); stepErr == nil && got {
				accepted.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), accepted.Load(), "one step, one acceptance")
}

func TestPutPendingStartsGeneration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g1 := id.MustParse("01920000-0000-7000-8000-000000000001")
	g2 := id.MustParse("01920000-0000-7000-8000-000000000002")

	newTOTP := func(t *testing.T, s mfa.EnrolmentStore, opts ...mfa.TOTPOption) *mfa.TOTP {
		t.Helper()

		m, err := mfa.NewTOTP(s, "Example", opts...)
		require.NoError(t, err)

		return m
	}

	type testCase struct {
		name   string
		run    func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error)
		assert func(t *testing.T, got any, err error)
	}

	cases := []testCase{
		{
			name: "a second begin replaces the generation and clears the proof and the code",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte("first"), Generation: g1,
				}))
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte("second"), Generation: g2,
					DeviceProvenAt: now, EmailCode: []byte("123456"),
					EmailCodeUntil: now.Add(10 * time.Minute), EmailCodeAttempts: 3,
				}))

				e, _, err := s.Get(t.Context(), "u-1")

				return e, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)

				e := got.(mfa.Enrolment)
				assert.Equal(t, g2, e.Generation)
				assert.True(t, e.DeviceProvenAt.IsZero(), "a begin clears the device proof")
				assert.Nil(t, e.EmailCode, "a begin clears the emailed code")
				assert.True(t, e.EmailCodeUntil.IsZero())
				assert.Zero(t, e.EmailCodeAttempts)
			},
		},
		{
			name: "a confirmed enrolment still refuses a new generation and keeps its own",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error) {
				require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte("secret"), Generation: g1,
				}))
				ok, err := s.Confirm(t.Context(), "u-1", 100, now)
				require.NoError(t, err)
				require.True(t, ok)

				putErr := s.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte("second"), Generation: g2,
				})

				e, _, err := s.Get(t.Context(), "u-1")
				require.NoError(t, err)

				return e, putErr
			},
			assert: func(t *testing.T, got any, err error) {
				require.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)
				assert.Equal(t, g1, got.(mfa.Enrolment).Generation)
			},
		},
		{
			name: "each TOTP begin draws a new generation, and the store holds the latest",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error) {
				m := newTOTP(t, s)

				_, first, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
				require.NoError(t, err)
				_, second, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
				require.NoError(t, err)

				e, _, err := s.Get(t.Context(), "u-1")

				return []id.ID{first, second, e.Generation}, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)

				gens := got.([]id.ID)
				assert.NotEqual(t, id.Nil, gens[0])
				assert.NotEqual(t, gens[0], gens[1], "every begin starts a new generation")
				assert.Equal(t, gens[1], gens[2], "the stored generation is the one returned")
			},
		},
		{
			name: "a consumer's identifier generator is the one used",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error) {
				ids := NewMockGenerator(gomock.NewController(t))
				ids.EXPECT().NewID().Return(g2, nil).Times(1)
				m := newTOTP(t, s, mfa.WithTOTPIDGenerator(ids))

				_, gen, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
				require.NoError(t, err)

				e, _, err := s.Get(t.Context(), "u-1")

				return []id.ID{gen, e.Generation}, err
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []id.ID{g2, g2}, got)
			},
		},
		{
			name: "a failing identifier generator stores nothing",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error) {
				ids := NewMockGenerator(gomock.NewController(t))
				ids.EXPECT().NewID().Return(id.Nil, errors.New("no identifiers today"))
				m := newTOTP(t, s, mfa.WithTOTPIDGenerator(ids))

				_, _, beginErr := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")

				_, ok, err := s.Get(t.Context(), "u-1")
				require.NoError(t, err)

				return ok, beginErr
			},
			assert: func(t *testing.T, got any, err error) {
				require.Error(t, err)
				assert.False(t, got.(bool), "no half-made enrolment is left behind")
			},
		},
		{
			name: "a generator returning the nil identifier stores nothing",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (any, error) {
				ids := NewMockGenerator(gomock.NewController(t))
				ids.EXPECT().NewID().Return(id.Nil, nil)
				m := newTOTP(t, s, mfa.WithTOTPIDGenerator(ids))

				_, gen, beginErr := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice@example.com")
				assert.Equal(t, id.Nil, gen)

				_, ok, err := s.Get(t.Context(), "u-1")
				require.NoError(t, err)

				return ok, beginErr
			},
			assert: func(t *testing.T, got any, err error) {
				require.Error(t, err, "a nil generation could never be proven or completed")
				assert.False(t, got.(bool), "no unprovable enrolment is left behind")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.run(t, mfa.NewMemoryEnrolmentStore())
			tc.assert(t, got, err)
		})
	}
}

// pendingOn puts a pending enrolment for user on generation gen.
func pendingOn(t *testing.T, s *mfa.MemoryEnrolmentStore, user identity.UserID, gen id.ID) {
	t.Helper()

	require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{
		User: user, Secret: []byte("secret"), Generation: gen,
	}))
}

// provenOn puts a pending enrolment on gen and proves its device at step 5
// with the emailed code "123456".
func provenOn(t *testing.T, s *mfa.MemoryEnrolmentStore, user identity.UserID, gen id.ID, at time.Time) {
	t.Helper()

	pendingOn(t, s, user, gen)

	ok, err := s.ProveDevice(t.Context(), user, gen, 5, []byte("123456"), at.Add(10*time.Minute), at)
	require.NoError(t, err)
	require.True(t, ok)
}

// stored reads user's enrolment, requiring that one exists.
func stored(t *testing.T, s *mfa.MemoryEnrolmentStore, user identity.UserID) mfa.Enrolment {
	t.Helper()

	e, ok, err := s.Get(t.Context(), user)
	require.NoError(t, err)
	require.True(t, ok)

	return e
}

func TestDeviceProofPort(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	later := now.Add(time.Minute)
	until := now.Add(10 * time.Minute)
	g1 := id.MustParse("01920000-0000-7000-8000-000000000001")
	g2 := id.MustParse("01920000-0000-7000-8000-000000000002")

	type result struct {
		ok bool
		e  mfa.Enrolment
	}

	type testCase struct {
		name   string
		run    func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error)
		assert func(t *testing.T, got result, err error)
	}

	// refusedUnchanged asserts a write that reported false and left the
	// enrolment exactly as want.
	refusedUnchanged := func(want func() mfa.Enrolment) func(*testing.T, result, error) {
		return func(t *testing.T, got result, err error) {
			require.NoError(t, err)
			assert.False(t, got.ok)
			assert.Equal(t, want(), got.e)
		}
	}

	pendingG1 := func() mfa.Enrolment {
		return mfa.Enrolment{User: "u-1", Secret: []byte("secret"), Generation: g1}
	}

	provenG1 := func() mfa.Enrolment {
		e := pendingG1()
		e.LastStep, e.DeviceProvenAt = 5, now
		e.EmailCode, e.EmailCodeUntil = []byte("123456"), until

		return e
	}

	cases := []testCase{
		// ProveDevice
		{
			name: "ProveDevice records the step, the proof and the code on the pending generation",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.ProveDevice(t.Context(), "u-1", g1, 5, []byte("123456"), until, now)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.ok)
				assert.Equal(t, provenG1(), got.e)
				assert.True(t, got.e.ConfirmedAt.IsZero(), "a proven device is not a confirmed enrolment")
			},
		},
		{
			name: "ProveDevice without an emailed code proves the device",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.ProveDevice(t.Context(), "u-1", g1, 5, nil, time.Time{}, now)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.ok)
				assert.Equal(t, now, got.e.DeviceProvenAt)
				assert.Nil(t, got.e.EmailCode)
			},
		},
		{
			name: "ProveDevice refuses another generation",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.ProveDevice(t.Context(), "u-1", g2, 5, []byte("123456"), until, now)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(pendingG1),
		},
		{
			name: "ProveDevice refuses the nil generation even on an enrolment that has none",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", id.Nil)
				ok, err := s.ProveDevice(t.Context(), "u-1", id.Nil, 5, []byte("123456"), until, now)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(func() mfa.Enrolment {
				return mfa.Enrolment{User: "u-1", Secret: []byte("secret")}
			}),
		},
		{
			name: "ProveDevice refuses a device already proven",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.ProveDevice(t.Context(), "u-1", g1, 6, []byte("654321"), until, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(provenG1),
		},
		{
			name: "ProveDevice refuses a confirmed enrolment",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.Confirm(t.Context(), "u-1", 4, now)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = s.ProveDevice(t.Context(), "u-1", g1, 5, []byte("123456"), until, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(func() mfa.Enrolment {
				e := pendingG1()
				e.ConfirmedAt, e.LastStep = now, 4

				return e
			}),
		},
		{
			name: "ProveDevice refuses a step not later than the recorded one",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.ProveDevice(t.Context(), "u-1", g1, 0, []byte("123456"), until, now)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(pendingG1),
		},
		{
			name: "ProveDevice refuses an unknown user and creates nothing",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				ok, err := s.ProveDevice(t.Context(), "nobody", g1, 5, []byte("123456"), until, now)
				_, exists, getErr := s.Get(t.Context(), "nobody")
				require.NoError(t, getErr)

				return result{ok: ok || exists}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.False(t, got.ok)
			},
		},
		{
			name: "ProveDevice keeps its own copy of the emailed code",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				code := []byte("123456")
				ok, err := s.ProveDevice(t.Context(), "u-1", g1, 5, code, until, now)
				code[0] = 'X'

				returned := stored(t, s, "u-1")
				require.Len(t, returned.EmailCode, 6)
				returned.EmailCode[1] = 'X'

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.ok)
				assert.Equal(t, []byte("123456"), got.e.EmailCode,
					"neither the caller's slice nor a returned one reaches stored state")
			},
		},

		// Complete
		{
			name: "Complete confirms a proven generation and clears the emailed code",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.Complete(t.Context(), "u-1", g1, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.ok)
				assert.Equal(t, later, got.e.ConfirmedAt)
				assert.Nil(t, got.e.EmailCode, "a completed enrolment keeps no emailed code")
				assert.Equal(t, until, got.e.EmailCodeUntil, "completion keeps the record that a code was issued")
				assert.Equal(t, int64(5), got.e.LastStep, "the proving step stays spent")
			},
		},
		{
			name: "Complete refuses another generation",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.Complete(t.Context(), "u-1", g2, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(provenG1),
		},
		{
			name: "Complete refuses the nil generation",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.Complete(t.Context(), "u-1", id.Nil, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(provenG1),
		},
		{
			name: "Complete refuses a device not yet proven",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.Complete(t.Context(), "u-1", g1, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(pendingG1),
		},
		{
			name: "Complete refuses an enrolment already confirmed",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.Complete(t.Context(), "u-1", g1, now)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = s.Complete(t.Context(), "u-1", g1, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: refusedUnchanged(func() mfa.Enrolment {
				e := provenG1()
				e.ConfirmedAt, e.EmailCode = now, nil

				return e
			}),
		},
		{
			name: "Complete refuses an unknown user",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				ok, err := s.Complete(t.Context(), "nobody", g1, now)

				return result{ok: ok}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.False(t, got.ok)
			},
		},

		// Confirm
		{
			name: "Confirm clears an outstanding emailed code and keeps the step forward",
			run: func(t *testing.T, s *mfa.MemoryEnrolmentStore) (result, error) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.Confirm(t.Context(), "u-1", 4, later)

				return result{ok: ok, e: stored(t, s, "u-1")}, err
			},
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.ok)
				assert.Equal(t, later, got.e.ConfirmedAt)
				assert.Nil(t, got.e.EmailCode, "a confirmed enrolment keeps no emailed code")
				assert.Equal(t, until, got.e.EmailCodeUntil, "confirmation keeps the record that a code was issued")
				assert.Equal(t, int64(5), got.e.LastStep, "the recorded step never moves backwards")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.run(t, mfa.NewMemoryEnrolmentStore())
			tc.assert(t, got, err)
		})
	}
}

func TestCompleteRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	g := id.MustParse("01920000-0000-7000-8000-000000000001")
	s := mfa.NewMemoryEnrolmentStore()
	provenOn(t, s, "u-1", g, time.Now())

	const goroutines = 8

	var (
		wg        sync.WaitGroup
		completed atomic.Int64
		start     = make(chan struct{})
	)

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if ok, err := s.Complete(ctx, "u-1", g, time.Now()); err == nil && ok {
				completed.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), completed.Load(), "one generation, one completion")
}

// enrolmentPathStore is a store the enrolment path can run on.
type enrolmentPathStore interface {
	mfa.EnrolmentStore
	mfa.DeviceProofStore
}

// blindStore is a deliberately broken store whose Complete ignores the
// generation it is given and completes whichever generation is current. It
// exists to show the two-session race test fails against such a store.
type blindStore struct {
	*mfa.MemoryEnrolmentStore
}

func (b blindStore) Complete(
	ctx context.Context, user identity.UserID, _ id.ID, at time.Time,
) (bool, error) {
	e, ok, err := b.Get(ctx, user)
	if err != nil || !ok {
		return false, err
	}

	return b.MemoryEnrolmentStore.Complete(ctx, user, e.Generation, at)
}

// raceOutcome is what the two-session race leaves behind.
type raceOutcome struct {
	completed bool
	enrolled  bool
	stored    mfa.Enrolment
	secretA   string
}

// runTwoSessionRace plays the scenario "a newer begin invalidates an earlier
// proof": session B begins and proves its device; session A begins again for
// the same user and proves its own device; then session B completes on the
// generation it recorded.
func runTwoSessionRace(t *testing.T, s enrolmentPathStore) raceOutcome {
	t.Helper()

	ctx := t.Context()
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	m, err := mfa.NewTOTP(s, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	_, genB, err := m.BeginEnrolmentGeneration(ctx, "u-1", "alice@example.com")
	require.NoError(t, err)

	proven, err := s.ProveDevice(ctx, "u-1", genB, 5, []byte("111111"), now.Add(10*time.Minute), now)
	require.NoError(t, err)
	require.True(t, proven, "session B proves its device")

	provA, genA, err := m.BeginEnrolmentGeneration(ctx, "u-1", "alice@example.com")
	require.NoError(t, err)
	require.NotEqual(t, genB, genA)

	proven, err = s.ProveDevice(ctx, "u-1", genA, 6, []byte("222222"), now.Add(10*time.Minute), now)
	require.NoError(t, err)
	require.True(t, proven, "session A proves its own device")

	completed, err := s.Complete(ctx, "u-1", genB, now)
	require.NoError(t, err)

	enrolled, err := m.Enrolled(ctx, "u-1")
	require.NoError(t, err)

	e, _, err := s.Get(ctx, "u-1")
	require.NoError(t, err)

	return raceOutcome{completed: completed, enrolled: enrolled, stored: e, secretA: provA.Secret}
}

func TestNewerBeginInvalidatesEarlierProof(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func() enrolmentPathStore
		assert func(t *testing.T, got raceOutcome)
	}

	cases := []testCase{
		{
			name:  "the memory store refuses the earlier generation",
			store: func() enrolmentPathStore { return mfa.NewMemoryEnrolmentStore() },
			assert: func(t *testing.T, got raceOutcome) {
				assert.False(t, got.completed, "completion on B's generation must fail")
				assert.False(t, got.enrolled, "u-1 must not be enrolled")
				assert.Equal(t, got.secretA, base32Secret(got.stored.Secret), "the pending secret is A's")
				assert.True(t, got.stored.ConfirmedAt.IsZero(), "A's secret must stay unconfirmed")
			},
		},
		{
			// The scenario is load-bearing: against a store whose completion
			// ignores the generation, B's emailed code confirms A's secret.
			name:  "broken variant is caught",
			store: func() enrolmentPathStore { return blindStore{mfa.NewMemoryEnrolmentStore()} },
			assert: func(t *testing.T, got raceOutcome) {
				assert.True(t, got.completed)
				assert.True(t, got.enrolled)
				assert.Equal(t, got.secretA, base32Secret(got.stored.Secret), "the secret confirmed is A's")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, runTwoSessionRace(t, tc.store()))
		})
	}
}

func TestChargeEmailCode(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	until := now.Add(10 * time.Minute)
	g1 := id.MustParse("01920000-0000-7000-8000-000000000001")
	g2 := id.MustParse("01920000-0000-7000-8000-000000000002")

	type result struct {
		count   int
		charged bool
		before  mfa.Enrolment
		after   mfa.Enrolment
	}

	type testCase struct {
		name string
		// setup prepares u-1's enrolment; the charge is then made for u-1 on
		// gen at at.
		setup  func(t *testing.T, s *mfa.MemoryEnrolmentStore)
		gen    id.ID
		at     time.Time
		assert func(t *testing.T, got result, err error)
	}

	charge := func(t *testing.T, s *mfa.MemoryEnrolmentStore, n int) {
		t.Helper()

		for range n {
			_, ok, err := s.ChargeEmailCode(t.Context(), "u-1", g1, now)
			require.NoError(t, err)
			require.True(t, ok)
		}
	}

	refusedUnchanged := func(t *testing.T, got result, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, got.charged)
		assert.Zero(t, got.count)
		assert.Equal(t, got.before, got.after, "a refused charge writes nothing")
	}

	cases := []testCase{
		{
			name:  "the first attempt on an outstanding code is charged",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) { provenOn(t, s, "u-1", g1, now) },
			gen:   g1,
			at:    now.Add(time.Minute),
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.charged)
				assert.Equal(t, 1, got.count)
				assert.Equal(t, 1, got.after.EmailCodeAttempts)
				assert.Equal(t, got.before.EmailCode, got.after.EmailCode, "a charge keeps the code comparable")
			},
		},
		{
			name: "the fifth attempt is charged",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
				provenOn(t, s, "u-1", g1, now)
				charge(t, s, mfa.MaxEmailCodeFailures-1)
			},
			gen: g1,
			at:  now,
			assert: func(t *testing.T, got result, err error) {
				require.NoError(t, err)
				assert.True(t, got.charged)
				assert.Equal(t, mfa.MaxEmailCodeFailures, got.count)
				assert.NotNil(t, got.after.EmailCode, "a correct code charged fifth must still compare")
			},
		},
		{
			name: "a sixth attempt is refused after five were charged",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
				provenOn(t, s, "u-1", g1, now)
				charge(t, s, mfa.MaxEmailCodeFailures)
			},
			gen:    g1,
			at:     now,
			assert: refusedUnchanged,
		},
		{
			name:   "another generation is refused",
			setup:  func(t *testing.T, s *mfa.MemoryEnrolmentStore) { provenOn(t, s, "u-1", g1, now) },
			gen:    g2,
			at:     now,
			assert: refusedUnchanged,
		},
		{
			name:   "the nil generation is refused",
			setup:  func(t *testing.T, s *mfa.MemoryEnrolmentStore) { provenOn(t, s, "u-1", g1, now) },
			gen:    id.Nil,
			at:     now,
			assert: refusedUnchanged,
		},
		{
			name:   "an unproven device is refused",
			setup:  func(t *testing.T, s *mfa.MemoryEnrolmentStore) { pendingOn(t, s, "u-1", g1) },
			gen:    g1,
			at:     now,
			assert: refusedUnchanged,
		},
		{
			name: "a proof with no emailed code is refused",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
				pendingOn(t, s, "u-1", g1)
				ok, err := s.ProveDevice(t.Context(), "u-1", g1, 5, nil, time.Time{}, now)
				require.NoError(t, err)
				require.True(t, ok)
			},
			gen:    g1,
			at:     now,
			assert: refusedUnchanged,
		},
		{
			name:   "a code at its expiry is refused",
			setup:  func(t *testing.T, s *mfa.MemoryEnrolmentStore) { provenOn(t, s, "u-1", g1, now) },
			gen:    g1,
			at:     until,
			assert: refusedUnchanged,
		},
		{
			name:   "a code past its expiry is refused",
			setup:  func(t *testing.T, s *mfa.MemoryEnrolmentStore) { provenOn(t, s, "u-1", g1, now) },
			gen:    g1,
			at:     now.Add(11 * time.Minute),
			assert: refusedUnchanged,
		},
		{
			name: "a confirmed enrolment is refused",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
				provenOn(t, s, "u-1", g1, now)
				ok, err := s.Complete(t.Context(), "u-1", g1, now)
				require.NoError(t, err)
				require.True(t, ok)
			},
			gen:    g1,
			at:     now,
			assert: refusedUnchanged,
		},
		{
			name: "a code out of attempts and past its expiry stays on the enrolment",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
				provenOn(t, s, "u-1", g1, now)
				charge(t, s, mfa.MaxEmailCodeFailures)
			},
			gen: g1,
			at:  now.Add(11 * time.Minute),
			assert: func(t *testing.T, got result, err error) {
				refusedUnchanged(t, got, err)
				assert.Equal(t, []byte("123456"), got.after.EmailCode, "neither exhaustion nor expiry clears the code")
				assert.Equal(t, until, got.after.EmailCodeUntil, "neither exhaustion nor expiry clears its expiry")
			},
		},
		{
			name: "a code a later begin cleared is refused",
			setup: func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
				provenOn(t, s, "u-1", g1, now)
				pendingOn(t, s, "u-1", g2)
			},
			gen:    g1,
			at:     now,
			assert: refusedUnchanged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := mfa.NewMemoryEnrolmentStore()
			tc.setup(t, s)

			before := stored(t, s, "u-1")
			n, ok, err := s.ChargeEmailCode(t.Context(), "u-1", tc.gen, tc.at)

			tc.assert(t, result{count: n, charged: ok, before: before, after: stored(t, s, "u-1")}, err)
		})
	}

	t.Run("an unknown user is refused", func(t *testing.T) {
		t.Parallel()

		n, ok, err := mfa.NewMemoryEnrolmentStore().ChargeEmailCode(t.Context(), "nobody", g1, now)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Zero(t, n)
	})
}

// TestChargeEmailCodeRace releases 20 charges on one code at once: exactly
// MaxEmailCodeFailures of them are charged, so no more than that many
// presented codes could ever be compared.
func TestChargeEmailCodeRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g := id.MustParse("01920000-0000-7000-8000-000000000001")
	s := mfa.NewMemoryEnrolmentStore()
	provenOn(t, s, "u-1", g, now)

	const goroutines = 20

	var (
		wg      sync.WaitGroup
		charged atomic.Int64
		start   = make(chan struct{})
	)

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if _, ok, err := s.ChargeEmailCode(ctx, "u-1", g, now); err == nil && ok {
				charged.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(mfa.MaxEmailCodeFailures), charged.Load(), "one code, five comparisons at most")
	assert.Equal(t, mfa.MaxEmailCodeFailures, stored(t, s, "u-1").EmailCodeAttempts)
}

// TestChargeVerifyAttempt pins what the memory store adds to the suite's
// cases: the window end it returns and keeps is truncated to the microsecond,
// as a durable store's is, and the limit and window are the caller's.
func TestChargeVerifyAttempt(t *testing.T) {
	t.Parallel()

	precise := time.Date(2026, 9, 24, 10, 0, 0, 123456789, time.UTC)

	type result struct {
		until   time.Time
		charged bool
		after   mfa.Enrolment
	}

	type testCase struct {
		name string
		// setup prepares u-1's enrolment; the charge is then made for u-1 at
		// at with limit and window.
		setup  func(t *testing.T, s *mfa.MemoryEnrolmentStore)
		at     time.Time
		limit  int
		window time.Duration
		assert func(t *testing.T, s *mfa.MemoryEnrolmentStore, got result, err error)
	}

	chargeN := func(n int, at time.Time, limit int, window time.Duration) func(*testing.T, *mfa.MemoryEnrolmentStore) {
		return func(t *testing.T, s *mfa.MemoryEnrolmentStore) {
			t.Helper()
			confirmed(t, s, "u-1", 1000, at)

			for range n {
				_, ok, err := s.ChargeVerifyAttempt(t.Context(), "u-1", at, limit, window)
				require.NoError(t, err)
				require.True(t, ok)
			}
		}
	}

	cases := []testCase{
		{
			name:   "a new window ends at the charge plus the window, truncated to the microsecond",
			setup:  chargeN(0, precise, mfa.DefaultVerifyAttemptLimit, mfa.DefaultVerifyAttemptWindow),
			at:     precise,
			limit:  mfa.DefaultVerifyAttemptLimit,
			window: mfa.DefaultVerifyAttemptWindow,
			assert: func(t *testing.T, s *mfa.MemoryEnrolmentStore, got result, err error) {
				require.NoError(t, err)
				require.True(t, got.charged)

				want := time.Date(2026, 9, 24, 10, 15, 0, 123456000, time.UTC)
				assert.True(t, want.Equal(got.until), "until is %v, want %v", got.until, want)
				assert.True(t, want.Equal(got.after.VerifyWindowUntil), "stored window end is %v, want %v",
					got.after.VerifyWindowUntil, want)
				assert.Equal(t, 1, got.after.VerifyAttempts)

				gaveBack, err := s.RefundVerifyAttempt(t.Context(), "u-1", got.until)
				require.NoError(t, err)
				assert.True(t, gaveBack, "the window end a charge returns is the one its give-back matches")
			},
		},
		{
			name:   "a consumer limit and window are the ones charged against",
			setup:  chargeN(3, precise, 3, 10*time.Minute),
			at:     precise.Add(9 * time.Minute),
			limit:  3,
			window: 10 * time.Minute,
			assert: func(t *testing.T, _ *mfa.MemoryEnrolmentStore, got result, err error) {
				require.NoError(t, err)
				assert.False(t, got.charged, "a fourth charge within a limit of 3 is refused")
				assert.Equal(t, 3, got.after.VerifyAttempts)
				want := precise.Add(10 * time.Minute).Truncate(time.Microsecond)
				assert.True(t, want.Equal(got.after.VerifyWindowUntil), "stored window end is %v, want %v",
					got.after.VerifyWindowUntil, want)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := mfa.NewMemoryEnrolmentStore()
			tc.setup(t, s)

			until, ok, err := s.ChargeVerifyAttempt(t.Context(), "u-1", tc.at, tc.limit, tc.window)

			tc.assert(t, s, result{until: until, charged: ok, after: stored(t, s, "u-1")}, err)
		})
	}
}
