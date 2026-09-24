package mfa_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
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
