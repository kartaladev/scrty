package gorm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A caller's transaction handle whose Begin failed carries its error. Each
// verification-attempt operation on it must report a store failure, never
// panic.
func TestEnrolmentStore_ChargeVerifyAttemptOnFailedTxReturnsError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		call   func(ctx context.Context, t *testing.T, s *enrolmentStore) error
		assert func(t *testing.T, err error)
	}

	failedTx := func(t *testing.T, err error) {
		require.Error(t, err)
		assert.ErrorContains(t, err, "begin failed")
	}

	cases := []testCase{
		{
			name: "charge",
			call: func(ctx context.Context, t *testing.T, s *enrolmentStore) error {
				_, ok, err := s.ChargeVerifyAttempt(ctx, "u", time.Now(), 5, time.Minute)
				assert.False(t, ok)
				return err
			},
			assert: func(t *testing.T, err error) { failedTx(t, err) },
		},
		{
			name: "give back",
			call: func(ctx context.Context, t *testing.T, s *enrolmentStore) error {
				ok, err := s.RefundVerifyAttempt(ctx, "u", time.Now())
				assert.False(t, ok)
				return err
			},
			assert: func(t *testing.T, err error) { failedTx(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base, _ := fakeDB(t, "base")
			tx, _ := fakeDB(t, "tx")
			_ = tx.AddError(errors.New("begin failed")) // the returned error is the one just added
			cfg, err := newConfig(base, nil, optIDGenerator, optClock, optResealOnRead)
			require.NoError(t, err)
			s := &enrolmentStore{c: cfg}

			var got error
			require.NotPanics(t, func() {
				got = tc.call(WithTx(t.Context(), tx), t, s)
			})
			tc.assert(t, got)
		})
	}
}
