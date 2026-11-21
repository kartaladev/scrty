package password_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// failingEncoder is a consumer's Encoder whose Encode answers err. It reads
// like plainEncoder everywhere else. It is a stub, not a generated mock,
// because the rows only need one fixed answer from one method.
type failingEncoder struct {
	plainEncoder

	err error
}

func (e failingEncoder) Encode(string) ([]byte, error) { return nil, e.err }

// TestPortErrors_Encoder pins that Change reads the consumer Encoder's error
// through the boundary sanitizer: a hostile error takes the plain
// encoder-failure branch and never reads as a too-long refusal.
func TestPortErrors_Encoder(t *testing.T) {
	eachPortErrRow(t, func(t *testing.T, row portErrRow) {
		def := swapDefaultLogger(t)
		pol := &recordingHandler{}

		p, err := password.NewPolicy(
			password.WithEncoder(failingEncoder{err: row.err()}),
			password.WithPolicyLogger(slog.New(pol)),
		)
		require.NoError(t, err)

		w := &recordingWrite{}
		got := within(t, func() error {
			return p.Change(t.Context(), &identity.Details{ID: "u1"}, p9, w.write)
		})

		require.Error(t, got)
		assert.Zero(t, w.calls, "a failed encode writes nothing")

		// The outcome is the plain outage's: the encoder's failure, not a
		// refusal of the candidate.
		assert.False(t, isWithin(t, got, password.ErrPasswordRejected), "errors.Is password.ErrPasswordRejected")
		assert.False(t, isWithin(t, got, password.ErrTooLong), "errors.Is password.ErrTooLong")

		var rejected password.RejectedError

		assert.False(t, errors.As(got, &rejected), "the failure is not a RejectedError")
		assert.NotContains(t, got.Error(), "secret-hash")

		wantRecords(t, row, pol)
		assert.Zero(t, abortRecords(def), "the record goes to the policy's logger, not the default")

		if row.hostile {
			assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
		}
	})
}

// TestPolicy_Change_EncoderTooLong pins that an Encode error a walk can read
// keeps its branch: ErrTooLong, bare or wrapped, is the user's too-long
// refusal, and a cancelled context changes nothing about it.
func TestPolicy_Change_EncoderTooLong(t *testing.T) {
	t.Parallel()

	errDown := errors.New("encoder: down")

	type testCase struct {
		name   string
		err    error
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, err error, w *recordingWrite)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	tooLong := func(t *testing.T, err error, w *recordingWrite) {
		t.Helper()

		var rejected password.RejectedError

		require.ErrorAs(t, err, &rejected)
		assert.Equal(t, password.RuleTooLong, rejected.Rule)
		assert.Zero(t, w.calls)
	}

	cases := []testCase{
		{name: "bare ErrTooLong", err: password.ErrTooLong, assert: tooLong},
		{name: "wrapped ErrTooLong", err: fmt.Errorf("encode: %w", password.ErrTooLong), assert: tooLong},
		{
			name: "plain failure is returned as it is",
			err:  errDown,
			assert: func(t *testing.T, err error, w *recordingWrite) {
				require.ErrorIs(t, err, errDown)
				assert.NotErrorIs(t, err, password.ErrPasswordRejected)
				assert.Zero(t, w.calls)
			},
		},
		{
			name: "cancelled context still refuses too long",
			err:  password.ErrTooLong,
			ctx:  cancelled,
			assert: func(t *testing.T, err error, w *recordingWrite) {
				if err != nil && errors.Is(err, context.Canceled) {
					return // Check honoured the cancellation first: nothing was encoded.
				}

				tooLong(t, err, w)
			},
		},
		{
			name: "cancelled context with a hostile error stays an encoder failure",
			err:  &hostileCycleOne{},
			ctx:  cancelled,
			assert: func(t *testing.T, err error, w *recordingWrite) {
				require.Error(t, err)
				assert.False(t, isWithin(t, err, password.ErrPasswordRejected), "errors.Is password.ErrPasswordRejected")
				assert.Zero(t, w.calls)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(
				password.WithEncoder(failingEncoder{err: tc.err}),
				password.WithPolicyLogger(slog.New(&recordingHandler{})),
			)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			w := &recordingWrite{}
			got := within(t, func() error {
				return p.Change(ctx, &identity.Details{ID: "u1"}, p9, w.write)
			})
			tc.assert(t, got, w)
		})
	}
}
