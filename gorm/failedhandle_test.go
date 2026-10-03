package gorm

import (
	"context"
	"errors"
	"testing"
	"time"

	gormdb "gorm.io/gorm"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// errBeginFailed is the failure a caller's handle carries, as a Begin that
// failed leaves it.
var errBeginFailed = errors.New("begin failed")

// TestStores_FailedHandleIsAnError pins that every gorm store operation run on
// a caller's handle that already carries an error returns an error wrapping
// it, runs no statement, and does not panic.
func TestStores_FailedHandleIsAnError(t *testing.T) {
	t.Parallel()

	// handleSource says where the errored handle rides.
	type handleSource int
	const (
		viaWithTx   handleSource = iota // a transaction attached with WithTx
		viaResolver                     // a transaction from a TxResolver
		viaBase                         // the base handle, with no transaction attached
	)

	type testCase struct {
		name   string
		source handleSource
		call   func(ctx context.Context, cfg *config) error
		assert func(t *testing.T, err error)
	}

	wrapsFailure := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		assert.ErrorIs(t, err, errBeginFailed)
	}

	cases := []testCase{
		{
			name: "enrolment charge",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&enrolmentStore{c: cfg}).ChargeVerifyAttempt(ctx, "u", time.Now(), 5, time.Minute)
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "enrolment give-back",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&enrolmentStore{c: cfg}).RefundVerifyAttempt(ctx, "u", time.Now())
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "recovery record latest completion",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&RecoveryRecordStore{c: cfg}).LatestCompletion(ctx, "u")
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "recovery code match",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Match(ctx, "u", []byte("digest"))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "passkey handle assign",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&PasskeyHandleStore{c: cfg}).Assign(ctx, "u", make([]byte, passkey.HandleSize))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "passkey user for handle",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&PasskeyHandleStore{c: cfg}).UserFor(ctx, make([]byte, passkey.HandleSize))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "passkey credential charge, through returning",
			call: func(ctx context.Context, cfg *config) error {
				_, _, err := (&PasskeyCredentialStore{c: cfg}).ChargeEmailAttempt(ctx, "u", id.ID{1}, time.Now())
				return err
			},
			assert: wrapsFailure,
		},
		{
			name: "a builder-chain operation",
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Remaining(ctx, "u")
				return err
			},
			assert: wrapsFailure,
		},
		{
			name:   "a resolver's handle carrying an error",
			source: viaResolver,
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Match(ctx, "u", []byte("digest"))
				return err
			},
			assert: wrapsFailure,
		},
		{
			name:   "the base handle carrying an error, with no transaction attached",
			source: viaBase,
			call: func(ctx context.Context, cfg *config) error {
				_, err := (&RecoveryCodeStore{c: cfg}).Match(ctx, "u", []byte("digest"))
				return err
			},
			assert: wrapsFailure,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base, _ := fakeDB(t, "base")
			tx, _ := fakeDB(t, "tx")
			_ = tx.AddError(errBeginFailed) // the returned error is the one just added

			ctx := t.Context()
			var opts []Option
			switch tc.source {
			case viaWithTx:
				ctx = WithTx(ctx, tx)
			case viaResolver:
				opts = []Option{WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return tx, true })}
			case viaBase:
				// Construction refuses an errored base, so the error is set after it:
				// a base that fails later, with nothing attached.
				_, err := newConfig(tx, nil)
				require.ErrorIs(t, err, ErrConfig)
				require.ErrorIs(t, err, errBeginFailed)
			}
			cfg, err := newConfig(base, opts, optIDGenerator, optClock, optResealOnRead)
			require.NoError(t, err)
			if tc.source == viaBase {
				_ = base.AddError(errBeginFailed)
			}

			var got error
			require.NotPanics(t, func() { got = tc.call(ctx, cfg) })
			tc.assert(t, got)
		})
	}
}
