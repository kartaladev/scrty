package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// fixedIDs is a consumer's identifier generator that always answers rid.
type fixedIDs struct{ rid id.ID }

func (g fixedIDs) NewID() (id.ID, error) { return g.rid, nil }

// faultyHold builds a recoverer that holds every recovery for 72 hours, over
// a record store and a hold token store that fail when e.faults says so, and
// a fixed record identifier.
func (e *completeEnv) faultyHold(t *testing.T, extra ...recovery.Option) (*recovery.Recoverer, *recordingTokenStore, id.ID) {
	t.Helper()

	tokens := &recordingTokenStore{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(e.clock)), f: e.faults}
	rid := newRecordID(t)

	d := e.completeDeps()
	d.Records = faultyRecordStore{RecordStore: e.records, f: e.faults}

	opts := append(holdFor(72*time.Hour), recovery.WithHoldTokenStore(tokens), recovery.WithIDGenerator(fixedIDs{rid}))
	r, err := recovery.NewRecoverer(d, e.recovererOpts(append(opts, extra...)...)...)
	require.NoError(t, err)

	return r, tokens, rid
}

// assertPending checks that the record rid is neither completed nor
// cancelled.
func (e *completeEnv) assertPending(t *testing.T, rid id.ID) {
	t.Helper()

	rec, err := e.records.Find(t.Context(), rid)
	require.NoError(t, err)
	assert.True(t, rec.CompletedAt.IsZero(), "the record is not completed")
	assert.True(t, rec.CancelledAt.IsZero(), "the record is not cancelled")
}

func TestRecoverer_FinishFailures(t *testing.T) {
	t.Parallel()

	errStore := errors.New("store unreachable")

	type testCase struct {
		name   string
		arm    func(e *completeEnv)
		disarm func(e *completeEnv)
		assert func(t *testing.T, e *completeEnv, r *recovery.Recoverer, rid id.ID, token string, res *recovery.Result, err error)
	}

	// refusedThenRedeemable checks that a failed finish changed nothing, and
	// that the same token finishes the recovery once the fault is gone.
	refusedThenRedeemable := func(check func(t *testing.T, err error)) func(
		*testing.T, *completeEnv, *recovery.Recoverer, id.ID, string, *recovery.Result, error,
	) {
		return func(t *testing.T, e *completeEnv, r *recovery.Recoverer, rid id.ID, token string, res *recovery.Result, err error) {
			check(t, err)
			assert.Nil(t, res)
			e.assertPending(t, rid)
			assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, e.held.snapshot(), "nothing is reset")
			assert.Empty(t, e.out.recoveredNotices())

			again, err := r.Finish(t.Context(), token)
			require.NoError(t, err, "the token is still good and the record still pending")
			assert.NotNil(t, again.Session)
		}
	}
	returned := func(t *testing.T, err error) {
		require.ErrorIs(t, err, errStore)
		require.NotErrorIs(t, err, recovery.ErrRefused)
		assert.NotContains(t, err.Error(), "unreachable", "the store's text is not returned")
	}
	refused := func(t *testing.T, err error) { require.ErrorIs(t, err, recovery.ErrRefused) }

	cases := []testCase{
		{
			name:   "a record store outage at the find is returned",
			arm:    func(e *completeEnv) { e.faults.arm(faultRecordsFind, errStore) },
			disarm: func(e *completeEnv) { e.faults.arm(faultRecordsFind, nil) },
			assert: refusedThenRedeemable(returned),
		},
		{
			name:   "a record store outage at the completion is returned",
			arm:    func(e *completeEnv) { e.faults.arm(faultRecordsComplete, errStore) },
			disarm: func(e *completeEnv) { e.faults.arm(faultRecordsComplete, nil) },
			assert: refusedThenRedeemable(returned),
		},
		{
			name:   "a completion that loses its conditional write is refused",
			arm:    func(e *completeEnv) { e.faults.arm(faultRecordsNoComplete, errStore) },
			disarm: func(e *completeEnv) { e.faults.arm(faultRecordsNoComplete, nil) },
			assert: refusedThenRedeemable(refused),
		},
		{
			name:   "a user lookup failure is returned, and the record stays pending",
			arm:    func(e *completeEnv) { e.failLookup(errStore) },
			disarm: func(e *completeEnv) { e.failLookup(nil) },
			assert: refusedThenRedeemable(func(t *testing.T, err error) {
				require.ErrorIs(t, err, errStore)
				require.NotErrorIs(t, err, recovery.ErrRefused)
			}),
		},
		{
			name:   "a user no longer found is refused, and the record stays pending",
			arm:    func(e *completeEnv) { e.failLookup(identity.ErrUserNotFound) },
			disarm: func(e *completeEnv) { e.failLookup(nil) },
			assert: refusedThenRedeemable(refused),
		},
		{
			name:   "a listing failure while planning is returned, and the record stays pending",
			arm:    func(e *completeEnv) { e.held.failListing(errStore) },
			disarm: func(e *completeEnv) { e.held.failListing(nil) },
			assert: refusedThenRedeemable(func(t *testing.T, err error) {
				require.ErrorIs(t, err, errStore)
				require.NotErrorIs(t, err, recovery.ErrRefused)
			}),
		},
		{
			name:   "a token that cannot be consumed is ignored, and the record still refuses a reuse",
			arm:    func(e *completeEnv) { e.faults.arm(faultTokensConsume, errStore) },
			disarm: func(e *completeEnv) { e.faults.arm(faultTokensConsume, nil) },
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer, rid id.ID, token string, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.NotNil(t, res.Session)
				assert.Empty(t, e.held.snapshot(), "the reset ran")

				rec, err := e.records.Find(t.Context(), rid)
				require.NoError(t, err)
				assert.False(t, rec.CompletedAt.IsZero(), "the record is completed")

				_, err = r.Finish(t.Context(), token)
				require.ErrorIs(t, err, recovery.ErrRefused, "the unconsumed token finishes nothing twice")
				assert.Len(t, e.out.recoveredNotices(), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			r, _, rid := e.faultyHold(t)

			h := heldRecovery(t.Context(), t, r, savedAndIssuedReq(e))
			e.clock.Advance(73 * time.Hour)

			tc.arm(e)
			res, err := r.Finish(t.Context(), h.CompletionToken)
			tc.disarm(e)

			tc.assert(t, e, r, rid, h.CompletionToken, res, err)
			assertCleanLogs(t, e, res)
		})
	}
}

func TestRecoverer_HoldStartFailures(t *testing.T) {
	t.Parallel()

	errStore := errors.New("store unreachable")

	type testCase struct {
		name  string
		fault string
		// assert checks what the steps before the failure left behind.
		assert func(t *testing.T, e *completeEnv, tokens *recordingTokenStore)
	}

	pendingRecords := func(t *testing.T, e *completeEnv) int {
		t.Helper()

		n, err := e.records.CancelPending(t.Context(), anaID, e.clock.Now())
		require.NoError(t, err)

		return n
	}

	cases := []testCase{
		{
			name:  "a record insert failure is returned before any token is issued",
			fault: faultRecordsInsert,
			assert: func(t *testing.T, e *completeEnv, tokens *recordingTokenStore) {
				assert.Empty(t, tokens.purposes(), "no hold token is issued")
				assert.Zero(t, pendingRecords(t, e))
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[1]), "the saved set is not voided")
			},
		},
		{
			name:  "a hold token that cannot be issued is returned before the set is voided",
			fault: faultTokensInsert,
			assert: func(t *testing.T, e *completeEnv, _ *recordingTokenStore) {
				assert.Equal(t, 1, pendingRecords(t, e), "the pending record was written")
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[1]), "the saved set is not voided")
			},
		},
		{
			name:  "a saved set that cannot be voided is returned before the notice",
			fault: faultCodesDeleteUser,
			assert: func(t *testing.T, e *completeEnv, tokens *recordingTokenStore) {
				assert.Len(t, tokens.purposes(), 2, "both hold tokens were issued")
				assert.Equal(t, 1, pendingRecords(t, e), "the pending record was written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			r, tokens, _ := e.faultyHold(t)
			e.faults.arm(tc.fault, errStore)

			res, err := r.Recover(t.Context(), savedAndIssuedReq(e))

			require.ErrorIs(t, err, errStore)
			assert.NotContains(t, err.Error(), "unreachable", "the store's text is not returned")
			assert.Nil(t, res, "no completion token is handed out")
			assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the proofs stay spent")
			assert.Empty(t, e.out.heldNotices(), "no held notice")
			assert.Empty(t, e.out.messages())
			assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, e.held.snapshot(), "nothing is reset")

			tc.assert(t, e, tokens)
			assertCleanLogs(t, e, res)
		})
	}
}

func TestRecoverer_CancelFailures(t *testing.T) {
	t.Parallel()

	errStore := errors.New("store unreachable")

	type testCase struct {
		name   string
		arm    func(e *completeEnv)
		disarm func(e *completeEnv)
		assert func(t *testing.T, e *completeEnv, r *recovery.Recoverer, rid id.ID, tokens *recordingTokenStore)
	}

	cases := []testCase{
		{
			name:   "a record store failure cancels nothing, sends no notice, and leaves the token good",
			arm:    func(e *completeEnv) { e.faults.arm(faultRecordsCancel, errStore) },
			disarm: func(e *completeEnv) { e.faults.arm(faultRecordsCancel, nil) },
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer, rid id.ID, tokens *recordingTokenStore) {
				assert.Empty(t, e.out.cancelledNotices())
				e.assertPending(t, rid)
				assert.Empty(t, tokens.consumedPurposes(), "the cancel token is not consumed")

				r.Cancel(t.Context(), e.cancelToken(t))
				assert.Len(t, e.out.cancelledNotices(), 1, "the same link cancels once the store is back")
			},
		},
		{
			name:   "a user lookup failure still cancels, but sends no notice",
			arm:    func(e *completeEnv) { e.failLookup(errStore) },
			disarm: func(e *completeEnv) { e.failLookup(nil) },
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer, rid id.ID, tokens *recordingTokenStore) {
				assert.Empty(t, e.out.cancelledNotices())
				assert.Len(t, e.out.messages(), 1, "only the held notice")
				assert.Equal(t, []string{recovery.CancelTokenPurpose}, tokens.consumedPurposes())

				rec, err := e.records.Find(t.Context(), rid)
				require.NoError(t, err)
				assert.False(t, rec.CancelledAt.IsZero(), "the record is cancelled")
				assert.Contains(t, e.logs.String(), "recovery: the user could not be loaded for the notice")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			r, tokens, rid := e.faultyHold(t)
			heldRecovery(t.Context(), t, r, issuedAndPasswordReq(e))

			tc.arm(e)
			r.Cancel(t.Context(), e.cancelToken(t))
			tc.disarm(e)

			tc.assert(t, e, r, rid, tokens)
			assertCleanLogs(t, e, nil)
		})
	}
}

func TestRecoverer_HoldOverrides(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// act runs the case with the consumer's store and generator wired.
		act    func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer)
		assert func(t *testing.T, e *completeEnv, rid id.ID, tokens *recordingTokenStore)
	}

	cases := []testCase{
		{
			name: "the consumer's generator names the held record",
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				heldRecovery(ctx, t, r, savedAndIssuedReq(e))
			},
			assert: func(t *testing.T, e *completeEnv, rid id.ID, _ *recordingTokenStore) {
				rec, err := e.records.Find(t.Context(), rid)
				require.NoError(t, err)
				assert.Equal(t, anaID, rec.User)
			},
		},
		{
			name: "the consumer's token store receives both hold tokens, and the finish consumes its own",
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.clock.Advance(73 * time.Hour)

				_, err := r.Finish(ctx, h.CompletionToken)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, _ *completeEnv, rid id.ID, tokens *recordingTokenStore) {
				assert.Equal(t, [][2]string{
					{recovery.FinishTokenPurpose, rid.String()},
					{recovery.CancelTokenPurpose, rid.String()},
				}, tokens.purposes())
				assert.Equal(t, []string{recovery.FinishTokenPurpose}, tokens.consumedPurposes())
			},
		},
		{
			name: "the consumer's token store sees the cancel consume its own token",
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				r.Cancel(ctx, e.cancelToken(t))
			},
			assert: func(t *testing.T, _ *completeEnv, _ id.ID, tokens *recordingTokenStore) {
				assert.Equal(t, []string{recovery.CancelTokenPurpose}, tokens.consumedPurposes())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			r, tokens, rid := e.faultyHold(t)

			tc.act(t.Context(), t, e, r)

			tc.assert(t, e, rid, tokens)
		})
	}
}

// TestRecoverer_IDGenerator pins that a consumer's generator names a record
// that completes at once, as well as a held one.
func TestRecoverer_IDGenerator(t *testing.T) {
	t.Parallel()

	e := newCompleteEnv(t)
	rid := newRecordID(t)
	r := e.recoverer(t, recovery.WithIDGenerator(fixedIDs{rid}))

	_, err := r.Recover(t.Context(), savedAndIssuedReq(e))
	require.NoError(t, err)

	rec, err := e.records.Find(t.Context(), rid)
	require.NoError(t, err)
	assert.Equal(t, anaID, rec.User)
	assert.True(t, rec.CompletedAt.Equal(monday1000))
}
