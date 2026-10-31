package recovery_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// riskOf returns a risk hook answering d and err, with the cancel link a hold
// needs.
func riskOf(d time.Duration, err error) []recovery.Option {
	return []recovery.Option{
		recovery.WithCancelLink(cancelBase),
		recovery.WithRisk(func(context.Context, recovery.RiskInput) (time.Duration, error) { return d, err }),
	}
}

// cancelToken reads the cancel token out of the link the only held notice
// carried.
func (e *completeEnv) cancelToken(t *testing.T) string {
	t.Helper()

	notices := e.out.heldNotices()
	require.Len(t, notices, 1)

	u, err := url.Parse(notices[0].link)
	require.NoError(t, err)

	tok := u.Query().Get(recovery.CancelLinkParam)
	require.NotEmpty(t, tok)

	return tok
}

func TestRecoverer_Hold(t *testing.T) {
	t.Parallel()

	errRisk := errors.New("risk service unreachable")
	thursday := monday1000.Add(72 * time.Hour)

	type testCase struct {
		name  string
		opts  []recovery.Option
		setup func(t *testing.T, e *completeEnv)
		ctx   func(ctx context.Context, e *completeEnv) context.Context
		// act runs the case; nil runs Recover once, over a saved and an
		// issued code.
		act    func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error)
		assert func(t *testing.T, e *completeEnv, res *recovery.Result, err error)
	}

	unchanged := func(t *testing.T, e *completeEnv) {
		t.Helper()
		assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, e.held.snapshot(), "the authenticators are unchanged")
		for _, sid := range e.prior {
			assert.True(t, e.loads(t, sid), "an earlier session still loads")
		}
	}
	finishAt := func(at time.Time) func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
		return func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
			h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
			e.clock.Advance(at.Sub(e.clock.Now()))

			return r.Finish(ctx, h.CompletionToken)
		}
	}
	priorTwo := func(t *testing.T, e *completeEnv) { e.prior = e.priorSessions(t, 2) }

	cases := []testCase{
		{
			name: "by default a recovery completes at once",
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Nil(t, res.Held)
				assert.NotNil(t, res.Session)
			},
		},
		{
			name:  "a fixed 72h delay holds the recovery, voiding only the saved set",
			opts:  holdFor(72 * time.Hour),
			setup: priorTwo,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Held)
				assert.NotEmpty(t, res.Held.CompletionToken)
				assert.True(t, res.Held.CompletableAt.Equal(thursday), "completable at %s", res.Held.CompletableAt)
				assert.Nil(t, res.Session, "no session is created")
				assert.Nil(t, res.Codes)

				unchanged(t, e)
				assert.Zero(t, e.held.removals())
				assert.Empty(t, e.out.recoveredNotices())

				notices := e.out.heldNotices()
				require.Len(t, notices, 1)
				assert.True(t, strings.HasPrefix(notices[0].link, cancelBase+"?"+recovery.CancelLinkParam+"="), notices[0].link)
				assert.NotContains(t, notices[0].link, res.Held.CompletionToken, "the link carries no completion token")
				assert.True(t, notices[0].until.Equal(thursday))
				assert.Equal(t, recovery.Notice{
					At:          monday1000,
					Removed:     []recovery.AuthenticatorRef{refTOTP, refEmail},
					CodesVoided: true,
					Repudiation: repudiation,
				}, notices[0].notice, "the held notice says the saved set was voided")

				sent := e.out.messages()
				require.Len(t, sent, 1)
				assert.Equal(t, anaUsername, sent[0].To)
				assert.Contains(t, sent[0].TextBody, notices[0].link)
				assert.NotContains(t, sent[0].TextBody, res.Held.CompletionToken)

				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]), "the proofs are spent at the start")
				n, err := e.codes.Remaining(t.Context(), anaID)
				require.NoError(t, err)
				assert.Zero(t, n.N, "the rest of the saved set is voided when the hold starts")
				for _, old := range e.saved[1:] {
					assert.False(t, e.savedUsable(t.Context(), t, old), "no code of the old set is usable during the hold")
				}
			},
		},
		{
			name: "finishing too early is refused, and the same token works after the hold",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))

				e.clock.Advance(48 * time.Hour) // Wednesday
				res, err := r.Finish(ctx, h.CompletionToken)
				require.ErrorIs(t, err, recovery.ErrNotYetCompletable)
				assert.Nil(t, res)
				unchanged(t, e)

				e.clock.Advance(24 * time.Hour) // Thursday

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.NotNil(t, res.Session)
			},
		},
		{
			name:  "finishing after the hold resets, revokes and confines",
			opts:  holdFor(72 * time.Hour),
			setup: priorTwo,
			act:   finishAt(thursday.Add(time.Hour)),
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				finished := thursday.Add(time.Hour)

				assert.Empty(t, e.held.snapshot(), "the authenticators are reset")
				for _, sid := range e.prior {
					assert.False(t, e.loads(t, sid), "an earlier session no longer loads")
				}

				require.NotNil(t, res.Session)
				s, err := e.sessions.Load(t.Context(), res.Session.ID)
				require.NoError(t, err)
				assert.Equal(t, session.MFARecoveryPending, s.MFA)
				assert.True(t, s.RecoveredAt.Equal(finished))
				assert.Len(t, res.Codes, 10, "the spent saved code's set is replaced at the finish")
				assert.Nil(t, res.Held)

				notices := e.out.recoveredNotices()
				require.Len(t, notices, 1)
				assert.True(t, notices[0].At.Equal(finished))
				assert.True(t, notices[0].CodesReplaced)

				at, ok, err := e.records.LatestCompletion(t.Context(), anaID)
				require.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, at.Equal(finished))
			},
		},
		{
			name: "the risk hook holds a risky recovery",
			opts: riskOf(48*time.Hour, nil),
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Held)
				assert.True(t, res.Held.CompletableAt.Equal(monday1000.Add(48*time.Hour)))
			},
		},
		{
			name: "the risk hook returning zero completes at once",
			opts: riskOf(0, nil),
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Nil(t, res.Held)
				assert.NotNil(t, res.Session)
			},
		},
		{
			name: "the hold is the longer of the delay and the risk hook",
			opts: append(holdFor(72*time.Hour),
				recovery.WithRisk(func(context.Context, recovery.RiskInput) (time.Duration, error) { return 96 * time.Hour, nil })),
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Held)
				assert.True(t, res.Held.CompletableAt.Equal(monday1000.Add(96*time.Hour)))
			},
		},
		{
			name: "a risk hook error refuses before anything is spent",
			opts: riskOf(time.Hour, errRisk),
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Empty(t, e.out.heldNotices())
			},
		},
		{
			name: "a login cancels the held recovery",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				require.NoError(t, r.CancelPending(ctx, anaID))

				e.clock.Advance(73 * time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				unchanged(t, e)
			},
		},
		{
			name: "the cancel link cancels, and notifies that the voided set stays void",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))

				e.clock.Advance(time.Hour)
				r.Cancel(ctx, e.cancelToken(t))

				e.clock.Advance(72 * time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				unchanged(t, e)

				n, err := e.codes.Remaining(t.Context(), anaID)
				require.NoError(t, err)
				assert.Zero(t, n.N, "the saved set is void")

				assert.Equal(t, []recovery.Notice{{
					At:          monday1000.Add(time.Hour),
					CodesVoided: true,
					Repudiation: repudiation,
				}}, e.out.cancelledNotices())

				sent := e.out.messages()
				require.Len(t, sent, 2, "the held notice, then the cancelled one")
				assert.Equal(t, anaUsername, sent[1].To)
			},
		},
		{
			name: "a cancel with no saved code spent leaves the set and still notifies",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, issuedAndPasswordReq(e))
				r.Cancel(ctx, e.cancelToken(t))
				e.clock.Advance(73 * time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved set was never touched")
				assert.Equal(t, []recovery.Notice{{At: monday1000, Repudiation: repudiation}}, e.out.cancelledNotices())

				sent := e.out.messages()
				require.Len(t, sent, 2, "the held notice, then the cancelled one")
				assert.Equal(t, anaUsername, sent[1].To)
			},
		},
		{
			name: "a finish token given to Cancel does nothing",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				r.Cancel(ctx, h.CompletionToken)
				e.clock.Advance(73 * time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err, "the finish still succeeds")
				assert.NotNil(t, res.Session)
				assert.Empty(t, e.out.cancelledNotices())
			},
		},
		{
			name: "a cancel token given to Finish is refused, and still cancels",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.clock.Advance(73 * time.Hour)

				res, err := r.Finish(ctx, e.cancelToken(t))
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)

				r.Cancel(ctx, e.cancelToken(t))

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Len(t, e.out.cancelledNotices(), 1)
			},
		},
		{
			name: "a finish past the completion window is refused",
			opts: holdFor(72 * time.Hour),
			act:  finishAt(thursday.Add(24*time.Hour + time.Second)),
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				unchanged(t, e)
			},
		},
		{
			name: "a configured completion window replaces the default",
			opts: append(holdFor(72*time.Hour), recovery.WithHoldCompletionWindow(time.Hour)),
			act:  finishAt(thursday.Add(time.Hour + time.Second)),
			assert: func(t *testing.T, _ *completeEnv, _ *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
			},
		},
		{
			name: "the plan is recomputed at the finish over what is held then",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.held.add(refSMS) // enrolled during the hold
				e.clock.Advance(73 * time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Empty(t, e.held.snapshot(), "the enrolment added during the hold is removed too")

				notices := e.out.recoveredNotices()
				require.Len(t, notices, 1)
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail, refSMS}, notices[0].Removed)
			},
		},
		{
			name: "in the reported mode, a reported loss the user no longer holds at the finish is dropped",
			opts: append(holdFor(72*time.Hour), recovery.WithResetReported()),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				req := savedAndIssuedReq(e)
				req.Lost = []string{refTOTP.String(), refEmail.String()}
				h := heldRecovery(ctx, t, r, req)

				e.held.drop(refEmail) // removed by the user during the hold
				e.held.add(refSMS)    // enrolled during the hold, never reported
				e.clock.Advance(73 * time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.Equal(t, []recovery.AuthenticatorRef{refSMS}, e.held.snapshot(),
					"the reported loss still held is removed, and the unreported one stays")

				notices := e.out.recoveredNotices()
				require.Len(t, notices, 1)
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP}, notices[0].Removed)
			},
		},
		{
			name: "a second finish is refused",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.clock.Advance(73 * time.Hour)

				_, err := r.Finish(ctx, h.CompletionToken)
				require.NoError(t, err)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				assert.Len(t, e.out.recoveredNotices(), 1)
			},
		},
		{
			name: "a malformed completion token is refused",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, _ *testing.T, _ *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				return r.Finish(ctx, "not-a-token")
			},
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
			},
		},
		{
			name: "Finish with no hold configured is refused",
			act: func(ctx context.Context, _ *testing.T, _ *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				return r.Finish(ctx, "not-a-token")
			},
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
			},
		},
		{
			name: "a user no longer active at the finish is refused, and the recovery stays pending",
			opts: holdFor(72 * time.Hour),
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.clock.Advance(73 * time.Hour)

				e.inactive.Store(true)
				res, err := r.Finish(ctx, h.CompletionToken)
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				unchanged(t, e)

				e.inactive.Store(false)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err, "nothing was spent by the refusal")
				assert.NotNil(t, res.Session)
			},
		},
		{
			name: "a client hanging up mid-finish does not leave it half done",
			opts: holdFor(72 * time.Hour),
			ctx: func(ctx context.Context, e *completeEnv) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				e.held.onRemove = cancel

				return ctx
			},
			act: finishAt(thursday.Add(time.Hour)),
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.Len(t, e.out.recoveredNotices(), 1)
				assert.Len(t, e.out.messages(), 2, "the held notice and the recovered one")
				assert.Empty(t, e.out.ctxErrs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			r := e.recoverer(t, tc.opts...)

			if tc.setup != nil {
				tc.setup(t, e)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, e)
			}

			var (
				res *recovery.Result
				err error
			)
			if tc.act != nil {
				res, err = tc.act(ctx, t, e, r)
			} else {
				res, err = r.Recover(ctx, savedAndIssuedReq(e))
			}

			tc.assert(t, e, res, err)
			assertCleanLogs(t, e, res)
		})
	}
}

func TestRecoverer_Holds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []recovery.Option
		assert func(t *testing.T, holds bool)
	}

	cases := []testCase{
		{name: "no hold", assert: func(t *testing.T, holds bool) { assert.False(t, holds) }},
		{name: "a delay", opts: holdFor(time.Hour), assert: func(t *testing.T, holds bool) { assert.True(t, holds) }},
		{name: "a risk hook", opts: riskOf(0, nil), assert: func(t *testing.T, holds bool) { assert.True(t, holds) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			tc.assert(t, e.recoverer(t, tc.opts...).Holds())
		})
	}
}

func TestRecoverer_CancelPending(t *testing.T) {
	t.Parallel()

	errStore := errors.New("record store unreachable")

	type testCase struct {
		name    string
		records func(e *completeEnv) recovery.RecordStore
		assert  func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:    "nothing pending is not an error",
			records: func(e *completeEnv) recovery.RecordStore { return e.records },
			assert:  func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "a store failure is returned behind fixed text, so the login fails closed",
			records: func(e *completeEnv) recovery.RecordStore {
				m := NewMockRecordStore(e.ctrl)
				m.EXPECT().CancelPending(gomock.Any(), anaID, monday1000).Return(0, errStore)

				return m
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errStore)
				assert.NotContains(t, err.Error(), "unreachable")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			d := e.completeDeps()
			d.Records = tc.records(e)

			r, err := recovery.NewRecoverer(d, e.recovererOpts(holdFor(time.Hour)...)...)
			require.NoError(t, err)

			tc.assert(t, r.CancelPending(t.Context(), anaID))
		})
	}
}

// faultyHold builds a recoverer that holds every recovery for 72 hours, over
// a record store and a hold token store that fail when e.faults says so, and
// a fixed record identifier.
func (e *completeEnv) faultyHold(t *testing.T, extra ...recovery.Option) (*recovery.Recoverer, *recordingTokenStore, id.ID) {
	t.Helper()

	tokens := &recordingTokenStore{MemoryStore: must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(e.clock))), f: e.faults}
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

// TestRecoverer_FinishFailures stands apart from TestRecoverer_Hold because its
// recoverer runs over the fault-injecting stores of faultyHold.
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
			name:   "a record store that finds no record and no error is refused as missing",
			arm:    func(e *completeEnv) { e.faults.arm(faultRecordsFindNil, errStore) },
			disarm: func(e *completeEnv) { e.faults.arm(faultRecordsFindNil, nil) },
			assert: refusedThenRedeemable(refused),
		},
		{
			name:   "a user loader answering for another user is refused, and the record stays pending",
			arm:    func(e *completeEnv) { e.otherUser.Store(true) },
			disarm: func(e *completeEnv) { e.otherUser.Store(false) },
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

// TestRecoverer_HoldStartFailures stands apart from TestRecoverer_Hold because
// its recoverer runs over the fault-injecting stores of faultyHold.
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

// TestRecoverer_CancelFailures stands apart from TestRecoverer_Hold because its
// recoverer runs over the fault-injecting stores of faultyHold.
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
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Recoverer, rid id.ID, tokens *recordingTokenStore) {
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

// TestRecoverer_HoldOverrides stands apart from TestRecoverer_Hold because its
// recoverer runs over the consumer's stores of faultyHold.
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

// TestRecoverer_FinishCancelRace releases 8 finishes and 8 cancels of one
// held recovery at once, after its hold, over the real in-memory stores.
// Exactly one of the sixteen may take effect: a finish that returns a result,
// or a cancel, seen through the Cancelled notice only the effective cancel
// sends. Run it with -race -count=3.
//
// It stands apart from TestRecoverer_Hold because it runs sixteen goroutines
// against one held recovery.
func TestRecoverer_FinishCancelRace(t *testing.T) {
	t.Parallel()

	const racers = 8

	e := newCompleteEnv(t)
	r := e.recoverer(t, holdFor(72*time.Hour)...)

	h := heldRecovery(t.Context(), t, r, savedAndIssuedReq(e))
	cancelToken := e.cancelToken(t)
	e.clock.Advance(73 * time.Hour)

	var (
		start    = make(chan struct{})
		wg       sync.WaitGroup
		finished atomic.Int32
		refused  atomic.Int32
		others   atomic.Int32
	)

	for range racers {
		wg.Go(func() {
			<-start

			_, err := r.Finish(t.Context(), h.CompletionToken)

			switch {
			case err == nil:
				finished.Add(1)
			case assert.ErrorIs(t, err, recovery.ErrRefused):
				refused.Add(1)
			default:
				others.Add(1)
			}
		})
		wg.Go(func() {
			<-start

			r.Cancel(t.Context(), cancelToken)
		})
	}

	close(start)
	wg.Wait()

	cancelled := len(e.out.cancelledNotices())
	assert.Equal(t, 1, int(finished.Load())+cancelled, "exactly one finish or cancel takes effect")
	assert.Equal(t, int32(racers)-finished.Load(), refused.Load(), "every other finish is refused")
	assert.Zero(t, others.Load())

	_, completed, err := e.records.LatestCompletion(t.Context(), anaID)
	require.NoError(t, err)
	assert.Equal(t, finished.Load() == 1, completed, "the record is completed only when a finish won")
	assert.Len(t, e.out.recoveredNotices(), int(finished.Load()))

	if cancelled == 1 {
		assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, e.held.snapshot(), "a cancel changes nothing")
	} else {
		assert.Empty(t, e.held.snapshot())
	}
}
