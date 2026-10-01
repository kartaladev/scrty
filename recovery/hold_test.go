package recovery_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

const cancelBase = "https://app.example.com/recovery/cancel"

// holdFor returns the options that hold every recovery for d.
func holdFor(d time.Duration) []recovery.Option {
	return []recovery.Option{recovery.WithDelay(d), recovery.WithCancelLink(cancelBase)}
}

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

// heldRecovery starts a recovery that must be held, and returns its hold.
func heldRecovery(ctx context.Context, t *testing.T, r *recovery.Recoverer, req recovery.Request) *recovery.Hold {
	t.Helper()

	res, err := r.Recover(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, res.Held)

	return res.Held
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
			opts: append(holdFor(72*time.Hour), recovery.WithCompletionWindow(time.Hour)),
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
