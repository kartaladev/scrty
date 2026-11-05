package recovery_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// The log lines a revocation failure writes, by level.
const (
	grantsFailedError = `level=ERROR msg="recovery: the user's application grants could not be revoked"`
	grantsFailedDebug = `level=DEBUG msg="recovery: the user's application grants could not be revoked"`
)

// errGrantStore is what a revoker's store fails with. Its text must reach
// neither the caller's error text nor the logs.
var errGrantStore = errors.New("grant store secret text")

// revocationSeen is what stood when the revoker was called.
type revocationSeen struct {
	savedUsable bool
	priorLoads  bool
}

// revocationWorld is one case's recovery, with a revoker whose failure position
// the case sets.
type revocationWorld struct {
	e     *completeEnv
	r     *recovery.Recoverer
	own   *recoveryEvents
	rid   id.ID
	prior []string

	mu   sync.Mutex
	seen []revocationSeen
	// verified is every MFA code the method was asked to verify, and
	// revokedAtVerify how many revocations had run by then, at each.
	verified        []string
	revokedAtVerify []int
}

// expectMFA makes ana hold TOTP, answered by verify. It records what it is
// asked, so a case can see the order against the revoker.
func (w *revocationWorld) expectMFA(verify func(code string) error) {
	w.e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil).AnyTimes()
	w.e.totp.EXPECT().Verify(gomock.Any(), anaID, gomock.Any()).DoAndReturn(
		func(_ context.Context, _ identity.UserID, code []byte) error {
			w.mu.Lock()
			w.verified = append(w.verified, string(code))
			w.revokedAtVerify = append(w.revokedAtVerify, len(w.seen))
			w.mu.Unlock()

			return verify(string(code))
		}).AnyTimes()
}

// verifications reports the MFA codes verified, and the revocations that had run
// by each.
func (w *revocationWorld) verifications() ([]string, []int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]string(nil), w.verified...), append([]int(nil), w.revokedAtVerify...)
}

// loads reports whether the session with this identifier still loads.
func (w *revocationWorld) loads(ctx context.Context, sid string) bool {
	_, err := w.e.sessions.Load(ctx, sid)

	return err == nil
}

// calls reports how many times the revoker was called.
func (w *revocationWorld) calls() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.seen)
}

// seenAt reports what stood at each call, in order.
func (w *revocationWorld) seenAt() []revocationSeen {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]revocationSeen(nil), w.seen...)
}

// revocationScript sets what one case's revoker does. Calls are counted from 1
// across every request the case makes, and a call nothing names succeeds.
type revocationScript struct {
	failAt map[int]error
	// failAfterEnd fails every call made once the user's sessions have ended,
	// which is the position of the second revocation whatever came before it.
	failAfterEnd error
	// honoursCtx answers the context the revoker was called with, as a revoker
	// bound to it would, at any call nothing else names.
	honoursCtx bool
	// hangUpAt holds the calls that find the caller gone: the caller's context
	// is cancelled during the call, which answers that context's error.
	hangUpAt map[int]bool
}

// newRevocationWorld builds a recoverer over a scripted revoker. cancel is what
// a hang-up the script names ends.
func newRevocationWorld(t *testing.T, script revocationScript, cancel context.CancelFunc, opts ...recovery.Option) *revocationWorld {
	t.Helper()

	w := &revocationWorld{e: newCompleteEnv(t), own: &recoveryEvents{}, rid: newRecordID(t)}
	w.prior = w.e.priorSessions(t, 1)

	g := NewMockGrantRevoker(gomock.NewController(t))
	g.EXPECT().RevokeUserGrants(gomock.Any(), anaID, "recovery").DoAndReturn(
		func(ctx context.Context, _ identity.UserID, _ string) error {
			seen := revocationSeen{
				savedUsable: w.e.savedUsable(ctx, t, w.e.saved[0]),
				priorLoads:  w.loads(ctx, w.prior[0]),
			}

			w.mu.Lock()
			w.seen = append(w.seen, seen)
			call := len(w.seen)
			w.mu.Unlock()

			if script.hangUpAt[call] {
				cancel()

				return ctx.Err()
			}

			if script.failAfterEnd != nil && !seen.priorLoads {
				return script.failAfterEnd
			}

			if err := script.failAt[call]; err != nil {
				return err
			}

			if script.honoursCtx {
				return ctx.Err()
			}

			return nil
		}).AnyTimes()

	base := []recovery.Option{
		recovery.WithGrantRevoker(g),
		recovery.WithSecurityEvents(w.own.sink),
		recovery.WithIDGenerator(fixedIDs{rid: w.rid}),
	}
	w.r = w.e.recoverer(t, append(base, opts...)...)

	return w
}

// assertNothingHappened checks that a failed attempt spent, wrote, removed,
// ended, sent and reported nothing, and charged the user nothing.
func (w *revocationWorld) assertNothingHappened(ctx context.Context, t *testing.T) {
	t.Helper()

	e := w.e
	assert.True(t, e.savedUsable(ctx, t, e.saved[0]), "the saved code is not spent")
	assert.True(t, e.issuedUsable(ctx, t, w.r, anaID, e.issued), "the issued code is not spent")
	assert.Zero(t, e.held.removals(), "no authenticator is removed")
	assert.True(t, w.loads(ctx, w.prior[0]), "the user's sessions stand")
	assert.Empty(t, e.out.recoveredNotices(), "no notice claims a recovery that failed")
	assert.Empty(t, w.own.all(), "a dependency failure is no refusal, and reports nothing")
	assert.Zero(t, e.failures.Load(), "no attempt is charged to the user")
}

// assertFirstFailure checks the shape of the error a first revocation's failure
// returns.
func assertFirstFailure(t *testing.T, res *recovery.Result, err, cause error) {
	t.Helper()

	require.ErrorIs(t, err, cause, "the failure still matches")
	assert.ErrorIs(t, err, recovery.ErrDependency)
	assert.NotErrorIs(t, err, recovery.ErrRefused, "a dependency failure is no refusal")
	assert.EqualError(t, err, "recovery: the user's application grants could not be revoked",
		"its text is the package's own")
	assert.Nil(t, res)
}

// assertCompletedDespiteGrants checks that a second revocation's failure left a
// completed recovery that says so.
func (w *revocationWorld) assertCompletedDespiteGrants(ctx context.Context, t *testing.T, res *recovery.Result, err error) {
	t.Helper()

	e := w.e

	require.NoError(t, err)
	require.NotNil(t, res.Session, "the recovery session is stored")
	assert.True(t, w.loads(ctx, res.Session.ID), "the recovery session loads")
	assert.Equal(t, issuedForPrefix+res.Session.ID, res.Credential)
	assert.True(t, res.GrantsNotRevoked, "the result says so")
	assert.Len(t, e.out.recoveredNotices(), 1, "the notice is still sent")

	if notices := e.out.recoveredNotices(); len(notices) == 1 {
		subject, _ := recovery.DefaultMessages().Recovered(notices[0])
		sent := e.out.messages()
		require.NotEmpty(t, sent)
		assert.Equal(t, subject, sent[len(sent)-1].Subject, "and it reached the sender")
	}

	assert.False(t, w.loads(ctx, w.prior[0]), "the user's other sessions ended")

	events := w.own.all()
	require.Len(t, events, 1, "one event, and no refusal")
	assert.Equal(t, event.GrantRevokeFailed, events[0].Name)
	assert.Equal(t, event.OutcomeFailure, events[0].Outcome)
	assert.Equal(t, anaID, events[0].User, "the event names the user")
	assert.Empty(t, events[0].Cause, "no error text is reported")

	logs := e.logs.String()
	assert.Contains(t, logs, grantsFailedError)
	assert.NotContains(t, logs, "secret text")
	assertCleanLogs(t, e, res)
}

// TestRecover_GrantRevocation pins spec account-recovery "A recovery that cannot
// revoke grants spends nothing, or says so" for a recovery that completes at
// once: the grants are revoked after every check and before anything is spent,
// where a failure spends nothing, and again after the sessions end, where a
// failure no longer aborts.
func TestRecover_GrantRevocation(t *testing.T) {
	t.Parallel()

	const firstMFACode, nextMFACode = "123456", "654321"

	// A recovery takes exactly two proofs, so an MFA code pairs with one code.
	savedAndMFA := func(e *completeEnv) recovery.Request {
		return recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "totp", MFACode: firstMFACode}
	}
	issuedAndMFA := func(e *completeEnv) recovery.Request {
		return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: firstMFACode}
	}

	// wrongMFACode checks that a refused MFA code ended and spent nothing, and was
	// charged as a refusal.
	wrongMFACode := func(ctx context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
		t.Helper()

		require.ErrorIs(t, err, recovery.ErrRefused)
		assert.True(t, recovery.RefusedAfterValidCode(err))
		assert.Nil(t, res)
		assert.Zero(t, w.calls(), "a refused MFA proof must not reach the revoker")
		assert.True(t, w.e.savedUsable(ctx, t, w.e.saved[0]), "the saved code is not spent")
		assert.True(t, w.e.issuedUsable(ctx, t, w.r, anaID, w.e.issued), "the issued code is not spent")
		assert.True(t, w.loads(ctx, w.prior[0]), "the user's sessions stand")
		assert.Equal(t, int32(1), w.e.failures.Load(), "the refusal is charged to the user")

		events := w.own.all()
		require.Len(t, events, 1)
		assert.Equal(t, event.RecoveryRefused, events[0].Name)
	}

	// mfaFirstFailure checks that a right MFA code with a failing first revocation
	// spent that code alone and charged nothing, and that the next code recovers.
	mfaFirstFailure := func(ctx context.Context, t *testing.T, w *revocationWorld, req recovery.Request, res *recovery.Result, err error) {
		t.Helper()

		assertFirstFailure(t, res, err, errGrantStore)
		w.assertNothingHappened(ctx, t)
		assert.Equal(t, 1, w.calls())

		codes, revoked := w.verifications()
		assert.Equal(t, []string{firstMFACode}, codes, "the MFA code is verified once, which spends it")
		assert.Equal(t, []int{0}, revoked, "and before anything is revoked")

		req.MFACode = nextMFACode
		retried, err := w.r.Recover(ctx, req)
		require.NoError(t, err, "the other proof still works, with the next MFA code")
		require.NotNil(t, retried.Session)
		assert.False(t, retried.GrantsNotRevoked)
		assert.Equal(t, 3, w.calls())
		assert.Zero(t, w.e.failures.Load(), "no attempt was charged as a refusal")
		assert.Empty(t, w.own.all(), "neither attempt reported anything")

		codes, revoked = w.verifications()
		assert.Equal(t, []string{firstMFACode, nextMFACode}, codes)
		assert.Equal(t, []int{0, 1}, revoked)
	}

	refuseMFA := func(w *revocationWorld, _ context.CancelFunc) {
		w.expectMFA(func(string) error { return mfa.ErrInvalidCode })
	}
	acceptMFA := func(w *revocationWorld, _ context.CancelFunc) {
		w.expectMFA(func(string) error { return nil })
	}

	type testCase struct {
		name   string
		script revocationScript
		opts   []recovery.Option
		req    func(e *completeEnv) recovery.Request
		// arrange runs once the world is built, before the first request. cancel
		// ends the caller's context.
		arrange func(w *revocationWorld, cancel context.CancelFunc)
		assert  func(ctx context.Context, t *testing.T, w *revocationWorld, req recovery.Request, res *recovery.Result, err error)
	}

	cases := []testCase{
		{
			name:   "the first revocation failing spends nothing, writes no record, and the same request then succeeds",
			script: revocationScript{failAt: map[int]error{1: errGrantStore}},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, req recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				assertFirstFailure(t, res, err, errGrantStore)
				w.assertNothingHappened(ctx, t)
				assert.Equal(t, 1, w.calls(), "the attempt stopped at the first revocation")
				assert.Contains(t, w.e.logs.String(), grantsFailedError, "an outage is logged as one")
				assert.NotContains(t, w.e.logs.String(), "secret text")

				_, ferr := w.e.records.Find(ctx, w.rid)
				require.ErrorIs(t, ferr, recovery.ErrRecordNotFound, "no record is written")

				retried, err := w.r.Recover(ctx, req)
				require.NoError(t, err, "the same proofs succeed")
				require.NotNil(t, retried.Session)
				assert.False(t, retried.GrantsNotRevoked)
				assert.Len(t, retried.Codes, len(w.e.saved))
				assert.Equal(t, 3, w.calls(), "the retry revoked twice")
				assert.Zero(t, w.e.failures.Load(), "no attempt was charged as a refusal")
				assert.Empty(t, w.own.all(), "neither attempt reported anything")

				_, ferr = w.e.records.Find(ctx, w.rid)
				require.NoError(t, ferr, "the retry wrote its record")
			},
		},
		{
			name:   "a caller hanging up during the first revocation is no outage: logged at DEBUG, with nothing spent",
			script: revocationScript{hangUpAt: map[int]bool{1: true}},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				assertFirstFailure(t, res, err, context.Canceled)
				// ctx is the case's own, which the hang-up ended.
				w.assertNothingHappened(context.WithoutCancel(ctx), t)
				assert.Equal(t, 1, w.calls())

				logs := w.e.logs.String()
				assert.Contains(t, logs, grantsFailedDebug)
				assert.NotContains(t, logs, grantsFailedError)
			},
		},
		{
			name:    "a wrong MFA code beside a saved code ends nothing, and is charged as before",
			req:     savedAndMFA,
			arrange: refuseMFA,
			assert:  wrongMFACode,
		},
		{
			name:    "a wrong MFA code beside an issued code ends nothing, and is charged as before",
			req:     issuedAndMFA,
			arrange: refuseMFA,
			assert:  wrongMFACode,
		},
		{
			name:    "a right MFA code beside a saved code with the first revocation failing spends that code alone, and the next recovers",
			script:  revocationScript{failAt: map[int]error{1: errGrantStore}},
			req:     savedAndMFA,
			arrange: acceptMFA,
			assert:  mfaFirstFailure,
		},
		{
			name:    "a right MFA code beside an issued code with the first revocation failing spends that code alone, and the next recovers",
			script:  revocationScript{failAt: map[int]error{1: errGrantStore}},
			req:     issuedAndMFA,
			arrange: acceptMFA,
			assert:  mfaFirstFailure,
		},
		{
			name:   "a caller hanging up once the MFA code was accepted does not stop the revocation: a proof is spent",
			script: revocationScript{honoursCtx: true},
			req:    savedAndMFA,
			arrange: func(w *revocationWorld, cancel context.CancelFunc) {
				w.expectMFA(func(string) error {
					cancel()

					return nil
				})
			},
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.False(t, res.GrantsNotRevoked)
				assert.Equal(t, 2, w.calls())

				_, revoked := w.verifications()
				assert.Equal(t, []int{0}, revoked, "the code was accepted before anything was revoked")
			},
		},
		{
			name:    "a held recovery with an MFA proof spends it at its start and revokes nothing",
			req:     issuedAndMFA,
			opts:    holdFor(time.Hour),
			arrange: acceptMFA,
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, res.Held)
				assert.Zero(t, w.calls())
				assert.False(t, w.e.issuedUsable(ctx, t, w.r, anaID, w.e.issued), "a hold spends everything at its start")

				codes, _ := w.verifications()
				assert.Equal(t, []string{firstMFACode}, codes)
			},
		},
		{
			name:   "a revoker's error wrapping a refusal is still a dependency failure: no refusal is reported",
			script: revocationScript{failAt: map[int]error{1: fmt.Errorf("outage: %w", recovery.ErrRefused)}},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				require.ErrorIs(t, err, recovery.ErrDependency)
				assert.Nil(t, res)
				w.assertNothingHappened(ctx, t)
			},
		},
		{
			name:   "only the second failing completes with a saved code spent: session stored, codes reissued, notice sent, and it says so",
			script: revocationScript{failAfterEnd: errGrantStore},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				w.assertCompletedDespiteGrants(ctx, t, res, err)
				assert.Equal(t, 2, w.calls())
				assert.Len(t, res.Codes, len(w.e.saved), "the saved set is reissued")
				assert.Equal(t, len(w.e.saved), res.Remaining.N)
			},
		},
		{
			name:   "only the second failing completes with no saved code spent: no codes to reissue, and it still says so",
			script: revocationScript{failAfterEnd: errGrantStore},
			req:    issuedAndPasswordReq,
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				w.assertCompletedDespiteGrants(ctx, t, res, err)
				assert.Empty(t, res.Codes)
			},
		},
		{
			name: "both succeeding revokes before the spend and again after the sessions end, reporting nothing",
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.False(t, res.GrantsNotRevoked)
				assert.Empty(t, w.own.all())
				assert.NotContains(t, w.e.logs.String(), "could not be revoked")
				assert.Equal(t, []revocationSeen{
					{savedUsable: true, priorLoads: true},
					{savedUsable: false, priorLoads: false},
				}, w.seenAt(), "the first runs before anything is spent, the second after the sessions end")
			},
		},
		{
			name:   "the keep option never calls the revoker",
			script: revocationScript{failAt: map[int]error{1: errGrantStore}, failAfterEnd: errGrantStore},
			opts:   []recovery.Option{recovery.WithoutRecoveryGrantRevocation()},
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.False(t, res.GrantsNotRevoked, "nothing failed: the grants were kept on purpose")
				assert.Zero(t, w.calls())
				assert.Empty(t, w.own.all())
			},
		},
		{
			name: "a refused proof revokes nothing: only someone holding valid proofs reaches it",
			req: func(e *completeEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: wrongCode, Issued: e.issued}
			},
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, _ *recovery.Result, err error) {
				t.Helper()

				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Zero(t, w.calls())
			},
		},
		{
			name:    "a credential that cannot be issued revokes nothing: the issuer runs first",
			arrange: func(w *revocationWorld, _ context.CancelFunc) { w.e.failIssue(errors.New("issuer down")) },
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ recovery.Request, _ *recovery.Result, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotErrorIs(t, err, recovery.ErrDependency, "the mark is the revocation's alone")
				assert.Zero(t, w.calls())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			w := newRevocationWorld(t, tc.script, cancel, tc.opts...)
			if tc.arrange != nil {
				tc.arrange(w, cancel)
			}

			req := savedAndIssuedReq(w.e)
			if tc.req != nil {
				req = tc.req(w.e)
			}

			res, err := w.r.Recover(ctx, req)
			tc.assert(ctx, t, w, req, res, err)
		})
	}
}

// TestFinish_GrantRevocation pins the same requirement for a held recovery:
// starting the hold revokes nothing, and its finish takes the same two steps,
// where a first failure leaves the finish able to be retried.
func TestFinish_GrantRevocation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script revocationScript
		opts   []recovery.Option
		assert func(ctx context.Context, t *testing.T, w *revocationWorld, token string, res *recovery.Result, err error)
	}

	// pendingAndUsable checks that a failed finish left the record pending and
	// changed nothing the finish changes.
	pendingAndUsable := func(ctx context.Context, t *testing.T, w *revocationWorld) {
		t.Helper()

		rec, err := w.e.records.Find(ctx, w.rid)
		require.NoError(t, err)
		assert.True(t, rec.CompletedAt.IsZero(), "the record stays pending")
		assert.Zero(t, w.e.held.removals(), "no authenticator is removed")
		assert.True(t, w.loads(ctx, w.prior[0]), "the user's sessions stand")
		assert.Empty(t, w.e.out.recoveredNotices(), "no notice claims a recovery that failed")
		assert.Empty(t, w.own.all(), "a dependency failure is no refusal, and reports nothing")
		assert.Zero(t, w.e.failures.Load(), "no attempt is charged to the user")
	}

	cases := []testCase{
		{
			name: "starting the hold calls nothing, and the finish revokes twice",
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ string, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.False(t, res.GrantsNotRevoked)
				assert.Empty(t, w.own.all())
				// The hold's spend voided the saved set, so what tells the two
				// calls apart is the sessions.
				assert.Equal(t, []revocationSeen{
					{savedUsable: false, priorLoads: true},
					{savedUsable: false, priorLoads: false},
				}, w.seenAt(), "the first runs before the record is completed, the second after the sessions end")
			},
		},
		{
			name:   "a first failure leaves the record pending and the token usable, and the retry succeeds",
			script: revocationScript{failAt: map[int]error{1: errGrantStore}},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, token string, res *recovery.Result, err error) {
				t.Helper()

				assertFirstFailure(t, res, err, errGrantStore)
				assert.Equal(t, 1, w.calls())
				assert.Contains(t, w.e.logs.String(), grantsFailedError)
				pendingAndUsable(ctx, t, w)

				retried, err := w.r.Finish(ctx, token)
				require.NoError(t, err, "the same token finishes")
				require.NotNil(t, retried.Session)
				assert.False(t, retried.GrantsNotRevoked)
				assert.Equal(t, 3, w.calls())
				assert.Zero(t, w.e.failures.Load(), "no attempt was charged as a refusal")
				assert.Empty(t, w.own.all(), "neither attempt reported anything")

				rec, err := w.e.records.Find(ctx, w.rid)
				require.NoError(t, err)
				assert.False(t, rec.CompletedAt.IsZero(), "the retry completed the record")
			},
		},
		{
			name:   "a caller hanging up during the first revocation is no outage: logged at DEBUG, with the record pending",
			script: revocationScript{hangUpAt: map[int]bool{1: true}},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, token string, res *recovery.Result, err error) {
				t.Helper()

				assertFirstFailure(t, res, err, context.Canceled)

				logs := w.e.logs.String()
				assert.Contains(t, logs, grantsFailedDebug)
				assert.NotContains(t, logs, grantsFailedError)

				live := context.WithoutCancel(ctx)
				pendingAndUsable(live, t, w)

				retried, err := w.r.Finish(live, token)
				require.NoError(t, err, "the same token finishes")
				require.NotNil(t, retried.Session)
			},
		},
		{
			name:   "only the second failing completes: session stored, codes reissued, notice sent, and it says so",
			script: revocationScript{failAfterEnd: errGrantStore},
			assert: func(ctx context.Context, t *testing.T, w *revocationWorld, _ string, res *recovery.Result, err error) {
				t.Helper()

				w.assertCompletedDespiteGrants(ctx, t, res, err)
				assert.Equal(t, 2, w.calls())
				assert.Len(t, res.Codes, len(w.e.saved), "the saved set is reissued")

				rec, err := w.e.records.Find(ctx, w.rid)
				require.NoError(t, err)
				assert.False(t, rec.CompletedAt.IsZero(), "the record is completed")
			},
		},
		{
			name:   "the keep option never calls the revoker",
			script: revocationScript{failAt: map[int]error{1: errGrantStore}, failAfterEnd: errGrantStore},
			opts:   []recovery.Option{recovery.WithoutRecoveryGrantRevocation()},
			assert: func(_ context.Context, t *testing.T, w *revocationWorld, _ string, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, res.GrantsNotRevoked)
				assert.Zero(t, w.calls())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// Shorter than a session's idle timeout, so what ends the prior
			// session is the finish and not the clock.
			w := newRevocationWorld(t, tc.script, cancel, append(holdFor(time.Minute), tc.opts...)...)

			hold := heldRecovery(ctx, t, w.r, savedAndIssuedReq(w.e))
			require.Zero(t, w.calls(), "starting a hold revokes nothing")
			require.True(t, w.loads(ctx, w.prior[0]), "and ends nothing")

			w.e.clock.Advance(time.Minute)

			res, err := w.r.Finish(ctx, hold.CompletionToken)
			tc.assert(ctx, t, w, hold.CompletionToken, res, err)
		})
	}
}
