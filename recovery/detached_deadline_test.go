package recovery_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// probe records the context of every call the doubles below see, by operation,
// and fails the call a case armed. The scenarios' caller context carries no
// deadline, so a deadline a double sees comes from the library.
type probe struct {
	mu    sync.Mutex
	ctxs  map[string][]context.Context
	armed map[string]armedFault
}

type armedFault struct {
	nth int // 1-based call number the fault fires on
	err error
}

func newProbe() *probe {
	return &probe{ctxs: map[string][]context.Context{}, armed: map[string]armedFault{}}
}

// reset forgets the calls seen so far and any armed fault.
func (p *probe) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ctxs = map[string][]context.Context{}
	p.armed = map[string]armedFault{}
}

// arm makes the nth call of op fail with err.
func (p *probe) arm(op string, nth int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.armed[op] = armedFault{nth: nth, err: err}
}

// hit records the call and returns the error armed for it, if any.
func (p *probe) hit(ctx context.Context, op string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ctxs[op] = append(p.ctxs[op], ctx)
	if f, ok := p.armed[op]; ok && f.nth == len(p.ctxs[op]) {
		return f.err
	}

	return nil
}

func (p *probe) seen(op string) []context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]context.Context(nil), p.ctxs[op]...)
}

type probeCodes struct {
	recovery.CodeStore
	p *probe
}

func (s probeCodes) ReplaceSet(ctx context.Context, u identity.UserID, h [][]byte, at time.Time) error {
	if err := s.p.hit(ctx, "codes.ReplaceSet"); err != nil {
		return err
	}

	return s.CodeStore.ReplaceSet(ctx, u, h, at)
}

func (s probeCodes) Spend(ctx context.Context, u identity.UserID, h []byte, at time.Time) (bool, error) {
	if err := s.p.hit(ctx, "codes.Spend"); err != nil {
		return false, err
	}

	return s.CodeStore.Spend(ctx, u, h, at)
}

func (s probeCodes) Remaining(ctx context.Context, u identity.UserID) (int, error) {
	if err := s.p.hit(ctx, "codes.Remaining"); err != nil {
		return 0, err
	}

	return s.CodeStore.Remaining(ctx, u)
}

func (s probeCodes) DeleteUser(ctx context.Context, u identity.UserID) (int, error) {
	if err := s.p.hit(ctx, "codes.DeleteUser"); err != nil {
		return 0, err
	}

	return s.CodeStore.DeleteUser(ctx, u)
}

type probeSessions struct {
	session.Store
	p *probe
}

func (s probeSessions) DeleteByUser(ctx context.Context, u identity.UserID) error {
	if err := s.p.hit(ctx, "sessions.DeleteByUser"); err != nil {
		return err
	}

	return s.Store.DeleteByUser(ctx, u)
}

func (s probeSessions) Create(ctx context.Context, sess *session.Session) error {
	if err := s.p.hit(ctx, "sessions.Create"); err != nil {
		return err
	}

	return s.Store.Create(ctx, sess)
}

type probeRecords struct {
	recovery.RecordStore
	p *probe
}

func (s probeRecords) Insert(ctx context.Context, r recovery.Record) error {
	if err := s.p.hit(ctx, "records.Insert"); err != nil {
		return err
	}

	return s.RecordStore.Insert(ctx, r)
}

func (s probeRecords) Complete(ctx context.Context, rid id.ID, at time.Time) (bool, error) {
	if err := s.p.hit(ctx, "records.Complete"); err != nil {
		return false, err
	}

	return s.RecordStore.Complete(ctx, rid, at)
}

func (s probeRecords) Cancel(ctx context.Context, rid id.ID, at time.Time) (int, error) {
	if err := s.p.hit(ctx, "records.Cancel"); err != nil {
		return 0, err
	}

	return s.RecordStore.Cancel(ctx, rid, at)
}

// probeTokens probes a one-time store's Insert and Consume under prefix.
type probeTokens struct {
	onetime.Store
	p      *probe
	prefix string
}

func (s probeTokens) Insert(ctx context.Context, tok onetime.Token) error {
	if err := s.p.hit(ctx, s.prefix+".Insert"); err != nil {
		return err
	}

	return s.Store.Insert(ctx, tok)
}

func (s probeTokens) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	if err := s.p.hit(ctx, s.prefix+".Consume"); err != nil {
		return err
	}

	return s.Store.Consume(ctx, tokenID, at)
}

type probeMethod struct {
	mfa.Method
	p *probe
}

func (m probeMethod) Verify(ctx context.Context, u identity.UserID, response []byte) error {
	if err := m.p.hit(ctx, "mfa.Verify"); err != nil {
		return err
	}

	return m.Method.Verify(ctx, u, response)
}

type probeKind struct {
	recovery.AuthenticatorKind
	p *probe
}

func (k probeKind) Remove(ctx context.Context, u identity.UserID, refs []recovery.AuthenticatorRef) error {
	if err := k.p.hit(ctx, "kind.Remove"); err != nil {
		return err
	}

	return k.AuthenticatorKind.Remove(ctx, u, refs)
}

type probeGrants struct{ p *probe }

func (g probeGrants) RevokeUserGrants(ctx context.Context, _ identity.UserID, _ string) error {
	return g.p.hit(ctx, "grants.Revoke")
}

type probeUsers struct {
	identity.UserLoader
	p *probe
}

func (u probeUsers) LoadByUserID(ctx context.Context, user identity.UserID) (*identity.Details, error) {
	if err := u.p.hit(ctx, "users.LoadByUserID"); err != nil {
		return nil, err
	}

	return u.UserLoader.LoadByUserID(ctx, user)
}

type probeSender struct {
	nonBlockingSender
	p *probe
}

func (s probeSender) Send(ctx context.Context, m notify.Message) error {
	if err := s.p.hit(ctx, "sender.Send"); err != nil {
		return err
	}

	return s.nonBlockingSender.Send(ctx, m)
}

// probeLimiter probes a limiter's four calls under prefix.
type probeLimiter struct {
	ratelimit.Limiter
	p      *probe
	prefix string
}

func (l probeLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	_ = l.p.hit(ctx, l.prefix+"Exceeded")

	return l.Limiter.Exceeded(ctx, key)
}

func (l probeLimiter) RecordFailure(ctx context.Context, key string) error {
	_ = l.p.hit(ctx, l.prefix+"RecordFailure")

	return l.Limiter.RecordFailure(ctx, key)
}

func (l probeLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	_ = l.p.hit(ctx, l.prefix+"Charge")

	return l.Limiter.Charge(ctx, key)
}

func (l probeLimiter) Refund(ctx context.Context, r ratelimit.Receipt) error {
	_ = l.p.hit(ctx, l.prefix+"Refund")

	return l.Limiter.Refund(ctx, r)
}

// deadlineWorld is a recoverer whose every detached collaborator is probed.
type deadlineWorld struct {
	e *completeEnv
	p *probe
	r *recovery.Recoverer

	// fault is armed on the probe by arm, at the start of the phase under test.
	fault *armSpec
}

type armSpec struct {
	op  string
	nth int
	err error
}

// arm starts the phase under test: it forgets the calls seen in any setup
// phase and arms the world's fault, if it has one.
func (w *deadlineWorld) arm() {
	w.p.reset()

	if w.fault != nil {
		w.p.arm(w.fault.op, w.fault.nth, w.fault.err)
	}
}

func newDeadlineWorld(t *testing.T, p *probe, hold bool) *deadlineWorld {
	t.Helper()

	e := newCompleteEnv(t)

	e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil).AnyTimes()
	e.totp.EXPECT().Verify(gomock.Any(), anaID, gomock.Any()).Return(nil).AnyTimes()

	codesLimiter := NewMockLimiter(e.ctrl)
	codesLimiter.EXPECT().Charge(gomock.Any(), gomock.Any()).Return(ratelimit.Receipt{}, false, nil).AnyTimes()
	codesLimiter.EXPECT().Refund(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	codesLimiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	codesLimiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	codes, err := recovery.NewCodes(
		recovery.WithCodesClock(e.clock),
		recovery.WithCodesStore(probeCodes{CodeStore: recovery.NewMemoryCodeStore(), p: p}),
		recovery.WithCodesLimiter(probeLimiter{Limiter: codesLimiter, p: p, prefix: "codes."}),
	)
	require.NoError(t, err)

	e.saved, err = codes.Generate(t.Context(), anaID)
	require.NoError(t, err)

	sessions, err := session.New(session.WithClock(e.clock), session.WithStore(probeSessions{
		Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(e.clock))), p: p,
	}))
	require.NoError(t, err)

	deps := e.completeDeps()
	deps.Users = probeUsers{UserLoader: e.users, p: p}
	deps.Sessions = sessions
	deps.Codes = codes
	deps.Records = probeRecords{RecordStore: e.records, p: p}
	deps.Sender = probeSender{nonBlockingSender: deps.Sender.(nonBlockingSender), p: p}

	opts := []recovery.Option{
		recovery.WithGrantRevoker(probeGrants{p: p}),
		recovery.WithMFAMethods(probeMethod{Method: e.totp, p: p}, challengeMethod(e.ctrl, "passkey")),
		recovery.WithAuthenticatorKinds(probeKind{AuthenticatorKind: e.kind, p: p}),
		recovery.WithIssuedCodeStore(probeTokens{Store: e.tokens, p: p, prefix: "issued"}),
		recovery.WithUserLimiter(probeLimiter{Limiter: e.limiter, p: p, prefix: "user."}),
		recovery.WithContactResolver(func(ctx context.Context, d *identity.Details) (string, error) {
			if err := p.hit(ctx, "resolver"); err != nil {
				return "", err
			}

			return mfa.UsernameAsAddress(ctx, d)
		}),
		recovery.WithIDGenerator(fixedIDs{rid: newRecordID(t)}),
	}
	if hold {
		holdTokens := probeTokens{
			Store:  must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(e.clock))),
			p:      p,
			prefix: "hold",
		}
		opts = append(opts, holdFor(time.Hour)...)
		opts = append(opts, recovery.WithHoldTokenStore(holdTokens))
	}

	e.altCodes = codes
	w := &deadlineWorld{e: e, p: p}
	w.r, err = recovery.NewRecoverer(deps, e.recovererOpts(opts...)...)
	require.NoError(t, err)

	return w
}

// TestRecoverer_DetachedCallsCarryDeadline pins the bound on every store and
// service call a recovery detaches from the caller's cancellation, the outcome
// a call that hits its bound has (the one a store error from it has), and that
// the sender and the limiters get no library deadline.
func TestRecoverer_DetachedCallsCarryDeadline(t *testing.T) {
	t.Parallel()

	timedOut := context.DeadlineExceeded

	// Scenarios. Each returns the recovery's result and error; a setup phase
	// resets the probe so that only the phase under test is observed.
	immediate := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		w.arm()

		return w.r.Recover(ctx, recovery.Request{
			Username: anaUsername, Saved: w.e.saved[0], MFAMethod: "totp", MFACode: "123456",
		})
	}
	// issuedWithMFA completes at once on an issued code and an MFA code, so the
	// saved set is not spent and the completion counts what remains.
	issuedWithMFA := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		w.arm()

		return w.r.Recover(ctx, recovery.Request{
			Username: anaUsername, Issued: w.e.issued, MFAMethod: "totp", MFACode: "123456",
		})
	}
	held := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		w.arm()

		return w.r.Recover(ctx, recovery.Request{
			Username: anaUsername, Saved: w.e.saved[0], MFAMethod: "totp", MFACode: "123456",
		})
	}
	heldIssued := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		w.arm()

		return w.r.Recover(ctx, recovery.Request{
			Username: anaUsername, Issued: w.e.issued, MFAMethod: "totp", MFACode: "123456",
		})
	}
	// heldSetup starts the hold the finish and cancel scenarios act on, with
	// no fault armed.
	heldSetup := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		fault := w.fault
		w.fault = nil
		defer func() { w.fault = fault }()

		return held(ctx, w)
	}
	finish := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		res, err := heldSetup(ctx, w)
		if err != nil {
			return nil, err
		}

		w.e.clock.Advance(2 * time.Hour)
		w.arm()

		return w.r.Finish(ctx, res.Held.CompletionToken)
	}
	cancel := func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error) {
		if _, err := heldSetup(ctx, w); err != nil {
			return nil, err
		}

		w.arm()
		w.r.Cancel(ctx, w.e.cancelToken(t))

		return nil, nil //nolint:nilnil // Cancel returns nothing
	}

	type testCase struct {
		name     string
		hold     bool
		scenario func(ctx context.Context, w *deadlineWorld) (*recovery.Result, error)
		op       string
		nth      int
		// bound is the library bound the call carries; zero means the library
		// gives the call no deadline.
		bound time.Duration
		// revocation marks a call bounded by the revocation timeout, which
		// is longer than the write timeout.
		revocation bool
		// preArm is a fault armed for the deadline run, to reach a call only a
		// failed proof makes.
		preArm error
		// assert sees the outcome of a run in which the call returned
		// DeadlineExceeded. Nil for a call with no library bound.
		assert func(t *testing.T, w *deadlineWorld, res *recovery.Result, err error)
	}

	refusedAsStoreError := func(t *testing.T, _ *deadlineWorld, _ *recovery.Result, err error) {
		require.ErrorIs(t, err, recovery.ErrRefused)
		assert.NotErrorIs(t, err, recovery.ErrDependency)
	}
	failsWithoutRefusal := func(t *testing.T, _ *deadlineWorld, res *recovery.Result, err error) {
		require.Error(t, err)
		assert.NotErrorIs(t, err, recovery.ErrRefused)
		assert.Nil(t, res)
	}
	noticeLostOnly := func(t *testing.T, w *deadlineWorld, _ *recovery.Result, err error) {
		require.NoError(t, err)
		assert.Empty(t, w.e.out.messages(), "no notice goes without an address")
	}

	const (
		immediateOnly = false
		withHold      = true
	)

	cases := []testCase{
		// spendMFA, spendCodes.
		{name: "immediate: MFA verify", hold: immediateOnly, scenario: immediate, op: "mfa.Verify", nth: 1, bound: detach.WriteTimeout, assert: refusedAsStoreError},
		{name: "immediate: first grant revocation", scenario: immediate, op: "grants.Revoke", nth: 1, bound: detach.RevocationTimeout, revocation: true,
			assert: func(t *testing.T, w *deadlineWorld, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrDependency)
				assert.Nil(t, res)
				assert.Contains(t, w.e.logs.String(), grantsFailedError, "a timed-out revocation is an ERROR, as a store error is")
			}},
		{name: "immediate: issued code consume", scenario: issuedWithMFA, op: "issued.Consume", nth: 1, bound: detach.WriteTimeout, assert: refusedAsStoreError},
		{name: "immediate: saved code spend", scenario: immediate, op: "codes.Spend", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		// complete.
		{name: "immediate: record insert", scenario: immediate, op: "records.Insert", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "complete: authenticator removal", scenario: immediate, op: "kind.Remove", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "complete: session revocation", scenario: immediate, op: "sessions.DeleteByUser", nth: 1, bound: detach.RevocationTimeout, revocation: true, assert: failsWithoutRefusal},
		{name: "complete: second grant revocation", scenario: immediate, op: "grants.Revoke", nth: 2, bound: detach.RevocationTimeout, revocation: true,
			assert: func(t *testing.T, _ *deadlineWorld, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.GrantsNotRevoked, "the failed second revocation is told to the consumer, and the recovery stands")
			}},
		{name: "complete: saved set replacement", scenario: immediate, op: "codes.ReplaceSet", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "complete: remaining count", scenario: issuedWithMFA, op: "codes.Remaining", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "complete: session commit", scenario: immediate, op: "sessions.Create", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "complete: contact resolver", scenario: immediate, op: "resolver", nth: 1, bound: detach.WriteTimeout, assert: noticeLostOnly},
		// hold start.
		{name: "held: MFA verify", hold: withHold, scenario: held, op: "mfa.Verify", nth: 1, bound: detach.WriteTimeout, assert: refusedAsStoreError},
		{name: "held: issued code consume", hold: withHold, scenario: heldIssued, op: "issued.Consume", nth: 1, bound: detach.WriteTimeout, assert: refusedAsStoreError},
		{name: "held: saved code spend", hold: withHold, scenario: held, op: "codes.Spend", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "held: record insert", hold: withHold, scenario: held, op: "records.Insert", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "held: finish token issue", hold: withHold, scenario: held, op: "hold.Insert", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "held: cancel token issue", hold: withHold, scenario: held, op: "hold.Insert", nth: 2, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "held: saved set void", hold: withHold, scenario: held, op: "codes.DeleteUser", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "held: contact resolver", hold: withHold, scenario: held, op: "resolver", nth: 1, bound: detach.WriteTimeout, assert: noticeLostOnly},
		// finish.
		{name: "finish: record completion", hold: withHold, scenario: finish, op: "records.Complete", nth: 1, bound: detach.WriteTimeout, assert: failsWithoutRefusal},
		{name: "finish: token consume", hold: withHold, scenario: finish, op: "hold.Consume", nth: 1, bound: detach.WriteTimeout,
			assert: func(t *testing.T, _ *deadlineWorld, res *recovery.Result, err error) {
				require.NoError(t, err, "a consume that fails is logged and ignored")
				require.NotNil(t, res)
			}},
		// cancel.
		{name: "cancel: record cancel", hold: withHold, scenario: cancel, op: "records.Cancel", nth: 1, bound: detach.WriteTimeout,
			assert: func(t *testing.T, w *deadlineWorld, _ *recovery.Result, _ error) {
				assert.Empty(t, w.e.out.cancelledNotices())
			}},
		{name: "cancel: token consume", hold: withHold, scenario: cancel, op: "hold.Consume", nth: 1, bound: detach.WriteTimeout,
			assert: func(t *testing.T, w *deadlineWorld, _ *recovery.Result, _ error) {
				assert.Len(t, w.e.out.cancelledNotices(), 1, "a failed consume is logged and the notice still goes")
			}},
		{name: "cancel: user loader", hold: withHold, scenario: cancel, op: "users.LoadByUserID", nth: 1, bound: detach.WriteTimeout,
			assert: func(t *testing.T, w *deadlineWorld, _ *recovery.Result, _ error) {
				assert.Empty(t, w.e.out.cancelledNotices())
			}},
		{name: "cancel: contact resolver", hold: withHold, scenario: cancel, op: "resolver", nth: 1, bound: detach.WriteTimeout,
			assert: func(t *testing.T, w *deadlineWorld, _ *recovery.Result, _ error) {
				assert.Len(t, w.e.out.messages(), 1, "only the hold notice went; the cancel notice has no address")
			}},
		// Class 1: a notice's sender owns its bound.
		{name: "complete: notice sender is not bounded", scenario: immediate, op: "sender.Send", nth: 1},
		{name: "held: notice sender is not bounded", hold: withHold, scenario: held, op: "sender.Send", nth: 1},
		{name: "cancel: notice sender is not bounded", hold: withHold, scenario: cancel, op: "sender.Send", nth: 1},
		// Class 5: limiter calls are bounded by the port's own contract.
		{name: "user limiter exceeded is not bounded", scenario: immediate, op: "user.Exceeded", nth: 1},
		{name: "user limiter record failure is not bounded", scenario: immediate, op: "user.RecordFailure", nth: 1, preArm: mfa.ErrInvalidCode},
		{name: "codes limiter charge is not bounded", scenario: immediate, op: "codes.Charge", nth: 1},
		{name: "codes limiter refund is not bounded", scenario: immediate, op: "codes.Refund", nth: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.bound > 0 {
				t.Run("carries a deadline", func(t *testing.T) {
					t.Parallel()

					p := newProbe()
					w := newDeadlineWorld(t, p, tc.hold)

					_, _ = tc.scenario(t.Context(), w)

					calls := p.seen(tc.op)
					require.GreaterOrEqual(t, len(calls), tc.nth, "the call was not reached")

					dl, ok := calls[tc.nth-1].Deadline()
					require.True(t, ok, "no deadline: a hung dependency holds the request goroutine without end")

					remaining := time.Until(dl)
					assert.Positive(t, remaining)
					assert.LessOrEqual(t, remaining, tc.bound)

					if tc.revocation {
						assert.Greater(t, remaining, detach.WriteTimeout, "a revocation gets the revocation timeout")
					}
				})

				t.Run("timing out has the outcome of a store error", func(t *testing.T) {
					t.Parallel()

					p := newProbe()
					w := newDeadlineWorld(t, p, tc.hold)
					w.fault = &armSpec{op: tc.op, nth: tc.nth, err: timedOut}

					res, err := tc.scenario(t.Context(), w)
					tc.assert(t, w, res, err)
				})

				return
			}

			t.Run("carries no library deadline", func(t *testing.T) {
				t.Parallel()

				p := newProbe()
				w := newDeadlineWorld(t, p, tc.hold)

				if tc.preArm != nil {
					w.fault = &armSpec{op: "mfa.Verify", nth: 1, err: tc.preArm}
				}

				_, _ = tc.scenario(t.Context(), w)

				calls := p.seen(tc.op)
				require.GreaterOrEqual(t, len(calls), tc.nth, "the call was not reached")

				_, ok := calls[tc.nth-1].Deadline()
				assert.False(t, ok, "the library bounded a call that belongs to its owner")
			})
		})
	}
}
