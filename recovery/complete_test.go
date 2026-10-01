package recovery_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// heldSet is what ana holds behind the kind mock: Held lists it and Remove
// takes from it, so a test sees the reset's effect rather than its calls.
type heldSet struct {
	mu        sync.Mutex
	refs      []recovery.AuthenticatorRef
	heldErr   error
	removeErr error
	removed   int
	// onRemove, when set, runs inside Remove, before anything is removed.
	onRemove func()
}

func (h *heldSet) held(context.Context, identity.UserID) ([]recovery.AuthenticatorRef, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.heldErr != nil {
		return nil, h.heldErr
	}

	return slices.Clone(h.refs), nil
}

func (h *heldSet) failListing(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.heldErr = err
}

func (h *heldSet) remove(_ context.Context, _ identity.UserID, refs []recovery.AuthenticatorRef) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.onRemove != nil {
		h.onRemove()
	}
	if h.removeErr != nil {
		return h.removeErr
	}

	h.removed++
	h.refs = slices.DeleteFunc(h.refs, func(r recovery.AuthenticatorRef) bool { return slices.Contains(refs, r) })

	return nil
}

func (h *heldSet) add(r recovery.AuthenticatorRef) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.refs = append(h.refs, r)
}

// drop removes r, as the user removing an authenticator themselves would.
func (h *heldSet) drop(r recovery.AuthenticatorRef) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.refs = slices.DeleteFunc(h.refs, func(x recovery.AuthenticatorRef) bool { return x == r })
}

func (h *heldSet) snapshot() []recovery.AuthenticatorRef {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.refs)
}

func (h *heldSet) removals() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.removed
}

// outbox is everything the recoverer sent and every notice it built.
type outbox struct {
	mu        sync.Mutex
	sent      []notify.Message
	sendErr   error
	ctxErrs   []error
	recovered []recovery.Notice
	held      []heldNotice
	cancelled []recovery.Notice
}

type heldNotice struct {
	notice recovery.Notice
	link   string
	until  time.Time
}

func (o *outbox) send(ctx context.Context, m notify.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// A well-behaved sender refuses a context that has ended.
	if err := ctx.Err(); err != nil {
		o.ctxErrs = append(o.ctxErrs, err)

		return err
	}

	o.sent = append(o.sent, m)

	return o.sendErr
}

func (o *outbox) messages() []notify.Message {
	o.mu.Lock()
	defer o.mu.Unlock()

	return slices.Clone(o.sent)
}

func (o *outbox) recoveredNotices() []recovery.Notice {
	o.mu.Lock()
	defer o.mu.Unlock()

	return slices.Clone(o.recovered)
}

func (o *outbox) heldNotices() []heldNotice {
	o.mu.Lock()
	defer o.mu.Unlock()

	return slices.Clone(o.held)
}

func (o *outbox) cancelledNotices() []recovery.Notice {
	o.mu.Lock()
	defer o.mu.Unlock()

	return slices.Clone(o.cancelled)
}

// completeEnv is a recovery world whose completion is observed through real
// in-memory stores: ana's saved set and issued code, her sessions, her
// authenticators behind heldSet, and the notices behind outbox.
type completeEnv struct {
	*recoverEnv

	records *recovery.MemoryRecordStore
	held    *heldSet
	out     *outbox
	// prior is the sessions a case created before recovering.
	prior []string
	// inactive makes ana's account inactive when loaded by reference.
	inactive atomic.Bool
	// lookupErr, when set, is what loading ana by reference returns.
	lookupErr atomic.Pointer[error]
	// altCodes is the saved-code manager a case gave the recoverer in place
	// of the fixture's.
	altCodes *recovery.Codes
}

// failLookup makes loading ana by reference fail with err; nil clears it.
func (e *completeEnv) failLookup(err error) {
	if err == nil {
		e.lookupErr.Store(nil)

		return
	}

	e.lookupErr.Store(&err)
}

func newCompleteEnv(t *testing.T) *completeEnv {
	t.Helper()

	e := &completeEnv{
		recoverEnv: newRecoverEnv(t),
		records:    recovery.NewMemoryRecordStore(),
		held:       &heldSet{refs: []recovery.AuthenticatorRef{refTOTP, refEmail}},
		out:        &outbox{},
	}

	e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).AnyTimes()
	e.users.EXPECT().LoadByUserID(gomock.Any(), anaID).DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
		if err := e.lookupErr.Load(); err != nil {
			return nil, *err
		}

		d := anaDetails()
		d.Active = !e.inactive.Load()

		return d, nil
	}).AnyTimes()
	e.kind.EXPECT().Held(gomock.Any(), anaID).DoAndReturn(e.held.held).AnyTimes()
	e.kind.EXPECT().Remove(gomock.Any(), anaID, gomock.Any()).DoAndReturn(e.held.remove).AnyTimes()
	e.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	e.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	e.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(e.out.send).AnyTimes()

	return e
}

// capturingMessages builds the default messages and records what each was
// given.
func (e *completeEnv) capturingMessages() recovery.Messages {
	def := recovery.DefaultMessages()
	msgs := NewMockMessages(e.ctrl)

	msgs.EXPECT().IssuedCode(gomock.Any(), gomock.Any()).DoAndReturn(def.IssuedCode).AnyTimes()
	msgs.EXPECT().Recovered(gomock.Any()).DoAndReturn(func(n recovery.Notice) (string, string) {
		e.out.mu.Lock()
		e.out.recovered = append(e.out.recovered, n)
		e.out.mu.Unlock()

		return def.Recovered(n)
	}).AnyTimes()
	msgs.EXPECT().Held(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(n recovery.Notice, link string, until time.Time) (string, string) {
			e.out.mu.Lock()
			e.out.held = append(e.out.held, heldNotice{notice: n, link: link, until: until})
			e.out.mu.Unlock()

			return def.Held(n, link, until)
		}).AnyTimes()
	msgs.EXPECT().Cancelled(gomock.Any()).DoAndReturn(func(n recovery.Notice) (string, string) {
		e.out.mu.Lock()
		e.out.cancelled = append(e.out.cancelled, n)
		e.out.mu.Unlock()

		return def.Cancelled(n)
	}).AnyTimes()
	msgs.EXPECT().Regenerated(gomock.Any()).DoAndReturn(def.Regenerated).AnyTimes()

	return msgs
}

// completeDeps returns the env's ports with its record store.
func (e *completeEnv) completeDeps() recovery.Deps {
	d := e.deps()
	d.Records = e.records

	return d
}

// recoverer builds a recoverer over the env, with every proof kind enabled.
func (e *completeEnv) recoverer(t *testing.T, extra ...recovery.Option) *recovery.Recoverer {
	t.Helper()

	r, err := recovery.NewRecoverer(e.completeDeps(), e.recovererOpts(extra...)...)
	require.NoError(t, err)

	return r
}

// recovererOpts enables every proof kind over the env, with the capturing
// messages, followed by extra.
func (e *completeEnv) recovererOpts(extra ...recovery.Option) []recovery.Option {
	return e.opts(append([]recovery.Option{recovery.WithMessages(e.capturingMessages())}, extra...)...)
}

// priorSessions creates n sessions for ana, as earlier logins would have.
func (e *completeEnv) priorSessions(t *testing.T, n int) []string {
	t.Helper()

	ids := make([]string, n)
	for i := range ids {
		s, err := e.sessions.Create(t.Context(), anaID, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		ids[i] = s.ID
	}

	return ids
}

// loads reports whether the session with this identifier still loads.
func (e *completeEnv) loads(t *testing.T, sid string) bool {
	t.Helper()

	_, err := e.sessions.Load(t.Context(), sid)

	return err == nil
}

// assertCleanLogs checks that no log record carries the username, the
// address, a code or a token.
func assertCleanLogs(t *testing.T, e *completeEnv, res *recovery.Result) {
	t.Helper()

	logs := e.logs.String()
	secrets := append([]string{anaUsername, e.issued, e.issuedU2}, e.saved...)
	if res != nil {
		secrets = append(secrets, res.Codes...)
		if res.Held != nil {
			secrets = append(secrets, res.Held.CompletionToken)
		}
	}
	for _, n := range e.out.heldNotices() {
		secrets = append(secrets, n.link)
	}

	for _, secret := range secrets {
		assert.NotContains(t, logs, secret, "no log record carries a username, a code or a token")
	}
}

// twoSet generates ana's saved set on altCodes, the code manager of two codes
// per set a case gave the recoverer, and returns its first code.
func (e *completeEnv) twoSet(ctx context.Context, t *testing.T) string {
	t.Helper()

	set, err := e.altCodes.Generate(ctx, anaID)
	require.NoError(t, err)
	require.Len(t, set, 2)

	return set[0]
}

func savedAndIssuedReq(e *completeEnv) recovery.Request {
	return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}
}

func issuedAndPasswordReq(e *completeEnv) recovery.Request {
	return recovery.Request{Username: anaUsername, Issued: e.issued, Password: []byte(anaPassword)}
}

func TestRecoverer_Complete(t *testing.T) {
	t.Parallel()

	errRemove := errors.New("enrolment store unreachable")
	errInsert := errors.New("record store unreachable")

	type testCase struct {
		name  string
		opts  func(e *completeEnv) []recovery.Option
		deps  func(e *completeEnv, d *recovery.Deps)
		setup func(t *testing.T, e *completeEnv)
		req   func(e *completeEnv) recovery.Request
		ctx   func(ctx context.Context, e *completeEnv) context.Context
		// act runs the recovery; nil runs Recover once with req.
		act    func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error)
		assert func(t *testing.T, e *completeEnv, res *recovery.Result, err error)
	}

	cases := []testCase{
		{
			name: "a spent saved code replaces the whole set",
			req:  savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.Len(t, res.Codes, 10)
				assert.Equal(t, recovery.Count{N: 10, Low: false}, res.Remaining, "the new set is counted")
				assert.Nil(t, res.Held)

				// The new set first: each refused old code is charged to the
				// saved-code limiter.
				assert.True(t, e.savedUsable(t.Context(), t, res.Codes[0]), "the new set is live")
				for _, old := range e.saved {
					assert.False(t, e.savedUsable(t.Context(), t, old), "every code of the old set is refused")
				}
			},
		},
		{
			name: "a reissued set is counted with the manager's low threshold",
			deps: func(e *completeEnv, d *recovery.Deps) {
				codes, err := recovery.NewCodes(recovery.WithSetSize(2))
				if err != nil {
					panic(err)
				}

				e.altCodes = codes
				d.Codes = codes
			},
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				return r.Recover(ctx, recovery.Request{Username: anaUsername, Saved: e.twoSet(ctx, t), Issued: e.issued})
			},
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.Len(t, res.Codes, 2)
				assert.Equal(t, recovery.Count{N: 2, Low: true}, res.Remaining,
					"two codes, at the default threshold of two, is low")
			},
		},
		{
			name: "the result carries the recovered user's details",
			req:  savedAndIssuedReq,
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Details)
				assert.Equal(t, anaID, res.Details.ID)
				assert.Equal(t, anaUsername, res.Details.Username)
				assert.Equal(t, res.Session.UserID, res.Details.ID)
			},
		},
		{
			name: "a finished hold's result carries the recovered user's details",
			opts: func(*completeEnv) []recovery.Option { return holdFor(time.Hour) },
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				h := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.clock.Advance(time.Hour)

				return r.Finish(ctx, h.CompletionToken)
			},
			assert: func(t *testing.T, _ *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Details)
				assert.Equal(t, anaID, res.Details.ID)
				assert.Len(t, res.Codes, 10)
				assert.Equal(t, recovery.Count{N: 10, Low: false}, res.Remaining)
			},
		},
		{
			name: "no saved code spent reports the remaining count",
			setup: func(t *testing.T, e *completeEnv) {
				for _, code := range e.saved[:8] {
					spendCode(t, e.codes, anaID, code)
				}
			},
			req: issuedAndPasswordReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Nil(t, res.Codes)
				assert.Equal(t, recovery.Count{N: 2, Low: true}, res.Remaining)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[9]), "the set is not replaced")
			},
		},
		{
			name: "the authenticators are reset",
			req:  savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Empty(t, e.held.snapshot())
			},
		},
		{
			name: "a consumer's reset policy decides what the reset removes",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithResetPolicy(
					func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) {
						return []recovery.AuthenticatorRef{refTOTP}, nil
					})}
			},
			req: savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, e.held.snapshot(),
					"the policy's choice, TOTP, is removed and email-code is kept")
			},
		},
		{
			name:  "other sessions end, and the recovery session is confined",
			setup: func(t *testing.T, e *completeEnv) { e.prior = e.priorSessions(t, 2) },
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				for _, sid := range e.prior {
					assert.False(t, e.loads(t, sid), "an earlier session no longer loads")
				}

				require.NotNil(t, res.Session)
				s, err := e.sessions.Load(t.Context(), res.Session.ID)
				require.NoError(t, err)
				assert.Equal(t, anaID, s.UserID)
				assert.Equal(t, session.MFARecoveryPending, s.MFA)
				assert.Equal(t, factor.Recovery, s.FirstFactor)
				assert.True(t, s.RecoveredAt.Equal(monday1000), "recovered at %s", s.RecoveredAt)
			},
		},
		{
			name:  "session revocation turned off keeps the earlier sessions",
			opts:  func(*completeEnv) []recovery.Option { return []recovery.Option{recovery.WithoutSessionRevocation()} },
			setup: func(t *testing.T, e *completeEnv) { e.prior = e.priorSessions(t, 2) },
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				for _, sid := range e.prior {
					assert.True(t, e.loads(t, sid), "an earlier session still loads")
				}
				assert.True(t, e.loads(t, res.Session.ID))
			},
		},
		{
			name: "the recovery session expires after the default 15 minutes",
			req:  savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)

				e.clock.Advance(14 * time.Minute)
				assert.True(t, e.loads(t, res.Session.ID), "alive at 14 minutes")

				e.clock.Advance(2 * time.Minute)
				_, err = e.sessions.Load(t.Context(), res.Session.ID)
				require.ErrorIs(t, err, session.ErrSessionExpired, "expired at 16 minutes")
			},
		},
		{
			name: "a configured session lifetime replaces the default",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithSessionLifetime(5 * time.Minute)}
			},
			req: savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)

				e.clock.Advance(6 * time.Minute)
				_, err = e.sessions.Load(t.Context(), res.Session.ID)
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
		{
			name: "the notice goes to the contact address and carries no code",
			req:  savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)

				assert.Equal(t, []recovery.Notice{{
					At:            monday1000,
					Removed:       []recovery.AuthenticatorRef{refTOTP, refEmail},
					CodesReplaced: true,
					Repudiation:   repudiation,
				}}, e.out.recoveredNotices())

				sent := e.out.messages()
				require.Len(t, sent, 1)
				assert.Equal(t, anaUsername, sent[0].To)
				assert.NotEmpty(t, sent[0].Subject)
				assert.Contains(t, sent[0].TextBody, "mfa:totp")
				assert.Contains(t, sent[0].TextBody, "mfa:email-code")
				assert.Contains(t, sent[0].TextBody, repudiation)
				assert.Contains(t, sent[0].TextBody, "28 September 2026 10:00 UTC")

				for _, code := range append(append([]string{e.issued}, e.saved...), res.Codes...) {
					assert.NotContains(t, sent[0].TextBody, code)
				}
			},
		},
		{
			name: "a consumer's contact resolver chooses the address",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
					return "ana.home@example.net", nil
				})}
			},
			req: savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.NoError(t, err)

				sent := e.out.messages()
				require.Len(t, sent, 1)
				assert.Equal(t, "ana.home@example.net", sent[0].To)
			},
		},
		{
			name: "a proven method is kept, and the notice names only what was removed",
			setup: func(_ *testing.T, e *completeEnv) {
				e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil).AnyTimes()
				e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil)
			},
			req: func(e *completeEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "totp", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP}, e.held.snapshot())

				notices := e.out.recoveredNotices()
				require.Len(t, notices, 1)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, notices[0].Removed)
			},
		},
		{
			name: "a reset failure is returned, with no session and nothing revoked",
			setup: func(t *testing.T, e *completeEnv) {
				e.prior = e.priorSessions(t, 2)
				e.held.removeErr = errRemove
			},
			req: savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, errRemove)
				assert.Nil(t, res)

				for _, sid := range e.prior {
					assert.True(t, e.loads(t, sid), "an earlier session still loads")
				}
				n, err := e.sessions.CountActiveByUser(t.Context(), anaID)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "no recovery session was created")

				assert.True(t, e.savedUsable(t.Context(), t, e.saved[1]), "the set is not replaced after a failed reset")
				assert.Empty(t, e.out.messages(), "no notice")
			},
		},
		{
			name: "a record store that cannot insert fails before the reset",
			deps: func(e *completeEnv, d *recovery.Deps) {
				records := NewMockRecordStore(e.ctrl)
				records.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errInsert)
				d.Records = records
			},
			setup: func(t *testing.T, e *completeEnv) { e.prior = e.priorSessions(t, 1) },
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, errInsert)
				assert.NotContains(t, err.Error(), "unreachable", "the store's text is not returned")
				assert.Nil(t, res)
				assert.Zero(t, e.held.removals(), "nothing is removed")
				assert.True(t, e.loads(t, e.prior[0]))
			},
		},
		{
			name:  "a refused queue is logged and the recovery stands",
			setup: func(_ *testing.T, e *completeEnv) { e.out.sendErr = errors.New("queue full") },
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.True(t, e.loads(t, res.Session.ID))
				assert.Contains(t, e.logs.String(), "recovery: the recovery notice could not be sent")
			},
		},
		{
			name: "a completed record is kept",
			req:  savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, _ *recovery.Result, err error) {
				require.NoError(t, err)

				at, ok, err := e.records.LatestCompletion(t.Context(), anaID)
				require.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, at.Equal(monday1000), "completed at %s", at)
			},
		},
		{
			name: "two recoveries back to back: the second revokes the first's session",
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				first, err := r.Recover(ctx, savedAndIssuedReq(e))
				require.NoError(t, err)

				issued, _, err := e.mint.Issue(ctx, string(anaID))
				require.NoError(t, err)

				second, err := r.Recover(ctx, recovery.Request{Username: anaUsername, Saved: first.Codes[0], Issued: issued})
				require.NoError(t, err)

				e.prior = []string{first.Session.ID}

				return second, nil
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				assert.False(t, e.loads(t, e.prior[0]), "the first recovery's session no longer loads")
				assert.True(t, e.loads(t, res.Session.ID), "only the latest loads")
			},
		},
		{
			name: "a client hanging up mid-completion does not leave it half done",
			ctx: func(ctx context.Context, e *completeEnv) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				e.held.onRemove = cancel

				return ctx
			},
			req: savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.Session)
				assert.Len(t, res.Codes, 10)
				assert.Len(t, e.out.messages(), 1, "the notice is still sent")
				assert.Empty(t, e.out.ctxErrs)
			},
		},
		{
			name: "a refused recovery completes nothing",
			setup: func(t *testing.T, e *completeEnv) {
				e.prior = e.priorSessions(t, 1)
			},
			req: func(e *completeEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issuedU2}
			},
			assert: func(t *testing.T, e *completeEnv, res *recovery.Result, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Nil(t, res)
				assert.True(t, e.loads(t, e.prior[0]))
				assert.Len(t, e.held.snapshot(), 2)
				assert.Empty(t, e.out.messages())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)

			var extra []recovery.Option
			if tc.opts != nil {
				extra = tc.opts(e)
			}

			d := e.completeDeps()
			if tc.deps != nil {
				tc.deps(e, &d)
			}

			r, err := recovery.NewRecoverer(d, e.recovererOpts(extra...)...)
			require.NoError(t, err)

			if tc.setup != nil {
				tc.setup(t, e)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, e)
			}

			var res *recovery.Result
			if tc.act != nil {
				res, err = tc.act(ctx, t, e, r)
			} else {
				res, err = r.Recover(ctx, tc.req(e))
			}

			tc.assert(t, e, res, err)
			assertCleanLogs(t, e, res)
		})
	}
}

// TestRecoverer_CompleteFailures pins D7's rule that a failure at any step
// from the record to the saved session is returned, with the proofs spent and
// the earlier steps done, and that no notice is sent for a recovery that did
// not complete.
func TestRecoverer_CompleteFailures(t *testing.T) {
	t.Parallel()

	errStore := errors.New("store unreachable")

	type testCase struct {
		name  string
		fault string
		req   func(e *completeEnv) recovery.Request
		// assert checks what the steps before the failure left behind.
		assert func(t *testing.T, e *completeEnv)
	}

	sessionsLeft := func(t *testing.T, e *completeEnv, want int, msg string) {
		t.Helper()

		n, err := e.sessions.CountActiveByUser(t.Context(), anaID)
		require.NoError(t, err)
		assert.Equal(t, want, n, msg)
	}

	cases := []testCase{
		{
			name:  "a revocation failure is returned after the reset, creating no session",
			fault: faultSessionsDelete,
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv) {
				assert.Empty(t, e.held.snapshot(), "the reset ran")
				sessionsLeft(t, e, 2, "the earlier sessions stay, and no recovery session was created")
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[1]), "the set was not replaced")
			},
		},
		{
			name:  "a reissue failure is returned after the revocation, creating no session",
			fault: faultCodesReplaceSet,
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv) {
				assert.Empty(t, e.held.snapshot(), "the reset ran")
				sessionsLeft(t, e, 0, "the earlier sessions were revoked, and no recovery session was created")
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[1]), "a failed replacement leaves the set whole")
			},
		},
		{
			name:  "a count failure is returned after the revocation, creating no session",
			fault: faultCodesRemaining,
			req:   issuedAndPasswordReq,
			assert: func(t *testing.T, e *completeEnv) {
				assert.Empty(t, e.held.snapshot(), "the reset ran")
				sessionsLeft(t, e, 0, "the earlier sessions were revoked, and no recovery session was created")
			},
		},
		{
			name:  "a session creation failure is returned after the reissue",
			fault: faultSessionsCreate,
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv) {
				assert.Empty(t, e.held.snapshot(), "the reset ran")
				sessionsLeft(t, e, 0, "no session was created")
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[1]), "the set was replaced")
			},
		},
		{
			name:  "a session save failure is returned after the creation",
			fault: faultSessionsSave,
			req:   savedAndIssuedReq,
			assert: func(t *testing.T, e *completeEnv) {
				assert.Empty(t, e.held.snapshot(), "the reset ran")
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[1]), "the set was replaced")
				sessionsLeft(t, e, 0, "the created session was deleted after the save failed, and its handle was never returned")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			r := e.recoverer(t)
			e.prior = e.priorSessions(t, 2)
			e.faults.arm(tc.fault, errStore)

			res, err := r.Recover(t.Context(), tc.req(e))

			require.ErrorIs(t, err, errStore)
			assert.Nil(t, res, "no session or code is handed out")
			assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the proofs stay spent")
			assert.Empty(t, e.out.messages(), "no notice for a recovery that did not complete")

			at, ok, lerr := e.records.LatestCompletion(t.Context(), anaID)
			require.NoError(t, lerr)
			assert.True(t, ok, "the completed record was written first")
			assert.True(t, at.Equal(monday1000))

			tc.assert(t, e)
			assertCleanLogs(t, e, res)
		})
	}
}
