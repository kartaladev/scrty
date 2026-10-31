package recovery_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// The operations a faults set can make fail. Each names the store and the
// method.
const (
	faultCodesReplaceSet   = "codes.ReplaceSet"
	faultCodesRemaining    = "codes.Remaining"
	faultCodesDeleteUser   = "codes.DeleteUser"
	faultSessionsDelete    = "sessions.DeleteByUser"
	faultSessionsCreate    = "sessions.Create"
	faultSessionsSave      = "sessions.Save"
	faultRecordsInsert     = "records.Insert"
	faultRecordsFind       = "records.Find"
	faultRecordsComplete   = "records.Complete"
	faultRecordsCancel     = "records.Cancel"
	faultTokensInsert      = "tokens.Insert"
	faultTokensConsume     = "tokens.Consume"
	faultRecordsNoComplete = "records.Complete=false"
	faultRecordsFindNil    = "records.Find=nil"
)

// faults is a set of armed failures the wrapper stores below consult before
// passing a call to the real in-memory store they wrap. An armed operation
// fails without reaching the real store, so the store is left exactly as a
// failed write would leave it.
type faults struct {
	mu   sync.Mutex
	errs map[string]error
}

func newFaults() *faults { return &faults{errs: map[string]error{}} }

// arm makes op fail with err; a nil err disarms it.
func (f *faults) arm(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err == nil {
		delete(f.errs, op)

		return
	}

	f.errs[op] = err
}

func (f *faults) err(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.errs[op]
}

// armed reports whether op is set to fail, without handing back its error.
func (f *faults) armed(op string) bool { return f.err(op) != nil }

// faultyCodeStore is a saved-code store that fails on demand.
type faultyCodeStore struct {
	recovery.CodeStore

	f *faults
}

func (s faultyCodeStore) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	if err := s.f.err(faultCodesReplaceSet); err != nil {
		return err
	}

	return s.CodeStore.ReplaceSet(ctx, user, hashes, at)
}

func (s faultyCodeStore) Remaining(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.f.err(faultCodesRemaining); err != nil {
		return 0, err
	}

	return s.CodeStore.Remaining(ctx, user)
}

func (s faultyCodeStore) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.f.err(faultCodesDeleteUser); err != nil {
		return 0, err
	}

	return s.CodeStore.DeleteUser(ctx, user)
}

// faultySessionStore is a session store that fails on demand.
type faultySessionStore struct {
	session.Store

	f *faults
}

func (s faultySessionStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if err := s.f.err(faultSessionsDelete); err != nil {
		return err
	}

	return s.Store.DeleteByUser(ctx, user)
}

func (s faultySessionStore) Create(ctx context.Context, sess *session.Session) error {
	if err := s.f.err(faultSessionsCreate); err != nil {
		return err
	}

	return s.Store.Create(ctx, sess)
}

func (s faultySessionStore) Save(ctx context.Context, sess *session.Session) error {
	if err := s.f.err(faultSessionsSave); err != nil {
		return err
	}

	return s.Store.Save(ctx, sess)
}

// faultyRecordStore is a recovery record store that fails on demand. With
// faultRecordsNoComplete armed, Complete reports that it lost the race without
// writing anything; with faultRecordsFindNil armed, Find returns no record and
// no error.
type faultyRecordStore struct {
	recovery.RecordStore

	f *faults
}

func (s faultyRecordStore) Insert(ctx context.Context, r recovery.Record) error {
	if err := s.f.err(faultRecordsInsert); err != nil {
		return err
	}

	return s.RecordStore.Insert(ctx, r)
}

func (s faultyRecordStore) Find(ctx context.Context, rid id.ID) (*recovery.Record, error) {
	if err := s.f.err(faultRecordsFind); err != nil {
		return nil, err
	}
	if s.f.armed(faultRecordsFindNil) {
		return nil, nil //nolint:nilnil // the fault is a store answering no record and no error
	}

	return s.RecordStore.Find(ctx, rid)
}

func (s faultyRecordStore) Complete(ctx context.Context, rid id.ID, at time.Time) (bool, error) {
	if err := s.f.err(faultRecordsComplete); err != nil {
		return false, err
	}
	if s.f.err(faultRecordsNoComplete) != nil {
		return false, nil //nolint:nilerr // the fault reports "not completed", not an error
	}

	return s.RecordStore.Complete(ctx, rid, at)
}

func (s faultyRecordStore) Cancel(ctx context.Context, rid id.ID, at time.Time) (int, error) {
	if err := s.f.err(faultRecordsCancel); err != nil {
		return 0, err
	}

	return s.RecordStore.Cancel(ctx, rid, at)
}

// recordingTokenStore is a one-time store that fails on demand and records
// every token inserted and consumed, as a consumer's store would see them.
type recordingTokenStore struct {
	*onetime.MemoryStore

	f *faults

	mu       sync.Mutex
	inserted []onetime.Token
	consumed []id.ID
}

func (s *recordingTokenStore) Insert(ctx context.Context, tok onetime.Token) error {
	if err := s.f.err(faultTokensInsert); err != nil {
		return err
	}

	s.mu.Lock()
	s.inserted = append(s.inserted, tok)
	s.mu.Unlock()

	return s.MemoryStore.Insert(ctx, tok)
}

func (s *recordingTokenStore) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	if err := s.f.err(faultTokensConsume); err != nil {
		return err
	}

	s.mu.Lock()
	s.consumed = append(s.consumed, tokenID)
	s.mu.Unlock()

	return s.MemoryStore.Consume(ctx, tokenID, at)
}

// purposes reports the purpose and subject of every token inserted, in order.
func (s *recordingTokenStore) purposes() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([][2]string, len(s.inserted))
	for i, t := range s.inserted {
		out[i] = [2]string{t.Purpose, t.Subject}
	}

	return out
}

// consumedPurposes reports the purpose of every token consumed, in order.
func (s *recordingTokenStore) consumedPurposes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	for _, cid := range s.consumed {
		for _, t := range s.inserted {
			if t.ID == cid {
				out = append(out, t.Purpose)
			}
		}
	}

	return out
}

// codesTime is the instant the fake clock of every Codes test reads.
var codesTime = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// newCodes builds a manager with the fake clock and the given options.
func newCodes(t *testing.T, opts ...recovery.CodesOption) *recovery.Codes {
	t.Helper()

	opts = append([]recovery.CodesOption{recovery.WithCodesClock(clockwork.NewFakeClockAt(codesTime))}, opts...)
	c, err := recovery.NewCodes(opts...)
	require.NoError(t, err)

	return c
}

// spendCode spends one generated code through the flow's check and spend.
func spendCode(t *testing.T, c *recovery.Codes, user identity.UserID, code string) {
	t.Helper()

	hash, err := c.Check(t.Context(), user, code)
	require.NoError(t, err)
	require.NoError(t, c.Spend(t.Context(), user, hash))
}

// mustGenerate generates a set for user and requires that it holds codes.
func mustGenerate(t *testing.T, c *recovery.Codes, user identity.UserID) []string {
	t.Helper()

	codes, err := c.Generate(t.Context(), user)
	require.NoError(t, err)
	require.NotEmpty(t, codes)

	return codes
}

// wrongCode is well formed but belongs to no set.
const wrongCode = "0000-0000-0000-0000-0000-0000-00"

// holdFor returns the options that hold every recovery for d.
func holdFor(d time.Duration) []recovery.Option {
	return []recovery.Option{recovery.WithHoldDelay(d), recovery.WithCancelLink(cancelBase)}
}

// heldRecovery starts a recovery that must be held, and returns its hold.
func heldRecovery(ctx context.Context, t *testing.T, r *recovery.Recoverer, req recovery.Request) *recovery.Hold {
	t.Helper()

	res, err := r.Recover(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, res.Held)

	return res.Held
}

// fixedIDs is a consumer's identifier generator that always answers rid.
type fixedIDs struct{ rid id.ID }

func (g fixedIDs) NewID() (id.ID, error) { return g.rid, nil }

// mfaMethods holds the mocks behind one MFA kind under test, by method name.
type mfaMethods struct {
	methods  map[string]*MockMethod
	removers map[string]*MockEnrolmentRemover
}

// declaredMethod returns a method mock that passes mfa.LookupsFor's checks
// under name.
func declaredMethod(ctrl *gomock.Controller, name string, channel factor.Channel) *MockMethod {
	m := NewMockMethod(ctrl)
	m.EXPECT().Name().Return(name).AnyTimes()
	m.EXPECT().Channel().Return(channel).AnyTimes()
	m.EXPECT().Response().Return(mfa.FormField("mfa_code", 64)).AnyTimes()

	return m
}

// removableMethods builds TOTP and email-code, both able to remove enrolments,
// in that configuration order.
func removableMethods(ctrl *gomock.Controller) (mfaMethods, []mfa.Method) {
	set := mfaMethods{methods: map[string]*MockMethod{}, removers: map[string]*MockEnrolmentRemover{}}
	var methods []mfa.Method

	for _, m := range []struct {
		name    string
		channel factor.Channel
	}{{"totp", factor.AuthenticatorApp}, {"email-code", factor.Email}} {
		set.methods[m.name] = declaredMethod(ctrl, m.name, m.channel)
		set.removers[m.name] = NewMockEnrolmentRemover(ctrl)
		methods = append(methods, removableMethod{set.methods[m.name], set.removers[m.name]})
	}

	return set, methods
}

// newRecordID draws a fresh record identifier.
func newRecordID(t *testing.T) id.ID {
	t.Helper()

	rid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return rid
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
	// otherUser makes loading ana by reference return another user's details.
	otherUser atomic.Bool
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
		if e.otherUser.Load() {
			d.ID = "u-2"
		}

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

const anaPassword = "correct horse"

// recoverEnv is one recovery case's world: ana holds a saved set and one
// issued code, TOTP and email-code enrolments, and a password.
type recoverEnv struct {
	*fixture

	tokens *onetime.MemoryStore
	mint   *onetime.Tokens
	saved  []string
	issued string
	// issuedU2 is an issued code minted for another user, u-2.
	issuedU2 string
	totp     *MockMethod
	limiter  *MockLimiter

	// passwordErr, when set, is what the password check returns for any
	// password; otherwise it accepts anaPassword only.
	passwordErr   error
	passwordCalls atomic.Int32
	failures      atomic.Int32
}

func newRecoverEnv(t *testing.T) *recoverEnv {
	t.Helper()

	f := newFixture(t)
	e := &recoverEnv{fixture: f, tokens: onetime.NewMemoryStore(), limiter: NewMockLimiter(f.ctrl)}
	e.totp = formMethod(f.ctrl, "totp")

	mint, err := onetime.New(recovery.IssuedCodePurpose, onetime.WithStore(e.tokens), onetime.WithClock(f.clock))
	require.NoError(t, err)
	e.mint = mint

	e.saved, err = f.codes.Generate(t.Context(), anaID)
	require.NoError(t, err)

	e.issued = e.issueFor(t, anaID)
	e.issuedU2 = e.issueFor(t, "u-2")

	return e
}

// issueFor mints an issued recovery code for user, as Start would.
func (e *recoverEnv) issueFor(t *testing.T, user identity.UserID) string {
	t.Helper()

	code, _, err := e.mint.Issue(t.Context(), string(user))
	require.NoError(t, err)

	return code
}

func (e *recoverEnv) passwordCheck(_ context.Context, username string, password []byte) error {
	e.passwordCalls.Add(1)

	if e.passwordErr != nil {
		return e.passwordErr
	}
	if username == anaUsername && string(password) == anaPassword {
		return nil
	}

	return fmt.Errorf("bad password: %w", authenticate.ErrAuthenticationFailed)
}

// opts enables all four proof kinds over the env's ports, followed by extra.
func (e *recoverEnv) opts(extra ...recovery.Option) []recovery.Option {
	return e.fixture.opts(append([]recovery.Option{
		recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA),
		recovery.WithPasswordCheck(e.passwordCheck),
		recovery.WithMFAMethods(e.totp, challengeMethod(e.ctrl, "passkey")),
		recovery.WithIssuedCodeStore(e.tokens),
		recovery.WithUserLimiter(e.limiter),
	}, extra...)...)
}

// defaults sets the expectations every case shares, after the case's own, so
// a case's expectation is matched first.
func (e *recoverEnv) defaults() {
	e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).AnyTimes()
	e.kind.EXPECT().Held(gomock.Any(), anaID).Return([]recovery.AuthenticatorRef{refTOTP, refEmail}, nil).AnyTimes()
	e.limiter.EXPECT().Exceeded(gomock.Any(), recovery.UserThrottleKey(anaID)).Return(false, nil).AnyTimes()
	e.limiter.EXPECT().RecordFailure(gomock.Any(), recovery.UserThrottleKey(anaID)).DoAndReturn(func(context.Context, string) error {
		e.failures.Add(1)

		return nil
	}).AnyTimes()
}

// savedUsable reports whether code is still an unspent saved code of ana's.
func (e *recoverEnv) savedUsable(ctx context.Context, t *testing.T, code string) bool {
	t.Helper()

	return e.codes.Confirm(ctx, anaID, code) == nil
}

// issuedUsable reports whether code is still an unspent issued code for user.
func (e *recoverEnv) issuedUsable(ctx context.Context, t *testing.T, r *recovery.Recoverer, user identity.UserID, code string) bool {
	t.Helper()

	return r.CheckIssued(ctx, user, code) == nil
}

// monday1000 is the fixed instant the recoverer tests start at: 28 September
// 2026, a Monday.
var monday1000 = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

const (
	anaUsername = "ana@example.com"
	anaID       = identity.UserID("u-1")
	repudiation = "reply to this message to reach our support team."
)

// anaDetails is the active user most cases recover.
func anaDetails() *identity.Details {
	return &identity.Details{ID: anaID, Username: anaUsername, Active: true}
}

// syncBuffer is a log sink safe for the concurrent writes of a race test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// fixture holds the ports behind one recoverer under test.
type fixture struct {
	ctrl     *gomock.Controller
	users    *MockUserLoader
	sender   *MockSender
	codes    *recovery.Codes
	sessions *session.Sessions
	kind     *MockAuthenticatorKind
	clock    *clockwork.FakeClock
	logs     *syncBuffer
	// faults arms failures in the code and session stores.
	faults *faults
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(monday1000)

	// The stores are the real in-memory ones behind wrappers that fail only
	// when a case arms a fault.
	flt := newFaults()

	codes, err := recovery.NewCodes(recovery.WithCodesClock(clk),
		recovery.WithCodesStore(faultyCodeStore{CodeStore: recovery.NewMemoryCodeStore(), f: flt}))
	require.NoError(t, err)

	// The store judges expiry on its own clock, so it gets the same one.
	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(faultySessionStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(clk)), f: flt}))
	require.NoError(t, err)

	return &fixture{
		ctrl:     ctrl,
		users:    NewMockUserLoader(ctrl),
		sender:   NewMockSender(ctrl),
		codes:    codes,
		sessions: sessions,
		kind:     namedKind(ctrl, recovery.MFAKind),
		clock:    clk,
		logs:     &syncBuffer{},
		faults:   flt,
	}
}

// deps returns the fixture's ports, with a sender that does not wait.
func (f *fixture) deps() recovery.Deps {
	nb := NewMockNonBlocking(f.ctrl)
	nb.EXPECT().NonBlocking().Return(true).AnyTimes()

	return recovery.Deps{
		Users:    f.users,
		Sessions: f.sessions,
		Sender:   nonBlockingSender{f.sender, nb},
		Codes:    f.codes,
	}
}

// opts returns a working configuration over saved and issued codes, followed
// by extra.
func (f *fixture) opts(extra ...recovery.Option) []recovery.Option {
	base := []recovery.Option{
		recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
		recovery.WithRepudiationContact(repudiation),
		recovery.WithAuthenticatorKinds(f.kind),
		recovery.WithClock(f.clock),
		recovery.WithLogger(slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	}

	return append(base, extra...)
}

// formMethod returns an MFA method that can serve as a recovery proof.
func formMethod(ctrl *gomock.Controller, name string) *MockMethod {
	return declaredMethod(ctrl, name, factor.AuthenticatorApp)
}

// challengeMethod returns a method with a begin step, which cannot serve as a
// recovery proof.
func challengeMethod(ctrl *gomock.Controller, name string) *MockChallengeMethod {
	m := NewMockChallengeMethod(ctrl)
	m.EXPECT().Name().Return(name).AnyTimes()
	m.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	m.EXPECT().Response().Return(mfa.FormField("mfa_code", 64)).AnyTimes()

	return m
}

// errFactory is what a consumer's limiter factory refuses a namespace with.
var errFactory = errors.New("factory: backend refused the namespace")

// refusingLimiter is a limiter reporting every key over its limit, expected to
// be consulted under key at least once.
func refusingLimiter(ctrl *gomock.Controller, key string) *MockLimiter {
	l := NewMockLimiter(ctrl)
	l.EXPECT().Exceeded(gomock.Any(), key).Return(true, nil).MinTimes(1)
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return l
}

var (
	refTOTP    = recovery.AuthenticatorRef{Kind: recovery.MFAKind, ID: "totp"}
	refEmail   = recovery.AuthenticatorRef{Kind: recovery.MFAKind, ID: "email-code"}
	refSMS     = recovery.AuthenticatorRef{Kind: recovery.MFAKind, ID: "sms"}
	refPasskey = recovery.AuthenticatorRef{Kind: "passkey", ID: "cred-1"}
)

// namedKind returns a kind mock answering name.
func namedKind(ctrl *gomock.Controller, name string) *MockAuthenticatorKind {
	k := NewMockAuthenticatorKind(ctrl)
	k.EXPECT().Kind().Return(name).AnyTimes()

	return k
}

const cancelBase = "https://app.example.com/recovery/cancel"

// removableMethod is an MFA method that can remove its enrolments, as TOTP
// can: a Method and an EnrolmentRemover in one value.
type removableMethod struct {
	*MockMethod
	*MockEnrolmentRemover
}

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

// nonBlockingSender is a sender that declares it does not wait for delivery,
// as notify.QueuedSender does.
type nonBlockingSender struct {
	*MockSender
	*MockNonBlocking
}
