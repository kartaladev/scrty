package passkey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// regStart is 09:00, the instant every registration fixture's clock starts at
// and its sessions are created at, unless a case says otherwise.
var regStart = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// testRP is a valid relying party.
var testRP = passkey.RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://example.com"}}

// usernames are the usernames the fixture's user loader knows.
var usernames = map[identity.UserID]string{"u-1": "ana@example.com", "u-2": "bo@example.com"}

// nonBlocking reports a sender as non-blocking, as a queued sender does.
type nonBlocking struct{ notify.Sender }

func (nonBlocking) NonBlocking() bool { return true }

// fixture holds the doubles the Passkeys is built over, and what they captured.
type fixture struct {
	ctrl     *gomock.Controller
	clock    *clockwork.FakeClock
	verifier *MockVerifier
	sender   *MockSender
	users    *MockUserLoader
	creds    *passkey.MemoryCredentialStore
	sessions *session.Sessions
	deps     passkey.Deps

	mu        sync.Mutex
	created   []passkey.CreationInput
	sent      []notify.Message
	sendErr   error
	verified  []passkey.RegistrationExpectation
	verifyFor map[string]func(nc *passkey.CredentialInput) error // by credential ID
}

// newFixture returns doubles whose verifier renders creation options and
// records their input, whose sender records every message, and whose loader
// knows usernames.
func newFixture(t *testing.T) *fixture {
	t.Helper()

	ctrl := gomock.NewController(t)
	f := &fixture{
		ctrl:     ctrl,
		clock:    clockwork.NewFakeClockAt(regStart),
		verifier: NewMockVerifier(ctrl),
		sender:   NewMockSender(ctrl),
		users:    NewMockUserLoader(ctrl),
		creds:    passkey.NewMemoryCredentialStore(),
	}

	f.verifier.EXPECT().RelyingParty().Return(testRP).AnyTimes()
	f.verifier.EXPECT().CreationOptions(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, in passkey.CreationInput) (json.RawMessage, error) {
			f.mu.Lock()
			defer f.mu.Unlock()

			f.created = append(f.created, in)

			return json.RawMessage(`{"publicKey":{}}`), nil
		}).AnyTimes()
	f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, msg notify.Message) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			if f.sendErr != nil {
				return f.sendErr
			}

			f.sent = append(f.sent, msg)

			return nil
		}).AnyTimes()
	f.verifier.EXPECT().ParseRegistration(gomock.Any()).DoAndReturn(f.parseRegistration).AnyTimes()
	f.verifier.EXPECT().VerifyRegistration(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		f.verifyRegistration).AnyTimes()
	f.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, u identity.UserID) (*identity.Details, error) {
			name, ok := usernames[u]
			if !ok {
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{ID: u, Username: name, Active: true}, nil
		}).AnyTimes()

	sessions, err := session.New(session.WithClock(f.clock),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(f.clock))))
	require.NoError(t, err)

	f.sessions = sessions

	f.deps = passkey.Deps{
		Verifier:    f.verifier,
		Credentials: f.creds,
		Users:       f.users,
		Sender:      nonBlocking{f.sender},
		Sessions:    f.sessions,
	}

	return f
}

// regResponse is the fixture's registration response body: the challenge as
// clientDataJSON carries it, the credential ID and the proposed name.
type regResponse struct {
	Challenge string `json:"challenge"`
	ID        string `json:"id"`
	Name      string `json:"name"`
}

// regBody returns a registration response body answering the token string
// challenge with credential credID.
func regBody(challenge, credID, name string) []byte {
	b, _ := json.Marshal(regResponse{
		Challenge: base64.RawURLEncoding.EncodeToString([]byte(challenge)), ID: credID, Name: name,
	})

	return b
}

// parseRegistration reads a regBody into a parsed registration; anything
// else does not parse.
func (f *fixture) parseRegistration(body []byte) (passkey.ParsedRegistration, error) {
	var r regResponse
	if err := json.Unmarshal(body, &r); err != nil || r.ID == "" {
		return nil, errors.New("unparseable")
	}

	p := NewMockParsedRegistration(f.ctrl)
	p.EXPECT().Challenge().Return(r.Challenge).AnyTimes()
	p.EXPECT().CredentialID().Return([]byte(r.ID)).AnyTimes()
	p.EXPECT().Name().Return(r.Name).AnyTimes()

	return p, nil
}

// verifyRegistration accepts every parsed registration as a user-verified,
// synced passkey with transports internal and hybrid and a zero counter,
// unless verifyFor holds an adjustment for its credential ID, whose error
// refuses it.
func (f *fixture) verifyRegistration(
	_ context.Context, p passkey.ParsedRegistration, exp passkey.RegistrationExpectation,
) (*passkey.CredentialInput, error) {
	f.mu.Lock()
	f.verified = append(f.verified, exp)
	adjust := f.verifyFor[string(p.CredentialID())]
	f.mu.Unlock()

	nc := &passkey.CredentialInput{
		CredentialID:   p.CredentialID(),
		PublicKey:      append([]byte("cose-"), p.CredentialID()...),
		UserVerified:   true,
		BackupEligible: true,
		BackupState:    true,
		Transports:     []string{"internal", "hybrid"},
		AAGUID:         make([]byte, 16),
	}

	if adjust != nil {
		if err := adjust(nc); err != nil {
			return nil, err
		}
	}

	return nc, nil
}

// verifications returns a copy of the expectations the verifier was given.
func (f *fixture) verifications() []passkey.RegistrationExpectation {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]passkey.RegistrationExpectation(nil), f.verified...)
}

// adjustVerify sets how the verifier treats credential credID.
func (f *fixture) adjustVerify(credID string, fn func(nc *passkey.CredentialInput) error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.verifyFor == nil {
		f.verifyFor = map[string]func(nc *passkey.CredentialInput) error{}
	}

	f.verifyFor[credID] = fn
}

// begin runs a registration begin for s and returns the challenge it issued.
func (f *fixture) begin(t *testing.T, m *passkey.Passkeys, s *session.Session) string {
	t.Helper()

	before := len(f.creations())

	_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})
	require.NoError(t, err)

	in := f.creations()
	require.Len(t, in, before+1)

	return in[before].Challenge
}

// manager builds a Passkeys value over the fixture's deps, on its clock, with a
// repudiation contact and opts.
func (f *fixture) manager(t *testing.T, opts ...passkey.Option) *passkey.Passkeys {
	t.Helper()

	base := []passkey.Option{passkey.WithClock(f.clock), passkey.WithRepudiationContact("help@example.com")}

	m, err := passkey.New(f.deps, append(base, opts...)...)
	require.NoError(t, err)

	return m
}

// withTOTP configures one TOTP lookup on the authenticator-app channel, which
// reports enrolled and err for every user.
func (f *fixture) withTOTP(enrolled bool, err error) {
	f.deps.MFAMethods = []policy.MFAMethodLookup{f.totp(enrolled, err)}
}

// totp is a TOTP lookup on the authenticator-app channel, which reports the
// user enrolled or not, or err.
func (f *fixture) totp(enrolled bool, err error) policy.MFAMethodLookup {
	lk := NewMockMFAMethodLookup(f.ctrl)
	lk.EXPECT().Name().Return("totp").AnyTimes()
	lk.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	lk.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(enrolled, err).AnyTimes()

	return lk
}

// creations returns a copy of the creation inputs the verifier was given.
func (f *fixture) creations() []passkey.CreationInput {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]passkey.CreationInput(nil), f.created...)
}

// messages returns a copy of the messages the sender was given.
func (f *fixture) messages() []notify.Message {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]notify.Message(nil), f.sent...)
}

// seedSessions stores u-1's laptop, phone and tablet sessions and u-2's
// session in the fixture's session manager, and returns their identifiers by
// device.
func (f *fixture) seedSessions(t *testing.T) map[string]string {
	t.Helper()

	sids := map[string]string{}

	for device, user := range map[string]identity.UserID{
		"laptop": "u-1", "phone": "u-1", "tablet": "u-1", "theirs": "u-2",
	} {
		s, err := f.sessions.Create(t.Context(), user)
		require.NoError(t, err)

		sids[device] = s.ID
	}

	return sids
}

// loads reports whether the session sid still loads from the fixture's
// session manager.
func (f *fixture) loads(t *testing.T, sid string) bool {
	t.Helper()

	_, err := f.sessions.Load(t.Context(), sid)

	return err == nil
}

// mockRevoker wires a gomock session revoker in place of the fixture's
// session manager, and returns it.
func (f *fixture) mockRevoker() *MockSessionRevoker {
	r := NewMockSessionRevoker(f.ctrl)
	f.deps.Sessions = r

	return r
}

// fullSession is a full password session of user created at regStart.
func fullSession(sid string, user identity.UserID) *session.Session {
	return &session.Session{ID: sid, UserID: user, CreatedAt: regStart, AuthenticatedAt: regStart, FirstFactor: factor.Password}
}

// recoveryDeps wires in-memory saved codes and a way-back check over them,
// with the fixture's clock. Unset fields of wb default to the fixture's
// loader and those codes. opts configure the codes after the clock.
func recoveryDeps(
	t *testing.T, f *fixture, wb recovery.WayBackDeps, opts ...recovery.CodesOption,
) *passkey.RecoveryDeps {
	t.Helper()

	codes, err := recovery.NewCodes(append([]recovery.CodesOption{recovery.WithCodesClock(f.clock)}, opts...)...)
	require.NoError(t, err)

	if wb.Users == nil {
		wb.Users = f.users
	}

	wb.Codes = codes

	check, err := recovery.NewWayBackCheck(wb)
	require.NoError(t, err)

	return &passkey.RecoveryDeps{Codes: codes, WayBack: check}
}

// assertionBody is the login fixture's assertion response body.
type assertionBody struct {
	Challenge string `json:"challenge"` // as clientDataJSON carries it
	ID        string `json:"id"`
	Handle    []byte `json:"handle"`
	Sig       string `json:"sig"` // "ok" verifies; anything else does not
	Count     uint32 `json:"count"`
	UV        bool   `json:"uv"`
	BE        bool   `json:"be"`
	BS        bool   `json:"bs"`
}

// parsedAssertion is a parsed assertionBody.
type parsedAssertion struct{ b assertionBody }

func (p parsedAssertion) Challenge() string    { return p.b.Challenge }
func (p parsedAssertion) CredentialID() []byte { return []byte(p.b.ID) }
func (p parsedAssertion) UserHandle() []byte   { return p.b.Handle }

// spyCredentials counts the lookups and counter writes made on a memory store.
type spyCredentials struct {
	*passkey.MemoryCredentialStore
	finds   atomic.Int32
	records atomic.Int32
	// useHook, when set, runs in place of RecordUse's write.
	useHook func(ctx context.Context, cid id.ID) (bool, error)
	// suspendHook, when set, runs in place of Suspend's write.
	suspendHook func(ctx context.Context, cid id.ID) (bool, error)
	// ctxFind makes Find fail on a cancelled context, as a durable store does.
	ctxFind bool
	// afterRecord, when set, runs with the outcome of every counter write.
	afterRecord func(recorded bool)
}

func (s *spyCredentials) Find(ctx context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	if s.ctxFind {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	return s.MemoryCredentialStore.Find(ctx, user, cid)
}

func (s *spyCredentials) Suspend(ctx context.Context, cid id.ID) (bool, error) {
	if s.suspendHook != nil {
		return s.suspendHook(ctx, cid)
	}

	return s.MemoryCredentialStore.Suspend(ctx, cid)
}

func (s *spyCredentials) RecordUse(ctx context.Context, cid id.ID, bs bool, at time.Time) (bool, error) {
	if s.useHook != nil {
		return s.useHook(ctx, cid)
	}

	return s.MemoryCredentialStore.RecordUse(ctx, cid, bs, at)
}

func (s *spyCredentials) FindByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	s.finds.Add(1)
	return s.MemoryCredentialStore.FindByCredentialID(ctx, credID)
}

func (s *spyCredentials) RecordAssertion(
	ctx context.Context, cid id.ID, n uint32, bs bool, at time.Time,
) (bool, error) {
	s.records.Add(1)

	ok, err := s.MemoryCredentialStore.RecordAssertion(ctx, cid, n, bs, at)
	if s.afterRecord != nil {
		s.afterRecord(ok)
	}

	return ok, err
}

// spyChallenges counts the purges made on a memory challenge store, and fails
// them with err when set.
type spyChallenges struct {
	*onetime.MemoryStore
	err     error
	mu      sync.Mutex
	reaps   int
	removed int
}

func (s *spyChallenges) DeleteExpiredBefore(ctx context.Context, purpose string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reaps++
	if s.err != nil {
		return 0, s.err
	}

	n, err := s.MemoryStore.DeleteExpiredBefore(ctx, purpose, since)
	s.removed += n

	return n, err
}

// purges returns how many purges ran and how many records they removed.
func (s *spyChallenges) purges() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.reaps, s.removed
}

// The login fixture's handles, one per user.
var (
	handleU1 = bytes.Repeat([]byte{0x01}, passkey.HandleSize)
	handleU2 = bytes.Repeat([]byte{0x02}, passkey.HandleSize)
)

// loginEnv is a manager over the fixture with one seeded credential, "key-1"
// of u-1: a device-bound security key with a stored counter of 42.
type loginEnv struct {
	f          *fixture
	m          *passkey.Passkeys
	creds      *spyCredentials
	challenges *spyChallenges
	cred       *passkey.Credential
	logs       *logBuffer
	binding    string
	sids       map[string]string // sessions seeded by fixture.seedSessions, by device

	mu        sync.Mutex
	requested []passkey.RequestInput
	verifies  int
	verifyErr error // when set, the verifier fails with it
}

// failVerifier makes the verifier fail every assertion with err.
func (e *loginEnv) failVerifier(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.verifyErr = err
}

// newLoginEnv wires the fixture for login. seed may adjust the credential
// before it is stored.
func newLoginEnv(t *testing.T, seed func(c *passkey.Credential)) *loginEnv {
	t.Helper()

	f := newFixture(t)
	e := &loginEnv{
		f:          f,
		creds:      &spyCredentials{MemoryCredentialStore: f.creds},
		challenges: &spyChallenges{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock))},
		logs:       &logBuffer{},
		binding:    "ceremony-cookie-value",
	}

	handles := passkey.NewMemoryHandleStore()
	_, err := handles.Assign(t.Context(), "u-1", handleU1)
	require.NoError(t, err)
	_, err = handles.Assign(t.Context(), "u-2", handleU2)
	require.NoError(t, err)

	f.deps.Credentials = e.creds
	f.deps.Handles = handles
	f.deps.Challenges = e.challenges

	f.verifier.EXPECT().RequestOptions(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, in passkey.RequestInput) (json.RawMessage, error) {
			e.mu.Lock()
			defer e.mu.Unlock()

			e.requested = append(e.requested, in)

			return json.RawMessage(`{"publicKey":{}}`), nil
		}).AnyTimes()
	f.verifier.EXPECT().ParseAssertion(gomock.Any()).DoAndReturn(
		func(body []byte) (passkey.ParsedAssertion, error) {
			var b assertionBody
			if err := json.Unmarshal(body, &b); err != nil || b.ID == "" {
				return nil, errors.New("unparseable")
			}

			return parsedAssertion{b}, nil
		}).AnyTimes()
	f.verifier.EXPECT().VerifyAssertion(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(
			_ context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation,
		) (*passkey.AssertionResult, error) {
			e.mu.Lock()
			e.verifies++
			failure := e.verifyErr
			e.mu.Unlock()

			if failure != nil {
				return nil, failure
			}

			b := p.(parsedAssertion).b
			signed, _ := passkey.DecodeChallenge(b.Challenge)

			if b.Sig != "ok" || signed != exp.Challenge || !bytes.Equal(c.CredentialID, []byte(b.ID)) {
				return nil, errors.New("signature does not verify")
			}

			return &passkey.AssertionResult{SignCount: b.Count, UserVerified: b.UV, BackupEligible: b.BE, BackupState: b.BS}, nil
		}).AnyTimes()

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	e.cred = &passkey.Credential{
		ID:           cid,
		User:         "u-1",
		CredentialID: []byte("key-1"),
		PublicKey:    []byte("cose-public-key-of-key-1"),
		SignCount:    42,
		AAGUID:       bytes.Repeat([]byte{0xAA}, 16),
		Name:         "Security key",
		CreatedAt:    regStart,
		State:        passkey.StateActive,
	}
	if seed != nil {
		seed(e.cred)
	}

	require.NoError(t, f.creds.Insert(t.Context(), e.cred))

	return e
}

// manager builds the manager, logging to e.logs.
func (e *loginEnv) manager(t *testing.T, opts ...passkey.Option) *passkey.Passkeys {
	t.Helper()

	e.m = e.f.manager(t, append([]passkey.Option{passkey.WithLogger(e.logs.logger())}, opts...)...)

	return e.m
}

// begin runs a passwordless begin bound to e.binding, and returns the token
// string it issued.
func (e *loginEnv) begin(t *testing.T) string {
	t.Helper()

	_, err := e.m.BeginLogin(t.Context(), e.binding)
	require.NoError(t, err)

	e.mu.Lock()
	defer e.mu.Unlock()

	require.NotEmpty(t, e.requested)

	return e.requested[len(e.requested)-1].Challenge
}

// verifyCount returns how many assertions the verifier was asked to verify.
func (e *loginEnv) verifyCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.verifies
}

// stored returns the seeded credential as stored now.
func (e *loginEnv) stored(t *testing.T) *passkey.Credential {
	t.Helper()

	c, err := e.f.creds.Find(t.Context(), "u-1", e.cred.ID)
	require.NoError(t, err)

	return c
}

// assertion returns a valid, user-verified assertion body from "key-1"
// answering challenge with counter 43, adjusted by adjust.
func assertion(challenge string, adjust func(b *assertionBody)) []byte {
	b := assertionBody{
		Challenge: base64.RawURLEncoding.EncodeToString([]byte(challenge)),
		ID:        "key-1",
		Handle:    handleU1,
		Sig:       "ok",
		Count:     43,
		UV:        true,
	}
	if adjust != nil {
		adjust(&b)
	}

	out, _ := json.Marshal(b)

	return out
}

// logBuffer collects JSON log records written by concurrent goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// records returns the written records, one line each.
func (b *logBuffer) records() []string {
	s := strings.TrimSpace(b.String())
	if s == "" {
		return nil
	}

	return strings.Split(s, "\n")
}

// logger returns a debug-level JSON logger writing to b.
func (b *logBuffer) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// assertNoSecrets fails when any of secrets, raw or in base64 (padded,
// unpadded, standard and URL alphabets) or hex, appears in out.
func assertNoSecrets(t *testing.T, out string, secrets ...[]byte) {
	t.Helper()

	for _, s := range secrets {
		forms := []string{
			string(s),
			base64.StdEncoding.EncodeToString(s),
			base64.RawStdEncoding.EncodeToString(s),
			base64.URLEncoding.EncodeToString(s),
			base64.RawURLEncoding.EncodeToString(s),
			hex.EncodeToString(s),
		}
		for _, f := range forms {
			assert.NotContains(t, out, f)
		}
	}
}

// countRecords counts the log records whose message is msg.
func countRecords(logs *logBuffer, msg string) int {
	n := 0

	for _, r := range logs.records() {
		if strings.Contains(r, `"msg":"`+msg+`"`) {
			n++
		}
	}

	return n
}

// sixDigits finds the emailed code in a message body.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// enrolmentSession is an enrolment-only session of user created at regStart.
func enrolmentSession(sid string, user identity.UserID) *session.Session {
	s := fullSession(sid, user)
	s.MFA, s.EnrolmentOriginDeadline = session.MFAEnrolmentPending, regStart.Add(time.Hour)

	return s
}

// emailedCode returns the code in the only message sent so far.
func emailedCode(t *testing.T, f *fixture) string {
	t.Helper()

	msgs := f.messages()
	require.Len(t, msgs, 1)

	code := sixDigits.FindString(msgs[0].TextBody)
	require.NotEmpty(t, code)

	return code
}

// permissive is a limiter that never refuses, so a test sees the store's own
// cap on emailed-code attempts.
func permissive(t *testing.T) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(1000, time.Minute)
	require.NoError(t, err)

	return l
}

// onlyCredential returns user's only credential.
func onlyCredential(t *testing.T, f *fixture, user identity.UserID) *passkey.Credential {
	t.Helper()

	held, err := f.creds.List(t.Context(), user)
	require.NoError(t, err)
	require.Len(t, held, 1)

	return held[0]
}

// errStore is the failure brokenCredentials reports.
var errStore = errors.New("credential store unavailable")

// brokenCredentials is a memory store whose reads and bulk deletes fail.
type brokenCredentials struct {
	*passkey.MemoryCredentialStore
}

func (brokenCredentials) List(context.Context, identity.UserID) ([]*passkey.Credential, error) {
	return nil, errStore
}

func (brokenCredentials) FindByCredentialID(context.Context, []byte) (*passkey.Credential, error) {
	return nil, errStore
}

func (brokenCredentials) DeleteUser(context.Context, identity.UserID) (int, error) {
	return 0, errStore
}

func (brokenCredentials) Delete(context.Context, identity.UserID, id.ID) (bool, error) {
	return false, errStore
}

// addCredential stores another credential of user in state st, named by its
// WebAuthn credential ID, and returns it.
func addCredential(t *testing.T, e *loginEnv, user identity.UserID, credID string, st passkey.State) *passkey.Credential {
	t.Helper()

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	c := &passkey.Credential{
		ID:           cid,
		User:         user,
		CredentialID: []byte(credID),
		PublicKey:    []byte("cose-" + credID),
		Transports:   []string{"usb", "nfc"},
		Name:         credID,
		CreatedAt:    regStart,
		State:        st,
	}
	if st == passkey.StatePending {
		c.Pending = passkey.PendingSavedCodes
	}

	require.NoError(t, e.f.creds.Insert(t.Context(), c))

	return c
}

// manageEnv is a manager whose user u-1 holds the login fixture's active
// security key and a suspended passkey, and u-2 one active passkey.
type manageEnv struct {
	*loginEnv
	suspendedCred, theirs *passkey.Credential
}

// seedSessions stores the fixture's sessions (see fixture.seedSessions).
func (e *manageEnv) seedSessions(t *testing.T) {
	t.Helper()

	e.sids = e.f.seedSessions(t)
}

// loads reports whether the session stored for device still loads.
func (e *manageEnv) loads(t *testing.T, device string) bool {
	t.Helper()

	return e.f.loads(t, e.sids[device])
}

// mockRevoker wires a gomock session revoker in place of the session manager.
func (e *manageEnv) mockRevoker() *MockSessionRevoker { return e.f.mockRevoker() }

// lastNotice returns the body of the only notice queued.
func (e *manageEnv) lastNotice(t *testing.T) string {
	t.Helper()

	msgs := e.f.messages()
	require.Len(t, msgs, 1)

	return msgs[0].TextBody
}

func newManageEnv(t *testing.T) *manageEnv {
	t.Helper()

	e := &manageEnv{loginEnv: newLoginEnv(t, func(c *passkey.Credential) {
		c.Transports = []string{"usb"}
		c.BackupEligible = false
	})}
	e.suspendedCred = addCredential(t, e.loginEnv, "u-1", "key-suspended", passkey.StateSuspended)
	e.theirs = addCredential(t, e.loginEnv, "u-2", "key-of-u-2", passkey.StateActive)

	return e
}

// exists reports whether user still holds credential cid.
func (e *manageEnv) exists(t *testing.T, user identity.UserID, cid id.ID) bool {
	t.Helper()

	_, err := e.f.creds.Find(t.Context(), user, cid)

	return err == nil
}
