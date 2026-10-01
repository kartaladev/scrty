package passkey_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
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

// fixture holds the doubles a Manager is built over, and what they captured.
type fixture struct {
	ctrl     *gomock.Controller
	clock    *clockwork.FakeClock
	verifier *MockVerifier
	sender   *MockSender
	users    *MockUserLoader
	creds    *passkey.MemoryCredentialStore
	deps     passkey.Deps

	mu        sync.Mutex
	created   []passkey.CreationInput
	sent      []notify.Message
	sendErr   error
	verified  []passkey.RegistrationExpectation
	verifyFor map[string]func(nc *passkey.NewCredential) error // by credential ID
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

	f.deps = passkey.Deps{
		Verifier:    f.verifier,
		Credentials: f.creds,
		Users:       f.users,
		Sender:      nonBlocking{f.sender},
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
) (*passkey.NewCredential, error) {
	f.mu.Lock()
	f.verified = append(f.verified, exp)
	adjust := f.verifyFor[string(p.CredentialID())]
	f.mu.Unlock()

	nc := &passkey.NewCredential{
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
func (f *fixture) adjustVerify(credID string, fn func(nc *passkey.NewCredential) error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.verifyFor == nil {
		f.verifyFor = map[string]func(nc *passkey.NewCredential) error{}
	}

	f.verifyFor[credID] = fn
}

// begin runs a registration begin for s and returns the challenge it issued.
func (f *fixture) begin(t *testing.T, m *passkey.Manager, s *session.Session) string {
	t.Helper()

	before := len(f.creations())

	_, err := m.BeginRegistration(t.Context(), s)
	require.NoError(t, err)

	in := f.creations()
	require.Len(t, in, before+1)

	return in[before].Challenge
}

// manager builds a Manager over the fixture's deps, on its clock, with a
// repudiation contact and opts.
func (f *fixture) manager(t *testing.T, opts ...passkey.Option) *passkey.Manager {
	t.Helper()

	base := []passkey.Option{passkey.WithClock(f.clock), passkey.WithRepudiationContact("help@example.com")}

	m, err := passkey.New(f.deps, append(base, opts...)...)
	require.NoError(t, err)

	return m
}

// withTOTP configures one TOTP lookup on the authenticator-app channel, which
// reports enrolled and err for every user.
func (f *fixture) withTOTP(enrolled bool, err error) {
	lk := NewMockMFAMethodLookup(f.ctrl)
	lk.EXPECT().Name().Return("totp").AnyTimes()
	lk.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	lk.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(enrolled, err).AnyTimes()
	f.deps.MFAMethods = []policy.MFAMethodLookup{lk}
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

// fullSession is a full password session of user created at regStart.
func fullSession(sid string, user identity.UserID) *session.Session {
	return &session.Session{ID: sid, UserID: user, CreatedAt: regStart, FirstFactor: factor.Password}
}

// synchronousSender is a sender that does not report notify.NonBlocking.
type synchronousSender struct{}

func (synchronousSender) Send(context.Context, notify.Message) error { return nil }

// typedNilLoader is a nil pointer whose type implements identity.UserLoader.
type typedNilLoader struct{}

func (*typedNilLoader) LoadByUsername(context.Context, string) (*identity.Details, error) {
	return nil, errors.New("unreachable")
}

func (*typedNilLoader) LoadByUserID(context.Context, identity.UserID) (*identity.Details, error) {
	return nil, errors.New("unreachable")
}

func TestNew(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(t *testing.T, f *fixture)
		opts   []passkey.Option
		noRepu bool
		assert func(t *testing.T, m *passkey.Manager, err error)
	}

	refused := func(t *testing.T, m *passkey.Manager, err error) {
		t.Helper()
		require.ErrorIs(t, err, passkey.ErrConfig)
		assert.Nil(t, m)
	}
	accepted := func(t *testing.T, m *passkey.Manager, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, m)
	}

	cases := []testCase{
		{name: "valid deps succeed", assert: accepted},
		{name: "nil verifier", deps: func(_ *testing.T, f *fixture) { f.deps.Verifier = nil }, assert: refused},
		{name: "nil users", deps: func(_ *testing.T, f *fixture) { f.deps.Users = nil }, assert: refused},
		{
			name:   "typed-nil users",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Users = (*typedNilLoader)(nil) },
			assert: refused,
		},
		{name: "nil sender", deps: func(_ *testing.T, f *fixture) { f.deps.Sender = nil }, assert: refused},
		{name: "missing repudiation contact", noRepu: true, assert: refused},
		{
			name: "invalid relying party",
			deps: func(t *testing.T, f *fixture) {
				v := NewMockVerifier(f.ctrl)
				v.EXPECT().RelyingParty().Return(passkey.RelyingParty{ID: "https://example.com"}).AnyTimes()
				f.deps.Verifier = v
			},
			assert: refused,
		},
		{
			name:   "synchronous sender",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sender = synchronousSender{} },
			assert: refused,
		},
		{
			name:   "synchronous sender with synchronous delivery accepted",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Sender = synchronousSender{} },
			opts:   []passkey.Option{passkey.WithSynchronousDelivery()},
			assert: accepted,
		},
		{name: "zero challenge TTL", opts: []passkey.Option{passkey.WithChallengeTTL(0)}, assert: refused},
		{name: "negative freshness", opts: []passkey.Option{passkey.WithManagementFreshness(-time.Minute)}, assert: refused},
		{name: "zero issuance limit", opts: []passkey.Option{passkey.WithRegistrationChallengeLimit(0)}, assert: refused},
		{name: "zero passkey limit", opts: []passkey.Option{passkey.WithPasskeyLimit(0)}, assert: refused},
		{name: "unknown user verification", opts: []passkey.Option{passkey.WithUserVerification(0)}, assert: refused},
		{name: "unknown resident key", opts: []passkey.Option{passkey.WithResidentKey(9)}, assert: refused},
		{name: "nil name resolver", opts: []passkey.Option{passkey.WithNameResolver(nil)}, assert: refused},
		{name: "nil registration check", opts: []passkey.Option{passkey.WithRegistrationCheck(nil)}, assert: refused},
		{name: "nil clock", opts: []passkey.Option{passkey.WithClock(nil)}, assert: refused},
		{name: "nil random", opts: []passkey.Option{passkey.WithRandom(nil)}, assert: refused},
		{name: "nil id generator", opts: []passkey.Option{passkey.WithIDGenerator(nil)}, assert: refused},
		{name: "nil login check", opts: []passkey.Option{passkey.WithLoginCheck(nil)}, assert: refused},
		{name: "unknown clone response", opts: []passkey.Option{passkey.WithCloneResponse(9)}, assert: refused},
		{name: "nil clone policy", opts: []passkey.Option{passkey.WithClonePolicy(nil)}, assert: refused},
		{name: "nil messages", opts: []passkey.Option{passkey.WithMessages(nil)}, assert: refused},
		{name: "nil contact resolver", opts: []passkey.Option{passkey.WithContactResolver(nil)}, assert: refused},
		{name: "zero log interval writes every record", opts: []passkey.Option{passkey.WithLogInterval(0)}, assert: accepted},
		{
			name:   "nil MFA method entry",
			deps:   func(_ *testing.T, f *fixture) { f.deps.MFAMethods = []policy.MFAMethodLookup{nil} },
			assert: refused,
		},
		{
			name:   "recovery without codes",
			deps:   func(_ *testing.T, f *fixture) { f.deps.Recovery = &passkey.RecoveryDeps{} },
			assert: refused,
		},
		{
			name: "recovery wired",
			deps: func(t *testing.T, f *fixture) {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.deps != nil {
				tc.deps(t, f)
			}

			opts := []passkey.Option{passkey.WithClock(f.clock)}
			if !tc.noRepu {
				opts = append(opts, passkey.WithRepudiationContact("help@example.com"))
			}

			m, err := passkey.New(f.deps, append(opts, tc.opts...)...)
			tc.assert(t, m, err)
		})
	}
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

// TestManagerRequiresRecoveryCodes pins what a passwordless login's wiring
// check reads: a manager needs saved codes wired unless they are, or the
// optional mode is chosen.
func TestManagerRequiresRecoveryCodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(t *testing.T, f *fixture)
		opts   []passkey.Option
		assert func(t *testing.T, requires bool)
	}

	cases := []testCase{
		{
			name:   "neither recovery nor the optional mode",
			assert: func(t *testing.T, requires bool) { assert.True(t, requires) },
		},
		{
			name:   "the optional mode",
			opts:   []passkey.Option{passkey.WithOptionalRecoveryCodes()},
			assert: func(t *testing.T, requires bool) { assert.False(t, requires) },
		},
		{
			name: "recovery wired",
			deps: func(t *testing.T, f *fixture) {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			},
			assert: func(t *testing.T, requires bool) { assert.False(t, requires) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.deps != nil {
				tc.deps(t, f)
			}

			tc.assert(t, f.manager(t, tc.opts...).RequiresRecoveryCodes())
		})
	}
}

// TestManagerChallengeTTL pins the lifetime a ceremony cookie is given: the
// default, or the consumer's.
func TestManagerChallengeTTL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []passkey.Option
		assert func(t *testing.T, ttl time.Duration)
	}

	cases := []testCase{
		{
			name:   "default",
			assert: func(t *testing.T, ttl time.Duration) { assert.Equal(t, 5*time.Minute, ttl) },
		},
		{
			name:   "consumer lifetime",
			opts:   []passkey.Option{passkey.WithChallengeTTL(90 * time.Second)},
			assert: func(t *testing.T, ttl time.Duration) { assert.Equal(t, 90*time.Second, ttl) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newFixture(t).manager(t, tc.opts...).ChallengeTTL())
		})
	}
}
