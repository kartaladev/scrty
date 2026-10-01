package recovery_test

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

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

// nonBlockingSender is a sender that declares it does not wait for delivery,
// as notify.QueuedSender does.
type nonBlockingSender struct {
	*MockSender
	*MockNonBlocking
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
	sessions *session.Manager
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
		recovery.WithCodeStore(faultyCodeStore{CodeStore: recovery.NewMemoryCodeStore(), f: flt}))
	require.NoError(t, err)

	// The store judges expiry on its own clock, so it gets the same one.
	sessions, err := session.NewManager(session.WithClock(clk),
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

func TestNewRecoverer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(f *fixture, d *recovery.Deps)
		opts   func(f *fixture) []recovery.Option
		assert func(t *testing.T, r *recovery.Recoverer, err error)
	}

	ok := func(t *testing.T, r *recovery.Recoverer, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, r)
	}
	configError := func(t *testing.T, r *recovery.Recoverer, err error) {
		t.Helper()
		require.ErrorIs(t, err, recovery.ErrConfig)
		assert.Nil(t, r)
	}
	with := func(extra ...recovery.Option) func(f *fixture) []recovery.Option {
		return func(f *fixture) []recovery.Option { return f.opts(extra...) }
	}
	proofs := func(kinds ...recovery.ProofKind) recovery.Option { return recovery.WithProofs(kinds...) }
	passwordOK := recovery.WithPasswordCheck(func(context.Context, string, []byte) error { return nil })

	cases := []testCase{
		{name: "saved and issued codes build a recoverer", assert: ok},

		// Issued codes.
		{name: "an issued-code lifetime of zero", opts: with(recovery.WithIssuedCodeTTL(0)), assert: configError},
		{name: "an issued-code lifetime of 25 hours", opts: with(recovery.WithIssuedCodeTTL(25 * time.Hour)), assert: configError},
		{name: "an issued-code lifetime of exactly 24 hours", opts: with(recovery.WithIssuedCodeTTL(24 * time.Hour)), assert: ok},
		{name: "an issuance limit of zero", opts: with(recovery.WithIssuedCodeLimit(0)), assert: configError},
		{name: "a nil issued-code store", opts: with(recovery.WithIssuedCodeStore(nil)), assert: configError},
		{
			name:   "a synchronous sender without acceptance",
			deps:   func(f *fixture, d *recovery.Deps) { d.Sender = f.sender },
			assert: configError,
		},
		{
			name:   "a synchronous sender with WithSynchronousDelivery",
			deps:   func(f *fixture, d *recovery.Deps) { d.Sender = f.sender },
			opts:   with(recovery.WithSynchronousDelivery()),
			assert: ok,
		},
		{
			name: "a missing repudiation contact",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(recovery.WithRepudiationContact(""))
			},
			assert: configError,
		},
		{name: "a blank repudiation contact", opts: with(recovery.WithRepudiationContact("  \n")), assert: configError},
		{name: "a nil contact resolver", opts: with(recovery.WithContactResolver(nil)), assert: configError},
		{name: "a nil message builder", opts: with(recovery.WithMessages(nil)), assert: configError},
		{name: "a nil clock", opts: with(recovery.WithClock(nil)), assert: configError},
		{name: "a nil logger is ignored", opts: with(recovery.WithLogger(nil)), assert: ok},

		// Ports.
		{name: "no user loader", deps: func(_ *fixture, d *recovery.Deps) { d.Users = nil }, assert: configError},
		{name: "no session manager", deps: func(_ *fixture, d *recovery.Deps) { d.Sessions = nil }, assert: configError},
		{
			name:   "a typed nil record store",
			deps:   func(_ *fixture, d *recovery.Deps) { d.Records = (*recovery.MemoryRecordStore)(nil) },
			assert: configError,
		},

		// Proof shape.
		{name: "saved codes only", opts: with(proofs(recovery.ProofSaved)), assert: configError},
		{name: "no proof kinds", opts: with(proofs()), assert: configError},
		{name: "a repeated proof kind", opts: with(proofs(recovery.ProofSaved, recovery.ProofSaved)), assert: configError},
		{name: "an unknown proof kind", opts: with(proofs(recovery.ProofSaved, "sms")), assert: configError},
		{
			name: "no recovery-code kind",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(proofs(recovery.ProofPassword, recovery.ProofMFA), passwordOK,
					recovery.WithMFAMethods(formMethod(f.ctrl, "totp")))
			},
			assert: configError,
		},

		// Each proof's port.
		{name: "saved codes without Deps.Codes", deps: func(_ *fixture, d *recovery.Deps) { d.Codes = nil }, assert: configError},
		{name: "issued codes without a sender", deps: func(_ *fixture, d *recovery.Deps) { d.Sender = nil }, assert: configError},
		{
			// The completion notice is mandatory, so a sender is required
			// whichever proof kinds are enabled.
			name:   "saved codes and password without a sender",
			deps:   func(_ *fixture, d *recovery.Deps) { d.Sender = nil },
			opts:   with(proofs(recovery.ProofSaved, recovery.ProofPassword), passwordOK),
			assert: configError,
		},
		{
			name:   "saved codes and password with a sender",
			opts:   with(proofs(recovery.ProofSaved, recovery.ProofPassword), passwordOK),
			assert: ok,
		},
		{name: "the password proof without a check", opts: with(proofs(recovery.ProofSaved, recovery.ProofPassword)), assert: configError},
		{
			name:   "the password proof with a nil check",
			opts:   with(proofs(recovery.ProofSaved, recovery.ProofPassword), recovery.WithPasswordCheck(nil)),
			assert: configError,
		},
		{
			name: "the MFA proof with an eligible method",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(proofs(recovery.ProofIssued, recovery.ProofMFA), recovery.WithMFAMethods(formMethod(f.ctrl, "totp")))
			},
			assert: ok,
		},
		{name: "the MFA proof with no method", opts: with(proofs(recovery.ProofIssued, recovery.ProofMFA)), assert: configError},
		{
			name: "the MFA proof with only a challenge method",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(proofs(recovery.ProofIssued, recovery.ProofMFA), recovery.WithMFAMethods(challengeMethod(f.ctrl, "passkey")))
			},
			assert: configError,
		},
		{
			name: "the MFA proof with only a JSON-body method",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(proofs(recovery.ProofIssued, recovery.ProofMFA), recovery.WithMFAMethods(jsonMethod(f.ctrl, "webauthn")))
			},
			assert: configError,
		},
		{
			name: "MFA methods with duplicate names",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(proofs(recovery.ProofIssued, recovery.ProofMFA),
					recovery.WithMFAMethods(formMethod(f.ctrl, "totp"), formMethod(f.ctrl, "totp")))
			},
			assert: configError,
		},

		// The reset and the flow.
		{name: "no authenticator kinds", opts: with(recovery.WithAuthenticatorKinds()), assert: configError},
		{
			name: "duplicate authenticator kinds",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(recovery.WithAuthenticatorKinds(f.kind, namedKind(f.ctrl, recovery.MFAKind)))
			},
			assert: configError,
		},
		{
			name: "the reported mode and a reset policy together",
			opts: with(recovery.WithResetReported(), recovery.WithResetPolicy(
				func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) { return nil, nil })),
			assert: configError,
		},
		{name: "the reported mode alone", opts: with(recovery.WithResetReported()), assert: ok},
		{name: "a nil reset policy", opts: with(recovery.WithResetPolicy(nil)), assert: configError},
		{name: "a nil user limiter", opts: with(recovery.WithUserLimiter(nil)), assert: configError},
		{name: "a nil risk hook", opts: with(recovery.WithRisk(nil)), assert: configError},

		// The completion.
		{name: "a session lifetime of zero", opts: with(recovery.WithSessionLifetime(0)), assert: configError},
		{name: "a negative session lifetime", opts: with(recovery.WithSessionLifetime(-time.Minute)), assert: configError},
		{
			name:   "a session lifetime of 13h against a 12h absolute timeout",
			opts:   with(recovery.WithSessionLifetime(13 * time.Hour)),
			assert: configError,
		},
		{
			name:   "a session lifetime equal to the absolute timeout",
			opts:   with(recovery.WithSessionLifetime(12 * time.Hour)),
			assert: ok,
		},
		{
			name: "the default session lifetime against a shorter absolute timeout",
			deps: func(f *fixture, d *recovery.Deps) {
				m, err := session.NewManager(session.WithClock(f.clock), session.WithAbsoluteTimeout(10*time.Minute),
					session.WithIdleTimeout(5*time.Minute))
				if err != nil {
					panic(err)
				}
				d.Sessions = m
			},
			assert: configError,
		},
		{name: "a nil id generator", opts: with(recovery.WithIDGenerator(nil)), assert: configError},
		{name: "session revocation turned off", opts: with(recovery.WithoutSessionRevocation()), assert: ok},

		// Holds.
		{name: "a delay without a cancel link", opts: with(recovery.WithDelay(72 * time.Hour)), assert: configError},
		{
			name:   "a risk hook without a cancel link",
			opts:   with(recovery.WithRisk(func(context.Context, recovery.RiskInput) (time.Duration, error) { return 0, nil })),
			assert: configError,
		},
		{
			name:   "a delay with an https cancel link",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("https://app.example.com/recovery/cancel")),
			assert: ok,
		},
		{
			name:   "a cancel link over http to a public host",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("http://app.example.com")),
			assert: configError,
		},
		{
			name:   "a cancel link over http to localhost",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("http://localhost:3000")),
			assert: ok,
		},
		{
			name:   "a cancel link over http to 127.0.0.1",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("http://127.0.0.1:3000/cancel")),
			assert: ok,
		},
		{
			name:   "a cancel link over http to ::1",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("http://[::1]:3000/cancel")),
			assert: ok,
		},
		{
			name:   "a relative cancel link",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("/recovery/cancel")),
			assert: configError,
		},
		{
			name:   "a cancel link carrying userinfo",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("https://user:pw@app.example.com/cancel")),
			assert: configError,
		},
		{
			name:   "a cancel link carrying a fragment",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("https://app.example.com/cancel#x")),
			assert: configError,
		},
		{
			name:   "an unparseable cancel link",
			opts:   with(recovery.WithCancelLink("https://app example.com/%zz")),
			assert: configError,
		},
		{
			name:   "a delay of zero",
			opts:   with(recovery.WithDelay(0), recovery.WithCancelLink("https://app.example.com/cancel")),
			assert: configError,
		},
		{
			name:   "a negative delay",
			opts:   with(recovery.WithDelay(-time.Hour), recovery.WithCancelLink("https://app.example.com/cancel")),
			assert: configError,
		},
		{name: "a completion window of zero", opts: with(recovery.WithCompletionWindow(0)), assert: configError},
		{name: "a nil hold token store", opts: with(recovery.WithHoldTokenStore(nil)), assert: configError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)

			d := f.deps()
			if tc.deps != nil {
				tc.deps(f, &d)
			}

			opts := f.opts()
			if tc.opts != nil {
				opts = tc.opts(f)
			}

			r, err := recovery.NewRecoverer(d, opts...)
			tc.assert(t, r, err)
		})
	}
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

// jsonMethod returns a method whose response is a whole JSON body, which cannot
// serve as a recovery proof.
func jsonMethod(ctrl *gomock.Controller, name string) *MockMethod {
	m := NewMockMethod(ctrl)
	m.EXPECT().Name().Return(name).AnyTimes()
	m.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	m.EXPECT().Response().Return(mfa.JSONBody(4096)).AnyTimes()

	return m
}
