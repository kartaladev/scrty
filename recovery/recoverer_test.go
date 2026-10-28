package recovery_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

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
				m, err := session.New(session.WithClock(f.clock), session.WithAbsoluteTimeout(10*time.Minute),
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
			name:   "a cancel link over http to LOCALHOST, folded in ASCII",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("http://LOCALHOST:8080/recovery/cancel")),
			assert: ok,
		},
		{
			// U+017F folds to "s" only under Unicode case folding.
			name:   "a cancel link over http to a Unicode-folded look-alike of localhost",
			opts:   with(recovery.WithDelay(72*time.Hour), recovery.WithCancelLink("http://localhoſt/recovery/cancel")),
			assert: configError,
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

// jsonMethod returns a method whose response is a whole JSON body, which cannot
// serve as a recovery proof.
func jsonMethod(ctrl *gomock.Controller, name string) *MockMethod {
	m := NewMockMethod(ctrl)
	m.EXPECT().Name().Return(name).AnyTimes()
	m.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	m.EXPECT().Response().Return(mfa.JSONBody(4096)).AnyTimes()

	return m
}

// taskNames returns the names of tasks, in order.
func taskNames(tasks []expiry.Task) []string {
	names := make([]string, 0, len(tasks))
	for _, task := range tasks {
		names = append(names, task.Name)
	}

	return names
}

// namedTask returns the task of tasks with the given name.
func namedTask(t *testing.T, tasks []expiry.Task, name string) expiry.Task {
	t.Helper()

	for _, task := range tasks {
		if task.Name == name {
			return task
		}
	}
	require.Failf(t, "no such task", "%q not among %v", name, taskNames(tasks))

	return expiry.Task{}
}

// noIssuedProofs enables saved codes and the password, and no issued codes.
var noIssuedProofs = recovery.WithProofs(recovery.ProofSaved, recovery.ProofPassword)

func TestRecoverer_ExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts are the options beyond the env's, which enable every proof
		// kind and no hold.
		opts func(e *completeEnv) []recovery.Option
		// defaultStore builds the recoverer with no issued-code store, so
		// the one it makes for itself is under test.
		defaultStore bool
		// assert runs against the recoverer built from opts.
		assert func(t *testing.T, e *completeEnv, r *recovery.Recoverer)
	}

	cases := []testCase{
		{
			name: "issued codes and no hold give the issued-code task only",
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				tasks := r.ExpiryTasks()

				assert.Equal(t, []string{"recovery-issued-codes"}, taskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "holds add the finish and cancel token tasks",
			opts: func(*completeEnv) []recovery.Option { return holdFor(time.Hour) },
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				tasks := r.ExpiryTasks()

				assert.Equal(t,
					[]string{"recovery-issued-codes", "recovery-finish-tokens", "recovery-cancel-tokens"},
					taskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "holds without issued codes give the hold token tasks only",
			opts: func(*completeEnv) []recovery.Option {
				return append(holdFor(time.Hour), noIssuedProofs)
			},
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				assert.Equal(t, []string{"recovery-finish-tokens", "recovery-cancel-tokens"}, taskNames(r.ExpiryTasks()))
			},
		},
		{
			name: "neither issued codes nor holds give no tasks",
			opts: func(*completeEnv) []recovery.Option { return []recovery.Option{noIssuedProofs} },
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				tasks := r.ExpiryTasks()

				require.NotNil(t, tasks)
				assert.Empty(t, tasks)
			},
		},
		{
			name:         "an expired issued code goes and a live one stays",
			defaultStore: true,
			assert:       assertExpiredIssuedCodeGoes,
		},
		{
			name:         "the default issued-code store follows a clock ahead of the system clock",
			defaultStore: true,
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				e.clock.Advance(time.Until(time.Now().Add(365 * 24 * time.Hour)))

				assertExpiredIssuedCodeGoes(t, e, r)
			},
		},
		{
			name: "each hold token task sweeps only its own tokens",
			opts: func(e *completeEnv) []recovery.Option {
				return append(holdFor(time.Hour),
					recovery.WithHoldTokenStore(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(e.clock))))
			},
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				ctx := t.Context()
				heldRecovery(ctx, t, r, recovery.Request{Username: anaUsername, Saved: e.saved[0], Password: []byte(anaPassword)})
				tasks := r.ExpiryTasks()
				// Inside the hold and its completion window, nothing goes.
				for _, name := range []string{"recovery-finish-tokens", "recovery-cancel-tokens"} {
					removed, err := namedTask(t, tasks, name).Run(ctx)
					require.NoError(t, err)
					assert.Zero(t, removed, name)
				}
				// Past the hold, the 24-hour window and the issuance window.
				e.clock.Advance(27 * time.Hour)

				for _, name := range []string{"recovery-finish-tokens", "recovery-cancel-tokens"} {
					removed, err := namedTask(t, tasks, name).Run(ctx)
					require.NoError(t, err)
					assert.Equal(t, 1, removed, name)
				}
			},
		},
		{
			name: "an issued-code store that cannot purge says so",
			opts: func(e *completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithIssuedCodeStore(struct{ onetime.Store }{e.tokens})}
			},
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				removed, err := namedTask(t, r.ExpiryTasks(), "recovery-issued-codes").Run(t.Context())

				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			var opts []recovery.Option
			if tc.opts != nil {
				opts = tc.opts(e)
			}
			if tc.defaultStore {
				// The env's own options name a store, so build from the fixture's.
				r, err := recovery.NewRecoverer(e.completeDeps(),
					e.fixture.opts(append([]recovery.Option{recovery.WithMessages(e.capturingMessages())}, opts...)...)...)
				require.NoError(t, err)
				tc.assert(t, e, r)

				return
			}

			tc.assert(t, e, e.recoverer(t, opts...))
		})
	}
}

// assertExpiredIssuedCodeGoes issues two codes an expiry apart and checks that
// the issued-code task removes the expired one and leaves the live one.
func assertExpiredIssuedCodeGoes(t *testing.T, e *completeEnv, r *recovery.Recoverer) {
	t.Helper()

	ctx := t.Context()
	// Start is open to anyone who knows a username.
	r.Start(ctx, anaUsername)
	// Past the code's lifetime and the hour-long issuance window.
	e.clock.Advance(2 * time.Hour)
	r.Start(ctx, anaUsername)
	require.Len(t, e.out.messages(), 2, "both starts must have issued a code")

	removed, err := namedTask(t, r.ExpiryTasks(), "recovery-issued-codes").Run(ctx)

	require.NoError(t, err)
	assert.Equal(t, 1, removed)
	removed, err = namedTask(t, r.ExpiryTasks(), "recovery-issued-codes").Run(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed, "the live code must stay")
}

// regeneratedMessages is a consumer's message builder: it replaces only the
// regeneration notice, and writes the instant it was given into the body.
type regeneratedMessages struct {
	recovery.Messages
}

func (regeneratedMessages) Regenerated(at time.Time) (string, string) {
	return "Codes renewed", "Your codes were renewed at " + at.UTC().Format(time.RFC3339) + "."
}

// assertNoCode checks that no message carries a code of codes.
func assertNoCode(t *testing.T, msgs []notify.Message, codes []string) {
	t.Helper()

	for _, m := range msgs {
		for _, code := range codes {
			assert.NotContains(t, m.Subject, code, "the notice carries no code")
			assert.NotContains(t, m.TextBody, code, "the notice carries no code")
		}
	}
}

func TestRecoverer_Regenerate(t *testing.T) {
	t.Parallel()

	errStore := errors.New("code store unreachable")

	type testCase struct {
		name   string
		opts   func(e *completeEnv) []recovery.Option
		setup  func(e *completeEnv)
		assert func(t *testing.T, e *completeEnv, codes []string, err error)
	}

	cases := []testCase{
		{
			name: "a new set, the old set void, and one notice to the address with no code",
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)

				// Confirm charges a refusal to the saved-code limiter, so the
				// new set is checked first and the old set by one code.
				assert.True(t, e.savedUsable(t.Context(), t, codes[0]), "the new set is usable")
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]), "the previous set is void")

				msgs := e.out.messages()
				require.Len(t, msgs, 1, "one notice")
				subject, body := recovery.DefaultMessages().Regenerated(monday1000)
				assert.Equal(t, notify.Message{To: anaUsername, Subject: subject, TextBody: body}, msgs[0])
				assertNoCode(t, msgs, append(codes, e.saved...))

				for _, code := range append(codes, e.saved...) {
					assert.NotContains(t, e.logs.String(), code, "no log record carries a code")
				}
			},
		},
		{
			name: "the consumer's messages and contact resolver are used",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{
					recovery.WithMessages(regeneratedMessages{Messages: recovery.DefaultMessages()}),
					recovery.WithContactResolver(func(_ context.Context, d *identity.Details) (string, error) {
						return "security+" + string(d.ID) + "@example.net", nil
					}),
				}
			},
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)

				msgs := e.out.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "security+u-1@example.net", msgs[0].To, "the consumer's resolver addresses it")
				assert.Equal(t, "Codes renewed", msgs[0].Subject, "the consumer's builder writes it")
				assert.Equal(t, "Your codes were renewed at 2026-09-28T10:00:00Z.", msgs[0].TextBody, "the notice names the time")
				assertNoCode(t, msgs, codes)
			},
		},
		{
			name:  "a refused queue is logged and the codes are still returned",
			setup: func(e *completeEnv) { e.out.sendErr = errors.New("queue full") },
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)
				assert.True(t, e.savedUsable(t.Context(), t, codes[0]), "the regeneration stands")
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Contains(t, e.logs.String(), "the recovery notice could not be sent")
			},
		},
		{
			name: "an address that cannot be resolved is logged and the codes are still returned",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
					return "", errors.New("directory down")
				})}
			},
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)
				assert.Empty(t, e.out.messages(), "no notice")
				assert.Contains(t, e.logs.String(), "the notice's contact address could not be resolved")
			},
		},
		{
			name:  "a user who cannot be loaded is logged and the codes are still returned",
			setup: func(e *completeEnv) { e.failLookup(errors.New("user store down")) },
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)
				assert.Empty(t, e.out.messages(), "no notice")
				assert.Contains(t, e.logs.String(), "the user could not be loaded for the notice")
			},
		},
		{
			name:  "a set that cannot be written is returned as an error and nothing is sent",
			setup: func(e *completeEnv) { e.faults.arm(faultCodesReplaceSet, errStore) },
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, codes)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the previous set stands")
				assert.Empty(t, e.out.messages(), "no notice")
			},
		},
		{
			name: "saved codes not enabled is a configuration error",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithProofs(recovery.ProofIssued, recovery.ProofPassword)}
			},
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, codes)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the set is unchanged")
				assert.Empty(t, e.out.messages(), "no notice")
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
			if tc.setup != nil {
				tc.setup(e)
			}

			r := e.recoverer(t, extra...)

			codes, err := r.Regenerate(t.Context(), anaID)
			tc.assert(t, e, codes, err)

			if err != nil {
				assert.False(t, strings.Contains(err.Error(), anaUsername), "no username in the error")
			}
		})
	}
}

// TestNewRecoverer_UserLimiterFactory pins where the per-user limiter comes
// from: the explicit limiter, then the factory, then the in-memory default.
// It stands apart from TestNewRecoverer because its cases run over recoverEnv
// and build mocks on their own controller.
func TestNewRecoverer_UserLimiterFactory(t *testing.T) {
	t.Parallel()

	key := recovery.UserThrottleKey(anaID)

	type testCase struct {
		name   string
		opts   func(t *testing.T) []recovery.Option
		assert func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, err error)
	}

	// verifyRefused asks for a recovery of ana's and reports that the limiter
	// refused it before any proof was judged.
	verifyRefused := func(t *testing.T, e *recoverEnv, r *recovery.Recoverer) {
		t.Helper()

		_, err := r.Verify(t.Context(), recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued})
		assert.Error(t, err, "the recovery is counted through the limiter the factory built")
	}

	cases := []testCase{
		{
			name: "default builds in-memory",
			opts: func(*testing.T) []recovery.Option { return nil },
			assert: func(t *testing.T, _ *recoverEnv, r *recovery.Recoverer, err error) {
				require.NoError(t, err)
				assert.NotNil(t, r)
			},
		},
		{
			name: "factory asked with namespace, limit, window",
			opts: func(t *testing.T) []recovery.Option {
				ctrl := gomock.NewController(t)
				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("recovery-user", 5, 15*time.Minute).
					Return(refusingLimiter(ctrl, key), nil).Times(1)

				return []recovery.Option{recovery.WithUserLimiterFactory(f)}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, err error) {
				require.NoError(t, err)
				verifyRefused(t, e, r)
			},
		},
		{
			name: "explicit limiter wins and factory not asked",
			opts: func(t *testing.T) []recovery.Option {
				ctrl := gomock.NewController(t)

				// No expectation: gomock fails the case if the factory is asked.
				f := NewMockLimiterFactory(ctrl)

				return []recovery.Option{
					recovery.WithUserLimiter(refusingLimiter(ctrl, key)),
					recovery.WithUserLimiterFactory(f),
				}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, err error) {
				require.NoError(t, err)
				verifyRefused(t, e, r)
			},
		},
		{
			name: "nil factory refused",
			opts: func(*testing.T) []recovery.Option {
				return []recovery.Option{recovery.WithUserLimiterFactory(nil)}
			},
			assert: func(t *testing.T, _ *recoverEnv, r *recovery.Recoverer, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, r)
			},
		},
		{
			name: "typed-nil factory refused",
			opts: func(*testing.T) []recovery.Option {
				return []recovery.Option{recovery.WithUserLimiterFactory((*MockLimiterFactory)(nil))}
			},
			assert: func(t *testing.T, _ *recoverEnv, r *recovery.Recoverer, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, r)
			},
		},
		{
			// The explicit limiter wins, but a factory replaced with nothing is
			// a wiring mistake whatever else was given.
			name: "typed-nil factory refused beside an explicit limiter",
			opts: func(t *testing.T) []recovery.Option {
				return []recovery.Option{
					recovery.WithUserLimiter(NewMockLimiter(gomock.NewController(t))),
					recovery.WithUserLimiterFactory((*MockLimiterFactory)(nil)),
				}
			},
			assert: func(t *testing.T, _ *recoverEnv, r *recovery.Recoverer, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, r)
			},
		},
		{
			name: "factory error fails construction",
			opts: func(t *testing.T) []recovery.Option {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("recovery-user", 5, 15*time.Minute).Return(nil, errFactory)

				return []recovery.Option{recovery.WithUserLimiterFactory(f)}
			},
			assert: func(t *testing.T, _ *recoverEnv, r *recovery.Recoverer, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				require.ErrorIs(t, err, errFactory)
				assert.Contains(t, err.Error(), `"recovery-user"`, "the error names the namespace")
				assert.Nil(t, r)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newRecoverEnv(t)
			e.defaults()

			r, err := recovery.NewRecoverer(e.deps(), e.fixture.opts(tc.opts(t)...)...)
			tc.assert(t, e, r, err)
		})
	}
}

// TestRecoverer_Enabled pins that the recoverer reports exactly the proof
// kinds WithProofs enabled, so a caller offers only those.
func TestRecoverer_Enabled(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		proofs []recovery.ProofKind
		assert func(t *testing.T, r *recovery.Recoverer)
	}

	cases := []testCase{
		{
			name:   "saved and issued codes",
			proofs: []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued},
			assert: func(t *testing.T, r *recovery.Recoverer) {
				assert.True(t, r.Enabled(recovery.ProofSaved))
				assert.True(t, r.Enabled(recovery.ProofIssued))
				assert.False(t, r.Enabled(recovery.ProofPassword))
				assert.False(t, r.Enabled(recovery.ProofMFA))
			},
		},
		{
			name:   "a saved code and the password: no issued codes",
			proofs: []recovery.ProofKind{recovery.ProofSaved, recovery.ProofPassword},
			assert: func(t *testing.T, r *recovery.Recoverer) {
				assert.True(t, r.Enabled(recovery.ProofSaved))
				assert.True(t, r.Enabled(recovery.ProofPassword))
				assert.False(t, r.Enabled(recovery.ProofIssued))
				assert.False(t, r.Enabled(recovery.ProofKind("unknown")))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newRecoverEnv(t)
			r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithProofs(tc.proofs...))...)
			require.NoError(t, err)

			tc.assert(t, r)
		})
	}
}
