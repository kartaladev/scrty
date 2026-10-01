package recovery_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
)

const anaPassword = "correct horse"

// withCancelLink is the cancel link every hold needs.
var withCancelLink = recovery.WithCancelLink("https://app.example.com/recovery/cancel")

// recoverEnv is one recovery case's world: ana holds a saved set and one
// issued code, TOTP and email-code enrolments, and a password.
type recoverEnv struct {
	*fixture

	tokens *onetime.MemoryStore
	mint   *onetime.Manager
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

	mint, err := onetime.NewManager(recovery.IssuedCodePurpose, onetime.WithStore(e.tokens), onetime.WithClock(f.clock))
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

// recoverOnce runs the check phase and, when it passes, the spend phase.
func recoverOnce(ctx context.Context, r *recovery.Recoverer, req recovery.Request) (*recovery.Verified, error) {
	v, err := r.Verify(ctx, req)
	if err != nil {
		return nil, err
	}

	return v, r.Spend(ctx, v)
}

func TestRecoverer_Shape(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []recovery.Option
		req  func(e *recoverEnv) recovery.Request
	}

	cases := []testCase{
		{name: "no username", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Saved: e.saved[0], Issued: e.issued}
		}},
		{name: "one proof", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Issued: e.issued}
		}},
		{name: "no proof", req: func(*recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername}
		}},
		{name: "three proofs", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued, Password: []byte(anaPassword)}
		}},
		{name: "password and TOTP without a recovery code", req: func(*recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Password: []byte(anaPassword), MFAMethod: "totp", MFACode: "123456"}
		}},
		{name: "password with an MFA method and no code", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Saved: e.saved[0], Password: []byte(anaPassword), MFAMethod: "totp"}
		}},
		{name: "an MFA code with no method", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Saved: e.saved[0], MFACode: "123456"}
		}},
		{
			name: "a proof of a kind that is not enabled",
			opts: []recovery.Option{recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued)},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], Password: []byte(anaPassword)}
			},
		},
		{name: "an MFA method that is not configured", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "sms", MFACode: "123456"}
		}},
		{name: "a challenge method is not eligible", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "passkey", MFACode: "123456"}
		}},
		{name: "a reported loss that is not kind:id", req: func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued, Lost: []string{"totp"}}
		}},
		{
			name: "reported mode: reporting nothing",
			opts: []recovery.Option{recovery.WithResetReported()},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}
			},
		},
		{
			name: "reported mode: reporting the MFA method presented as a proof as lost",
			opts: []recovery.Option{recovery.WithResetReported()},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: "123456", Lost: []string{"mfa:email-code", "mfa:totp"}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// No expectation is set on any port: a shape refusal calls none of
			// them, and records nothing on the user limiter.
			e := newRecoverEnv(t)
			r, err := recovery.NewRecoverer(e.deps(), e.opts(tc.opts...)...)
			require.NoError(t, err)

			req := tc.req(e)
			_, err = r.Verify(t.Context(), req)
			require.ErrorIs(t, err, recovery.ErrMalformed)
			assert.False(t, recovery.RefusedAfterValidCode(err))
			assert.Zero(t, e.passwordCalls.Load())

			if req.Saved != "" {
				assert.True(t, e.savedUsable(t.Context(), t, req.Saved))
			}
			if req.Issued != "" {
				assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, req.Issued))
			}
		})
	}
}

func TestRecoverer_Verify(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("store unreachable: ana@example.com row 42")
	errConsumer := errors.New("consumer says no")

	type testCase struct {
		name  string
		opts  func(e *recoverEnv) []recovery.Option
		setup func(e *recoverEnv)
		ctx   func(ctx context.Context) context.Context
		// run recovers; nil runs recoverOnce over req.
		req    func(e *recoverEnv) recovery.Request
		run    func(t *testing.T, ctx context.Context, e *recoverEnv, r *recovery.Recoverer) (*recovery.Verified, error)
		assert func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error)
	}

	savedAndIssued := func(e *recoverEnv) recovery.Request {
		return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}
	}
	savedAndPassword := func(pw string) func(e *recoverEnv) recovery.Request {
		return func(e *recoverEnv) recovery.Request {
			return recovery.Request{Username: anaUsername, Saved: e.saved[0], Password: []byte(pw)}
		}
	}
	issuedAndTOTP := func(e *recoverEnv) recovery.Request {
		return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: "123456"}
	}
	nothingSpent := func(t *testing.T, e *recoverEnv, r *recovery.Recoverer) {
		t.Helper()
		assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved code stays redeemable")
		assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the issued code stays redeemable")
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, recovery.ErrRefused)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	}
	totpVerifies := func(e *recoverEnv) {
		e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
		e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil)
	}

	cases := []testCase{
		{
			name: "saved and issued codes succeed, and both are spent",
			req:  savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, anaID, v.User())
				assert.Equal(t, []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}, v.Proofs())
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, v.Plan(), "the default removes everything held")
				assert.Empty(t, v.Proven())
				assert.Zero(t, v.Hold())
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved code is spent")
				assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the issued code is spent")
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[1]), "the rest of the set is untouched")
				assert.Zero(t, e.failures.Load())
			},
		},
		{
			name: "a saved code and the password succeed",
			req:  savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.ProofKind{recovery.ProofSaved, recovery.ProofPassword}, v.Proofs())
				assert.Equal(t, int32(1), e.passwordCalls.Load())
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]))
			},
		},
		{
			name:  "an issued code and TOTP succeed, and TOTP is proven and kept",
			setup: totpVerifies,
			req:   issuedAndTOTP,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.ProofKind{recovery.ProofIssued, recovery.ProofMFA}, v.Proofs())
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP}, v.Proven())
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, v.Plan())
				assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued))
			},
		},
		{
			name: "an unknown user and a wrong saved code look alike",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), "bob@example.com").Return(nil, identity.ErrUserNotFound)
			},
			run: func(t *testing.T, ctx context.Context, e *recoverEnv, r *recovery.Recoverer) (*recovery.Verified, error) {
				_, unknown := recoverOnce(ctx, r, recovery.Request{Username: "bob@example.com", Saved: e.saved[0], Issued: e.issued})
				_, wrong := recoverOnce(ctx, r, recovery.Request{Username: anaUsername, Saved: e.saved[0] + "X", Issued: e.issued})

				require.ErrorIs(t, unknown, recovery.ErrRefused)
				require.ErrorIs(t, wrong, recovery.ErrRefused)
				assert.Equal(t, unknown.Error(), wrong.Error())

				return nil, nil
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, _ error) {
				nothingSpent(t, e, r)
				assert.Equal(t, int32(1), e.failures.Load(), "the known user's refusal is counted")
			},
		},
		{
			name: "an unknown user with a password is refused before the password check",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), "bob@example.com").Return(nil, identity.ErrUserNotFound)
				e.passwordErr = policy.ErrAccountLocked
			},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: "bob@example.com", Saved: e.saved[0], Password: []byte("x")}
			},
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error(), "the plain refusal")
				assert.False(t, recovery.RefusedAfterValidCode(err))
				assert.Zero(t, e.passwordCalls.Load(), "no password is hashed for an unknown username")
			},
		},
		{
			name: "neither an unknown user nor a known user with a wrong saved code reaches the password check",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), "bob@example.com").Return(nil, identity.ErrUserNotFound)
			},
			run: func(t *testing.T, ctx context.Context, e *recoverEnv, r *recovery.Recoverer) (*recovery.Verified, error) {
				_, unknown := recoverOnce(ctx, r, recovery.Request{
					Username: "bob@example.com", Saved: e.saved[0], Password: []byte(anaPassword),
				})
				require.ErrorIs(t, unknown, recovery.ErrRefused)
				assert.Zero(t, e.passwordCalls.Load(), "the unknown username paid for a password check")

				_, wrong := recoverOnce(ctx, r, recovery.Request{
					Username: anaUsername, Saved: e.saved[0] + "X", Password: []byte(anaPassword),
				})
				require.ErrorIs(t, wrong, recovery.ErrRefused)
				assert.Zero(t, e.passwordCalls.Load(), "the known user's wrong code paid for a password check")

				return nil, nil
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, _ error) {
				nothingSpent(t, e, r)
			},
		},
		{
			name: "a disabled user is refused",
			setup: func(e *recoverEnv) {
				d := anaDetails()
				d.Active = false
				e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(d, nil)
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				nothingSpent(t, e, r)
			},
		},
		{
			name:  "a locked account: the lockout error comes back unchanged and nothing is spent",
			setup: func(e *recoverEnv) { e.passwordErr = policy.ErrAccountLocked },
			req:   savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, policy.ErrAccountLocked)
				assert.Equal(t, policy.ErrAccountLocked.Error(), err.Error())
				assert.True(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "a wrong password keeps the codes, and a retry succeeds",
			run: func(t *testing.T, ctx context.Context, e *recoverEnv, r *recovery.Recoverer) (*recovery.Verified, error) {
				_, err := recoverOnce(ctx, r, savedAndPassword("wrong")(e))
				refused(t, err)
				assert.True(t, recovery.RefusedAfterValidCode(err), "the saved code was valid")
				assert.True(t, e.savedUsable(ctx, t, e.saved[0]))

				return recoverOnce(ctx, r, savedAndPassword(anaPassword)(e))
			},
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "a consumer check refuses unchanged, the codes stay redeemable, and a later allow succeeds",
			opts: func(e *recoverEnv) []recovery.Option {
				var calls atomic.Int32

				return e.opts(recovery.WithChecks(nil, func(_ context.Context, user identity.UserID, proofs []recovery.ProofKind) error {
					assert.Equal(t, anaID, user)
					assert.Equal(t, []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}, proofs)

					if calls.Add(1) == 1 {
						return errConsumer
					}

					return nil
				}))
			},
			run: func(t *testing.T, ctx context.Context, e *recoverEnv, r *recovery.Recoverer) (*recovery.Verified, error) {
				_, err := recoverOnce(ctx, r, savedAndIssued(e))
				require.ErrorIs(t, err, errConsumer)
				assert.Equal(t, errConsumer.Error(), err.Error())
				assert.True(t, recovery.RefusedAfterValidCode(err))
				nothingSpent(t, e, r)

				return recoverOnce(ctx, r, savedAndIssued(e))
			},
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "an issued code minted for u-2 is refused for u-1, and nothing is spent",
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issuedU2}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.False(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "u-1's saved code stays redeemable")
				assert.True(t, e.issuedUsable(t.Context(), t, r, "u-2", e.issuedU2), "u-2's code stays redeemable for u-2")
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "a wrong MFA code spends no recovery code",
			setup: func(e *recoverEnv) {
				e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(errors.New("mfa: invalid code"))
			},
			req: issuedAndTOTP,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.True(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued))
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name:  "an MFA method the user is not enrolled on is refused before any spend",
			setup: func(e *recoverEnv) { e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(false, nil) },
			req:   issuedAndTOTP,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued))
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name:  "an MFA enrolment lookup failure refuses behind fixed text and counts nothing",
			setup: func(e *recoverEnv) { e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(false, errOutage) },
			req:   issuedAndTOTP,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, errOutage)
				assert.NotContains(t, err.Error(), "row 42")
				assert.False(t, recovery.RefusedAfterValidCode(err), "an outage is not counted against the source")
				assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued))
				assert.Zero(t, e.failures.Load())
			},
		},
		{
			name:  "a listing failure refuses, spends nothing and counts nothing",
			setup: func(e *recoverEnv) { e.kind.EXPECT().Held(gomock.Any(), anaID).Return(nil, errOutage) },
			req:   savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, errOutage)
				assert.NotContains(t, err.Error(), "row 42")
				assert.False(t, recovery.RefusedAfterValidCode(err))
				nothingSpent(t, e, r)
				assert.Zero(t, e.failures.Load())
			},
		},
		{
			name: "reported mode: reporting what is not held is malformed and nothing is spent",
			opts: func(e *recoverEnv) []recovery.Option { return e.opts(recovery.WithResetReported()) },
			req: func(e *recoverEnv) recovery.Request {
				req := savedAndIssued(e)
				req.Lost = []string{"mfa:sms"}

				return req
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, recovery.ErrMalformed)
				nothingSpent(t, e, r)
			},
		},
		{
			name: "reported mode: the reported loss is the plan",
			opts: func(e *recoverEnv) []recovery.Option { return e.opts(recovery.WithResetReported()) },
			req: func(e *recoverEnv) recovery.Request {
				req := savedAndIssued(e)
				req.Lost = []string{"mfa:email-code"}

				return req
			},
			assert: func(t *testing.T, _ *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, v.Reported())
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, v.Plan())
			},
		},
		{
			name: "a consumer policy's choice is the plan",
			opts: func(e *recoverEnv) []recovery.Option {
				return e.opts(recovery.WithResetPolicy(func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) {
					return []recovery.AuthenticatorRef{refTOTP}, nil
				}))
			},
			req: savedAndIssued,
			assert: func(t *testing.T, _ *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.AuthenticatorRef{refTOTP}, v.Plan())
			},
		},
		{
			name: "a policy error refuses before any spend and is counted",
			opts: func(e *recoverEnv) []recovery.Option {
				return e.opts(recovery.WithResetPolicy(func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) {
					return nil, errConsumer
				}))
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, errConsumer)
				assert.True(t, recovery.RefusedAfterValidCode(err))
				nothingSpent(t, e, r)
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "the risk hook's hold is recorded, from what it was given",
			opts: func(e *recoverEnv) []recovery.Option {
				return e.opts(withCancelLink, recovery.WithRisk(func(_ context.Context, in recovery.RiskInput) (time.Duration, error) {
					assert.Equal(t, recovery.RiskInput{
						User:   anaID,
						Source: "203.0.113.7",
						Proofs: []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued},
						Now:    monday1000,
					}, in)

					return 48 * time.Hour, nil
				}))
			},
			req: func(e *recoverEnv) recovery.Request {
				req := savedAndIssued(e)
				req.Source = "203.0.113.7"

				return req
			},
			assert: func(t *testing.T, _ *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, 48*time.Hour, v.Hold())
			},
		},
		{
			name: "the risk hook returning zero holds nothing",
			opts: func(e *recoverEnv) []recovery.Option {
				return e.opts(withCancelLink, recovery.WithRisk(func(context.Context, recovery.RiskInput) (time.Duration, error) { return 0, nil }))
			},
			req: savedAndIssued,
			assert: func(t *testing.T, _ *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Zero(t, v.Hold())
			},
		},
		{
			name: "a risk hook error refuses behind fixed text before any spend",
			opts: func(e *recoverEnv) []recovery.Option {
				return e.opts(withCancelLink, recovery.WithRisk(func(context.Context, recovery.RiskInput) (time.Duration, error) {
					return time.Hour, errOutage
				}))
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				require.ErrorIs(t, err, errOutage)
				assert.NotContains(t, err.Error(), "row 42")
				nothingSpent(t, e, r)
			},
		},
		{
			name: "a throttled user is refused before any code is checked",
			setup: func(e *recoverEnv) {
				e.limiter.EXPECT().Exceeded(gomock.Any(), recovery.UserThrottleKey(anaID)).Return(true, nil)
			},
			req: savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.Zero(t, e.passwordCalls.Load())
				nothingSpent(t, e, r)
			},
		},
		{
			name: "a user limiter that cannot answer refuses",
			setup: func(e *recoverEnv) {
				// Not exceeded, so only honouring the error refuses.
				e.limiter.EXPECT().Exceeded(gomock.Any(), recovery.UserThrottleKey(anaID)).Return(false, errOutage)
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				nothingSpent(t, e, r)
			},
		},
		{
			name: "saved-code throttling is refused like a wrong code",
			opts: func(e *recoverEnv) []recovery.Option {
				codeLimiter := NewMockLimiter(e.ctrl)
				codeLimiter.EXPECT().Exceeded(gomock.Any(), recovery.CodeThrottleKey(anaID)).Return(true, nil).AnyTimes()
				// The limiter is valid, so construction cannot fail.
				e.codes, _ = recovery.NewCodes(recovery.WithCodeLimiter(codeLimiter))

				return e.opts()
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.NotErrorIs(t, err, recovery.ErrCodeThrottled)
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "a user lookup failure is an error behind fixed text, not a refusal",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, errOutage)
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, errOutage)
				assert.NotErrorIs(t, err, recovery.ErrRefused)
				assert.NotContains(t, err.Error(), "ana@example.com")
				nothingSpent(t, e, r)
				assert.Zero(t, e.failures.Load())
			},
		},
		{
			name: "a cancelled context stops at the lookup and spends nothing",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).DoAndReturn(
					func(ctx context.Context, _ string) (*identity.Details, error) { return nil, ctx.Err() })
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, context.Canceled)
				nothingSpent(t, e, r)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newRecoverEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}

			opts := e.opts()
			if tc.opts != nil {
				opts = tc.opts(e)
			}

			e.defaults()

			r, err := recovery.NewRecoverer(e.deps(), opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var v *recovery.Verified
			if tc.run != nil {
				v, err = tc.run(t, ctx, e, r)
			} else {
				v, err = recoverOnce(ctx, r, tc.req(e))
			}

			tc.assert(t, e, r, v, err)
		})
	}
}

func TestRecoverer_SpendOrder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		req    func(e *recoverEnv) recovery.Request
		expect func(e *recoverEnv, tokens *MockTokenStore, codes *MockCodeStore)
	}

	cases := []testCase{
		{
			name: "the MFA proof is spent before the issued code",
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: "123456"}
			},
			expect: func(e *recoverEnv, tokens *MockTokenStore, _ *MockCodeStore) {
				e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				gomock.InOrder(
					e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil),
					tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(e.tokens.Consume),
				)
			},
		},
		{
			name: "the MFA proof is spent before the saved code",
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "totp", MFACode: "123456"}
			},
			expect: func(e *recoverEnv, _ *MockTokenStore, codes *MockCodeStore) {
				e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				gomock.InOrder(
					e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil),
					codes.EXPECT().Spend(gomock.Any(), anaID, gomock.Any(), gomock.Any()).Return(true, nil),
				)
			},
		},
		{
			name: "the issued code is consumed before the saved code is spent",
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}
			},
			expect: func(e *recoverEnv, tokens *MockTokenStore, codes *MockCodeStore) {
				gomock.InOrder(
					tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(e.tokens.Consume),
					codes.EXPECT().Spend(gomock.Any(), anaID, gomock.Any(), gomock.Any()).Return(true, nil),
				)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, tokens, codeStore, mem := newMockedStoresEnv(t)

			tc.expect(e, tokens, codeStore)
			delegateChecks(e, tokens, codeStore, mem)
			e.defaults()

			r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithIssuedCodeStore(tokens))...)
			require.NoError(t, err)

			_, err = recoverOnce(t.Context(), r, tc.req(e))
			require.NoError(t, err)
		})
	}
}

// newMockedStoresEnv is a recovery env whose issued-code and saved-code stores
// are mocks, so a case can script the spends. ana's saved set lives in the
// returned memory store, which the saved-code mock reads through.
func newMockedStoresEnv(t *testing.T) (*recoverEnv, *MockTokenStore, *MockCodeStore, *recovery.MemoryCodeStore) {
	t.Helper()

	e := newRecoverEnv(t)
	tokens := NewMockTokenStore(e.ctrl)
	codeStore := NewMockCodeStore(e.ctrl)

	mem := recovery.NewMemoryCodeStore()
	codes, err := recovery.NewCodes(recovery.WithCodeStore(mem), recovery.WithCodesClock(e.clock))
	require.NoError(t, err)
	e.saved, err = codes.Generate(t.Context(), anaID)
	require.NoError(t, err)

	spending, err := recovery.NewCodes(recovery.WithCodeStore(codeStore), recovery.WithCodesClock(e.clock))
	require.NoError(t, err)
	e.codes = spending

	return e, tokens, codeStore, mem
}

// delegateChecks makes the mock stores behave as the memory stores behind them
// for the check phase, leaving only the spends for a case to script.
func delegateChecks(e *recoverEnv, tokens *MockTokenStore, codes *MockCodeStore, mem *recovery.MemoryCodeStore) {
	tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(e.tokens.FindByID).AnyTimes()
	codes.EXPECT().Match(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(mem.Match).AnyTimes()
}

func TestRecoverer_SpendFailure(t *testing.T) {
	t.Parallel()

	errDown := errors.New("db down: ana@example.com row 42")

	type testCase struct {
		name string
		// expect scripts the spends; cancel ends the context the recovery was
		// given.
		expect func(e *recoverEnv, tokens *MockTokenStore, codes *MockCodeStore, cancel context.CancelFunc)
		assert func(t *testing.T, e *recoverEnv, err error)
	}

	cases := []testCase{
		{
			name: "a saved-code store outage during the spend is returned uncounted, unmarked and scrubbed",
			expect: func(e *recoverEnv, tokens *MockTokenStore, codes *MockCodeStore, _ context.CancelFunc) {
				tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(e.tokens.Consume)
				codes.EXPECT().Spend(gomock.Any(), anaID, gomock.Any(), gomock.Any()).Return(false, errDown)
			},
			assert: func(t *testing.T, e *recoverEnv, err error) {
				require.ErrorIs(t, err, errDown)
				assert.NotErrorIs(t, err, recovery.ErrRefused, "an outage is not a refusal")
				assert.False(t, recovery.RefusedAfterValidCode(err), "an outage is not counted against the source")
				assert.NotContains(t, err.Error(), "row 42")
				assert.Zero(t, e.failures.Load(), "an outage is not counted against the user")
			},
		},
		{
			name: "a caller that hangs up after the first spend does not leave the recovery half-spent",
			expect: func(e *recoverEnv, tokens *MockTokenStore, codes *MockCodeStore, cancel context.CancelFunc) {
				tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, tokenID id.ID, at time.Time) error {
						err := e.tokens.Consume(ctx, tokenID, at)
						cancel()

						return err
					})
				codes.EXPECT().Spend(gomock.Any(), anaID, gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ identity.UserID, _ []byte, _ time.Time) (bool, error) {
						if err := ctx.Err(); err != nil {
							return false, err
						}

						return true, nil
					})
			},
			assert: func(t *testing.T, e *recoverEnv, err error) {
				require.NoError(t, err, "a recovery that starts spending runs to the end")
				assert.Zero(t, e.failures.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, tokens, codeStore, mem := newMockedStoresEnv(t)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			tc.expect(e, tokens, codeStore, cancel)
			delegateChecks(e, tokens, codeStore, mem)
			e.defaults()

			r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithIssuedCodeStore(tokens))...)
			require.NoError(t, err)

			req := recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}
			v, err := r.Verify(ctx, req)
			require.NoError(t, err)

			tc.assert(t, e, r.Spend(ctx, v))
		})
	}
}

func TestRefusedAfterValidCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, got bool)
	}

	cases := []testCase{
		{name: "nil", err: nil, assert: func(t *testing.T, got bool) { assert.False(t, got) }},
		{name: "a bare refusal", err: recovery.ErrRefused, assert: func(t *testing.T, got bool) { assert.False(t, got) }},
		{
			name:   "an unrelated error",
			err:    errors.New("other"),
			assert: func(t *testing.T, got bool) { assert.False(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, recovery.RefusedAfterValidCode(tc.err))
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
