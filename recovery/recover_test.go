package recovery_test

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
)

// withCancelLink is the cancel link every hold needs.
var withCancelLink = recovery.WithCancelLink("https://app.example.com/recovery/cancel")

// recoverOnce runs the check phase and, when it passes, the spend phase.
func recoverOnce(ctx context.Context, r *recovery.Recoverer, req recovery.Request) (*recovery.Verified, error) {
	v, err := r.Verify(ctx, req)
	if err != nil {
		return nil, err
	}

	return v, r.Spend(ctx, v)
}

// TestRecoverer_Shape stands apart from TestRecoverer_Verify because every case
// shares one malformed-request assertion and sets no port expectation.
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
	errCallerLeft := errors.New("the caller left")
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
				e.passwordErr = lockout.ErrAccountLocked
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
			setup: func(e *recoverEnv) { e.passwordErr = lockout.ErrAccountLocked },
			req:   savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, lockout.ErrAccountLocked)
				assert.Equal(t, lockout.ErrAccountLocked.Error(), err.Error())
				assert.True(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name: "a lock concealed as a failed authentication is refused behind fixed text and stays identifiable",
			setup: func(e *recoverEnv) {
				e.passwordErr = fmt.Errorf("check for ana@example.com: %w",
					errors.Join(authenticate.ErrAuthenticationFailed, lockout.ErrAccountLocked))
			},
			req: savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				require.ErrorIs(t, err, lockout.ErrAccountLocked, "the consumer's handler can still tell it is a lock")
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error(), "the check's own text stays beneath")
				assert.True(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name:  "a bare authentication failure is refused with ErrRefused and its text",
			setup: func(e *recoverEnv) { e.passwordErr = authenticate.ErrAuthenticationFailed },
			req:   savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error())
				assert.Equal(t, int32(1), e.failures.Load())
			},
		},
		{
			name:  "an unavailable user store is not a failed proof",
			setup: func(e *recoverEnv) { e.passwordErr = authenticate.ErrUnavailable },
			req:   savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, authenticate.ErrUnavailable)
				assert.NotErrorIs(t, err, recovery.ErrRefused, "an outage read as a refused proof")
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed, "an outage read as a refused proof")
				assert.False(t, recovery.RefusedAfterValidCode(err),
					"the outage was marked as a refusal after a valid code")
				assert.Zero(t, e.failures.Load(), "the outage was counted against the user's recovery limit")
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved code stays redeemable")
			},
		},
		{
			name: "a password load the caller's context ended is refused, marked, and not counted against the user",
			setup: func(e *recoverEnv) {
				e.passwordErr = errors.Join(authenticate.ErrAuthenticationFailed, context.Canceled)
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			req: savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.ErrorIs(t, err, context.Canceled, "the check's error stays beneath the refusal")
				assert.True(t, recovery.RefusedAfterValidCode(err),
					"not marked, so the HTTP layer would not charge the source")
				assert.Zero(t, e.failures.Load(),
					"counted against the user's recovery limit, though no password was compared")
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved code stays redeemable")
			},
		},
		{
			name: "a refusal naming a cancellation the caller never made is counted against the user",
			setup: func(e *recoverEnv) {
				e.passwordErr = errors.Join(authenticate.ErrAuthenticationFailed, context.Canceled)
			},
			req: savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.True(t, recovery.RefusedAfterValidCode(err))
				assert.Equal(t, int32(1), e.failures.Load(),
					"a check's error was read as the caller leaving while the caller still waited")
			},
		},
		{
			name:  "a bare authentication failure while the caller's context has ended is counted against the user",
			setup: func(e *recoverEnv) { e.passwordErr = authenticate.ErrAuthenticationFailed },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			req: savedAndPassword(anaPassword),
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, _ *recovery.Verified, err error) {
				refused(t, err)
				assert.True(t, recovery.RefusedAfterValidCode(err))
				assert.Equal(t, int32(1), e.failures.Load(),
					"a password refused before the caller left was read as a load the caller cut short")
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
				assert.False(t, recovery.RefusedAfterValidCode(err), "an outage is not marked as a refusal after a valid code")
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
				codeLimiter.EXPECT().Charge(gomock.Any(), recovery.CodeThrottleKey(anaID)).
					Return(ratelimit.Receipt{}, true, nil).AnyTimes()
				// The limiter is valid, so construction cannot fail.
				e.codes, _ = recovery.NewCodes(recovery.WithCodesLimiter(codeLimiter))

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
			name: "a user lookup failure is an outage with none of the driver's text, not a refusal",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, errOutage)
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, authenticate.ErrUnavailable)
				assert.NotErrorIs(t, err, recovery.ErrRefused)
				assert.NotErrorIs(t, err, errOutage, "the driver's error reached the caller")
				assert.NotContains(t, err.Error(), errOutage.Error())
				assert.NotContains(t, err.Error(), "ana@example.com")
				assert.False(t, recovery.RefusedAfterValidCode(err))
				nothingSpent(t, e, r)
				assert.Zero(t, e.failures.Load())
			},
		},
		{
			name: "a lookup the caller's context ended with a cause is not an outage",
			setup: func(e *recoverEnv) {
				e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).DoAndReturn(
					func(ctx context.Context, _ string) (*identity.Details, error) {
						return nil, context.Cause(ctx)
					})
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancelCause(ctx)
				cancel(errCallerLeft)

				return cctx
			},
			req: savedAndIssued,
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, errCallerLeft)
				assert.NotErrorIs(t, err, authenticate.ErrUnavailable,
					"the caller leaving was read as the user store failing")
				nothingSpent(t, e, r)
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
	codes, err := recovery.NewCodes(recovery.WithCodesStore(mem), recovery.WithCodesClock(e.clock))
	require.NoError(t, err)
	e.saved, err = codes.Generate(t.Context(), anaID)
	require.NoError(t, err)

	spending, err := recovery.NewCodes(recovery.WithCodesStore(codeStore), recovery.WithCodesClock(e.clock))
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

// TestRecoverer_SpendFailure stands apart from TestRecoverer_SpendOrder because
// its cases end the recovery's context and assert the error.
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
				assert.False(t, recovery.RefusedAfterValidCode(err), "an outage is not marked as a refusal after a valid code")
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

// TestRecoverer_RacingRecoveries releases 16 recoveries of ana at once, all
// presenting the same saved and issued codes, over the real in-memory stores.
// Exactly one may succeed. Run it with -race -count=3.
// It stands apart from TestRecoverer_Verify because it runs sixteen goroutines
// against one recoverer.
func TestRecoverer_RacingRecoveries(t *testing.T) {
	t.Parallel()

	const racers = 16

	e := newRecoverEnv(t)
	e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).AnyTimes()
	e.kind.EXPECT().Held(gomock.Any(), anaID).Return([]recovery.AuthenticatorRef{refTOTP}, nil).AnyTimes()

	// A limit no racer reaches, so losing is decided by the spends alone.
	limiter, err := ratelimit.NewMemoryLimiter(1000, time.Hour)
	require.NoError(t, err)

	r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithUserLimiter(limiter))...)
	require.NoError(t, err)

	req := recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}

	var (
		start     = make(chan struct{})
		wg        sync.WaitGroup
		successes atomic.Int32
		refusals  atomic.Int32
		others    atomic.Int32
	)

	for range racers {
		wg.Go(func() {
			<-start

			_, err := recoverOnce(t.Context(), r, req)

			switch {
			case err == nil:
				successes.Add(1)
			case assert.ErrorIs(t, err, recovery.ErrRefused):
				refusals.Add(1)
			default:
				others.Add(1)
			}
		})
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(), "exactly one recovery succeeds")
	assert.Equal(t, int32(racers-1), refusals.Load(), "every other recovery is refused")
	assert.Zero(t, others.Load())
	assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]))
	assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued))
}

// TestRecoverer_ProofChannels pins that the two proofs of a recovery never
// share a delivery channel: an issued code arrives by email, so it does not
// pair with an MFA method whose codes arrive by email, while a saved code does.
// It stands apart from TestRecoverer_Verify because every case adds an emailed
// MFA method beside the fixture's TOTP.
func TestRecoverer_ProofChannels(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(e *recoverEnv, email *MockMethod)
		req    func(e *recoverEnv) recovery.Request
		assert func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error)
	}

	cases := []testCase{
		{
			// The email method mock has no Enrolled or Verify expectation, so
			// a check of the MFA proof would fail the test on its own.
			name: "an issued code with an emailed MFA code is malformed, and nothing is checked or spent",
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "email-code", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, _ *recovery.Verified, err error) {
				require.ErrorIs(t, err, recovery.ErrMalformed, "an emailed recovery code plus an emailed MFA code recovered the account")
				assert.False(t, recovery.RefusedAfterValidCode(err))
				assert.True(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the issued code stays redeemable")
				assert.Zero(t, e.failures.Load(), "a malformed recovery counts nothing")
			},
		},
		{
			name: "saved code with an emailed MFA code still recovers",
			setup: func(_ *recoverEnv, email *MockMethod) {
				email.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				email.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil)
			},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "email-code", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *recoverEnv, _ *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.ProofKind{recovery.ProofSaved, recovery.ProofMFA}, v.Proofs())
				assert.Equal(t, []recovery.AuthenticatorRef{refEmail}, v.Proven())
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]), "the saved code is spent")
			},
		},
		{
			name: "an issued code with TOTP still recovers",
			setup: func(e *recoverEnv, _ *MockMethod) {
				e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil)
				e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(nil)
			},
			req: func(e *recoverEnv) recovery.Request {
				return recovery.Request{Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: "123456"}
			},
			assert: func(t *testing.T, e *recoverEnv, r *recovery.Recoverer, v *recovery.Verified, err error) {
				require.NoError(t, err)
				assert.Equal(t, []recovery.ProofKind{recovery.ProofIssued, recovery.ProofMFA}, v.Proofs())
				assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued), "the issued code is spent")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newRecoverEnv(t)
			email := declaredMethod(e.ctrl, "email-code", factor.Email)
			if tc.setup != nil {
				tc.setup(e, email)
			}
			e.defaults()

			r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithMFAMethods(e.totp, email))...)
			require.NoError(t, err)

			v, err := recoverOnce(t.Context(), r, tc.req(e))
			tc.assert(t, e, r, v, err)
		})
	}
}

// totpCodeAt computes the code an authenticator holding secret shows at at,
// straight from the RFC 6238 generator rather than through mfa.
func totpCodeAt(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), at,
		totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)

	return code
}

// A recovery that proves the account with a TOTP code calls the method's
// Verify directly, so it is bound by the same per-enrolment attempt charge as
// a login: a wrong code is charged, and a valid one gives its own charge back.
// It stands apart from TestRecoverer_Verify because it drives a real TOTP
// method on a fake clock.
func TestRecoverer_TOTPProofIsCharged(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	e := newRecoverEnv(t)

	secret := []byte("recovery-totp-secret")
	store := mfa.NewMemoryEnrolmentStore()
	gen := id.MustParse("01920000-0000-7000-8000-0000000000f1")
	require.NoError(t, store.PutPending(ctx, mfa.Enrolment{User: anaID, Secret: secret, Generation: gen}))
	confirmed, err := store.Confirm(ctx, anaID, gen, 0, e.clock.Now())
	require.NoError(t, err)
	require.True(t, confirmed)

	method, err := mfa.NewTOTP(store, "scrty-test", mfa.WithClock(e.clock))
	require.NoError(t, err)

	e.defaults()

	r, err := recovery.NewRecoverer(e.deps(), e.fixture.opts(
		recovery.WithProofs(recovery.ProofIssued, recovery.ProofMFA),
		recovery.WithMFAMethods(method),
		recovery.WithIssuedCodeStore(e.tokens),
		recovery.WithUserLimiter(e.limiter),
	)...)
	require.NoError(t, err)

	accepted := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		accepted[totpCodeAt(t, secret, e.clock.Now().Add(d))] = true
	}

	wrong := "000000"
	for _, c := range []string{"000000", "111111", "222222"} {
		if !accepted[c] {
			wrong = c

			break
		}
	}

	attempts := func() int {
		got, ok, err := store.Get(ctx, anaID)
		require.NoError(t, err)
		require.True(t, ok)

		return got.VerifyAttempts
	}

	_, err = recoverOnce(ctx, r, recovery.Request{
		Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: wrong,
	})
	require.ErrorIs(t, err, recovery.ErrRefused)
	assert.Equal(t, 1, attempts(), "the wrong code was charged against the enrolment")

	v, err := recoverOnce(ctx, r, recovery.Request{
		Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: totpCodeAt(t, secret, e.clock.Now()),
	})
	require.NoError(t, err)
	assert.Equal(t, []recovery.ProofKind{recovery.ProofIssued, recovery.ProofMFA}, v.Proofs())
	assert.Equal(t, 1, attempts(), "the valid code gave its own charge back")
}
