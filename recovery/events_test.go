package recovery_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/secevent"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/token/onetime"
)

// recoveryEvents is a security-event sink that keeps what it receives, in the
// order given by the steps it shares with the sender (see order).
type recoveryEvents struct {
	mu     sync.Mutex
	events []security.Event

	// order, when set, is appended "event" on every delivery, beside what the
	// sender appends, so a row can see which came first.
	order *[]string
}

func (r *recoveryEvents) sink(_ context.Context, e security.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
	if r.order != nil {
		*r.order = append(*r.order, "event")
	}
}

func (r *recoveryEvents) all() []security.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]security.Event(nil), r.events...)
}

// onFaultStore is a one-time token store that answers a lookup or a spend
// through a hook a case sets, and otherwise passes it on to the real store. A
// hook that returns an error fails the call; one that returns nil lets it
// through.
type onFaultStore struct {
	onetime.Store

	find    atomic.Pointer[func(ctx context.Context) error]
	consume atomic.Pointer[func(ctx context.Context) error]
}

func (s *onFaultStore) FindByID(ctx context.Context, tid id.ID) (*onetime.Token, error) {
	if hook := s.find.Load(); hook != nil {
		if err := (*hook)(ctx); err != nil {
			return nil, err
		}
	}

	return s.Store.FindByID(ctx, tid)
}

func (s *onFaultStore) Consume(ctx context.Context, tid id.ID, at time.Time) error {
	if hook := s.consume.Load(); hook != nil {
		if err := (*hook)(ctx); err != nil {
			return err
		}
	}

	return s.Store.Consume(ctx, tid, at)
}

// failing returns a hook that fails every call with err.
func failing(err error) *func(context.Context) error {
	hook := func(context.Context) error { return err }

	return &hook
}

// TestSecurityEvents_RecoveryStart pins that every start reports
// scrty_recovery_started, for a username that names an account and for one
// that names none alike, carrying the user only when there is one, and that
// the sink is called as the start's last step in both cases, after the code is
// sent, so a sink that takes time holds a start for an unknown username as
// long as one for a known username.
func TestSecurityEvents_RecoveryStart(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("store unreachable: ana@example.com")

	type testCase struct {
		name     string
		username string
		setup    func(f *fixture)
		opts     []recovery.Option
		assert   func(t *testing.T, got []security.Event, order []string)
	}

	started := func(user identity.UserID) func(t *testing.T, got []security.Event, order []string) {
		return func(t *testing.T, got []security.Event, _ []string) {
			t.Helper()

			require.Len(t, got, 1)
			assert.Equal(t, security.RecoveryStarted, got[0].Name)
			assert.Equal(t, security.OutcomeSuccess, got[0].Outcome)
			assert.Equal(t, user, got[0].User)
			assert.Equal(t, monday1000, got[0].At, "the recoverer's clock")
		}
	}

	cases := []testCase{
		{
			name:     "a known username: reported with the user, after the code is sent",
			username: anaUsername,
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil)
			},
			assert: func(t *testing.T, got []security.Event, order []string) {
				started(anaID)(t, got, order)
				assert.Equal(t, []string{"send", "event"}, order, "the sink is the start's last step")
			},
		},
		{
			name:     "an unknown username: reported alike, without a user",
			username: "nobody@example.com",
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), "nobody@example.com").Return(nil, identity.ErrUserNotFound)
			},
			assert: started(""),
		},
		{
			name:     "an inactive account: reported alike, without a user",
			username: anaUsername,
			setup: func(f *fixture) {
				d := anaDetails()
				d.Active = false
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(d, nil)
			},
			assert: started(""),
		},
		{
			name:     "an account whose contact address could not be resolved: still reported, with the user",
			username: anaUsername,
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil)
			},
			opts: []recovery.Option{recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
				return "", errOutage
			})},
			assert: started(anaID),
		},
		{
			name:     "an account whose contact address is empty: still reported, with the user",
			username: anaUsername,
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil)
			},
			opts: []recovery.Option{recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
				return "", nil
			})},
			assert: started(anaID),
		},
		{
			name:     "a user loader that failed: reported alike, without a user",
			username: anaUsername,
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, errOutage)
			},
			assert: started(""),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var order []string

			own := &recoveryEvents{order: &order}
			f := newFixture(t)
			tc.setup(f)
			f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, notify.Message) error {
				order = append(order, "send")

				return nil
			}).AnyTimes()

			r, err := recovery.NewRecoverer(f.deps(), f.opts(append([]recovery.Option{recovery.WithSecurityEvents(own.sink)}, tc.opts...)...)...)
			require.NoError(t, err)

			r.Start(t.Context(), tc.username)
			tc.assert(t, own.all(), order)
		})
	}
}

// TestSecurityEvents_RecoveryRefused pins that a completion refused for its
// proofs reports scrty_recovery_refused, naming no user, through the
// recoverer's own sink outside a chain and through the chain's delivery alone
// inside one; that a refused finish is reported alike; and that a dependency
// failure and a request whose own context ended before the verdict report
// nothing.
func TestSecurityEvents_RecoveryRefused(t *testing.T) {
	t.Parallel()

	errIssuer := errors.New("issuer: signing key unreachable")
	errDown := errors.New("store unreachable: ana@example.com")

	// savedAndIssued presents ana's saved and issued codes, both good.
	savedAndIssued := func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
		_, err := r.Recover(ctx, savedAndIssuedReq(e))

		return err
	}

	// heldToken is well formed and names no record: a store asked for it is
	// the first to answer.
	const heldToken = "0190f0a0-0000-7000-8000-000000000001.secret"

	type testCase struct {
		name string

		// store arms the issued-code store the recoverer reads, given the
		// request's cancel function.
		store func(f *onFaultStore, cancel context.CancelFunc)

		// holdStore makes the armed store the hold token store as well, which
		// a case about a finish needs (the case's opts configure the hold).
		holdStore bool

		// opts adds options to the recoverer, given the request's cancel
		// function.
		opts func(e *completeEnv, cancel context.CancelFunc) []recovery.Option

		setup func(e *completeEnv)

		// chain, when set, is the delivery the request carries.
		chain *recoveryEvents

		act    func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error
		assert func(t *testing.T, own, chain *recoveryEvents, err error)
	}

	wrongSaved := func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
		_, err := r.Recover(ctx, recovery.Request{Username: anaUsername, Saved: "AAAA-BBBB-CCCC", Issued: e.issued})

		return err
	}

	// kept checks that a refusal the library answered for a dependency's
	// failure is still the refusal: the same error and text, and reported as
	// nothing.
	kept := func(t *testing.T, own *recoveryEvents, err error) {
		t.Helper()

		require.ErrorIs(t, err, recovery.ErrRefused)
		assert.Empty(t, own.all(), "a dependency failure reports no refusal")
	}

	refusedOnce := func(t *testing.T, got []security.Event) {
		t.Helper()

		require.Len(t, got, 1)
		assert.Equal(t, security.RecoveryRefused, got[0].Name)
		assert.Equal(t, security.OutcomeFailure, got[0].Outcome)
		assert.Empty(t, got[0].User, "a refusal names no user")
		assert.Equal(t, monday1000, got[0].At, "the recoverer's clock")
	}

	// mfaVerifies arms ana's TOTP method to answer a verification with verr,
	// and byMFA presents a saved code and a TOTP code, so the spend reaches it.
	mfaVerifies := func(verr error) func(e *completeEnv) {
		return func(e *completeEnv) {
			e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil).AnyTimes()
			e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(verr)
		}
	}
	byMFA := func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
		_, err := r.Recover(ctx, recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "totp", MFACode: "123456"})

		return err
	}

	// savedLimiter gives the recoverer a saved-code manager whose limiter
	// answers a charge as given.
	savedLimiter := func(exceeded bool, err error) func(e *completeEnv, _ context.CancelFunc) []recovery.Option {
		return func(e *completeEnv, _ context.CancelFunc) []recovery.Option {
			l := NewMockLimiter(e.ctrl)
			l.EXPECT().Charge(gomock.Any(), gomock.Any()).Return(ratelimit.Receipt{}, exceeded, err).AnyTimes()

			codes, cerr := recovery.NewCodes(recovery.WithCodesClock(e.clock), recovery.WithCodesLimiter(l))
			require.NoError(t, cerr)
			e.codes = codes

			return nil
		}
	}

	cases := []testCase{
		{
			name: "outside a chain a refused completion is reported to the own sink",
			act:  wrongSaved,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name:  "on a request a chain delivers for, only the chain's delivery is called",
			chain: &recoveryEvents{},
			act:   wrongSaved,
			assert: func(t *testing.T, own, chain *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.Empty(t, own.all(), "one outcome is reported once")
				refusedOnce(t, chain.all())
			},
		},
		{
			name: "a refused finish is reported",
			act: func(ctx context.Context, _ *completeEnv, r *recovery.Recoverer) error {
				_, err := r.Finish(ctx, "not-a-completion-token")

				return err
			},
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name: "a completed recovery reports no refusal",
			act: func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
				_, err := r.Recover(ctx, savedAndIssuedReq(e))

				return err
			},
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.NoError(t, err)
				assert.Empty(t, own.all())
			},
		},
		{
			name: "a credential issuer that failed reports nothing",
			setup: func(e *completeEnv) {
				e.issueErr.Store(&errIssuer)
			},
			act: func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
				_, err := r.Recover(ctx, savedAndIssuedReq(e))

				return err
			},
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, errIssuer)
				assert.Empty(t, own.all())
			},
		},
		{
			name: "a wrong issued code is reported",
			act: func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
				_, err := r.Recover(ctx, recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued + "x"})

				return err
			},
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name: "an issued-code store that failed reports nothing, and the answer is still a refusal",
			store: func(f *onFaultStore, _ context.CancelFunc) {
				f.find.Store(failing(errDown))
			},
			act: savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error(), "the text is the refusal's own")
				assert.NotContains(t, err.Error(), errDown.Error())
			},
		},
		{
			name: "a request that ended during the issued-code lookup reports nothing",
			store: func(f *onFaultStore, cancel context.CancelFunc) {
				hook := func(ctx context.Context) error {
					cancel()

					return ctx.Err()
				}
				f.find.Store(&hook)
			},
			act: savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
			},
		},
		{
			name: "an issued-code store that failed at the spend reports nothing",
			store: func(f *onFaultStore, _ context.CancelFunc) {
				f.consume.Store(failing(errDown))
			},
			act: savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
			},
		},
		{
			name: "a user limiter that failed reports nothing, and the answer is still a refusal",
			opts: func(e *completeEnv, _ context.CancelFunc) []recovery.Option {
				l := NewMockLimiter(e.ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errDown).AnyTimes()

				return []recovery.Option{recovery.WithUserLimiter(l)}
			},
			act: savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error(), "the text is the refusal's own")
			},
		},
		{
			name: "a saved-code limiter that failed reports nothing, and the answer is still a refusal",
			opts: savedLimiter(false, errDown),
			act:  savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
				assert.NotErrorIs(t, err, recovery.ErrCodeThrottled, "the answer is the refusal, not the throttle")
				assert.NotErrorIs(t, err, ratelimit.ErrThrottled)
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error(), "the text is the refusal's own")
			},
		},
		{
			name: "a throttled saved-code presentation is reported",
			opts: savedLimiter(true, nil),
			act:  savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name:  "an MFA method whose store failed reports nothing, and the answer is still a refusal",
			setup: mfaVerifies(fmt.Errorf("mfa: totp store: %w", errDown)),
			act:   byMFA,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, recovery.ErrRefused.Error(), err.Error(), "the text is the refusal's own")
				assert.True(t, recovery.RefusedAfterValidCode(err), "still marked, so the source pays")
			},
		},
		{
			name:  "a wrong MFA code is reported",
			setup: mfaVerifies(mfa.ErrInvalidCode),
			act:   byMFA,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name:  "an MFA code whose enrolment's attempts are spent is reported",
			setup: mfaVerifies(mfa.ErrVerifyAttemptsExhausted),
			act:   byMFA,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name:  "an MFA method that refused its authenticator is reported",
			setup: mfaVerifies(fmt.Errorf("%w: suspected clone", mfa.ErrAuthenticatorRefused)),
			act:   byMFA,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name:  "an MFA method that refused a response from the same channel is reported",
			setup: mfaVerifies(fmt.Errorf("%w: code sent to the recovery address", mfa.ErrSameChannel)),
			act:   byMFA,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name: "an issued code the store does not hold is a refusal, and is reported",
			store: func(f *onFaultStore, _ context.CancelFunc) {
				f.find.Store(failing(onetime.ErrTokenNotFound))
			},
			act: savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				refusedOnce(t, own.all())
			},
		},
		{
			name: "a risk hook that failed reports nothing, and the answer is still a refusal",
			opts: func(*completeEnv, context.CancelFunc) []recovery.Option {
				return riskOf(0, errDown)
			},
			act: savedAndIssued,
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
				assert.True(t, recovery.RefusedAfterValidCode(err), "still marked, so the source pays")
			},
		},
		{
			name: "a hold token store that failed at a finish reports nothing, and the answer is still a refusal",
			opts: func(*completeEnv, context.CancelFunc) []recovery.Option {
				return holdFor(time.Hour)
			},
			holdStore: true,
			store: func(f *onFaultStore, _ context.CancelFunc) {
				f.find.Store(failing(errDown))
			},
			act: func(ctx context.Context, _ *completeEnv, r *recovery.Recoverer) error {
				_, err := r.Finish(ctx, heldToken)

				return err
			},
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				kept(t, own, err)
			},
		},
		{
			name: "a request that ended during the password check reports nothing",
			opts: func(_ *completeEnv, cancel context.CancelFunc) []recovery.Option {
				return []recovery.Option{recovery.WithPasswordCheck(func(context.Context, string, []byte) error {
					cancel()

					return errors.Join(authenticate.ErrAuthenticationFailed, context.Canceled)
				})}
			},
			act: func(ctx context.Context, e *completeEnv, r *recovery.Recoverer) error {
				_, err := r.Recover(ctx, issuedAndPasswordReq(e))

				return err
			},
			assert: func(t *testing.T, own, _ *recoveryEvents, err error) {
				require.ErrorIs(t, err, recovery.ErrRefused)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, own.all())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			own := &recoveryEvents{}
			e := newCompleteEnv(t)

			faulty := &onFaultStore{Store: e.tokens}

			extra := []recovery.Option{recovery.WithSecurityEvents(own.sink), recovery.WithIssuedCodeStore(faulty)}
			if tc.opts != nil {
				extra = append(extra, tc.opts(e, cancel)...)
			}

			if tc.holdStore {
				hold := &onFaultStore{Store: must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(e.clock)))}
				faulty = hold
				extra = append(extra, recovery.WithHoldTokenStore(hold))
			}

			if tc.store != nil {
				tc.store(faulty, cancel)
			}

			r := e.recoverer(t, extra...)

			if tc.setup != nil {
				tc.setup(e)
			}

			if tc.chain != nil {
				ctx = secevent.With(ctx, tc.chain.sink)
			}

			tc.assert(t, own, tc.chain, tc.act(ctx, e, r))
		})
	}
}
