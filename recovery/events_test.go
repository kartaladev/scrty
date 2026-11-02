package recovery_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/secevent"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/security"
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

			r, err := recovery.NewRecoverer(f.deps(), f.opts(recovery.WithSecurityEvents(own.sink))...)
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

	type testCase struct {
		name string

		// opts adds options to the recoverer, given the request's cancel
		// function.
		opts func(cancel context.CancelFunc) []recovery.Option

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

	refusedOnce := func(t *testing.T, got []security.Event) {
		t.Helper()

		require.Len(t, got, 1)
		assert.Equal(t, security.RecoveryRefused, got[0].Name)
		assert.Equal(t, security.OutcomeFailure, got[0].Outcome)
		assert.Empty(t, got[0].User, "a refusal names no user")
		assert.Equal(t, monday1000, got[0].At, "the recoverer's clock")
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
			name: "a request that ended during the password check reports nothing",
			opts: func(cancel context.CancelFunc) []recovery.Option {
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

			extra := []recovery.Option{recovery.WithSecurityEvents(own.sink)}
			if tc.opts != nil {
				extra = append(extra, tc.opts(cancel)...)
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
