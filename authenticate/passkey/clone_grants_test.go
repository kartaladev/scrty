package passkey_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/pkg/id"
)

// nilGrantRevoker is a revoker whose pointer is nil, as a consumer's unset
// variable would be once it reached the option.
type nilGrantRevoker struct{}

func (*nilGrantRevoker) RevokeUserGrants(context.Context, identity.UserID, string) error { return nil }

// TestClone_RevokesGrants pins what a suspected clone does to the user's
// application grants: revoked once the credential is really suspended, kept by
// the option, a failure logged with the refusal standing, and nothing changed
// with no revoker.
func TestClone_RevokesGrants(t *testing.T) {
	t.Parallel()

	const user = identity.UserID("u-1")

	outage := errors.New("grant store secret text")

	type testCase struct {
		name string
		// opts are the manager's options besides the revoker.
		opts func(g *MockGrantRevoker) []passkey.Option
		// expect arms the revoker; nil means it must not be called.
		expect func(t *testing.T, g *MockGrantRevoker)
		// arm adjusts the credential store.
		arm func(e *loginEnv)
		// count is the presented counter over the stored 42; zero means a clone.
		count uint32
		twice bool
		// hangUp ends the request's context as the clone is decided.
		hangUp bool
		assert func(t *testing.T, e *loginEnv, err error)
	}

	withRevoker := func(g *MockGrantRevoker, more ...passkey.Option) []passkey.Option {
		return append([]passkey.Option{passkey.WithGrantRevoker(g)}, more...)
	}

	revokes := func(_ *testing.T, g *MockGrantRevoker) {
		g.EXPECT().RevokeUserGrants(gomock.Any(), user, "passkey_clone").Return(nil).Times(1)
	}

	refused := func(t *testing.T, e *loginEnv, err error) {
		t.Helper()

		require.ErrorIs(t, err, passkey.ErrCloneSuspected)
		assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
	}

	cases := []testCase{
		{
			name:   "a suspension revokes the user's grants with the clone's cause",
			expect: revokes,
			assert: refused,
		},
		{
			name:   "a second clone of a suspended credential revokes nothing more",
			expect: revokes,
			twice:  true,
			assert: refused,
		},
		{
			name:   "a client that hung up does not stop it: the revocation is detached",
			hangUp: true,
			expect: func(t *testing.T, g *MockGrantRevoker) {
				g.EXPECT().RevokeUserGrants(gomock.Any(), user, "passkey_clone").DoAndReturn(
					func(ctx context.Context, _ identity.UserID, _ string) error {
						assert.NoError(t, ctx.Err())

						return nil
					}).Times(1)
			},
			assert: refused,
		},
		{
			name: "a failure is logged without its text, and the refusal stands",
			expect: func(_ *testing.T, g *MockGrantRevoker) {
				g.EXPECT().RevokeUserGrants(gomock.Any(), user, "passkey_clone").Return(outage).Times(1)
			},
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()

				refused(t, e, err)
				assert.NotErrorIs(t, err, outage, "the refusal is about the clone")
				assert.Contains(t, e.logs.String(), "the user's application grants could not be revoked")
				assert.NotContains(t, e.logs.String(), "secret text")
				assert.Len(t, e.f.messages(), 1, "the notice still goes out")
			},
		},
		{
			name: "keeping the sessions does not keep the grants: the two choices are separate",
			opts: func(g *MockGrantRevoker) []passkey.Option {
				return withRevoker(g, passkey.WithoutSessionRevocationOnClone())
			},
			expect: revokes,
			assert: refused,
		},
		{
			name: "the keep option keeps the grants",
			opts: func(g *MockGrantRevoker) []passkey.Option {
				return withRevoker(g, passkey.WithoutCloneGrantRevocation())
			},
			assert: refused,
		},
		{
			name: "the keep option given first still keeps",
			opts: func(g *MockGrantRevoker) []passkey.Option {
				return []passkey.Option{passkey.WithoutCloneGrantRevocation(), passkey.WithGrantRevoker(g)}
			},
			assert: refused,
		},
		{
			name:   "with no revoker a clone behaves as it always did",
			opts:   func(*MockGrantRevoker) []passkey.Option { return nil },
			assert: refused,
		},
		{
			name: "a credential another assertion suspended first revokes nothing here",
			arm: func(e *loginEnv) {
				e.creds.suspendHook = func(context.Context, id.ID) (bool, error) { return false, nil }
			},
			assert: func(t *testing.T, _ *loginEnv, err error) {
				t.Helper()

				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
			},
		},
		{
			name: "a policy that only refuses suspends nothing and revokes nothing",
			opts: func(g *MockGrantRevoker) []passkey.Option {
				return withRevoker(g, passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
					return passkey.CloneRefuse
				}))
			},
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()

				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
			},
		},
		{
			name: "the signal-only response allows the login and revokes nothing",
			opts: func(g *MockGrantRevoker) []passkey.Option {
				return withRevoker(g, passkey.WithCloneResponse(passkey.CloneSignalOnly))
			},
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
			},
		},
		{
			name:  "an assertion whose counter moves forward is no clone",
			count: 43,
			assert: func(t *testing.T, e *loginEnv, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, nil)
			g := NewMockGrantRevoker(gomock.NewController(t))
			if tc.expect != nil {
				tc.expect(t, g)
			}
			if tc.arm != nil {
				tc.arm(e)
			}

			opts := withRevoker(g)
			if tc.opts != nil {
				opts = tc.opts(g)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tc.hangUp {
				opts = append(opts, passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
					cancel()

					return passkey.CloneRefuseSuspend
				}))
			}

			e.manager(t, opts...)

			count := tc.count
			if count == 0 {
				count = 41
			}

			authenticate := func(challenge string) error {
				_, err := e.m.Authenticate(ctx, assertion(challenge, func(b *assertionBody) { b.Count = count }), e.binding)

				return err
			}

			err := authenticate(e.begin(t))
			if tc.twice {
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				require.ErrorIs(t, authenticate(e.begin(t)), passkey.ErrSuspended)
			}

			tc.assert(t, e, err)
		})
	}
}

// TestClone_GrantRevocationFailure pins what is left of a revocation that failed.
// A credential suspends once, so nothing would ask again: the operator has only
// what is written and reported here to know that the grants are still live.
func TestClone_GrantRevocationFailure(t *testing.T) {
	t.Parallel()

	const lost = "the user's application grants could not be revoked"

	outage := errors.New("grant store secret text")

	type testCase struct {
		name string
		// revoked is what the revoker answers.
		revoked error
		// watched puts a chain's delivery on the request.
		watched bool
		// suspensions is how many clones the credential store really suspends.
		suspensions int
		assert      func(t *testing.T, e *loginEnv, events []event.Event, err error)
	}

	cases := []testCase{
		{
			name:        "a failure is reported to the chain the request runs in, naming the user and nothing of the failure",
			revoked:     outage,
			watched:     true,
			suspensions: 1,
			assert: func(t *testing.T, _ *loginEnv, events []event.Event, err error) {
				t.Helper()

				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.NotErrorIs(t, err, outage, "the refusal is about the clone")
				require.Len(t, events, 1)
				assert.Equal(t, "scrty_grant_revoke_failed", events[0].Name)
				assert.Equal(t, event.OutcomeFailure, events[0].Outcome)
				assert.Equal(t, identity.UserID("u-1"), events[0].User)
				assert.False(t, events[0].At.IsZero())
				assert.Empty(t, events[0].Cause, "a store's error is never carried")
				assert.NotContains(t, fmt.Sprintf("%+v", events[0]), outage.Error())
			},
		},
		{
			name:        "a failure on a request no chain watches is still logged, and the refusal stands",
			revoked:     outage,
			suspensions: 1,
			assert: func(t *testing.T, e *loginEnv, events []event.Event, err error) {
				t.Helper()

				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Empty(t, events)
				assert.Equal(t, 1, strings.Count(e.logs.String(), lost), e.logs.String())
			},
		},
		{
			name:        "every failure is logged: another user's must not be sampled away",
			revoked:     outage,
			suspensions: 3,
			assert: func(t *testing.T, e *loginEnv, _ []event.Event, err error) {
				t.Helper()

				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Equal(t, 3, strings.Count(e.logs.String(), lost), e.logs.String())
				assert.NotContains(t, e.logs.String(), outage.Error())
			},
		},
		{
			name:        "a revocation that succeeded reports no failure",
			watched:     true,
			suspensions: 1,
			assert: func(t *testing.T, e *loginEnv, events []event.Event, err error) {
				t.Helper()

				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Empty(t, events)
				assert.NotContains(t, e.logs.String(), lost)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				mu     sync.Mutex
				events []event.Event
			)

			ctx := t.Context()
			if tc.watched {
				ctx = eventsink.With(ctx, func(_ context.Context, e event.Event) {
					mu.Lock()
					defer mu.Unlock()

					events = append(events, e)
				})
			}

			e := newLoginEnv(t, nil)
			// Reporting each as the one that suspended leaves the credential active, which
			// stands for as many credentials as a row needs, each suspended once.
			e.creds.suspendHook = func(context.Context, id.ID) (bool, error) { return true, nil }

			g := NewMockGrantRevoker(gomock.NewController(t))
			g.EXPECT().RevokeUserGrants(gomock.Any(), identity.UserID("u-1"), "passkey_clone").
				Return(tc.revoked).Times(tc.suspensions)
			e.manager(t, passkey.WithGrantRevoker(g))

			var err error
			for range tc.suspensions {
				challenge := e.begin(t)
				_, err = e.m.Authenticate(ctx, assertion(challenge, func(b *assertionBody) { b.Count = 41 }), e.binding)
			}

			mu.Lock()
			defer mu.Unlock()

			tc.assert(t, e, events, err)
		})
	}
}

// TestClone_GrantRevokerOption pins what New refuses and what a chain reads.
func TestClone_GrantRevokerOption(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(g *MockGrantRevoker) []passkey.Option
		assert func(t *testing.T, m *passkey.Passkeys, err error)
	}

	decided := func(want bool) func(*testing.T, *passkey.Passkeys, error) {
		return func(t *testing.T, m *passkey.Passkeys, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, want, m.CloneGrantsDecided())
		}
	}

	refused := func(t *testing.T, _ *passkey.Passkeys, err error) {
		t.Helper()

		require.ErrorIs(t, err, passkey.ErrConfig)
	}

	cases := []testCase{
		{
			name:   "no revoker is refused",
			opts:   func(*MockGrantRevoker) []passkey.Option { return []passkey.Option{passkey.WithGrantRevoker(nil)} },
			assert: refused,
		},
		{
			name: "a typed nil is refused",
			opts: func(*MockGrantRevoker) []passkey.Option {
				return []passkey.Option{passkey.WithGrantRevoker((*nilGrantRevoker)(nil))}
			},
			assert: refused,
		},
		{name: "neither option leaves it undecided", opts: func(*MockGrantRevoker) []passkey.Option { return nil }, assert: decided(false)},
		{
			name:   "a revoker decides it",
			opts:   func(g *MockGrantRevoker) []passkey.Option { return []passkey.Option{passkey.WithGrantRevoker(g)} },
			assert: decided(true),
		},
		{
			name: "the keep option decides it",
			opts: func(*MockGrantRevoker) []passkey.Option {
				return []passkey.Option{passkey.WithoutCloneGrantRevocation()}
			},
			assert: decided(true),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			all := append([]passkey.Option{passkey.WithRepudiationContact("help@example.com")},
				tc.opts(NewMockGrantRevoker(gomock.NewController(t)))...)

			m, err := passkey.New(f.deps, all...)
			tc.assert(t, m, err)
		})
	}
}
