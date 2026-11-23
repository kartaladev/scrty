// The memo is exercised through one table for checks made one after another,
// and through separate tests for the concurrent cases, whose goroutines,
// barriers and cancellations do not fit the shape of a sequential row.
package authorize_test

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

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// leadCheck is the privilege check most memo tests repeat.
func leadCheck(privilege string) authorize.PrivilegeAttributes {
	return authorize.PrivilegeAttributes{Group: "crm", Resource: "lead", Required: []string{privilege}}
}

// leadGrants grants every privilege the memo tests ask for, with all.
func leadGrants() []*identity.ResourcePrivileges {
	privileges := make([]identity.Privilege, 0, 10)
	for i := range 10 {
		privileges = append(privileges, identity.Privilege{Name: fmt.Sprintf("p%d", i), Granted: true})
	}

	return scoped("crm", "lead", privileges...)
}

var errConnection = errors.New("connection refused")

func TestMemo(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		expect func(roles *MockRoleLoader)
		assert func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer)
	}

	cases := []testCase{
		{
			name: "ten checks one load",
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil).Times(1)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				ctx = authorize.WithRequestMemo(withRole(ctx, "clerk"))
				for i := range 10 {
					require.NoError(t, authorizer.Authorize(ctx, leadCheck(fmt.Sprintf("p%d", i))))
				}
			},
		},
		{
			name: "a job with a memo makes five checks for one load",
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil).Times(1)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				// A child context made after the memo still reaches it.
				ctx = authorize.WithRequestMemo(withRole(ctx, "clerk"))
				for i := range 5 {
					child, cancel := context.WithCancel(ctx)
					require.NoError(t, authorizer.Authorize(child, leadCheck(fmt.Sprintf("p%d", i))))
					cancel()
				}
			},
		},
		{
			name: "absent means no memo",
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil).Times(2)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				ctx = withRole(ctx, "clerk")
				require.NoError(t, authorizer.Authorize(ctx, leadCheck("p0")))
				require.NoError(t, authorizer.Authorize(ctx, leadCheck("p1")))
			},
		},
		{
			name: "each memo is fresh, so the next request sees a change",
			expect: func(roles *MockRoleLoader) {
				gomock.InOrder(
					roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
						Return(scoped("crm", "lead", identity.Privilege{Name: "p0", Granted: true}), nil),
					roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
						Return(scoped("crm", "lead", identity.Privilege{Name: "p0"}), nil),
				)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				base := withRole(ctx, "clerk")
				first := authorize.WithRequestMemo(base)
				require.NoError(t, authorizer.Authorize(first, leadCheck("p0")))

				// Installing a memo again replaces it rather than reusing it.
				second := authorize.WithRequestMemo(first)
				require.ErrorIs(t, authorizer.Authorize(second, leadCheck("p0")), authorize.ErrNotGranted)
			},
		},
		{
			name: "error not remembered",
			expect: func(roles *MockRoleLoader) {
				gomock.InOrder(
					roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(nil, errConnection),
					roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil),
				)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				ctx = authorize.WithRequestMemo(withRole(ctx, "clerk"))

				err := authorizer.Authorize(ctx, leadCheck("p0"))
				require.ErrorIs(t, err, errConnection)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "an outage read as a denial")

				require.NoError(t, authorizer.Authorize(ctx, leadCheck("p0")))
				require.NoError(t, authorizer.Authorize(ctx, leadCheck("p1")), "the success was not remembered")
			},
		},
		{
			name: "not found remembered",
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
					Return(nil, identity.ErrPrivilegesNotFound).Times(1)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				ctx = authorize.WithRequestMemo(withRole(ctx, "clerk"))
				for range 3 {
					deniedFor(authorize.ErrNotGranted)(t, authorizer.Authorize(ctx, leadCheck("p0")))
				}
			},
		},
		{
			name: "bound of 32",
			expect: func(roles *MockRoleLoader) {
				for i := range 32 {
					roles.EXPECT().LoadPrivileges(gomock.Any(), fmt.Sprintf("role-%d", i)).
						Return(leadGrants(), nil).Times(1)
				}

				roles.EXPECT().LoadPrivileges(gomock.Any(), "role-32").Return(leadGrants(), nil).Times(2)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				memo := authorize.WithRequestMemo(ctx)
				for range 2 {
					for i := range 33 {
						require.NoError(t, authorizer.Authorize(withRole(memo, fmt.Sprintf("role-%d", i)), leadCheck("p0")))
					}
				}
			},
		},
		{
			name: "role names are remembered exactly as the loader is asked for them",
			expect: func(roles *MockRoleLoader) {
				roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil).Times(1)
				roles.EXPECT().LoadPrivileges(gomock.Any(), "Clerk").Return(nil, identity.ErrPrivilegesNotFound).Times(1)
			},
			assert: func(t *testing.T, ctx context.Context, authorizer *authorize.PrivilegeAuthorizer) {
				memo := authorize.WithRequestMemo(ctx)
				require.NoError(t, authorizer.Authorize(withRole(memo, "clerk"), leadCheck("p0")))
				deniedFor(authorize.ErrNotGranted)(t, authorizer.Authorize(withRole(memo, "Clerk"), leadCheck("p0")))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			roles := NewMockRoleLoader(ctrl)
			tc.expect(roles)

			authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
			require.NoError(t, err)

			tc.assert(t, t.Context(), authorizer)
		})
	}
}

// TestMemo_SeparateAuthorizersDoNotShare pins the memo key: two privilege
// authorizers over different loaders, behind one FirstOf-free request sharing
// one memo, each get their own loader's answer for the same role name.
func TestMemo_SeparateAuthorizersDoNotShare(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	granting := NewMockRoleLoader(ctrl)
	granting.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil).Times(1)

	refusing := NewMockRoleLoader(ctrl)
	refusing.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(nil, identity.ErrPrivilegesNotFound).Times(1)

	first, err := authorize.NewPrivilegeAuthorizer(granting)
	require.NoError(t, err)

	second, err := authorize.NewPrivilegeAuthorizer(refusing)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))

	for range 2 {
		require.NoError(t, first.Authorize(ctx, leadCheck("p0")))
		deniedFor(authorize.ErrNotGranted)(t, second.Authorize(ctx, leadCheck("p0")))
	}
}

func TestMemo_ConcurrentChecksOneLoad(t *testing.T) {
	t.Parallel()

	const checkers = 8

	var (
		loads   atomic.Int32
		started atomic.Int32
	)

	allStarted := make(chan struct{})
	release := make(chan struct{})

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").AnyTimes().
		DoAndReturn(func(ctx context.Context, _ string) ([]*identity.ResourcePrivileges, error) {
			loads.Add(1)

			// Hold the load open until every checker has started, so the
			// others arrive while it is in flight rather than after it.
			select {
			case <-allStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			return leadGrants(), nil
		})

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))

	names := make([]string, checkers)
	for i := range checkers {
		names[i] = fmt.Sprintf("p%d", i)
	}

	var wg sync.WaitGroup

	errs := make([]error, checkers)
	answers := make([]authorize.Holdings, checkers)

	for i := range checkers {
		wg.Go(func() {
			<-release

			if started.Add(1) == checkers {
				close(allStarted)
			}

			// Half the checks decide one privilege, half report every one, so
			// both read the shared load.
			if i%2 == 0 {
				errs[i] = authorizer.Authorize(ctx, leadCheck(names[i]))

				return
			}

			answers[i], errs[i] = authorizer.InspectPrivileges(ctx, "crm", "lead", names)
		})
	}

	close(release)
	wg.Wait()

	// Every check saw the one loaded grant: every privilege held, as granted.
	want := make(authorize.Holdings, checkers)
	for i, name := range names {
		want[i] = authorize.Holding{Privilege: name, Held: true, Scope: identity.ScopeAll}
	}

	for i, err := range errs {
		assert.NoError(t, err, "checker %d", i)

		if i%2 == 1 {
			assert.Equal(t, want, answers[i], "checker %d saw different privileges", i)
		}
	}

	assert.Equal(t, int32(1), loads.Load(), "concurrent checks under one memo loaded more than once")
}

// TestMemo_LoaderOwnTimeoutReachesEveryWaiter: a loader that times out on its
// own, a statement timeout say, while the loading check's context is still
// live, is an outage every waiter shares. The waiters do not load again one
// after another, each paying the timeout.
func TestMemo_LoaderOwnTimeoutReachesEveryWaiter(t *testing.T) {
	t.Parallel()

	const checkers = 8

	var (
		loads   atomic.Int32
		started atomic.Int32
	)

	allStarted := make(chan struct{})
	release := make(chan struct{})

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").AnyTimes().
		DoAndReturn(func(ctx context.Context, _ string) ([]*identity.ResourcePrivileges, error) {
			loads.Add(1)

			select {
			case <-allStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			// Give every started checker time to reach the in-flight entry,
			// then time out on the loader's own deadline, not the caller's.
			time.Sleep(50 * time.Millisecond)

			return nil, fmt.Errorf("statement timeout: %w", context.DeadlineExceeded)
		})

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))

	var wg sync.WaitGroup

	errs := make([]error, checkers)
	for i := range checkers {
		wg.Go(func() {
			<-release

			if started.Add(1) == checkers {
				close(allStarted)
			}

			errs[i] = authorizer.Authorize(ctx, leadCheck(fmt.Sprintf("p%d", i)))
		})
	}

	close(release)
	wg.Wait()

	require.NoError(t, ctx.Err(), "the checks' context ended; the test proves nothing")

	for i, err := range errs {
		require.ErrorIs(t, err, context.DeadlineExceeded, "checker %d", i)
		assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "checker %d read an outage as a denial", i)
	}

	assert.Equal(t, int32(1), loads.Load(), "waiters retried a load that failed on the loader's own deadline")
}

// TestMemo_WaiterContextEnds: a waiter whose own context ends stops waiting
// with its context's error, and the load it abandoned is still remembered for
// everyone else.
func TestMemo_WaiterContextEnds(t *testing.T) {
	t.Parallel()

	var loads atomic.Int32

	entered := make(chan struct{})
	finish := make(chan struct{})

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").AnyTimes().
		DoAndReturn(func(context.Context, string) ([]*identity.ResourcePrivileges, error) {
			if loads.Add(1) == 1 {
				close(entered)
				<-finish
			}

			return leadGrants(), nil
		})

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))

	loaderDone := make(chan error, 1)
	go func() { loaderDone <- authorizer.Authorize(ctx, leadCheck("p0")) }()

	<-entered

	waiterCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()

	err = authorizer.Authorize(waiterCtx, leadCheck("p1"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "a waiter's ended context read as a denial")

	close(finish)
	require.NoError(t, <-loaderDone)

	require.NoError(t, authorizer.Authorize(ctx, leadCheck("p2")))
	assert.Equal(t, int32(1), loads.Load(), "the abandoned wait poisoned the entry")
}

// TestMemo_LoaderCancellationDoesNotReachWaiters: when the check that is
// loading has its own context cancelled, a waiter whose context is still live
// loads again rather than failing with someone else's cancellation.
func TestMemo_LoaderCancellationDoesNotReachWaiters(t *testing.T) {
	t.Parallel()

	var loads atomic.Int32

	entered := make(chan struct{})

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").AnyTimes().
		DoAndReturn(func(ctx context.Context, _ string) ([]*identity.ResourcePrivileges, error) {
			if loads.Add(1) == 1 {
				close(entered)
				<-ctx.Done()

				return nil, ctx.Err()
			}

			return leadGrants(), nil
		})

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))
	loaderCtx, cancelLoader := context.WithCancel(ctx)

	loaderDone := make(chan error, 1)
	go func() { loaderDone <- authorizer.Authorize(loaderCtx, leadCheck("p0")) }()

	<-entered

	waiterDone := make(chan error, 1)
	go func() { waiterDone <- authorizer.Authorize(ctx, leadCheck("p1")) }()

	// Give the waiter time to reach the in-flight entry. Should it arrive
	// later, it loads for itself, and the outcome asserted is the same.
	time.Sleep(50 * time.Millisecond)
	cancelLoader()

	require.ErrorIs(t, <-loaderDone, context.Canceled)
	require.NoError(t, <-waiterDone, "the waiter failed with the loader's cancellation")
	assert.Equal(t, int32(2), loads.Load())
}

// TestMemo_LoaderEndedWithAnyErrorWaiterLoadsAgain: when the loading check's
// context ended, a live waiter loads again whatever error the loader returned,
// including one that does not wrap the cancellation, such as a driver's
// "connection closed". A live caller never inherits another's cancellation.
func TestMemo_LoaderEndedWithAnyErrorWaiterLoadsAgain(t *testing.T) {
	t.Parallel()

	var loads atomic.Int32

	entered := make(chan struct{})

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").AnyTimes().
		DoAndReturn(func(ctx context.Context, _ string) ([]*identity.ResourcePrivileges, error) {
			if loads.Add(1) == 1 {
				close(entered)
				<-ctx.Done()

				return nil, errors.New("conn closed")
			}

			return leadGrants(), nil
		})

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))
	loaderCtx, cancelLoader := context.WithCancel(ctx)

	loaderDone := make(chan error, 1)
	go func() { loaderDone <- authorizer.Authorize(loaderCtx, leadCheck("p0")) }()

	<-entered

	waiterDone := make(chan error, 1)
	go func() { waiterDone <- authorizer.Authorize(ctx, leadCheck("p1")) }()

	time.Sleep(50 * time.Millisecond)
	cancelLoader()

	require.Error(t, <-loaderDone)
	require.NoError(t, <-waiterDone, "the waiter inherited the loading check's failure")
	assert.Equal(t, int32(2), loads.Load())
}

// TestMemo_PanicNotRemembered: a loader that panics leaves no entry behind.
// The panic reaches the check that loaded, a check waiting on that load gets
// an error rather than blocking forever, and the next check loads again.
func TestMemo_PanicNotRemembered(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	explode := make(chan struct{})

	ctrl := gomock.NewController(t)
	roles := NewMockRoleLoader(ctrl)
	gomock.InOrder(
		roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").
			DoAndReturn(func(context.Context, string) ([]*identity.ResourcePrivileges, error) {
				close(entered)
				<-explode
				panic("loader exploded")
			}),
		roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").Return(leadGrants(), nil),
	)

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	ctx := authorize.WithRequestMemo(withRole(t.Context(), "clerk"))

	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()

		_ = authorizer.Authorize(ctx, leadCheck("p0"))
	}()

	<-entered

	waiterDone := make(chan error, 1)
	go func() { waiterDone <- authorizer.Authorize(ctx, leadCheck("p1")) }()

	// Give the waiter time to reach the in-flight entry. Should it arrive
	// later, it loads for itself and the second expectation answers it.
	time.Sleep(50 * time.Millisecond)
	close(explode)

	assert.Equal(t, "loader exploded", <-recovered, "the panic did not reach the check that loaded")

	select {
	case err := <-waiterDone:
		if err != nil {
			assert.NotErrorIs(t, err, authorize.ErrAccessDenied, "a panicking loader read as a denial")

			// The waiter saw the panic; the next check must load again.
			require.NoError(t, authorizer.Authorize(ctx, leadCheck("p2")))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a check waiting on a panicking load is stuck on its entry")
	}
}
