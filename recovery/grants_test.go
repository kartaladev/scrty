package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

// nilRevoker is a revoker whose pointer is nil, as a consumer's unset variable
// would be once it reached the option.
type nilRevoker struct{}

func (*nilRevoker) RevokeUserGrants(context.Context, identity.UserID, string) error { return nil }

// TestRecoverer_RevokesGrants pins what a completed recovery does to the
// recovered user's application grants: revoked by default once a revoker is
// present, kept by the option, a failure returned, and nothing changed when no
// provider is in use.
func TestRecoverer_RevokesGrants(t *testing.T) {
	t.Parallel()

	errGrants := errors.New("grant store secret text")

	// A recovery revokes twice: before the spend and after the sessions end.
	revokes := func(g *MockGrantRevoker, err error) {
		g.EXPECT().RevokeUserGrants(gomock.Any(), anaID, "recovery").Return(err).Times(2)
	}

	type testCase struct {
		name string
		// expect arms the revoker; nil means it must not be called.
		expect func(g *MockGrantRevoker)
		// opts are what the recoverer is built with besides the env's own, and
		// by default the revoker alone.
		opts func(g *MockGrantRevoker) []recovery.Option
		// act runs the recovery.
		act    func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error)
		assert func(t *testing.T, e *completeEnv, prior []string, res *recovery.Result, err error)
	}

	recoverNow := func(ctx context.Context, _ *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
		return r.Recover(ctx, savedAndIssuedReq(e))
	}

	completed := func(t *testing.T, e *completeEnv, prior []string, res *recovery.Result, err error) {
		t.Helper()

		require.NoError(t, err)
		require.NotNil(t, res.Session)
		assert.False(t, e.loads(t, prior[0]), "the user's other sessions end as well")
	}

	cases := []testCase{
		{
			name:   "a recovery that completes at once revokes the user's grants, recording its cause",
			expect: func(g *MockGrantRevoker) { revokes(g, nil) },
			act:    recoverNow,
			assert: completed,
		},
		{
			name: "a client that hung up does not stop the revocation: the completion is detached",
			expect: func(g *MockGrantRevoker) {
				g.EXPECT().RevokeUserGrants(gomock.Any(), anaID, "recovery").DoAndReturn(
					func(ctx context.Context, _ identity.UserID, _ string) error { return ctx.Err() }).Times(2)
			},
			act: func(ctx context.Context, _ *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				e.held.onRemove = cancel

				return r.Recover(ctx, savedAndIssuedReq(e))
			},
			assert: completed,
		},
		{
			name:   "a kept session does not keep the grants: the two choices are separate",
			expect: func(g *MockGrantRevoker) { revokes(g, nil) },
			opts: func(g *MockGrantRevoker) []recovery.Option {
				return []recovery.Option{recovery.WithGrantRevoker(g), recovery.WithoutSessionRevocation()}
			},
			act: recoverNow,
			assert: func(t *testing.T, e *completeEnv, prior []string, _ *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, e.loads(t, prior[0]), "the session option is what kept this")
			},
		},
		{
			name: "the keep option keeps the grants while the sessions still end",
			opts: func(g *MockGrantRevoker) []recovery.Option {
				return []recovery.Option{recovery.WithGrantRevoker(g), recovery.WithoutRecoveryGrantRevocation()}
			},
			act:    recoverNow,
			assert: completed,
		},
		{
			name: "the keep option given before the revoker still keeps, whichever came first",
			opts: func(g *MockGrantRevoker) []recovery.Option {
				return []recovery.Option{recovery.WithoutRecoveryGrantRevocation(), recovery.WithGrantRevoker(g)}
			},
			act:    recoverNow,
			assert: completed,
		},
		{
			name:   "with no revoker a recovery behaves as it always did",
			opts:   func(*MockGrantRevoker) []recovery.Option { return nil },
			act:    recoverNow,
			assert: completed,
		},
		{
			name: "the keep option with no revoker changes nothing",
			opts: func(*MockGrantRevoker) []recovery.Option {
				return []recovery.Option{recovery.WithoutRecoveryGrantRevocation()}
			},
			act:    recoverNow,
			assert: completed,
		},
		{
			name: "a revoker's failure is returned behind fixed text, with nothing spent or ended",
			expect: func(g *MockGrantRevoker) {
				g.EXPECT().RevokeUserGrants(gomock.Any(), anaID, "recovery").Return(errGrants).Times(1)
			},
			act: recoverNow,
			assert: func(t *testing.T, e *completeEnv, prior []string, res *recovery.Result, err error) {
				t.Helper()

				require.ErrorIs(t, err, errGrants, "the failure still matches")
				assert.NotContains(t, err.Error(), "secret text", "its text is the package's own")
				assert.NotErrorIs(t, err, recovery.ErrRefused, "a dependency failure is no refusal")
				assert.Nil(t, res)
				assert.True(t, e.loads(t, prior[0]), "the sessions stand")
				assert.Empty(t, e.out.recoveredNotices(), "no notice claims a recovery that failed")

				remaining, rerr := e.codes.Remaining(t.Context(), anaID)
				require.NoError(t, rerr)
				assert.Equal(t, len(e.saved), remaining.N, "the old set stands, with nothing spent")
			},
		},
		{
			name: "a hold revokes nothing: it changes nothing until its finish",
			opts: func(g *MockGrantRevoker) []recovery.Option {
				return append(holdFor(time.Hour), recovery.WithGrantRevoker(g))
			},
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				t.Helper()

				return r.Recover(ctx, savedAndIssuedReq(e))
			},
			assert: func(t *testing.T, e *completeEnv, prior []string, res *recovery.Result, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, res.Held)
				assert.True(t, e.loads(t, prior[0]), "the sessions stand until the finish too")
			},
		},
		{
			name:   "a held recovery's finish revokes, through the same completion",
			expect: func(g *MockGrantRevoker) { revokes(g, nil) },
			opts: func(g *MockGrantRevoker) []recovery.Option {
				return append(holdFor(time.Hour), recovery.WithGrantRevoker(g))
			},
			act: func(ctx context.Context, t *testing.T, e *completeEnv, r *recovery.Recoverer) (*recovery.Result, error) {
				t.Helper()

				hold := heldRecovery(ctx, t, r, savedAndIssuedReq(e))
				e.clock.Advance(time.Hour)

				return r.Finish(ctx, hold.CompletionToken)
			},
			assert: completed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			g := NewMockGrantRevoker(gomock.NewController(t))
			if tc.expect != nil {
				tc.expect(g)
			}

			opts := []recovery.Option{recovery.WithGrantRevoker(g)}
			if tc.opts != nil {
				opts = tc.opts(g)
			}

			prior := e.priorSessions(t, 1)

			res, err := tc.act(t.Context(), t, e, e.recoverer(t, opts...))
			tc.assert(t, e, prior, res, err)
		})
	}
}

// TestRecoverer_GrantRevokerOption pins the wiring mistakes the option refuses.
func TestRecoverer_GrantRevokerOption(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		g      recovery.GrantRevoker
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, recovery.ErrConfig)
		assert.ErrorContains(t, err, "WithGrantRevoker")
	}

	cases := []testCase{
		{name: "no revoker is refused", g: nil, assert: refused},
		{name: "a typed nil is refused", g: (*nilRevoker)(nil), assert: refused},
		{
			name:   "a revoker is accepted",
			g:      NewMockGrantRevoker(gomock.NewController(t)),
			assert: func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			_, err := recovery.NewRecoverer(e.completeDeps(), e.recovererOpts(recovery.WithGrantRevoker(tc.g))...)
			tc.assert(t, err)
		})
	}
}
