package recovery_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/recovery"
)

// errFactory is what a consumer's limiter factory refuses a namespace with.
var errFactory = errors.New("factory: backend refused the namespace")

// refusingLimiter is a limiter reporting every key over its limit, expected to
// be consulted under key at least once.
func refusingLimiter(ctrl *gomock.Controller, key string) *MockLimiter {
	l := NewMockLimiter(ctrl)
	l.EXPECT().Exceeded(gomock.Any(), key).Return(true, nil).MinTimes(1)
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return l
}

// TestNewCodes_LimiterFactory pins where the code-presentation limiter comes
// from: the explicit limiter, then the factory, then the in-memory default.
// It is a table of its own because Codes and Recoverer are built over different
// fixtures.
func TestNewCodes_LimiterFactory(t *testing.T) {
	t.Parallel()

	key := recovery.CodeThrottleKey(anaID)

	type testCase struct {
		name   string
		opts   func(t *testing.T) []recovery.CodesOption
		assert func(t *testing.T, c *recovery.Codes, err error)
	}

	cases := []testCase{
		{
			name: "default builds in-memory",
			opts: func(*testing.T) []recovery.CodesOption { return nil },
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				for range 5 {
					require.ErrorIs(t, c.Confirm(t.Context(), anaID, wrongCode), recovery.ErrRefused)
				}

				_, err = c.Check(t.Context(), anaID, wrongCode)
				assert.ErrorIs(t, err, recovery.ErrCodeThrottled, "the default counts 5 failures per 15 minutes")
			},
		},
		{
			name: "factory asked with namespace, limit, window",
			opts: func(t *testing.T) []recovery.CodesOption {
				ctrl := gomock.NewController(t)
				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("recovery-codes", 5, 15*time.Minute).
					Return(refusingLimiter(ctrl, key), nil).Times(1)

				return []recovery.CodesOption{recovery.WithCodeLimiterFactory(f)}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				_, err = c.Check(t.Context(), anaID, wrongCode)
				assert.ErrorIs(t, err, recovery.ErrCodeThrottled,
					"the presentation is counted through the limiter the factory built")
			},
		},
		{
			name: "explicit limiter wins and factory not asked",
			opts: func(t *testing.T) []recovery.CodesOption {
				ctrl := gomock.NewController(t)

				// No expectation: gomock fails the case if the factory is asked.
				f := NewMockLimiterFactory(ctrl)

				return []recovery.CodesOption{
					recovery.WithCodeLimiter(refusingLimiter(ctrl, key)),
					recovery.WithCodeLimiterFactory(f),
				}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				_, err = c.Check(t.Context(), anaID, wrongCode)
				assert.ErrorIs(t, err, recovery.ErrCodeThrottled)
			},
		},
		{
			name: "nil factory refused",
			opts: func(*testing.T) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodeLimiterFactory(nil)}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, c)
			},
		},
		{
			name: "typed-nil factory refused",
			opts: func(*testing.T) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodeLimiterFactory((*MockLimiterFactory)(nil))}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, c)
			},
		},
		{
			// The explicit limiter wins, but a factory replaced with nothing is
			// a wiring mistake whatever else was given.
			name: "typed-nil factory refused beside an explicit limiter",
			opts: func(t *testing.T) []recovery.CodesOption {
				return []recovery.CodesOption{
					recovery.WithCodeLimiter(NewMockLimiter(gomock.NewController(t))),
					recovery.WithCodeLimiterFactory((*MockLimiterFactory)(nil)),
				}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, c)
			},
		},
		{
			name: "factory error fails construction",
			opts: func(t *testing.T) []recovery.CodesOption {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("recovery-codes", 5, 15*time.Minute).Return(nil, errFactory)

				return []recovery.CodesOption{recovery.WithCodeLimiterFactory(f)}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				require.ErrorIs(t, err, errFactory)
				assert.Contains(t, err.Error(), `"recovery-codes"`, "the error names the namespace")
				assert.Nil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := recovery.NewCodes(tc.opts(t)...)
			tc.assert(t, c, err)
		})
	}
}

// TestNewRecoverer_UserLimiterFactory pins where the per-user limiter comes
// from: the explicit limiter, then the factory, then the in-memory default.
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
