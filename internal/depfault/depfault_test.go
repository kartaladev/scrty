package depfault_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

var (
	errDown    = errors.New("store unreachable: ana@example.com")
	errRefused = errors.New("depfault_test: refused")
)

// failingStore fails the two calls the decorator watches, with findErr and
// consumeErr, and answers nothing else.
type failingStore struct {
	onetime.Store

	findErr    error
	consumeErr error
}

func (s failingStore) FindByID(context.Context, id.ID) (*onetime.Token, error) {
	return nil, s.findErr
}

func (s failingStore) Consume(context.Context, id.ID, time.Time) error { return s.consumeErr }

// reapingFailingStore is failingStore that can purge.
type reapingFailingStore struct{ failingStore }

func (reapingFailingStore) DeleteExpiredBefore(context.Context, string, time.Time) (int, error) {
	return 7, nil
}

func TestStore_RecordsOnlyFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		inner  failingStore
		watch  bool
		call   func(ctx context.Context, s onetime.Store)
		assert func(t *testing.T, w *depfault.Watch)
	}

	find := func(ctx context.Context, s onetime.Store) { _, _ = s.FindByID(ctx, id.Nil) }
	consume := func(ctx context.Context, s onetime.Store) { _ = s.Consume(ctx, id.Nil, time.Time{}) }

	cases := []testCase{
		{
			name: "a lookup that failed is recorded", inner: failingStore{findErr: errDown}, watch: true, call: find,
			assert: func(t *testing.T, w *depfault.Watch) { assert.ErrorIs(t, w.Failure(), errDown) },
		},
		{
			name: "a spend that failed is recorded", inner: failingStore{consumeErr: errDown}, watch: true, call: consume,
			assert: func(t *testing.T, w *depfault.Watch) { assert.ErrorIs(t, w.Failure(), errDown) },
		},
		{
			name:  "a token the store does not hold is an answer, not a failure",
			inner: failingStore{findErr: onetime.ErrTokenNotFound}, watch: true, call: find,
			assert: func(t *testing.T, w *depfault.Watch) { assert.NoError(t, w.Failure()) },
		},
		{
			name:  "a spend that lost the race is an answer, not a failure",
			inner: failingStore{consumeErr: onetime.ErrTokenNotFound}, watch: true, call: consume,
			assert: func(t *testing.T, w *depfault.Watch) { assert.NoError(t, w.Failure()) },
		},
		{
			name: "the first failure is kept", inner: failingStore{findErr: errDown, consumeErr: errRefused}, watch: true,
			call: func(ctx context.Context, s onetime.Store) { find(ctx, s); consume(ctx, s) },
			assert: func(t *testing.T, w *depfault.Watch) {
				require.ErrorIs(t, w.Failure(), errDown)
				assert.NotErrorIs(t, w.Failure(), errRefused)
			},
		},
		{
			name: "a call whose context carries no watch passes through", inner: failingStore{findErr: errDown},
			call: find, assert: func(t *testing.T, w *depfault.Watch) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, w := depfault.Watching(t.Context())
			if !tc.watch {
				ctx = t.Context()
			}

			tc.call(ctx, depfault.Store(tc.inner))
			tc.assert(t, w)
		})
	}
}

func TestStore_OffersReaperExactlyWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		inner  onetime.Store
		assert func(t *testing.T, s onetime.Store)
	}

	cases := []testCase{
		{
			name:  "a store that can purge still can, and answers as before",
			inner: reapingFailingStore{},
			assert: func(t *testing.T, s onetime.Store) {
				r, ok := s.(onetime.Reaper)
				require.True(t, ok)

				n, err := r.DeleteExpiredBefore(t.Context(), "p", time.Time{})
				require.NoError(t, err)
				assert.Equal(t, 7, n)
			},
		},
		{
			name:  "a store that cannot purge is not made to look as if it could",
			inner: failingStore{},
			assert: func(t *testing.T, s onetime.Store) {
				_, ok := s.(onetime.Reaper)
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { t.Parallel(); tc.assert(t, depfault.Store(tc.inner)) })
	}
}

func TestRefusalAndSilent(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		err    func() error
		assert func(t *testing.T, err error, silent bool)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	cases := []testCase{
		{
			name: "a dependency's failure answered as a refusal keeps the refusal and its text, and is silent",
			err:  func() error { return depfault.Refusal(errDown, errRefused) },
			assert: func(t *testing.T, err error, silent bool) {
				require.ErrorIs(t, err, errRefused)
				assert.ErrorIs(t, err, errDown)
				assert.Equal(t, errRefused.Error(), err.Error())
				assert.True(t, silent)
			},
		},
		{
			name:   "a refusal that answers nothing is not silent",
			err:    func() error { return errRefused },
			assert: func(t *testing.T, _ error, silent bool) { assert.False(t, silent) },
		},
		{
			name:   "a nil cause is no refusal",
			err:    func() error { return depfault.Refusal(nil, errRefused) },
			assert: func(t *testing.T, err error, _ bool) { assert.NoError(t, err) },
		},
		{
			name:   "an error of the caller's own ended context is silent",
			ctx:    cancelled,
			err:    func() error { return errors.Join(errRefused, context.Canceled) },
			assert: func(t *testing.T, _ error, silent bool) { assert.True(t, silent) },
		},
		{
			name:   "a refusal beside an ended context that it does not wrap is not silent",
			ctx:    cancelled,
			err:    func() error { return errRefused },
			assert: func(t *testing.T, _ error, silent bool) { assert.False(t, silent) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			err := tc.err()
			tc.assert(t, err, depfault.Silent(ctx, err))
		})
	}
}
