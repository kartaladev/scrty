package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
)

// TestLockoutReturnedErrors pins the diagnostic-redaction requirement for the
// account lockout policy's own store-facing methods (design decision 8):
// RecordFailure, Reset and PurgeExpired return the attempt store's failure
// behind fixed library text, with the store's own error still reachable by
// identity, and a bare AttemptReaper sentinel still comes back unchanged.
func TestLockoutReturnedErrors(t *testing.T) {
	t.Parallel()

	failingAttemptStore := func(t *testing.T) *MockAttemptStore {
		t.Helper()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(errLeakyStore).AnyTimes()
		store.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(errLeakyStore).AnyTimes()

		return store
	}

	assertFixedText := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		for _, v := range leakedValues {
			assert.NotContains(t, err.Error(), v, "the returned error quoted the store's own text")
		}
		assert.ErrorIs(t, err, errLeakyStore, "the store's own error is no longer reachable")

		// A store failure must not read as any of the policy's own sentinels:
		// diag.Wrap's kinds are matched by every error it carries, so passing
		// a sentinel as a kind would make an unrelated outage look like that
		// specific refusal (design decision 8).
		assert.NotErrorIs(t, err, policy.ErrRetainSinceRequired,
			"a store outage must not read as a retain-since cutoff being required")
		assert.NotErrorIs(t, err, policy.ErrReapUnsupported,
			"a store outage must not read as the store lacking reap support")
		assert.NotErrorIs(t, err, policy.ErrPolicyDenied,
			"a store outage must not read as the policy's own denial reason")
	}

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "recording a failure the store cannot write",
			run: func(t *testing.T) error {
				t.Helper()

				p := lockoutWith(t, policy.WithAttemptStore(failingAttemptStore(t)))

				return p.RecordFailure(t.Context(), "alice@example.com")
			},
			assert: assertFixedText,
		},
		{
			name: "clearing failures the store cannot reset",
			run: func(t *testing.T) error {
				t.Helper()

				p := lockoutWith(t, policy.WithAttemptStore(failingAttemptStore(t)))

				return p.Reset(t.Context(), "alice@example.com")
			},
			assert: assertFixedText,
		},
		{
			name: "purging expired failures the store cannot sweep",
			run: func(t *testing.T) error {
				t.Helper()

				store := newReapableAttemptStore(t)
				store.reaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), gomock.Any()).Return(0, errLeakyStore)

				p := lockoutWith(t, policy.WithAttemptStore(store))

				_, err := p.PurgeExpired(t.Context())

				return err
			},
			assert: assertFixedText,
		},
		{
			name: "purging passes a bare retain-since sentinel through unchanged",
			run: func(t *testing.T) error {
				t.Helper()

				store := newReapableAttemptStore(t)
				store.reaper.EXPECT().
					DeleteAttemptsBefore(gomock.Any(), gomock.Any()).
					Return(0, policy.ErrRetainSinceRequired)

				p := lockoutWith(t, policy.WithAttemptStore(store))

				_, err := p.PurgeExpired(t.Context())

				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Same(t, policy.ErrRetainSinceRequired, err,
					"a store's own bare sentinel must come back as itself, text included")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}
