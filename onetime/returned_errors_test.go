package onetime_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/onetime"
)

// TestOnetimeReturnedErrors pins task 5.7: an error caused by the store at
// Issue, IssuedCount or PurgeExpired carries fixed library text, with the
// store's own error still reachable by identity.
func TestOnetimeReturnedErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) onetime.Store
		call   func(t *testing.T, m *onetime.Manager) error
		assert func(t *testing.T, err error)
	}

	// wrappedAs returns the shape every site here shares: the error carries
	// text, the fixture's text is gone, and the store's own error is still
	// reachable by identity.
	wrappedAs := func(text string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.EqualError(t, err, text)
			assert.NotContains(t, err.Error(), "alice@example.com")
			assert.NotContains(t, err.Error(), "u-123")
			assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
		}
	}

	cases := []testCase{
		{
			name: "Issue's store insert fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *onetime.Manager) error {
				t.Helper()
				_, _, err := m.Issue(t.Context(), "ada@example.com")
				return err
			},
			assert: wrappedAs("onetime: store token"),
		},
		{
			name: "IssuedCount's store count fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().CountRecentBySubject(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(0, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *onetime.Manager) error {
				t.Helper()
				_, err := m.IssuedCount(t.Context(), "ada@example.com")
				return err
			},
			assert: wrappedAs("onetime: count recent issuance"),
		},
		{
			name: "PurgeExpired's reaper fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := newReapableStore(NewMockStore(ctrl), NewMockReaper(ctrl))
				s.MockReaper.EXPECT().DeleteExpiredBefore(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(0, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *onetime.Manager) error {
				t.Helper()
				_, err := m.PurgeExpired(t.Context())
				return err
			},
			assert: wrappedAs("onetime: purge expired tokens"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := onetime.NewManager("magic-link", onetime.WithStore(tc.store(t, ctrl)))
			require.NoError(t, err)

			tc.assert(t, tc.call(t, m))
		})
	}
}
