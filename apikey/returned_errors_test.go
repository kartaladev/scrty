package apikey_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// TestAPIKeyReturnedErrors pins task 5.7: an error caused by the store at
// Issue, List, Revoke or Rotate carries fixed library text, with the store's
// own error still reachable by identity — except a bare ErrKeyNotFound, which
// a store's contract documents and which comes back unchanged, text
// included, so nothing that already matched on it changes.
func TestAPIKeyReturnedErrors(t *testing.T) {
	t.Parallel()

	const principal = identity.UserID("svc-billing")

	newKeyID := func(t *testing.T) id.ID {
		t.Helper()
		keyID, err := id.NewV7Generator().NewID()
		require.NoError(t, err)
		return keyID
	}

	// oldKeyID is fixed, rather than minted per case, so the
	// "keeps both identifiers" row below can assert it appears in the text.
	oldKeyID := newKeyID(t)

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) apikey.Store
		call   func(t *testing.T, m *apikey.Manager) error
		assert func(t *testing.T, err error)
	}

	// wrapped is the shape shared by every site that always wraps: the
	// fixture's own error is reachable, its text is gone, and a sentinel this
	// call never matched before still does not match now.
	wrapped := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
		assert.NotErrorIs(t, err, apikey.ErrKeyNotFound,
			"an outage must not read as a key nobody issued")
	}

	// bareSentinel is the shape a call whose store answers with the bare
	// sentinel shares: the exact value comes back, unchanged.
	bareSentinel := func(t *testing.T, err error) {
		t.Helper()
		assert.Same(t, apikey.ErrKeyNotFound, err, "a bare sentinel comes back unchanged, text included")
	}

	cases := []testCase{
		{
			name: "Issue's store put fails",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				_, _, err := m.Issue(t.Context(), principal, "nightly export", nil, 0)
				return err
			},
			assert: wrapped,
		},
		{
			name: "List's store list fails",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				_, err := m.List(t.Context(), principal)
				return err
			},
			assert: wrapped,
		},
		{
			name: "Revoke's store revoke fails with an outage",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				return m.Revoke(t.Context(), newKeyID(t))
			},
			assert: wrapped,
		},
		{
			name: "Revoke's store returns ErrKeyNotFound bare",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(apikey.ErrKeyNotFound)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				return m.Revoke(t.Context(), newKeyID(t))
			},
			assert: bareSentinel,
		},
		{
			name: "Rotate's store get fails with an outage",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Get(gomock.Any(), gomock.Any()).Return(apikey.Key{}, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				_, _, err := m.Rotate(t.Context(), newKeyID(t), 0)
				return err
			},
			assert: wrapped,
		},
		{
			name: "Rotate's store get returns ErrKeyNotFound bare",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Get(gomock.Any(), gomock.Any()).Return(apikey.Key{}, apikey.ErrKeyNotFound)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				_, _, err := m.Rotate(t.Context(), newKeyID(t), 0)
				return err
			},
			assert: bareSentinel,
		},
		{
			name: "Rotate's own revoke fails, keeping both key identifiers in the text",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, keyID id.ID) (apikey.Key, error) {
						return apikey.Key{ID: keyID, Principal: principal}, nil
					})
				s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Manager) error {
				t.Helper()
				_, _, err := m.Rotate(t.Context(), oldKeyID, 0)
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				wrapped(t, err)
				assert.Contains(t, err.Error(), oldKeyID.String(), "the old key's identifier stays, for an operator to revoke by hand")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := apikey.NewManager(apikey.WithStore(tc.store(t, ctrl)))
			require.NoError(t, err)

			tc.assert(t, tc.call(t, m))
		})
	}
}
