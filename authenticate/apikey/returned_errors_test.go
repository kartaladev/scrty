package apikey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/apikey"
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

	// lostRace is a store on which Rotate reads oldKeyID live and issues its
	// replacement, then finds the old key already revoked by a concurrent
	// writer, in that order; revokeReplacement answers the revoke of the
	// replacement, and replacement receives its identifier.
	lostRace := func(ctrl *gomock.Controller, replacement *id.ID, revokeReplacement func() (bool, error)) apikey.Store {
		s := NewMockStore(ctrl)
		gomock.InOrder(
			s.EXPECT().Get(gomock.Any(), oldKeyID).Return(apikey.Key{ID: oldKeyID, Principal: principal}, nil),
			s.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, rec apikey.Key) error {
				*replacement = rec.ID
				return nil
			}),
			s.EXPECT().Revoke(gomock.Any(), oldKeyID, gomock.Any()).Return(false, nil),
			s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, keyID id.ID, _ time.Time) (bool, error) {
					if keyID != *replacement {
						return false, errors.New("revoked something other than the replacement")
					}
					return revokeReplacement()
				}),
		)
		return s
	}

	// Each lost-race row writes its own replacement identifier.
	var revokedReplacement, unrevokedReplacement id.ID

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) apikey.Store
		call   func(t *testing.T, m *apikey.Keys) error
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
			call: func(t *testing.T, m *apikey.Keys) error {
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
			call: func(t *testing.T, m *apikey.Keys) error {
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
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errRedactionFixture)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
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
				s.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, apikey.ErrKeyNotFound)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
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
			call: func(t *testing.T, m *apikey.Keys) error {
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
			call: func(t *testing.T, m *apikey.Keys) error {
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
				gomock.InOrder(
					s.EXPECT().Revoke(gomock.Any(), oldKeyID, gomock.Any()).Return(false, errRedactionFixture),
					// The replacement is ended on the way out.
					s.EXPECT().Revoke(gomock.Any(), gomock.Not(oldKeyID), gomock.Any()).Return(true, nil),
				)
				return s
			},
			call: func(t *testing.T, m *apikey.Keys) error {
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
		{
			name: "Rotate finds the old key already revoked, revokes its replacement and is refused",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				return lostRace(ctrl, &revokedReplacement, func() (bool, error) { return true, nil })
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				fresh, _, err := m.Rotate(t.Context(), oldKeyID, 0)
				assert.Empty(t, fresh, "a refused rotation returns no key")
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
			},
		},
		{
			name: "Rotate loses the race and cannot revoke its replacement, naming it for an operator",
			store: func(t *testing.T, ctrl *gomock.Controller) apikey.Store {
				t.Helper()
				return lostRace(ctrl, &unrevokedReplacement, func() (bool, error) { return false, errRedactionFixture })
			},
			call: func(t *testing.T, m *apikey.Keys) error {
				t.Helper()
				fresh, _, err := m.Rotate(t.Context(), oldKeyID, 0)
				assert.Empty(t, fresh, "a refused rotation returns no key")
				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
				assert.Contains(t, err.Error(), unrevokedReplacement.String(),
					"the replacement left live is named, for an operator to revoke by hand")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			m, err := apikey.New(apikey.WithStore(tc.store(t, ctrl)))
			require.NoError(t, err)

			tc.assert(t, tc.call(t, m))
		})
	}
}
