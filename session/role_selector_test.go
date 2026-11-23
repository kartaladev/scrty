package session_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/session"
)

// The manager records a selection through its store's RoleSelector, over a
// selecting store and over the sealing store wrapping one, passing the
// store's refusals through and hiding any other failure behind text that
// names no session; over a store with no selection it offers none and
// refuses every selection as a configuration error.
func TestSessionsSelectRole(t *testing.T) {
	t.Parallel()

	const sessionID = "sel-session-identifier"
	errInner := errors.New("inner store: no row for " + sessionID)
	// errUnstorable stands in for a durable store's refusal of a role it
	// cannot hold, which it returns wrapped in its own text.
	errUnstorable := errors.New("the session's selected role cannot be stored")

	type testCase struct {
		name    string
		sealed  bool
		store   func(ctrl *gomock.Controller) session.Store
		selects bool
		assert  func(t *testing.T, err error)
	}

	selecting := func(result error) func(ctrl *gomock.Controller) session.Store {
		return func(ctrl *gomock.Controller) session.Store {
			selector := NewMockRoleSelector(ctrl)
			selector.EXPECT().SelectRole(gomock.Any(), sessionID, "audit").Return(result)

			return selectingStore{MockStore: NewMockStore(ctrl), MockRoleSelector: selector}
		}
	}
	plain := func(ctrl *gomock.Controller) session.Store { return NewMockStore(ctrl) }
	refusedAs := func(sentinel error) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, sentinel)
			assert.NotContains(t, err.Error(), sessionID)
		}
	}

	var cases []testCase
	for _, sealed := range []bool{false, true} {
		over := "a selecting store"
		if sealed {
			over = "the sealing store over " + over
		}
		cases = append(cases,
			testCase{
				name: "over " + over + ", a selection is recorded", sealed: sealed, selects: true,
				store: selecting(nil),
				assert: func(t *testing.T, err error) {
					require.NoError(t, err)
				},
			},
			testCase{
				name: "over " + over + ", not found passes through", sealed: sealed, selects: true,
				store: selecting(session.ErrNotFound), assert: refusedAs(session.ErrNotFound),
			},
			testCase{
				name: "over " + over + ", superseded passes through", sealed: sealed, selects: true,
				store: selecting(session.ErrSuperseded), assert: refusedAs(session.ErrSuperseded),
			},
			testCase{
				name: "over " + over + ", expired passes through", sealed: sealed, selects: true,
				store: selecting(session.ErrExpired), assert: refusedAs(session.ErrExpired),
			},
			testCase{
				name: "over " + over + ", an unstorable role's refusal passes through", sealed: sealed, selects: true,
				store:  selecting(fmt.Errorf("store: select role: %w", errUnstorable)),
				assert: refusedAs(errUnstorable),
			},
			testCase{
				name:   "over " + over + ", another failure keeps its cause behind text naming no session",
				sealed: sealed, selects: true,
				store: selecting(errInner), assert: refusedAs(errInner),
			},
			testCase{
				name:   "over a store with no selection, sealed " + fmt.Sprint(sealed) + ", it is a configuration error",
				sealed: sealed, selects: false,
				store: plain, assert: refusedAs(session.ErrConfig),
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := tc.store(gomock.NewController(t))
			if tc.sealed {
				var err error
				store, err = session.NewEncryptedStore(store, fakeCipher{key: 0x2a})
				require.NoError(t, err)
			}
			m, err := session.New(session.WithStore(store))
			require.NoError(t, err)

			assert.Equal(t, tc.selects, m.SelectsRoles())
			tc.assert(t, m.SelectRole(t.Context(), sessionID, "audit"))
		})
	}
}
