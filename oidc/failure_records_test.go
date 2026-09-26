package oidc_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// TestCallbackFailureRecords pins that a flow store's completion failure is
// recorded through the fixed reason and the error's type, never the store's
// own text — unlike the callback's invalid-id-token record, which keeps the
// library's own protocol-failure text on purpose.
func TestCallbackFailureRecords(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	flows := func(t *testing.T) oidc.FlowStore {
		t.Helper()
		s := NewMockFlowStore(gomock.NewController(t))
		s.EXPECT().Complete(gomock.Any(), "h", "corp", "s").Return(oidc.Flow{}, errRedactionFixture)
		return s
	}

	e := newCallbackEnv(t, now, flows)
	_, err := e.m.Callback(t.Context(), "corp", "the-code", "s", "h")
	require.ErrorIs(t, err, errRedactionFixture, "the store's error is still reachable by identity")
	require.ErrorIs(t, err, oidc.ErrFlowUnspent)

	logs := e.logs.String()
	assert.NotContains(t, logs, "alice@example.com")
	assert.NotContains(t, logs, "u-123")
	assert.Contains(t, logs, "reason=flow-store")
	assert.Contains(t, logs, "error_type=")
}

// TestHandoffFailureRecords pins that every handoff redemption stopped by a
// consumer dependency — the user loader, the store's find, the store's
// consume — is recorded through a fixed reason and the error's type, never the
// dependency's own text. The fixture error quotes a username and a user
// reference the manager never held, which scrubbing known values cannot catch.
func TestHandoffFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		store   func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore
		arrange func(f *handoffRedeemFixture)
		assert  func(t *testing.T, logs string)
	}

	// failureRecord asserts the one record a dependency failure writes: no
	// dependency text, the fixed reason exactly once, and the error's type.
	// op, when not empty, is the operation the record must also name — find
	// or consume, for the two handoff-store call sites that share one
	// reason.
	failureRecord := func(reason, op string) func(t *testing.T, logs string) {
		return func(t *testing.T, logs string) {
			t.Helper()
			assert.NotContains(t, logs, "alice@example.com")
			assert.NotContains(t, logs, "u-123")
			assert.NotContains(t, logs, "[redacted]", "the record carries no scrubbed dependency text either")
			assert.Contains(t, logs, "reason="+reason)
			assert.Contains(t, logs, "error_type=*errors.errorString")
			assert.Equal(t, 1, strings.Count(logs, " reason="), "the record names its reason exactly once")
			if op != "" {
				assert.Contains(t, logs, "op="+op)
			}
		}
	}

	loads := func(f *handoffRedeemFixture) {
		f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
	}

	cases := []testCase{
		{
			name: "a user loader failure",
			arrange: func(f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errRedactionFixture)
			},
			assert: failureRecord("user-loader", ""),
		},
		{
			name: "a store find failure",
			store: func(_ *testing.T, ctrl *gomock.Controller, _ *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).Return(nil, errRedactionFixture)
				return s
			},
			assert: failureRecord("handoff-store", "find"),
		},
		{
			name: "a store consume failure",
			store: func(_ *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).DoAndReturn(mem.FindByTokenID)
				s.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			arrange: loads,
			assert:  failureRecord("handoff-store", "consume"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newHandoffRedeemFixture(t, tc.store)
			if tc.arrange != nil {
				tc.arrange(f)
			}

			res, err := f.m.Redeem(t.Context(), f.code)
			refusedAsInvalid(t, res, err)
			tc.assert(t, f.logs.String())
		})
	}

	// A find failure and a consume failure share the reason handoff-store.
	// Before op distinguished them, the second failure's sampling key was
	// identical to the first's, so it was suppressed rather than recorded —
	// an operator could see one failure and not tell which call it was.
	t.Run("a find failure and a consume failure in one window write separate records", func(t *testing.T) {
		t.Parallel()

		mem := oidc.NewMemoryHandoffStore()
		issuer, err := oidc.NewHandoffManager(mem, NewMockUserLoader(gomock.NewController(t)))
		require.NoError(t, err)

		code1, err := issuer.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)
		code2, err := issuer.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)

		tokenID1, _ := splitHandoffCode(t, code1)
		tokenID2, _ := splitHandoffCode(t, code2)

		ctrl := gomock.NewController(t)
		store := NewMockHandoffStore(ctrl)
		store.EXPECT().FindByTokenID(gomock.Any(), tokenID1).Return(nil, errRedactionFixture)
		store.EXPECT().FindByTokenID(gomock.Any(), tokenID2).DoAndReturn(mem.FindByTokenID)
		store.EXPECT().Consume(gomock.Any(), tokenID2, gomock.Any()).Return(errRedactionFixture)

		users := NewMockUserLoader(ctrl)
		users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)

		logs := &handoffLogSink{}
		m, err := oidc.NewHandoffManager(store, users, oidc.WithHandoffLogger(logs.Logger()))
		require.NoError(t, err)

		res1, err1 := m.Redeem(t.Context(), code1)
		refusedAsInvalid(t, res1, err1)
		res2, err2 := m.Redeem(t.Context(), code2)
		refusedAsInvalid(t, res2, err2)

		out := logs.String()
		assert.Equal(t, 2, strings.Count(out, "reason=handoff-store"),
			"both the find and the consume failure wrote a record")
		assert.Contains(t, out, "op=find")
		assert.Contains(t, out, "op=consume")
	})
}
