package onetime_test

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/onetime"
)

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// TestOnetimeStoreFailureRecords pins that a store failure at either of the
// manager's two store call sites — reading a token during Check and marking
// one consumed — is recorded through a fixed reason and the error's type,
// never the store's own text, while the public token identifier stays.
func TestOnetimeStoreFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) onetime.Store
		act    func(t *testing.T, m *onetime.Manager) error
		assert func(t *testing.T, err error, logs string)
	}

	// storeFailureRecord asserts what both store call sites promise: the
	// token refused, and a record with the fixed reason, the store's error
	// type and the public token id, never the store's text.
	storeFailureRecord := func(t *testing.T, err error, logs string) {
		t.Helper()
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.NotContains(t, logs, "alice@example.com")
		assert.NotContains(t, logs, "u-123")
		assert.Contains(t, logs, "reason=token-store")
		assert.Contains(t, logs, "error_type=*errors.errorString", "the store's own error type")
		assert.Contains(t, logs, "token_id="+checkTokenID.String(), "the public token identifier stays")
	}

	cases := []testCase{
		{
			name: "Check's store read fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				s := NewMockStore(ctrl)
				s.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(nil, errRedactionFixture)
				return s
			},
			act: func(t *testing.T, m *onetime.Manager) error {
				t.Helper()
				_, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
				return err
			},
			assert: storeFailureRecord,
		},
		{
			name: "Consume's store write fails",
			store: func(t *testing.T, ctrl *gomock.Controller) onetime.Store {
				t.Helper()
				rec := liveRecord(t)
				s := NewMockStore(ctrl)
				s.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
				s.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).Return(errRedactionFixture)
				return s
			},
			act: func(t *testing.T, m *onetime.Manager) error {
				t.Helper()
				c, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
				require.NoError(t, err)
				return m.Consume(t.Context(), c)
			},
			assert: storeFailureRecord,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			ctrl := gomock.NewController(t)
			clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))

			m, err := onetime.NewManager("magic-link",
				onetime.WithStore(tc.store(t, ctrl)),
				onetime.WithClock(clk),
				onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			require.NoError(t, err)

			actErr := tc.act(t, m)
			tc.assert(t, actErr, logs.String())
		})
	}
}
