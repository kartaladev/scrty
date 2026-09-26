package apikey_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/pkg/id"
)

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// failsWithFixture is a working store whose last-use write alone fails, with
// an error a test chooses rather than the package's own fixed errStore.
type failsWithFixture struct {
	apikey.Store
	err error
}

func (s failsWithFixture) TouchLastUsed(context.Context, id.ID, time.Time) error { return s.err }

// TestAPIKeyStoreFailureRecords pins that a store failure at either of the
// manager's two store call sites during Verify — reading the record and
// recording last use — is recorded through a fixed reason and the error's
// type, never the store's own text, while the public key identifier stays.
func TestAPIKeyStoreFailureRecords(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		store  func(t *testing.T, inner apikey.Store) apikey.Store
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "the record read fails",
			store: func(t *testing.T, _ apikey.Store) apikey.Store {
				t.Helper()
				s := NewMockStore(gomock.NewController(t))
				s.EXPECT().Get(gomock.Any(), gomock.Any()).Return(apikey.Key{}, errRedactionFixture)
				return s
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
			},
		},
		{
			name: "the last-use write fails, and verification still succeeds",
			store: func(_ *testing.T, inner apikey.Store) apikey.Store {
				return failsWithFixture{Store: inner, err: errRedactionFixture}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err, "a best-effort write never fails the verification it rode in on")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := base
			inner := apikey.NewMemoryStore()
			issuer, err := apikey.NewManager(
				apikey.WithStore(inner), apikey.WithClock(func() time.Time { return now }))
			require.NoError(t, err)

			presented, rec, err := issuer.Issue(t.Context(), "svc-billing", "nightly export",
				[]string{"invoices:read"}, 7*24*time.Hour)
			require.NoError(t, err)

			var logs bytes.Buffer
			verifier, err := apikey.NewManager(
				apikey.WithStore(tc.store(t, inner)),
				apikey.WithClock(func() time.Time { return now }),
				apikey.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			require.NoError(t, err)

			_, _, verifyErr := verifier.Verify(t.Context(), presented)
			tc.assert(t, verifyErr)

			out := logs.String()
			assert.NotContains(t, out, "alice@example.com")
			assert.NotContains(t, out, "u-123")
			assert.Contains(t, out, "reason=key-store")
			assert.Contains(t, out, "error_type=")
			assert.Contains(t, out, "key_id="+rec.ID.String(), "the public key identifier stays")
		})
	}
}
