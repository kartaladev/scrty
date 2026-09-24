package apikey_test

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// TestManagerVerify pins that every refusal is one error. A revoked key that
// looked different from an unknown one would tell a scanner which identifiers
// were ever real, and an outage that looked different from a refusal would
// announce when the store was down.
func TestManagerVerify(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		prepare func(t *testing.T, m *apikey.Manager, valid string) string
		store   func(t *testing.T, inner apikey.Store) apikey.Store
		at      time.Time
		assert  func(t *testing.T, p identity.Principal, rec apikey.Key, err error)
	}

	unchanged := func(_ *testing.T, _ *apikey.Manager, valid string) string { return valid }

	refused := func(t *testing.T, p identity.Principal, rec apikey.Key, err error) {
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Empty(t, p.ID)
		assert.Empty(t, p.Scopes)
		assert.Zero(t, rec.ID, "a refusal yields no record")
	}

	cases := []testCase{
		{
			name:    "a valid key yields a service principal",
			prepare: unchanged,
			at:      base,
			assert: func(t *testing.T, p identity.Principal, rec apikey.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.KindService, p.Kind)
				assert.True(t, p.IsService())
				assert.Equal(t, identity.UserID("svc-billing"), p.ID)
				assert.Equal(t, "nightly export", p.Name)
				assert.Equal(t, []string{"invoices:read", "invoices:export"}, p.Scopes)
				assert.Equal(t, identity.UserID("svc-billing"), rec.Principal)
			},
		},
		{
			name: "an unknown identifier",
			prepare: func(t *testing.T, _ *apikey.Manager, valid string) string {
				other, err := newID()
				require.NoError(t, err)

				_, secret, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				return "sk_" + other.String() + "." + secret
			},
			at:     base,
			assert: refused,
		},
		{
			name: "a wrong secret",
			prepare: func(_ *testing.T, _ *apikey.Manager, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				return "sk_" + idPart + "." +
					base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
			},
			at:     base,
			assert: refused,
		},
		{
			name:    "an expired key",
			prepare: unchanged,
			at:      base.Add(8 * 24 * time.Hour),
			assert:  refused,
		},
		{
			name:    "a key verified on the instant it expires is still accepted",
			prepare: unchanged,
			at:      base.Add(7 * 24 * time.Hour),
			assert: func(t *testing.T, _ identity.Principal, _ apikey.Key, err error) {
				require.NoError(t, err, "accepted while now is not after expiry")
			},
		},
		{
			name: "a revoked key",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				parsed, err := id.Parse(idPart)
				require.NoError(t, err)
				require.NoError(t, m.Revoke(t.Context(), parsed))

				return valid
			},
			at:     base,
			assert: refused,
		},
		{
			name:    "a store outage",
			prepare: unchanged,
			store: func(t *testing.T, _ apikey.Store) apikey.Store {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(apikey.Key{}, errStore).
					AnyTimes()

				return store
			},
			at:     base,
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			now := base
			inner := apikey.NewMemoryStore()

			m, err := apikey.NewManager(
				apikey.WithStore(inner),
				apikey.WithClock(func() time.Time { return now }),
			)
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "nightly export",
				[]string{"invoices:read", "invoices:export"}, 7*24*time.Hour)
			require.NoError(t, err)

			presented := tc.prepare(t, m, valid)

			verifier := m
			if tc.store != nil {
				verifier, err = apikey.NewManager(
					apikey.WithStore(tc.store(t, inner)),
					apikey.WithClock(func() time.Time { return now }),
				)
				require.NoError(t, err)
			}

			now = tc.at

			p, rec, verifyErr := verifier.Verify(ctx, presented)
			tc.assert(t, p, rec, verifyErr)
		})
	}
}

func TestManagerExpiry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	now := base

	m, err := apikey.NewManager(apikey.WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	never, _, err := m.Issue(ctx, "svc-billing", "forever", nil, 0)
	require.NoError(t, err)

	now = base.AddDate(5, 0, 0)

	_, _, err = m.Verify(ctx, never)
	assert.NoError(t, err, "a lifetime of zero or less never expires")
}

func TestManagerRevoke(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m, err := apikey.NewManager()
	require.NoError(t, err)

	presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
	require.NoError(t, err)

	_, _, err = m.Verify(ctx, presented)
	require.NoError(t, err)

	require.NoError(t, m.Revoke(ctx, rec.ID))

	_, _, err = m.Verify(ctx, presented)
	assert.ErrorIs(t, err, apikey.ErrVerificationFailed)

	unknown, err := newID()
	require.NoError(t, err)
	assert.ErrorIs(t, m.Revoke(ctx, unknown), apikey.ErrKeyNotFound)
}

// TestVerifyNeverDiscloseThePresentedKey pins that neither the error a refusal
// returns nor anything this package logs carries the string the caller
// presented. A refusal that echoed the key would put it in every log line the
// caller's own error handling writes.
func TestVerifyNeverDiscloseThePresentedKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		prepare func(t *testing.T, m *apikey.Manager, valid string) string
	}

	cases := []testCase{
		{
			name:    "a malformed key",
			prepare: func(_ *testing.T, _ *apikey.Manager, _ string) string { return "sk_nonsense.aaaa" },
		},
		{
			name: "an unknown identifier",
			prepare: func(t *testing.T, _ *apikey.Manager, valid string) string {
				other, err := newID()
				require.NoError(t, err)

				_, secret, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				return "sk_" + other.String() + "." + secret
			},
		},
		{
			name: "a revoked key",
			prepare: func(t *testing.T, m *apikey.Manager, valid string) string {
				idPart, _, _ := strings.Cut(strings.TrimPrefix(valid, "sk_"), ".")

				parsed, err := id.Parse(idPart)
				require.NoError(t, err)
				require.NoError(t, m.Revoke(t.Context(), parsed))

				return valid
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			var logged bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

			m, err := apikey.NewManager(apikey.WithLogger(logger))
			require.NoError(t, err)

			valid, _, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			presented := tc.prepare(t, m, valid)

			_, _, verifyErr := m.Verify(ctx, presented)
			require.ErrorIs(t, verifyErr, apikey.ErrVerificationFailed)

			assert.NotContains(t, verifyErr.Error(), presented, "the error echoed the presented key")

			_, secret, found := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")
			if found {
				assert.NotContains(t, logged.String(), secret, "a log record carried the secret")
			}

			assert.NotContains(t, logged.String(), presented, "a log record carried the presented key")
		})
	}
}
