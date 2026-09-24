package magiclink_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/onetime"
)

func TestRedeemFailuresAreUniform(t *testing.T) {
	t.Parallel()

	keepValid := func(_ *testing.T, _ *onetime.Manager, valid string) (string, string) {
		return valid, ""
	}

	type testCase struct {
		name    string
		prepare func(t *testing.T, tokens *onetime.Manager, valid string) (presented, binding string)
		loader  identity.UserLoader
		store   func(inner onetime.Store) onetime.Store
		bound   bool
	}

	cases := []testCase{
		{
			name:    "malformed token",
			prepare: func(*testing.T, *onetime.Manager, string) (string, string) { return "nonsense", "" },
		},
		{
			name: "unknown token",
			prepare: func(t *testing.T, _ *onetime.Manager, _ string) (string, string) {
				return freshUnknownToken(t), ""
			},
		},
		{
			name: "expired token",
			prepare: func(t *testing.T, tokens *onetime.Manager, valid string) (string, string) {
				advanceClockPast(t, tokens)

				return valid, ""
			},
		},
		{
			name: "already consumed",
			prepare: func(t *testing.T, tokens *onetime.Manager, valid string) (string, string) {
				consume(t, tokens, valid)

				return valid, ""
			},
		},
		{
			name: "wrong secret",
			prepare: func(_ *testing.T, _ *onetime.Manager, valid string) (string, string) {
				return valid[:len(valid)-4] + "AAAA", ""
			},
		},
		{
			name:    "wrong binding",
			bound:   true,
			prepare: func(_ *testing.T, _ *onetime.Manager, valid string) (string, string) { return valid, "wrong-nonce" },
		},
		{
			name:    "user not found",
			prepare: keepValid,
			loader:  stubLoader{byID: map[identity.UserID]*identity.Details{}},
		},
		{
			name:    "user disabled",
			prepare: keepValid,
			loader:  stubLoader{byID: map[identity.UserID]*identity.Details{"u-1": {ID: "u-1", Active: false}}},
		},
		{
			name:    "user mismatched",
			prepare: keepValid,
			loader:  stubLoader{byID: map[identity.UserID]*identity.Details{"u-1": {ID: "u-9", Active: true}}},
		},
		{
			name:    "loader outage",
			prepare: keepValid,
			loader:  stubLoader{err: errStoreDown},
		},
		{
			name:    "the consume write fails",
			prepare: keepValid,
			store:   func(inner onetime.Store) onetime.Store { return consumeFailsStore{Store: inner} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loader := tc.loader
			if loader == nil {
				loader = activeByID()
			}

			var store onetime.Store = onetime.NewMemoryStore()
			if tc.store != nil {
				store = tc.store(store)
			}

			tokens := tokensWithStore(t, store)

			m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
				magiclink.WithSameDeviceBinding(false))
			require.NoError(t, err)

			issueOpts := []onetime.IssueOption(nil)
			if tc.bound {
				issueOpts = append(issueOpts, onetime.WithBinding("the-right-nonce"))
			}

			valid, _, err := tokens.Issue(t.Context(), "u-1", issueOpts...)
			require.NoError(t, err)

			presented, binding := tc.prepare(t, tokens, valid)

			r, redeemErr := m.Redeem(t.Context(), presented, binding)

			assert.ErrorIs(t, redeemErr, magiclink.ErrInvalidLink,
				"every one of these is the same error to the caller")
			assert.Empty(t, r.Principal.ID, "no session may be established")
		})
	}
}

func TestConsumerChecksReturnedUnchanged(t *testing.T) {
	t.Parallel()

	termsNotAccepted := errors.New("terms not accepted")

	var secondRan atomic.Bool

	first := func(context.Context, identity.Principal, time.Time) error { return termsNotAccepted }
	second := func(context.Context, identity.Principal, time.Time) error {
		secondRan.Store(true)

		return nil
	}

	tokens := testTokens(t)

	m, err := magiclink.NewManager(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")

	_, err = m.Redeem(t.Context(), presented, "", first, second)

	assert.ErrorIs(t, err, termsNotAccepted, "returned unchanged, not wrapped in ErrInvalidLink")
	assert.NotErrorIs(t, err, magiclink.ErrInvalidLink)
	assert.False(t, secondRan.Load(), "later checks do not run")

	// And the link survived.
	_, err = m.Redeem(t.Context(), presented, "")
	assert.NoError(t, err)
}

func TestRedeemChecksSeeTheResolvedPrincipal(t *testing.T) {
	t.Parallel()

	changed := time.Date(2025, 11, 2, 9, 30, 0, 0, time.UTC)

	loader := stubLoader{byID: map[identity.UserID]*identity.Details{
		"u-1": {ID: "u-1", Username: "ada@example.com", Name: "Ada", Active: true, PasswordChangedAt: changed},
	}}

	tokens := testTokens(t)

	m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	var (
		seenPrincipal identity.Principal
		seenChanged   time.Time
	)

	check := func(_ context.Context, p identity.Principal, passwordChangedAt time.Time) error {
		seenPrincipal = p
		seenChanged = passwordChangedAt

		return nil
	}

	r, err := m.Redeem(t.Context(), issueFor(t, tokens, "u-1"), "", check)
	require.NoError(t, err)

	assert.Equal(t, identity.UserID("u-1"), seenPrincipal.ID)
	assert.Equal(t, "Ada", seenPrincipal.Name)
	assert.Equal(t, changed, seenChanged)
	assert.Equal(t, changed, r.PasswordChangedAt)
}

func TestRedeemLogsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tokens := testTokens(t)

	m, err := magiclink.NewManager(tokens,
		stubLoader{err: errStoreDown},
		&recordingSender{}, "https://app.example.com",
		magiclink.WithLogger(logger))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")
	binding := "the-binding-nonce"

	m.Request(t.Context(), "ada@example.com", "/")

	_, err = m.Redeem(t.Context(), presented, binding)
	require.ErrorIs(t, err, magiclink.ErrInvalidLink)

	logged := buf.String()
	require.NotEmpty(t, logged, "the causes are logged, or this proves nothing")

	assert.NotContains(t, logged, presented, "the token must not be logged")
	assert.NotContains(t, logged, binding, "the binding value must not be logged")
	assert.NotContains(t, logged, "ada@example.com", "the submitted address must not be logged")
}
