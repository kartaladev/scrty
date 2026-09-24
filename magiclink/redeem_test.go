package magiclink_test

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/onetime"
)

func TestRedeemOrdering(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		loader identity.UserLoader
		checks []magiclink.Check
		assert func(t *testing.T, r magiclink.Redemption, err error, consumes int)
	}

	notConsumed := func(wantErr error) func(*testing.T, magiclink.Redemption, error, int) {
		return func(t *testing.T, r magiclink.Redemption, err error, consumes int) {
			assert.ErrorIs(t, err, wantErr)
			assert.Empty(t, r.Principal.ID, "a refusal establishes nobody")
			assert.Zero(t, consumes, "a refusal before the last step must not spend the link")
		}
	}

	consumerErr := errors.New("terms not accepted")

	cases := []testCase{
		{
			name:   "the user is gone",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name: "the user is disabled",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1", Active: false},
			}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name:   "the loader is down",
			loader: stubLoader{err: errStoreDown},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name: "the loader answers with another user",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-9", Active: true},
			}},
			assert: notConsumed(magiclink.ErrInvalidLink),
		},
		{
			name:   "a consumer check refuses",
			loader: activeByID(),
			checks: []magiclink.Check{
				func(context.Context, identity.Principal, time.Time) error { return consumerErr },
			},
			assert: notConsumed(consumerErr),
		},
		{
			name:   "everything passes",
			loader: activeByID(),
			assert: func(t *testing.T, r magiclink.Redemption, err error, consumes int) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
				assert.Equal(t, 1, consumes, "success is the only thing that spends it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &countingTokenStore{Store: onetime.NewMemoryStore()}
			tokens := tokensWithStore(t, store)

			m, err := magiclink.NewManager(tokens, tc.loader, &recordingSender{}, "https://app.example.com",
				magiclink.WithSameDeviceBinding(false))
			require.NoError(t, err)

			presented := issueFor(t, tokens, "u-1")

			before := store.Consumes()
			r, redeemErr := m.Redeem(t.Context(), presented, "", tc.checks...)

			tc.assert(t, r, redeemErr, store.Consumes()-before)
		})
	}
}

func TestRedeemBindsToUserReference(t *testing.T) {
	t.Parallel()

	t.Run("a reissued username does not inherit a live link", func(t *testing.T) {
		t.Parallel()

		loader := &mutableLoader{
			byUsername: map[string]*identity.Details{
				"ada": {ID: "u-1", Username: "ada", Active: true},
			},
			byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1", Username: "ada", Active: true},
			},
		}

		sender := &recordingSender{}

		m, err := magiclink.NewManager(testTokens(t), loader, sender, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		// The link goes out through the real request path, so what it records
		// about the user is the production decision under test.
		m.Request(t.Context(), "ada", "/")
		require.Equal(t, 1, sender.Count())

		link, err := url.Parse(extractLink(t, sender.Last().TextBody))
		require.NoError(t, err)

		presented := link.Query().Get("token")
		require.NotEmpty(t, presented)

		// u-1 is deleted and the username is given to u-2.
		loader.reassign("u-1", &identity.Details{ID: "u-2", Username: "ada", Active: true})

		r, err := m.Redeem(t.Context(), presented, "")
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
		assert.Empty(t, r.Principal.ID, "no session may be established for u-2")
	})

	t.Run("a loader that answers with another user is refused", func(t *testing.T) {
		t.Parallel()

		loader := stubLoader{byID: map[identity.UserID]*identity.Details{
			"u-1": {ID: "u-9", Active: true}, // asked for u-1, answers u-9
		}}

		tokens := testTokens(t)

		m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		r, err := m.Redeem(t.Context(), issueFor(t, tokens, "u-1"), "")
		assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
		assert.Empty(t, r.Principal.ID)
	})
}

func TestRefusalDoesNotSpendLink(t *testing.T) {
	t.Parallel()

	t.Run("a refusal, then the cause is fixed, then the same link works", func(t *testing.T) {
		t.Parallel()

		mustEnrol := errors.New("enrolment required")

		var enrolled atomic.Bool

		check := func(context.Context, identity.Principal, time.Time) error {
			if !enrolled.Load() {
				return mustEnrol
			}

			return nil
		}

		tokens := testTokens(t)

		m, err := magiclink.NewManager(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		_, err = m.Redeem(t.Context(), presented, "", check)
		require.ErrorIs(t, err, mustEnrol)

		enrolled.Store(true)

		r, err := m.Redeem(t.Context(), presented, "", check)
		require.NoError(t, err, "the link survived the refusal")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})

	t.Run("a transient loader failure, then recovery", func(t *testing.T) {
		t.Parallel()

		loader := &flakyLoader{err: errStoreDown}

		tokens := testTokens(t)

		m, err := magiclink.NewManager(tokens, loader, &recordingSender{}, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		_, err = m.Redeem(t.Context(), presented, "")
		require.ErrorIs(t, err, magiclink.ErrInvalidLink)

		loader.Recover()

		_, err = m.Redeem(t.Context(), presented, "")
		assert.NoError(t, err)
	})
}

func TestRedeemRace(t *testing.T) {
	t.Parallel()

	tokens := testTokens(t)

	m, err := magiclink.NewManager(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	presented := issueFor(t, tokens, "u-1")
	ctx := t.Context()

	const goroutines = 16

	var (
		wg        sync.WaitGroup
		succeeded atomic.Int64
		checkRuns atomic.Int64
		start     = make(chan struct{})
	)

	// A check runs for every racing attempt, which is why a check is
	// documented as having to be free of side effects.
	check := func(context.Context, identity.Principal, time.Time) error {
		checkRuns.Add(1)

		return nil
	}

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			<-start

			if _, redeemErr := m.Redeem(ctx, presented, "", check); redeemErr == nil {
				succeeded.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "one link, one session")
	assert.Positive(t, checkRuns.Load())
}

func TestRedeemRequiresBinding(t *testing.T) {
	t.Parallel()

	// issueThroughRequest runs the real request path and hands back the token
	// from the emailed link together with the binding nonce the caller got.
	issueThroughRequest := func(t *testing.T, m *magiclink.Manager, sender *recordingSender) (string, string) {
		t.Helper()

		result := m.Request(t.Context(), "ada@example.com", "/")
		require.Equal(t, 1, sender.Count())

		u, err := url.Parse(extractLink(t, sender.Last().TextBody))
		require.NoError(t, err)

		return u.Query().Get("token"), result.BindingNonce
	}

	t.Run("by default the binding is required", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		m, err := magiclink.NewManager(testTokens(t), activeByID(), sender, "https://app.example.com")
		require.NoError(t, err)

		token, nonce := issueThroughRequest(t, m, sender)
		require.Len(t, nonce, magiclink.BindingNonceLength)

		_, err = m.Redeem(t.Context(), token, "another-device")
		require.ErrorIs(t, err, magiclink.ErrInvalidLink, "another device holds no binding")

		r, err := m.Redeem(t.Context(), token, nonce)
		require.NoError(t, err, "the refusal did not spend the link")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})

	t.Run("a consumer may disable it", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		m, err := magiclink.NewManager(testTokens(t), activeByID(), sender, "https://app.example.com",
			magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		token, nonce := issueThroughRequest(t, m, sender)
		assert.Empty(t, nonce)

		r, err := m.Redeem(t.Context(), token, "whatever-another-device-sent")
		require.NoError(t, err, "a presented binding is ignored when binding is off")
		assert.Equal(t, identity.UserID("u-1"), r.Principal.ID)
	})
}
