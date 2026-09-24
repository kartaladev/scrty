package magiclink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
)

// sendCounter is what every sender in these tests offers: how many messages it
// was handed, whether or not it managed to deliver them.
type sendCounter interface {
	notify.Sender
	Count() int
}

func TestRequestIsUniform(t *testing.T) {
	t.Parallel()

	known := &identity.Details{ID: "u-1", Username: "ada@example.com", Active: true}

	type testCase struct {
		name   string
		loader identity.UserLoader
		tokens func(t *testing.T) *onetime.Manager
		sender func() sendCounter
		opts   []magiclink.Option
		// prepare runs before the request under test, so a branch that needs
		// history can build it.
		prepare func(t *testing.T, m *magiclink.Manager)
		assert  func(t *testing.T, got magiclink.RequestResult, sent int)
	}

	// sameShape is the assertion the whole capability rests on: whatever
	// happened, the caller is handed a nonce of one fixed length and can tell
	// nothing from it.
	sameShape := func(wantSent int) func(*testing.T, magiclink.RequestResult, int) {
		return func(t *testing.T, got magiclink.RequestResult, sent int) {
			assert.Len(t, got.BindingNonce, magiclink.BindingNonceLength,
				"every branch returns a binding nonce of the same length")
			assert.Equal(t, wantSent, sent)
		}
	}

	cases := []testCase{
		{
			name:   "an active user, and a link is sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			assert: sameShape(1),
		},
		{
			name:   "an unknown address",
			loader: stubLoader{byUsername: map[string]*identity.Details{}},
			assert: sameShape(0),
		},
		{
			name: "a disabled user",
			loader: stubLoader{byUsername: map[string]*identity.Details{
				"ada@example.com": {ID: "u-1", Username: "ada@example.com", Active: false},
			}},
			assert: sameShape(0),
		},
		{
			name:   "the loader is down",
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
			assert: sameShape(0),
		},
		{
			name:   "the issuance limit is reached",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			prepare: func(t *testing.T, m *magiclink.Manager) {
				t.Helper()

				for range 5 {
					m.Request(t.Context(), "ada@example.com", "/")
				}
			},
			assert: sameShape(0),
		},
		{
			name:   "the token store fails",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			tokens: tokensWithFailingStore,
			assert: sameShape(0),
		},
		{
			name:   "the message cannot be sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			sender: func() sendCounter { return &failingSender{err: errors.New("smtp: 451 temporary failure")} },
			// The attempt is made and its failure is swallowed, so the caller
			// cannot tell a delivered link from an undelivered one either.
			assert: sameShape(1),
		},
		{
			name:   "the random source fails",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			opts:   []magiclink.Option{magiclink.WithRandom(failingReader{})},
			assert: func(t *testing.T, got magiclink.RequestResult, sent int) {
				// The one documented exception: with no randomness there is no
				// nonce to return and no link to issue. What a caller can tell
				// from it is that the random source is broken, which is the
				// same for every address.
				assert.Empty(t, got.BindingNonce)
				assert.Zero(t, sent)
			},
		},
		{
			name:   "binding disabled, and a link is sent",
			loader: stubLoader{byUsername: map[string]*identity.Details{"ada@example.com": known}},
			opts:   []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, got magiclink.RequestResult, sent int) {
				assert.Empty(t, got.BindingNonce, "a disabled binding returns no nonce, ever")
				assert.Equal(t, 1, sent)
			},
		},
		{
			name:   "binding disabled, and the address is unknown",
			loader: stubLoader{byUsername: map[string]*identity.Details{}},
			opts:   []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, got magiclink.RequestResult, sent int) {
				assert.Empty(t, got.BindingNonce)
				assert.Zero(t, sent)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var sender sendCounter = &recordingSender{}
			if tc.sender != nil {
				sender = tc.sender()
			}

			tokens := testTokens(t)
			if tc.tokens != nil {
				tokens = tc.tokens(t)
			}

			m, err := magiclink.NewManager(tokens, tc.loader, sender, "https://app.example.com", tc.opts...)
			require.NoError(t, err)

			if tc.prepare != nil {
				tc.prepare(t, m)
			}

			before := sender.Count()
			got := m.Request(t.Context(), "ada@example.com", "/dashboard")

			tc.assert(t, got, sender.Count()-before)
		})
	}
}

func TestRequestResolvesAddress(t *testing.T) {
	t.Parallel()

	t.Run("by default the address reaches the loader unchanged", func(t *testing.T) {
		t.Parallel()

		loader := &recordingLoader{}

		m, err := magiclink.NewManager(testTokens(t), loader, &recordingSender{}, "https://app.example.com")
		require.NoError(t, err)

		m.Request(t.Context(), " Ada@Example.com", "/")

		assert.Equal(t, []string{" Ada@Example.com"}, loader.Usernames(),
			"never trimmed, never case-folded")
	})

	t.Run("a consumer resolver is the only path", func(t *testing.T) {
		t.Parallel()

		loader := &recordingLoader{}
		sender := &recordingSender{}

		resolver := func(_ context.Context, address string) (*identity.Details, error) {
			if address == "ada@example.com" {
				return &identity.Details{ID: "u-7", Active: true}, nil
			}

			return nil, identity.ErrUserNotFound
		}

		m, err := magiclink.NewManager(testTokens(t), loader, sender, "https://app.example.com",
			magiclink.WithAddressResolver(resolver))
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/")

		assert.Empty(t, loader.Usernames(), "LoadByUsername is not called")
		assert.Equal(t, 1, sender.Count())
	})
}

func TestRequestIssuanceLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		opts  []magiclink.Option
		limit int
	}

	cases := []testCase{
		{name: "the default of five", limit: 5},
		{name: "a consumer limit of two", opts: []magiclink.Option{magiclink.WithIssuanceLimit(2)}, limit: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sender := &recordingSender{}

			m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender,
				"https://app.example.com", tc.opts...)
			require.NoError(t, err)

			for range tc.limit + 1 {
				m.Request(t.Context(), "ada@example.com", "/")
			}

			assert.Equal(t, tc.limit, sender.Count(),
				"the attempt past the limit issues nothing and sends nothing")
		})
	}
}
