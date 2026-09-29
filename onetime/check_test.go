package onetime_test

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
)

var (
	// checkTokenID and checkSecret stand for one issued token, spelled out so
	// that each row can vary exactly one thing about the record behind it.
	checkTokenID = id.MustParse("01999f00-0000-7000-8000-00000000abcd")
	checkSecret  = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xA5}, 32))
	checkBinding = "device-nonce-a"
)

// liveRecord is the record Issue would have written for checkTokenID: unspent,
// issued at issuedAt and valid for the default quarter of an hour.
func liveRecord(t *testing.T) onetime.Token {
	t.Helper()

	return onetime.Token{
		ID:         checkTokenID,
		Purpose:    "magic-link",
		Subject:    "ada@example.com",
		SecretHash: sha256Of(checkSecret),
		IssuedAt:   issuedAt,
		ExpiresAt:  issuedAt.Add(15 * time.Minute),
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		record    func(t *testing.T) onetime.Token
		storeErr  error
		presented string
		binding   string
		at        time.Time // when the check runs; zero means a minute after issue
		opts      []onetime.Option
		assert    func(t *testing.T, c onetime.Checked, err error, logs string)
	}

	refused := func(t *testing.T, c onetime.Checked, err error, _ string) {
		t.Helper()

		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.Zero(t, c, "a refused check still handed back a proof of checking")
	}

	cases := []testCase{
		{
			name:      "a live token checks and yields its record",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			assert: func(t *testing.T, c onetime.Checked, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, checkTokenID, c.Token().ID)
				assert.Equal(t, "ada@example.com", c.Token().Subject)
			},
		},
		{
			name:      "a token one moment before expiry still checks",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(15*time.Minute - time.Nanosecond),
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			// Expiry is an instant the token does not survive, not one it is
			// still good for. Anything else makes the boundary a matter of the
			// store's clock resolution.
			name:      "a token exactly at its expiry is refused",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(15 * time.Minute),
			assert:    refused,
		},
		{
			name:      "a token past its expiry is refused",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(16 * time.Minute),
			assert:    refused,
		},
		{
			name: "a consumer time-to-live keeps a token alive that the default would have expired",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.ExpiresAt = issuedAt.Add(24 * time.Hour)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			at:        issuedAt.Add(16 * time.Minute),
			opts:      []onetime.Option{onetime.WithTTL(24 * time.Hour)},
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "a token issued for another purpose is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.Purpose = "email-code"

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			assert:    refused,
		},
		{
			name: "a token already consumed is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.ConsumedAt = issuedAt.Add(30 * time.Second)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			assert:    refused,
		},
		{
			name:      "a wrong secret is refused",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, 32)),
			assert:    refused,
		},
		{
			name: "a wrong binding is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.BindingHash = sha256Of(checkBinding)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   "device-nonce-b",
			assert:    refused,
		},
		{
			name: "a bound token checks with its own binding",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.BindingHash = sha256Of(checkBinding)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   checkBinding,
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "a bound token presented with no binding is refused",
			record: func(t *testing.T) onetime.Token {
				t.Helper()

				rec := liveRecord(t)
				rec.BindingHash = sha256Of(checkBinding)

				return rec
			},
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   "",
			assert:    refused,
		},
		{
			// A token issued without a binding has nothing to compare against,
			// so a presented one is simply not part of the decision. Refusing
			// it would make an unbound token behave as though it were bound to
			// the empty string.
			name:      "an unbound token ignores a presented binding",
			record:    liveRecord,
			presented: checkTokenID.String() + "." + checkSecret,
			binding:   "device-nonce-b",
			assert: func(t *testing.T, _ onetime.Checked, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name:      "a record that does not exist is refused exactly like a wrong secret",
			storeErr:  onetime.ErrTokenNotFound,
			presented: checkTokenID.String() + "." + checkSecret,
			assert:    refused,
		},
		{
			name:      "a store that cannot answer is refused the same way and logged at error level",
			storeErr:  errStoreDown,
			presented: checkTokenID.String() + "." + checkSecret,
			assert: func(t *testing.T, c onetime.Checked, err error, logs string) {
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.NotErrorIs(t, err, errStoreDown,
					"the store's own failure reached the caller, who can now tell an outage from a bad token")
				assert.Zero(t, c)
				assert.Contains(t, logs, "level=ERROR", "a store outage passed unreported")
				assert.NotContains(t, logs, checkSecret, "the log carried the presented secret")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			ctrl := gomock.NewController(t)

			store := NewMockStore(ctrl)
			// No EXPECT for Insert or Consume: any write during a check is the
			// failure this table pins on every row.
			switch {
			case tc.storeErr != nil:
				store.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, tc.storeErr)
			case tc.record != nil:
				rec := tc.record(t)
				store.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&rec, nil)
			}

			at := tc.at
			if at.IsZero() {
				at = issuedAt.Add(time.Minute)
			}
			clk := clockwork.NewFakeClockAt(at)

			opts := append([]onetime.Option{
				onetime.WithStore(store),
				onetime.WithClock(clk),
				onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
			}, tc.opts...)

			m, err := onetime.NewManager("magic-link", opts...)
			require.NoError(t, err)

			c, err := m.Check(t.Context(), tc.presented, tc.binding)
			tc.assert(t, c, err, logs.String())
		})
	}
}

func TestCheckRefusesMalformedTokensWithoutReadingTheStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		presented string
	}

	cases := []testCase{
		{name: "an empty string", presented: ""},
		{name: "no separator", presented: checkTokenID.String() + checkSecret},
		{name: "an empty identifier", presented: "." + checkSecret},
		{name: "an empty secret", presented: checkTokenID.String() + "."},
		{name: "an identifier that is not an identifier", presented: "not-an-id." + checkSecret},
		{name: "a separator and nothing else", presented: "."},
		{name: "an oversized identifier half", presented: strings.Repeat("a", 4096) + "." + checkSecret},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			// No EXPECT at all: a malformed token must be refused on its own
			// shape, before it can buy a caller a single store lookup.
			store := NewMockStore(ctrl)

			clk := clockwork.NewFakeClockAt(issuedAt)
			m, err := onetime.NewManager("magic-link",
				onetime.WithStore(store), onetime.WithClock(clk))
			require.NoError(t, err)

			c, err := m.Check(t.Context(), tc.presented, "")
			require.ErrorIs(t, err, onetime.ErrInvalidToken)
			assert.Zero(t, c)
		})
	}
}

func TestCheckingRepeatedlyWritesNothingAndKeepsSucceeding(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	rec := liveRecord(t)

	store := NewMockStore(ctrl)
	// Three reads, no writes. A check that wrote could not be run once per
	// racing caller, which is the whole reason it is separate from Consume.
	store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil).Times(3)

	clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))
	m, err := onetime.NewManager("magic-link",
		onetime.WithStore(store), onetime.WithClock(clk))
	require.NoError(t, err)

	for range 3 {
		c, err := m.Check(t.Context(), checkTokenID.String()+"."+checkSecret, "")
		require.NoError(t, err)
		assert.Equal(t, checkTokenID, c.Token().ID)
	}
}
