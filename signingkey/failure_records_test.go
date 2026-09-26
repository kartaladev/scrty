package signingkey_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// TestSigningKeyStoreFailureRecords pins that a failure during rotation or
// reload is recorded through a fixed reason and the failing dependency's own
// error type — never the library's wrapping of it, and never its text — while
// the public algorithm identifier and key id stay.
func TestSigningKeyStoreFailureRecords(t *testing.T) {
	// undecodable is a genuine record whose private half has been cut short,
	// so the store returns it and the library cannot parse it.
	undecodable := realRecordFor(t, signingkey.EdDSA, epoch)
	undecodable.Kid = "kid-undecodable"
	undecodable.Private = slices.Clone(undecodable.Private[:len(undecodable.Private)-8])
	_, parseErr := x509.ParsePKCS8PrivateKey(undecodable.Private)
	require.Error(t, parseErr)

	type testCase struct {
		name string
		// store configures the mock; construction's own LoadAll and Store
		// calls come first.
		store  func(s *MockKeyStore)
		assert func(t *testing.T, rec map[string]any)
	}

	// afterConstruction answers construction's first call with first, and
	// every later call with later.
	afterConstruction := func(first, later func() ([]signingkey.Record, error)) func(context.Context) ([]signingkey.Record, error) {
		var calls atomic.Int32
		return func(context.Context) ([]signingkey.Record, error) {
			if calls.Add(1) == 1 {
				return first()
			}
			return later()
		}
	}
	empty := func() ([]signingkey.Record, error) { return nil, nil }

	cases := []testCase{
		{
			name: "a store write failure during rotation",
			store: func(s *MockKeyStore) {
				var writes atomic.Int32
				s.EXPECT().LoadAll(gomock.Any()).Return(nil, nil).AnyTimes()
				s.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
					func(context.Context, signingkey.Record) error {
						if writes.Add(1) > 1 {
							return errRedactionFixture
						}
						return nil
					}).AnyTimes()
			},
			assert: func(t *testing.T, rec map[string]any) {
				assert.Equal(t, signingkey.EdDSA, rec["alg"], "the public algorithm identifier stays")
				assert.Equal(t, "signing-key-store", rec["reason"])
				assert.Equal(t, "*errors.errorString", rec["error_type"], "the store's own error type, not the library's wrapping")
			},
		},
		{
			name: "a store read failure during reload",
			store: func(s *MockKeyStore) {
				s.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				s.EXPECT().LoadAll(gomock.Any()).DoAndReturn(afterConstruction(empty,
					func() ([]signingkey.Record, error) { return nil, errRedactionFixture })).AnyTimes()
			},
			assert: func(t *testing.T, rec map[string]any) {
				assert.NotContains(t, rec, "alg", "a whole-store reload belongs to no algorithm")
				assert.Equal(t, "signing-key-store", rec["reason"])
				assert.Equal(t, "*errors.errorString", rec["error_type"], "the store's own error type, not the library's wrapping")
			},
		},
		{
			name: "a stored key that cannot be decoded during reload",
			store: func(s *MockKeyStore) {
				s.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				s.EXPECT().LoadAll(gomock.Any()).DoAndReturn(afterConstruction(empty,
					func() ([]signingkey.Record, error) { return []signingkey.Record{undecodable}, nil })).AnyTimes()
			},
			assert: func(t *testing.T, rec map[string]any) {
				assert.Equal(t, "key-decode", rec["reason"], "a decode failure is not a store failure")
				assert.Equal(t, signingkey.EdDSA, rec["alg"])
				assert.Equal(t, "kid-undecodable", rec["kid"], "the record names the public key id it could not decode")
				assert.Equal(t, fmt.Sprintf("%T", parseErr), rec["error_type"], "the decode error's own type, not the library's wrapping")
				for key, v := range rec {
					if text, ok := v.(string); ok {
						assert.NotContains(t, text, string(undecodable.Private), "key %q carries key material", key)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(epoch)
			report := &failureReport{}
			recorder, logger := newLogRecorder()

			store := NewMockKeyStore(gomock.NewController(t))
			tc.store(store)

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clock),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithLogger(logger),
				signingkey.WithErrorHook(report.hook),
				signingkey.WithReloadInterval(100*time.Millisecond),
				signingkey.WithRotateInterval(time.Second),
				signingkey.WithHousekeepingInterval(12*time.Hour),
				signingkey.WithLifetime(24*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			require.NoError(t, km.Start(t.Context()))

			clock.Advance(time.Second)
			require.Eventually(t, func() bool { return report.hooks() >= 1 },
				10*time.Second, 5*time.Millisecond, "the failure reaches the consumer's error hook")
			require.Eventually(t, func() bool { return recorder.written() >= 1 },
				10*time.Second, 5*time.Millisecond, "the failure reaches the logger")

			records := recorder.records(t)
			require.NotEmpty(t, records, "the failure reaches the logger")
			tc.assert(t, records[0])

			for _, rec := range records {
				assert.NotContains(t, rec, "error", "no record carries the dependency's error text")
				for key, v := range rec {
					if text, ok := v.(string); ok {
						assert.NotContains(t, text, "alice@example.com", "key %q", key)
						assert.NotContains(t, text, "u-123", "key %q", key)
					}
				}
			}

			hooked, _ := report.snapshot()
			require.NotEmpty(t, hooked, "the failure reaches the consumer's error hook")
			for _, err := range hooked {
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the hook receives fixed text, not the dependency's own error")
				assert.NotContains(t, err.Error(), "u-123",
					"the hook receives fixed text, not the dependency's own error")
			}
		})
	}
}
