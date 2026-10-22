package storetest_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// The in-memory defaults each run the portable suite for their contract. The
// test names carry the backend, so a failure reads as the case and "Memory".

func TestMemorySessionStore(t *testing.T) {
	t.Parallel()

	storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
		t.Helper()
		return session.NewMemoryStore(session.WithMemoryStoreClock(clk.(clock.Timed)))
	})
}

// xorCipher seals reversibly and binds the additional data, which is all the
// encrypting store's contract rests on: Open refuses a value sealed for other
// additional data, so a wrapper that sealed a field for one session and read it
// back for another would fail the suite. It hides nothing from a reader; this
// module's real ciphers are exercised by the durable stores' own tests.
type xorCipher struct{}

var errAdditionalData = errors.New("xor cipher: additional data does not match")

func (xorCipher) Seal(plaintext, additionalData []byte) ([]byte, error) {
	out := append(bytes.Clone(additionalData), 0x00)
	for _, b := range plaintext {
		out = append(out, b^0x5a)
	}

	return out, nil
}

func (xorCipher) Open(ciphertext, additionalData []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(ciphertext, append(bytes.Clone(additionalData), 0x00))
	if !ok {
		return nil, errAdditionalData
	}

	plaintext := make([]byte, 0, len(rest))
	for _, b := range rest {
		plaintext = append(plaintext, b^0x5a)
	}

	return plaintext, nil
}

// The encrypting wrapper is a Store like any other, so it runs the same suite
// over the in-memory store: every case that passes bare must pass sealed.
func TestEncryptedSessionStore(t *testing.T) {
	t.Parallel()

	storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
		t.Helper()

		s, err := session.NewEncryptedStore(
			session.NewMemoryStore(session.WithMemoryStoreClock(clk.(clock.Timed))), xorCipher{})
		require.NoError(t, err)

		return s
	})
}

// The in-memory one-time store carries a reaper, so its run requires one.
func TestMemoryOneTimeStore(t *testing.T) {
	t.Parallel()

	storetest.RunOneTimeStoreSuite(t, func(t *testing.T, clk clock.Clock) onetime.Store {
		t.Helper()
		return onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
	}, storetest.RequireReaper())
}

// The in-memory attempt store has no reaper, so it runs without
// RequireReaper and the suite's purge cases log that they did not run; the
// conforming store in broken_attempts_test.go runs them.
func TestMemoryAttemptStore(t *testing.T) {
	t.Parallel()

	storetest.RunAttemptStoreSuite(t, func(t *testing.T) policy.AttemptStore {
		t.Helper()
		return policy.NewMemoryAttemptStore()
	})
}

// The in-memory attempt store also keeps consecutive-failure streaks.
func TestMemoryFailureStreak(t *testing.T) {
	t.Parallel()

	newStore := func(*testing.T) storetest.StreakStore { return policy.NewMemoryAttemptStore() }
	storetest.RunFailureStreakSuite(t, newStore)
	storetest.RunFailureStreakRace(t, newStore)
}

func TestMemorySigningKeyStore(t *testing.T) {
	t.Parallel()

	storetest.RunSigningKeyStoreSuite(t, func(t *testing.T) signingkey.KeyStore {
		t.Helper()
		return signingkey.NewInMemoryKeyStore()
	})
}

func TestMemoryEnrolmentStore(t *testing.T) {
	t.Parallel()

	storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
		t.Helper()
		return mfa.NewMemoryEnrolmentStore()
	})
	storetest.RunDeviceProofSuite(t, func(t *testing.T) storetest.DeviceProofEnrolmentStore {
		t.Helper()
		return mfa.NewMemoryEnrolmentStore()
	})
}

func TestMemoryAPIKeyStore(t *testing.T) {
	t.Parallel()

	storetest.RunAPIKeyStoreSuite(t, func(t *testing.T) apikey.Store {
		t.Helper()
		return apikey.NewMemoryStore()
	})
}

func TestMemoryRecoveryCodeStore(t *testing.T) {
	t.Parallel()

	storetest.RunRecoveryCodeStoreSuite(t, func(t *testing.T, _ clock.Clock) recovery.CodeStore {
		t.Helper()
		return recovery.NewMemoryCodeStore()
	})
}

func TestMemoryRecoveryRecordStore(t *testing.T) {
	t.Parallel()

	storetest.RunRecoveryRecordStoreSuite(t, func(t *testing.T, _ clock.Clock) recovery.RecordStore {
		t.Helper()
		return recovery.NewMemoryRecordStore()
	})
}

func TestMemoryPasskeyCredentialStore(t *testing.T) {
	t.Parallel()

	storetest.RunPasskeyCredentialStoreSuite(t, func(t *testing.T) passkey.CredentialStore {
		t.Helper()
		return passkey.NewMemoryCredentialStore()
	})
}

func TestMemoryPasskeyHandleStore(t *testing.T) {
	t.Parallel()

	storetest.RunPasskeyHandleStoreSuite(t, func(t *testing.T) passkey.HandleStore {
		t.Helper()
		return passkey.NewMemoryHandleStore()
	})
}
