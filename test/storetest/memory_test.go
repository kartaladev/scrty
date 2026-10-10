package storetest_test

import (
	"testing"

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
