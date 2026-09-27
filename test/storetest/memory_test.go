package storetest_test

import (
	"testing"
	"time"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// The in-memory defaults each run the portable suite for their contract. The
// test names carry the backend, so a failure reads as the case and "Memory".

func TestMemorySessionStore(t *testing.T) {
	t.Parallel()

	storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
		t.Helper()
		return session.NewMemoryStore(session.WithMemoryStoreClock(now))
	})
}

// The in-memory one-time store carries a reaper, so its run requires one.
func TestMemoryOneTimeStore(t *testing.T) {
	t.Parallel()

	storetest.RunOneTimeStoreSuite(t, func(t *testing.T, now func() time.Time) onetime.Store {
		t.Helper()
		return onetime.NewMemoryStore(onetime.WithMemoryStoreClock(now))
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
