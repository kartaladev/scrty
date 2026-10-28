package mfa_test

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// failAfterReader serves n bytes from the secure source, then fails. Beginning
// an enrolment reads the 20-byte secret, so n = 20 lets a begin succeed and
// makes drawing the emailed code the read that fails.
type failAfterReader struct {
	mu sync.Mutex
	n  int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.n <= 0 {
		return 0, errors.New("entropy pool exhausted")
	}

	p = p[:min(len(p), r.n)]
	r.n -= len(p)

	return rand.Read(p)
}

// lockedWriter serialises writes from concurrent records.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.w.Write(p)
}

// errMFAFixture is a dependency failure whose text quotes a value the library
// never saw (an address) and one it did (the user reference). Neither may
// reach the text of an error an mfa method returns.
var errMFAFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// base32Secret renders a raw secret the way an authenticator is given it.
func base32Secret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// fixtureGen is the enrolment generation the fixtures that write straight to
// a store begin on, and then confirm and accept steps on.
var fixtureGen = id.MustParse("01920000-0000-7000-8000-0000000000f0")

// enrolConfirmed writes a confirmed enrolment straight to the store, on
// fixtureGen, with a last step of zero so that no verification under test is
// refused as a replay of a step this fixture recorded.
func enrolConfirmed(t *testing.T, s mfa.EnrolmentStore, user identity.UserID, secret []byte) {
	t.Helper()

	require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: user, Secret: secret, Generation: fixtureGen}))

	ok, err := s.Confirm(t.Context(), user, fixtureGen, 0, time.Now())
	require.NoError(t, err)
	require.True(t, ok)
}

// codeAt computes the code a well-behaved authenticator would show at at.
//
// It goes through pquerna/otp directly rather than through anything in mfa, so
// a bug shared by the implementation and the expectation cannot hide here.
func codeAt(t *testing.T, secret []byte, at time.Time, digits int, period time.Duration) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(base32Secret(secret), at, totp.ValidateOpts{
		Period:    uint(period.Seconds()),
		Digits:    otp.Digits(digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	return code
}

// codeForSecret is codeAt for a secret already in the base32 form an enrolment
// hands back.
func codeForSecret(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	return codeAt(t, raw, at, 6, 30*time.Second)
}

// stubRequirement is the consumer's record of who must use a second factor. It
// is deliberately independent of any enrolment store, which is the property
// TestTOTPRemoveEnrolment exists to pin.
type stubRequirement struct{ required map[identity.UserID]bool }

func (s *stubRequirement) Required(_ context.Context, user identity.UserID) (bool, error) {
	return s.required[user], nil
}

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil an
// unchecked constructor error hands over.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// failingEnrolmentStore is a store that is there but cannot answer: a
// connection refused, or a secret that will not open.
type failingEnrolmentStore struct{ err error }

func (s failingEnrolmentStore) Get(
	context.Context, identity.UserID,
) (mfa.Enrolment, bool, error) {
	return mfa.Enrolment{}, false, s.err
}

func (s failingEnrolmentStore) PutPending(context.Context, mfa.Enrolment) error { return s.err }

func (s failingEnrolmentStore) Confirm(
	context.Context, identity.UserID, id.ID, int64, time.Time,
) (bool, error) {
	return false, s.err
}

func (s failingEnrolmentStore) AcceptStep(
	context.Context, identity.UserID, id.ID, int64,
) (bool, error) {
	return false, s.err
}

func (s failingEnrolmentStore) Delete(context.Context, identity.UserID) error { return s.err }

func (s failingEnrolmentStore) ChargeVerifyAttempt(
	context.Context, identity.UserID, time.Time, int, time.Duration,
) (time.Time, bool, error) {
	return time.Time{}, false, s.err
}

func (s failingEnrolmentStore) RefundVerifyAttempt(
	context.Context, identity.UserID, time.Time,
) (bool, error) {
	return false, s.err
}
