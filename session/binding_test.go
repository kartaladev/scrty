package session_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

var (
	bindingK  = session.KeyBinding{JKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
	bindingK2 = session.KeyBinding{JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}
	bindingX  = session.KeyBinding{X5TS256: "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}
	bindingKX = session.KeyBinding{JKT: bindingK.JKT, X5TS256: bindingX.X5TS256}
)

// rotationOutcome is what a case's run hands its assertion: the session the
// call returned, the successor the issuing step was handed (nil when no step
// ran) and the call's error.
type rotationOutcome struct {
	got  *session.Session
	seen *session.Session
	old  *session.Session
	err  error
}

// stepRecorder returns an issuing step that records the successor it is
// handed into seen.
func stepRecorder(seen **session.Session) func(*session.Session) (string, error) {
	return func(successor *session.Session) (string, error) {
		copied := *successor
		*seen = &copied

		return "credential", nil
	}
}

// assertNothingRotated fails unless old is stored, unsuperseded, and is the
// only record in store.
func assertNothingRotated(t *testing.T, store *session.MemoryStore, old *session.Session) {
	t.Helper()

	assert.Equal(t, 1, store.Len(), "a successor was stored")
	stored, err := store.Load(t.Context(), old.ID)
	require.NoError(t, err)
	assert.True(t, stored.SupersededAt.IsZero(), "the old session was superseded")
}

func TestSessions_KeyBinding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome
		assert func(t *testing.T, store *session.MemoryStore, o rotationOutcome)
	}

	bound := func(t *testing.T, m *session.Sessions, b session.KeyBinding) *session.Session {
		t.Helper()
		s, err := m.Create(t.Context(), testUser, session.WithKeyBinding(b))
		require.NoError(t, err)

		return s
	}

	cases := []testCase{
		{
			name: "a session built with a binding is stored bound",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser, session.WithKeyBinding(bindingK))

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingK, o.got.KeyBinding)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, bindingK, stored.KeyBinding)
			},
		},
		{
			name: "a session built without a binding is unbound",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser)

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.True(t, o.got.KeyBinding.IsZero())
			},
		},
		{
			name: "a binding with both members is refused and nothing is stored",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser, session.WithKeyBinding(bindingKX))

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assert.Nil(t, o.got)
				assert.Zero(t, store.Len())
			},
		},
		{
			name: "renewal keeps the binding, and the issuing step sees it",
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingK)
				clk.Advance(time.Minute)
				var seen *session.Session
				next, _, _, err := m.RotateWithGraceIssuing(t.Context(), s, 10*time.Second, stepRecorder(&seen))

				return rotationOutcome{got: next, seen: seen, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingK, o.got.KeyBinding)
				require.NotNil(t, o.seen)
				assert.Equal(t, bindingK, o.seen.KeyBinding)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, bindingK, stored.KeyBinding)
			},
		},
		{
			name: "a certificate binding is carried the same way",
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingX)
				clk.Advance(time.Minute)
				next, _, err := m.RotateWithGrace(t.Context(), s, 0)

				return rotationOutcome{got: next, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingX, o.got.KeyBinding)
			},
		},
		{
			// The successor's binding is the stored record's, never the
			// caller's copy's.
			name: "rotation of a copy with the binding cleared keeps it, and the issuing step sees it",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingK)
				copied := *s
				copied.KeyBinding = session.KeyBinding{}
				var seen *session.Session
				next, _, err := m.RotateIssuing(t.Context(), &copied, stepRecorder(&seen))

				return rotationOutcome{got: next, seen: seen, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingK, o.got.KeyBinding)
				require.NotNil(t, o.seen)
				assert.Equal(t, bindingK, o.seen.KeyBinding)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, bindingK, stored.KeyBinding)
			},
		},
		{
			name: "rotation of a copy rebound to another key keeps the stored binding",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingK)
				copied := *s
				copied.KeyBinding = bindingK2
				next, err := m.Rotate(t.Context(), &copied)

				return rotationOutcome{got: next, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingK, o.got.KeyBinding)
			},
		},
		{
			name: "saving a copy with the binding cleared leaves the stored session bound",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingK)
				copied := *s
				copied.KeyBinding = session.KeyBinding{}

				return rotationOutcome{got: s, err: m.Save(t.Context(), &copied)}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, bindingK, stored.KeyBinding)
			},
		},
		{
			name: "a binding changed between building and storing is refused and nothing is stored",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				p, err := m.Prepare(testUser, session.WithKeyBinding(bindingK))
				require.NoError(t, err)
				p.Session().KeyBinding = bindingK2
				s, err := p.Commit(t.Context())

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assert.Nil(t, o.got)
				assert.Zero(t, store.Len())
			},
		},
		{
			name: "a binding added between building and storing is refused",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				p, err := m.Prepare(testUser)
				require.NoError(t, err)
				p.Session().KeyBinding = bindingK
				s, err := p.Commit(t.Context())

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assert.Zero(t, store.Len())
			},
		},
		{
			name: "re-authentication cannot rebind a bound session",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingK)
				var seen *session.Session
				next, _, err := m.RotateIssuing(t.Context(), s, stepRecorder(&seen),
					session.WithReauthenticationBinding(bindingK2))

				return rotationOutcome{got: next, seen: seen, old: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assert.Nil(t, o.got)
				assert.Nil(t, o.seen, "the issuing step ran")
				assertNothingRotated(t, store, o.old)
			},
		},
		{
			name: "re-authentication with the session's own key keeps it bound",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := bound(t, m, bindingK)
				next, err := m.Rotate(t.Context(), s, session.WithReauthenticationBinding(bindingK))

				return rotationOutcome{got: next, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingK, o.got.KeyBinding)
			},
		},
		{
			name: "re-authentication binds an unbound session, and the issuing step sees it",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				var seen *session.Session
				next, _, err := m.RotateIssuing(t.Context(), s, stepRecorder(&seen),
					session.WithReauthenticationBinding(bindingK2))

				return rotationOutcome{got: next, seen: seen, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, bindingK2, o.got.KeyBinding)
				require.NotNil(t, o.seen)
				assert.Equal(t, bindingK2, o.seen.KeyBinding)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, bindingK2, stored.KeyBinding)
			},
		},
		{
			name: "re-authentication with a binding of both members is refused",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				next, err := m.Rotate(t.Context(), s, session.WithReauthenticationBinding(bindingKX))

				return rotationOutcome{got: next, old: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assertNothingRotated(t, store, o.old)
			},
		},
		{
			// Renewal never binds: a thief holding an unbound session must
			// not renew it under their own key.
			name: "a renewal asking to bind is refused",
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				clk.Advance(time.Minute)
				next, _, err := m.RotateWithGrace(t.Context(), s, 10*time.Second,
					session.WithReauthenticationBinding(bindingK))

				return rotationOutcome{got: next, old: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assert.Nil(t, o.got)
				assertNothingRotated(t, store, o.old)
			},
		},
		{
			// A strict rotation never extends a session, so a new lifetime is
			// a wiring mistake rather than an option it ignores.
			name: "a strict rotation asking for a new lifetime is refused",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser)
				require.NoError(t, err)
				next, err := m.Rotate(t.Context(), s, session.WithSuccessorLifetime(time.Hour))

				return rotationOutcome{got: next, old: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assertNothingRotated(t, store, o.old)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, store := managerOnClock(t, clk)

			tc.assert(t, store, tc.run(t, m, clk))
		})
	}
}

// entropyThen hands out its first n bytes from crypto-quality-looking data and
// then fails, so the identifier is minted and the CSRF token's read fails.
type entropyThen struct {
	left int
	err  error
}

func (r *entropyThen) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, r.err
	}
	n := min(len(p), r.left)
	copy(p, bytes.Repeat([]byte{0x5a}, n))
	r.left -= n

	return n, nil
}

var _ io.Reader = (*entropyThen)(nil)

func TestSessions_CSRFToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		run    func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome
		assert func(t *testing.T, store *session.MemoryStore, o rotationOutcome)
	}

	withToken := func(t *testing.T, m *session.Sessions) *session.Session {
		t.Helper()
		s, err := m.Create(t.Context(), testUser, session.WithCSRFToken())
		require.NoError(t, err)
		require.NotEmpty(t, s.CSRFToken)

		return s
	}

	cases := []testCase{
		{
			name: "no token unless asked",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser)

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Empty(t, o.got.CSRFToken)
			},
		},
		{
			name: "asked for, the token is 32 random bytes, base64url without padding, and is stored",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser, session.WithCSRFToken())

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				raw, err := base64.RawURLEncoding.Strict().DecodeString(o.got.CSRFToken)
				require.NoError(t, err)
				assert.Len(t, raw, 32)
				assert.NotEqual(t, o.got.ID, o.got.CSRFToken, "the token is not the session identifier")
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, o.got.CSRFToken, stored.CSRFToken)
			},
		},
		{
			name: "a new sign-in gets a new token",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				first := withToken(t, m)
				second := withToken(t, m)

				return rotationOutcome{got: second, old: first}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				assert.NotEqual(t, o.old.CSRFToken, o.got.CSRFToken)
			},
		},
		{
			name: "renewal within a grace window keeps the token, and the issuing step sees it",
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s := withToken(t, m)
				clk.Advance(time.Minute)
				var seen *session.Session
				next, _, _, err := m.RotateWithGraceIssuing(t.Context(), s, 10*time.Second, stepRecorder(&seen))

				return rotationOutcome{got: next, seen: seen, old: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, o.old.CSRFToken, o.got.CSRFToken)
				require.NotNil(t, o.seen)
				assert.Equal(t, o.old.CSRFToken, o.seen.CSRFToken)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, o.old.CSRFToken, stored.CSRFToken)
			},
		},
		{
			name: "re-rotation inside the window keeps the token",
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s := withToken(t, m)
				clk.Advance(time.Minute)
				_, _, err := m.RotateWithGrace(t.Context(), s, 10*time.Second)
				require.NoError(t, err)
				clk.Advance(time.Second)
				again, kind, err := m.RotateWithGrace(t.Context(), s, 10*time.Second)
				require.Equal(t, session.RenewalReRotation, kind)

				return rotationOutcome{got: again, old: s, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, o.old.CSRFToken, o.got.CSRFToken)
			},
		},
		{
			name: "renewal without a grace window, twice over, keeps the token",
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s := withToken(t, m)
				clk.Advance(time.Minute)
				next, _, err := m.RotateWithGrace(t.Context(), s, 0)
				require.NoError(t, err)
				clk.Advance(time.Minute)
				last, _, err := m.RotateWithGrace(t.Context(), next, 0)

				return rotationOutcome{got: last, old: s, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, o.old.CSRFToken, o.got.CSRFToken)
			},
		},
		{
			// Recovery renews a predecessor whose window has ended, while its
			// successor is unused.
			name: "a recovery renewal outside the window keeps the token",
			opts: []session.Option{session.WithUnusedSuccessorRecovery()},
			run: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock) rotationOutcome {
				s := withToken(t, m)
				clk.Advance(time.Minute)
				_, _, err := m.RotateWithGrace(t.Context(), s, 10*time.Second)
				require.NoError(t, err)
				clk.Advance(time.Minute)
				again, kind, err := m.RotateWithGrace(t.Context(), s, 10*time.Second)
				require.Equal(t, session.RenewalRecovery, kind)

				return rotationOutcome{got: again, old: s, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, o.old.CSRFToken, o.got.CSRFToken)
			},
		},
		{
			name: "re-authentication of a copy with the token cleared keeps it, and the issuing step sees it",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := withToken(t, m)
				copied := *s
				copied.CSRFToken = ""
				var seen *session.Session
				next, _, err := m.RotateIssuing(t.Context(), &copied, stepRecorder(&seen))

				return rotationOutcome{got: next, seen: seen, old: s, err: err}
			},
			assert: func(t *testing.T, _ *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				assert.Equal(t, o.old.CSRFToken, o.got.CSRFToken)
				require.NotNil(t, o.seen)
				assert.Equal(t, o.old.CSRFToken, o.seen.CSRFToken)
			},
		},
		{
			name: "saving a copy with the token cleared keeps the stored token",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s := withToken(t, m)
				copied := *s
				copied.CSRFToken = ""

				return rotationOutcome{got: s, err: m.Save(t.Context(), &copied)}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.NoError(t, o.err)
				stored, err := store.Load(t.Context(), o.got.ID)
				require.NoError(t, err)
				assert.Equal(t, o.got.CSRFToken, stored.CSRFToken)
			},
		},
		{
			name: "a token changed between building and storing is refused and nothing is stored",
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				p, err := m.Prepare(testUser, session.WithCSRFToken())
				require.NoError(t, err)
				p.Session().CSRFToken = "T2"
				s, err := p.Commit(t.Context())

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.ErrorIs(t, o.err, session.ErrConfig)
				assert.NotContains(t, o.err.Error(), "T2")
				assert.Nil(t, o.got)
				assert.Zero(t, store.Len())
			},
		},
		{
			name: "a random source failing for the token stores nothing",
			opts: []session.Option{session.WithRandom(&entropyThen{left: 32, err: errNoEntropy})},
			run: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock) rotationOutcome {
				s, err := m.Create(t.Context(), testUser, session.WithCSRFToken())

				return rotationOutcome{got: s, err: err}
			},
			assert: func(t *testing.T, store *session.MemoryStore, o rotationOutcome) {
				require.Error(t, o.err)
				assert.True(t, errors.Is(o.err, errNoEntropy))
				assert.Nil(t, o.got)
				assert.Zero(t, store.Len())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, store := managerOnClock(t, clk, tc.opts...)

			tc.assert(t, store, tc.run(t, m, clk))
		})
	}
}
