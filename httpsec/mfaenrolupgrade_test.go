package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// moveTo sets the harness's timeline, shared by the session manager, its store
// and the TOTP method, to at.
func moveTo(h *enrolHarness, at time.Time) { h.clock.Advance(at.Sub(h.clock.Now())) }

// failingCreates is a session store whose Create answers errStoreLeaky once
// failing is set, and behaves as the store it wraps otherwise.
type failingCreates struct {
	session.Store

	failing *atomic.Bool
}

func (s failingCreates) Create(ctx context.Context, sess *session.Session) error {
	if s.failing.Load() {
		return errStoreLeaky
	}

	return s.Store.Create(ctx, sess)
}

// upgradeDay is the morning the enrolment timelines run on.
var upgradeDay = time.Date(2026, time.September, 28, 0, 0, 0, 0, time.UTC)

// clockAt is hh:mm on upgradeDay.
func clockAt(hh, mm int) time.Time {
	return upgradeDay.Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute)
}

// onTimeline rebuilds the harness's session manager and TOTP method on one
// shared clock, starting at 09:00, with a 12-hour absolute timeout. Inserts
// into the session store, which is how a rotation writes, fail while failing is
// set.
func onTimeline(t *testing.T, h *enrolHarness, failing *atomic.Bool) {
	t.Helper()

	// A fresh fake rather than a move: the timeline's instants are UTC, and a
	// move would keep the harness clock's location.
	h.clock = clockwork.NewFakeClockAt(clockAt(9, 0))

	store := session.NewMemoryStore(session.WithMemoryStoreClock(h.clock))

	var err error
	h.sessions, err = session.NewManager(
		session.WithStore(failingCreates{Store: store, failing: failing}),
		session.WithClock(h.clock),
		session.WithAbsoluteTimeout(12*time.Hour),
	)
	require.NoError(t, err)

	h.totp, err = mfa.NewTOTP(h.store, enrolIssuer, mfa.WithClock(h.clock))
	require.NoError(t, err)

	h.method = h.totp
}

// issuedFor records the session identifier every token was issued for.
func issuedFor(h *enrolHarness) *atomic.Value {
	var issued atomic.Value

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			issued.Store(id)

			return "token-for-" + id, nil
		})

	return &issued
}

// TestVerifyUpgradesEnrolmentSession pins the last step of the path: a session
// that entered it at 09:00, with its absolute deadline lowered to 09:15,
// becomes a full session only by verifying a fresh code at the verify
// endpoint, which restores the deadline it would have had and rotates it; a
// session already past its lowered deadline is refused as ended and never
// rotated, and a rotation that fails leaves it exactly as it was.
func TestVerifyUpgradesEnrolmentSession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// before runs after the emailed code was redeemed at 09:08, and before
		// the verification.
		before func(t *testing.T, h *enrolHarness, s *session.Session, failing *atomic.Bool)

		assert func(t *testing.T, h *enrolHarness, s *session.Session, issued *atomic.Value, out served)
	}

	// untouched is a refusal that changed nothing: the pinned session is as
	// verification found it, and no credential was issued.
	untouched := func(t *testing.T, h *enrolHarness, issued *atomic.Value) {
		t.Helper()

		assert.Nil(t, issued.Load(), "no credential is issued")

		kept := h.pinned
		assert.Equal(t, session.MFAPending, kept.MFA, "the challenge stays pending")
		assert.True(t, kept.MFASatisfiedAt.IsZero())
		assert.Equal(t, clockAt(9, 15), kept.AbsoluteExpiresAt, "the lowered deadline stays")
		assert.Equal(t, clockAt(21, 0), kept.EnrolmentOriginDeadline, "the marker stays")
		assert.False(t, kept.EnrolmentGeneration.IsZero(), "the generation stays")
	}

	cases := []testCase{
		{
			name: "a fresh code at 09:09",
			before: func(_ *testing.T, h *enrolHarness, _ *session.Session, _ *atomic.Bool) {
				moveTo(h, clockAt(9, 9))
			},
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, issued *atomic.Value, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				id, ok := issued.Load().(string)
				require.True(t, ok, "a credential is issued")
				require.NotEqual(t, s.ID, id, "for the rotated session")

				rotated := h.stored(t, id)
				assert.Equal(t, session.MFASatisfied, rotated.MFA)
				assert.Equal(t, clockAt(21, 0), rotated.AbsoluteExpiresAt,
					"the deadline a login at 09:00 would have had")
				assert.Equal(t, clockAt(9, 39), rotated.IdleExpiresAt,
					"the default 30-minute idle deadline, counted from the verification at 09:09")
				assert.True(t, rotated.EnrolmentOriginDeadline.IsZero(), "the marker is cleared")
				assert.True(t, rotated.EnrolmentGeneration.IsZero(), "the generation is cleared")

				_, err := h.sessions.Load(t.Context(), s.ID)
				require.Error(t, err, "the old handle no longer loads")
			},
		},
		{
			// A session the store loaded at 09:14 reaches verification at
			// 09:16, past the deadline it was lowered to.
			name: "a session past its lowered deadline",
			before: func(t *testing.T, h *enrolHarness, s *session.Session, _ *atomic.Bool) {
				t.Helper()

				moveTo(h, clockAt(9, 14))
				h.pinned = h.stored(t, s.ID)
				moveTo(h, clockAt(9, 16))
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, issued *atomic.Value, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "the session has ended")
				require.ErrorIs(t, out.err, session.ErrSessionExpired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				untouched(t, h, issued)
			},
		},
		{
			name: "a rotation that fails",
			before: func(t *testing.T, h *enrolHarness, s *session.Session, failing *atomic.Bool) {
				t.Helper()

				moveTo(h, clockAt(9, 9))
				h.pinned = h.stored(t, s.ID)
				failing.Store(true)
			},
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, issued *atomic.Value, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, errStoreLeaky)
				untouched(t, h, issued)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			o := &outbox{}
			o.accepting(h, nil)

			var failing atomic.Bool

			onTimeline(t, h, &failing)
			issued := issuedFor(h)

			s := h.enrolmentOnly(t, factor.Password)
			require.Equal(t, clockAt(9, 15), s.AbsoluteExpiresAt)

			c := h.chain(t, s)
			secret := h.beginDoc(t, c).Secret

			moveTo(h, clockAt(9, 7))
			emailed := h.prove(t, c, o, secret)

			moveTo(h, clockAt(9, 8))
			require.NoError(t, serve(t, c, emailCodeRequest(t.Context(), emailed)).err)
			require.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)

			tc.before(t, h, s, &failing)

			tc.assert(t, h, s, issued, serve(t, c, post(t.Context(), testMFAVerifyPath,
				"code="+h.codeFor(t, secret))))
		})
	}
}

// TestConfirmationIsNotASecondFactor pins that completing an enrolment is not
// verifying it: a session whose enrolment was just confirmed through the path
// is refused a protected route with the ordinary MFA challenge, and the
// handler never runs.
func TestConfirmationIsNotASecondFactor(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	o := &outbox{}
	o.accepting(h, nil)

	s := h.enrolmentOnly(t, factor.Password)
	c := h.chain(t, s)
	emailed := h.prove(t, c, o, h.beginDoc(t, c).Secret)
	require.NoError(t, serve(t, c, emailCodeRequest(t.Context(), emailed)).err)
	require.True(t, h.enrolled(t))

	out := serve(t, c, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))

	var challenge *httpsec.ChallengeError
	require.True(t, errors.As(out.err, &challenge), "got %v", out.err)
	assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
	assert.False(t, out.handlerRan)
}
