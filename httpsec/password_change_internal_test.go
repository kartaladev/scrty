package httpsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// TestPasswordChange_ResolutionTarget pins which session a password change's
// resolution is saved on: the gate's own session, or the latest successor a
// role switch rotated it into, and never a session of another sign-in, which
// is refused so that nothing is saved.
func TestPasswordChange_ResolutionTarget(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01890a5d-ac96-774b-bcce-b302099a8057")
	gated := &session.Session{ID: "gated", UserID: "ada", FamilyID: family}
	own := &session.Session{ID: "rotated", UserID: "ada", FamilyID: family}

	type testCase struct {
		name string

		// current is what the role source holds now; nil means no source.
		current *session.Session

		// nilGated passes no gated session, as a defect in the caller would.
		nilGated bool

		assert func(t *testing.T, target *session.Session, err error)
	}

	cases := []testCase{
		{
			name: "without a role source the gate's own session",
			assert: func(t *testing.T, target *session.Session, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, gated, target)
			},
		},
		{
			name:    "a source still on the gate's session gives that session itself",
			current: &session.Session{ID: "gated", UserID: "ada", FamilyID: family},
			assert: func(t *testing.T, target *session.Session, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, gated, target, "the copy the gate holds, not the source's")
			},
		},
		{
			name:    "a source moved to a successor in the same sign-in gives the successor",
			current: own,
			assert: func(t *testing.T, target *session.Session, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, own, target)
			},
		},
		{
			name:    "a session of another family is refused",
			current: &session.Session{ID: "elsewhere", UserID: "ada", FamilyID: id.MustParse("01890a5d-ac96-774b-bcce-b302099a8058")},
			assert: func(t *testing.T, target *session.Session, err error) {
				t.Helper()
				require.ErrorIs(t, err, errResolutionNotOwn)
				assert.Nil(t, target)
			},
		},
		{
			name:    "a session of another user is refused",
			current: &session.Session{ID: "elsewhere", UserID: "mallory", FamilyID: family},
			assert: func(t *testing.T, target *session.Session, err error) {
				t.Helper()
				require.ErrorIs(t, err, errResolutionNotOwn)
				assert.Nil(t, target)
			},
		},
		{
			name:     "no gated session is refused",
			nilGated: true,
			assert: func(t *testing.T, target *session.Session, err error) {
				t.Helper()
				require.ErrorIs(t, err, errResolutionNotOwn)
				assert.Nil(t, target)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var src *roleSource
			if tc.current != nil {
				src = &roleSource{session: gated, current: tc.current}
			}

			from := gated
			if tc.nilGated {
				from = nil
			}

			target, err := resolutionTarget(from, gated, src)
			tc.assert(t, target, err)
		})
	}
}

// TestPasswordChange_AdoptResolution pins which fields a password change's
// resolution carries onto the session it saves, and that restoring from a copy
// taken before puts back exactly those: the second-factor state and the marker
// always, the deadlines only when the resolution ended a recovery, so a
// rotation's fresh idle deadline is never overwritten and a failed save leaves
// the in-memory session as it was stored.
func TestPasswordChange_AdoptResolution(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	generation := id.MustParse("01890a5d-ac96-774b-bcce-b302099a8057")

	// target is the session the resolution is saved on: a rotation's
	// successor, with its own fresh deadlines.
	target := func() *session.Session {
		return &session.Session{
			ID: "successor", MFA: session.MFARecoveryPending, PasswordChangePending: true,
			AbsoluteExpiresAt: base.Add(12 * time.Hour), IdleExpiresAt: base.Add(30 * time.Minute),
		}
	}

	// resolved is what resolve worked out from the session it gated: older
	// deadlines, as a restored recovery has.
	resolved := func() *session.Session {
		return &session.Session{
			ID: "gated", MFA: session.MFANone, PasswordChangePending: false,
			AbsoluteExpiresAt: base.Add(2 * time.Hour), IdleExpiresAt: base.Add(10 * time.Second),
			EnrolmentGeneration: generation,
		}
	}

	type testCase struct {
		name      string
		deadlines bool
		assert    func(t *testing.T, adopted, before *session.Session)
	}

	cases := []testCase{
		{
			name: "without deadlines only the marker and the second-factor state are adopted",
			assert: func(t *testing.T, adopted, before *session.Session) {
				t.Helper()
				assert.Equal(t, session.MFANone, adopted.MFA)
				assert.False(t, adopted.PasswordChangePending)
				assert.Equal(t, before.IdleExpiresAt, adopted.IdleExpiresAt, "the rotation's idle deadline stays")
				assert.Equal(t, before.AbsoluteExpiresAt, adopted.AbsoluteExpiresAt)
				assert.Equal(t, before.EnrolmentGeneration, adopted.EnrolmentGeneration)
				assert.Equal(t, "successor", adopted.ID, "nothing else is touched")
			},
		},
		{
			name:      "with deadlines the restored ones are adopted too",
			deadlines: true,
			assert: func(t *testing.T, adopted, _ *session.Session) {
				t.Helper()
				assert.Equal(t, session.MFANone, adopted.MFA)
				assert.False(t, adopted.PasswordChangePending)
				assert.Equal(t, base.Add(10*time.Second), adopted.IdleExpiresAt)
				assert.Equal(t, base.Add(2*time.Hour), adopted.AbsoluteExpiresAt)
				assert.Equal(t, generation, adopted.EnrolmentGeneration)
				assert.Equal(t, "successor", adopted.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dst := target()
			before := *dst

			adoptResolution(dst, resolved(), tc.deadlines)
			tc.assert(t, dst, &before)

			// The failed-save rollback, with the same flag, restores exactly
			// what was adopted.
			adoptResolution(dst, &before, tc.deadlines)
			assert.Equal(t, before, *dst, "the session is as it was before the resolution")
		})
	}
}
