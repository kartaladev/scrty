package httpsec

import (
	"testing"

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
