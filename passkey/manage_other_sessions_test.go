package passkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/session"
)

// TestRemove_EndsOtherSessionsByFamily pins that a removal ending the user's
// other sessions keeps the whole sign-in that made it, whichever of its
// identifiers is presented: the predecessor A still inside its renewal window,
// or its successor B. Only the user's other sign-ins end.
func TestRemove_EndsOtherSessionsByFamily(t *testing.T) {
	t.Parallel()

	const grace = 30 * time.Second

	type signIn struct{ predecessor, successor, other *session.Session }

	type testCase struct {
		name    string
		present func(si signIn) *session.Session
		assert  func(t *testing.T, e *manageEnv, si signIn, err error)
	}

	cases := []testCase{
		{
			name:    "presenting the predecessor inside its window keeps its live successor",
			present: func(si signIn) *session.Session { return si.predecessor },
			assert: func(t *testing.T, e *manageEnv, si signIn, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, e.f.loads(t, si.successor.ID),
					"the removing sign-in's live successor must still load")
				assert.False(t, e.f.loads(t, si.other.ID), "the user's other sign-in must end")
			},
		},
		{
			name:    "presenting the successor keeps it, ends its superseded predecessor and the other sign-in",
			present: func(si signIn) *session.Session { return si.successor },
			assert: func(t *testing.T, e *manageEnv, si signIn, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, e.f.loads(t, si.successor.ID), "the removing session must still load")
				assert.False(t, e.f.loads(t, si.predecessor.ID),
					"a superseded predecessor, which a thief may hold, must end with the credential change")
				assert.False(t, e.f.loads(t, si.other.ID), "the user's other sign-in must end")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newManageEnv(t)
			ctx := t.Context()

			a, err := e.f.sessions.Create(ctx, "u-1")
			require.NoError(t, err)
			other, err := e.f.sessions.Create(ctx, "u-1")
			require.NoError(t, err)

			b, _, err := e.f.sessions.RotateWithGrace(ctx, a, grace)
			require.NoError(t, err)

			e.f.clock.Advance(grace / 2)

			loadedA, err := e.f.sessions.Load(ctx, a.ID)
			require.NoError(t, err, "the predecessor must load inside its window")
			loadedB, err := e.f.sessions.Load(ctx, b.ID)
			require.NoError(t, err)

			si := signIn{predecessor: loadedA, successor: loadedB, other: other}

			m := e.manager(t)
			err = m.Remove(ctx, tc.present(si), e.cred.ID, passkey.RegistrationContext{}, passkey.EndOtherSessions())
			tc.assert(t, e, si, err)
		})
	}
}
