package authorize_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// TestFirstOf_InspectPrivileges calls the manager's method directly, without
// HeldPrivileges, so the manager's own check of a member's answer and its own
// copy of the answer are pinned apart from the ones HeldPrivileges makes.
func TestFirstOf_InspectPrivileges(t *testing.T) {
	t.Parallel()

	names := []string{"view", "update"}

	type testCase struct {
		name   string
		answer authorize.Holdings
		assert func(t *testing.T, answer, got authorize.Holdings, err error)
	}

	cases := []testCase{
		{
			name:   "an answer for other names than asked is refused as a configuration error",
			answer: authorize.Holdings{{Privilege: "view"}, {Privilege: "delete"}},
			assert: func(t *testing.T, _, got authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.Nil(t, got)
			},
		},
		{
			name:   "an answer of the wrong length is refused as a configuration error",
			answer: authorize.Holdings{{Privilege: "view"}},
			assert: func(t *testing.T, _, got authorize.Holdings, err error) {
				require.ErrorIs(t, err, authorize.ErrConfig)
				assert.Nil(t, got)
			},
		},
		{
			name: "the caller owns the slice it is given",
			answer: authorize.Holdings{
				{Privilege: "view", Held: true, Scope: identity.ScopeAll},
				{Privilege: "update"},
			},
			assert: func(t *testing.T, answer, got authorize.Holdings, err error) {
				require.NoError(t, err)
				require.Len(t, got, 2)

				got[0] = authorize.Holding{Privilege: "edited"}

				assert.Equal(t, "view", answer[0].Privilege, "the member's kept answer changed with the caller's edit")
				assert.True(t, answer[0].Held)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			member := NewMockInspectingAuthorizer(ctrl)
			member.EXPECT().InspectPrivileges(gomock.Any(), "crm", "lead", names).Return(tc.answer, nil)

			manager, err := authorize.NewFirstOf(member)
			require.NoError(t, err)

			got, err := manager.InspectPrivileges(t.Context(), "crm", "lead", names)
			tc.assert(t, tc.answer, got, err)
		})
	}
}
