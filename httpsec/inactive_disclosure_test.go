package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// TestChain_InactiveDisclosure pins how form login and Basic answer a correct password for an
// inactive account: by default as a wrong password, the inactive refusal kept beneath for the
// consumer's own handler, and as that refusal alone, answered 403, only when the consumer chose to
// disclose it. A wrong password for the same account never says it is inactive.
func TestChain_InactiveDisclosure(t *testing.T) {
	t.Parallel()

	const (
		rightPassword = "the inactive account's own password"
		wrongPassword = "a wrong guess"
	)

	inactiveHash := []byte("inactive-hash")

	type testCase struct {
		name     string
		opts     []httpsec.Option
		basic    bool
		password string
		assert   func(t *testing.T, out served)
	}

	concealed := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.ErrorIs(t, out.err, authenticate.ErrAccountInactive,
			"a consumer's own handler can still tell the account is inactive")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err), "as for a wrong password")
		assert.False(t, out.handlerRan)
	}

	disclosed := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAccountInactive)
		assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed,
			"a disclosed refusal is the inactive refusal alone")
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
	}

	uniform := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.NotErrorIs(t, out.err, authenticate.ErrAccountInactive,
			"a wrong password must not tell the account is inactive")
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}

	cases := []testCase{
		{
			name:     "form login conceals an inactive account by default",
			password: rightPassword,
			assert:   concealed,
		},
		{
			name:     "Basic conceals an inactive account by default, challenged",
			basic:    true,
			password: rightPassword,
			assert: func(t *testing.T, out served) {
				concealed(t, out)
				assert.Equal(t, `Basic realm="Restricted"`, out.rec.Header().Get("WWW-Authenticate"))
			},
		},
		{
			name:     "form login discloses an inactive account when asked",
			opts:     []httpsec.Option{httpsec.WithInactiveDisclosure()},
			password: rightPassword,
			assert:   disclosed,
		},
		{
			name:     "a disclosed Basic refusal has no challenge",
			opts:     []httpsec.Option{httpsec.WithInactiveDisclosure()},
			basic:    true,
			password: rightPassword,
			assert: func(t *testing.T, out served) {
				disclosed(t, out)
				assert.Empty(t, out.rec.Header().Get("WWW-Authenticate"),
					"WWW-Authenticate belongs to a 401, and this is a 403")
			},
		},
		{
			name:     "disclosure needs the password at form login",
			opts:     []httpsec.Option{httpsec.WithInactiveDisclosure()},
			password: wrongPassword,
			assert:   uniform,
		},
		{
			name:     "disclosure needs the password over Basic",
			opts:     []httpsec.Option{httpsec.WithInactiveDisclosure()},
			basic:    true,
			password: wrongPassword,
			assert: func(t *testing.T, out served) {
				uniform(t, out)
				assert.Equal(t, `Basic realm="Restricted"`, out.rec.Header().Get("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLockResponseHarness(t, true)

			h.users.EXPECT().LoadByUsername(gomock.Any(), "ada").
				Return(&identity.Details{ID: "u-ada", Username: "ada", Password: inactiveHash, Active: false}, nil)
			h.enc.EXPECT().Match(tc.password, inactiveHash).Return(tc.password == rightPassword).Times(1)

			c, err := h.chain(t, nil, tc.opts...)
			require.NoError(t, err)

			if tc.basic {
				tc.assert(t, basicFrom(t, c, loginGuardSource, "ada", tc.password))

				return
			}

			tc.assert(t, formLoginFrom(t, c, loginGuardSource, "ada", tc.password))
		})
	}
}
