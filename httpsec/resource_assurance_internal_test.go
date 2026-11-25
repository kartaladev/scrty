package httpsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
)

// TestAccessTokenInput_FailsClosedOnLocalUser pins that a source that records nothing of whom the
// token names is judged as naming a local user, so the MFA requirement judges it.
func TestAccessTokenInput_FailsClosedOnLocalUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		vt     *verifiedToken
		assert func(t *testing.T, in interface {
			NamesLocalUser() bool
		}, user identity.UserID)
	}

	p := &identity.Principal{ID: "u-1", Kind: identity.KindUser}

	cases := []testCase{
		{
			name: "a source that sets nothing",
			vt:   &verifiedToken{principal: p, kind: factor.ExternalAccessToken},
			assert: func(t *testing.T, in interface{ NamesLocalUser() bool }, user identity.UserID) {
				assert.True(t, in.NamesLocalUser())
				assert.Equal(t, p.ID, user)
			},
		},
		{
			name: "a source that marks the caller external",
			vt:   &verifiedToken{principal: p, kind: factor.ExternalAccessToken, external: true},
			assert: func(t *testing.T, in interface{ NamesLocalUser() bool }, user identity.UserID) {
				assert.False(t, in.NamesLocalUser())
				assert.Empty(t, user)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := accessTokenInput(p, tc.vt.kind, tc.vt, time.Now())
			tc.assert(t, in.AccessTokenAssurance, in.User)
		})
	}
}
