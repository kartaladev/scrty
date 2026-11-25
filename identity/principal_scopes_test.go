package identity_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/identity"
)

// TestPrincipalFromDetails_CarriesNoScopes pins that a user's principal, as a session
// authenticates it, carries no scopes: scopes are an access token's, added only by the code that
// authenticated one.
func TestPrincipalFromDetails_CarriesNoScopes(t *testing.T) {
	t.Parallel()

	details := &identity.Details{
		ID: "u-1", Active: true,
		Roles: []*identity.AssignedRole{{ID: "admin", Name: "admin", Primary: true}},
	}

	type testCase struct {
		name  string
		build func() *identity.Principal
	}

	cases := []testCase{
		{
			name:  "PrincipalFromDetails",
			build: func() *identity.Principal { return identity.PrincipalFromDetails(details) },
		},
		{
			name:  "PrincipalFromDetailsAt",
			build: func() *identity.Principal { return identity.PrincipalFromDetailsAt(details, time.Now()) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := tc.build()

			assert.NotNil(t, p)
			assert.Empty(t, p.Scopes)
		})
	}
}
