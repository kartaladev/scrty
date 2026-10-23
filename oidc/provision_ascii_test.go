package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

func TestBroker_RefusesProvisioningForUnicodeFoldedDomain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		email     string
		allowed   []string
		admitted  bool
		wantEmail string
	}

	cases := []testCase{
		{
			name:  "the Kelvin sign in the email domain is not a k in the allowlist",
			email: "bob@K.example", allowed: []string{"k.example"},
		},
		{
			name:  "the Kelvin sign in the allowlist is not a k in the email domain",
			email: "bob@k.example", allowed: []string{"K.example"},
		},
		{
			name:  "the long s in the email domain is not an s in the allowlist",
			email: "bob@ſ.example", allowed: []string{"s.example"},
		},
		{
			name:  "a no-break space around the allowlist entry is not trimmed",
			email: "bob@corp.example", allowed: []string{"corp.example "},
		},
		{
			name:  "ASCII letter case is still ignored",
			email: "Bob@CORP.example", allowed: []string{"Corp.Example"},
			admitted: true, wantEmail: "Bob@CORP.example",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			prov := NewMockUserProvisioner(ctrl)
			users := NewMockUserLoader(ctrl)

			if tc.admitted {
				prov.EXPECT().Provision(gomock.Any(), tc.wantEmail, gomock.Any()).
					Return(&identity.Details{ID: "u-9", Username: tc.wantEmail, Active: true}, nil)
			}

			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users,
				oidc.WithProvisioner(prov),
				oidc.WithJIT("corp"),
				oidc.WithJITEmailDomains("corp", tc.allowed...),
			)
			require.NoError(t, err)

			p, err := b.Broker(t.Context(), provisionIdentity("corp", tc.email))

			if tc.admitted {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-9"), p.ID)

				return
			}

			require.ErrorIs(t, err, oidc.ErrProvisioningRefused)
			require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
			assert.Nil(t, p)
		})
	}
}
