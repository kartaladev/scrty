package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

func TestBroker_RefusesProvisioningForUnicodeFoldedDomain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		email   string
		allowed []string
		expect  func(prov *MockUserProvisioner)
		assert  func(t *testing.T, p *identity.Principal, err error)
	}

	refused := func(t *testing.T, p *identity.Principal, err error) {
		t.Helper()

		require.ErrorIs(t, err, oidc.ErrProvisioningRefused)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Nil(t, p)
	}

	cases := []testCase{
		{
			name:  "the Kelvin sign in the email domain is not a k in the allowlist",
			email: "bob@K.example", allowed: []string{"k.example"},
			assert: refused,
		},
		{
			name:  "the Kelvin sign in the allowlist is not a k in the email domain",
			email: "bob@k.example", allowed: []string{"K.example"},
			assert: refused,
		},
		{
			name:  "the long s in the email domain is not an s in the allowlist",
			email: "bob@ſ.example", allowed: []string{"s.example"},
			assert: refused,
		},
		{
			name:  "a no-break space around the allowlist entry is not trimmed",
			email: "bob@corp.example", allowed: []string{"corp.example "},
			assert: refused,
		},
		{
			name:  "ASCII letter case is still ignored",
			email: "Bob@CORP.example", allowed: []string{"Corp.Example"},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "Bob@CORP.example", gomock.Any()).
					Return(&identity.Details{ID: "u-9", Username: "Bob@CORP.example", Active: true}, nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-9"), p.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			prov := NewMockUserProvisioner(ctrl)
			users := NewMockUserLoader(ctrl)

			if tc.expect != nil {
				tc.expect(prov)
			}

			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users,
				oidc.WithBrokerProvisioner(prov),
				oidc.WithBrokerJIT("corp"),
				oidc.WithBrokerJITEmailDomains("corp", tc.allowed...),
			)
			require.NoError(t, err)

			p, err := b.Broker(t.Context(), provisionIdentity("corp", tc.email))

			tc.assert(t, p, err)
		})
	}
}
