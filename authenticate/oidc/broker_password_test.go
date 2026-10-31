package oidc_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// provisionedWithHash matches the Provision options of an email-named corp
// user, with hash as its password when hash is not empty.
func provisionedWithHash(hash string) gomock.Matcher {
	opts := []identity.UserOption{
		identity.WithUserName("bob@corp.example"),
		identity.WithUserEmail("bob@corp.example"),
		identity.WithUserRoles(),
	}
	if hash != "" {
		opts = append(opts, identity.WithUserPassword([]byte(hash)))
	}
	return provisionedWith(opts...)
}

func TestBrokerPasswordClaim(t *testing.T) {
	t.Parallel()

	created := &identity.Details{ID: "u-9", Username: "bob@corp.example", Active: true}

	type testCase struct {
		name   string
		opts   []oidc.BrokerOption
		logins []oidc.ExternalIdentity
		expect func(prov *MockUserProvisioner)
		assert func(t *testing.T, errs []error, logs string)
	}

	cases := []testCase{
		{
			name:   "a cost-12 bcrypt hash is provisioned exactly as presented",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost12)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash(hashCost12)).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.NotContains(t, logs, hashCost12, "a mapped hash never reaches a log")
			},
		},
		{
			name:   "plaintext is ignored and never logged",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", "hunter2")},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0], "an ignored value does not fail the login")
				assert.NotContains(t, logs, "hunter2")
				assert.Contains(t, logs, "level=WARN")
				assert.Contains(t, logs, "not a bcrypt hash")
				assert.Contains(t, logs, "provider=corp")
			},
		},
		{
			name:   "a claim that is not a string is ignored",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", 42)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.Contains(t, logs, "not a bcrypt hash")
			},
		},
		{
			name:   "an absent claim is ignored",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", nil)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.NotContains(t, logs, "level=WARN")
			},
		},
		{
			name:   "a hash with a bcrypt shape but a trailing byte is not a bcrypt hash",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost12+"x")},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.Contains(t, logs, "not a bcrypt hash")
				assert.NotContains(t, logs, hashCost12)
			},
		},
		{
			name:   "cost 31 is ignored with a warning naming the cost and the band",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost31)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.Contains(t, logs, "level=WARN")
				assert.Contains(t, logs, "cost=31")
				assert.Contains(t, logs, "min_cost=10")
				assert.Contains(t, logs, "max_cost=15")
				assert.NotContains(t, logs, hashCost31)
			},
		},
		{
			name: "a second out-of-band cost for the same provider logs at debug",
			logins: []oidc.ExternalIdentity{
				passwordClaimIdentity("s-1", hashCost31),
				passwordClaimIdentity("s-2", hashCost31),
			},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil).Times(2)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
				costLines := linesContaining(logs, "cost=31")
				require.Len(t, costLines, 2)
				assert.Contains(t, costLines[0], "level=WARN")
				assert.Contains(t, costLines[1], "level=DEBUG")
			},
		},
		{
			name: "a malformed claim does not silence the cost warning",
			logins: []oidc.ExternalIdentity{
				passwordClaimIdentity("s-1", "hunter2"),
				passwordClaimIdentity("s-2", hashCost31),
			},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil).Times(2)
			},
			assert: func(t *testing.T, _ []error, logs string) {
				costLines := linesContaining(logs, "cost=31")
				require.Len(t, costLines, 1)
				assert.Contains(t, costLines[0], "level=WARN")
			},
		},
		{
			name:   "cost 4 is outside the default band",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost04)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.Contains(t, logs, "cost=4")
			},
		},
		{
			name:   "a consumer can widen the band to accept cost 4",
			opts:   []oidc.BrokerOption{oidc.WithBrokerPasswordClaimCostRange(4, 15)},
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost04)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash(hashCost04)).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, _ string) {
				require.NoError(t, errs[0])
			},
		},
		{
			name:   "a consumer can narrow the band to refuse cost 13",
			opts:   []oidc.BrokerOption{oidc.WithBrokerPasswordClaimCostRange(10, 12)},
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost13)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWithHash("")).Return(created, nil)
			},
			assert: func(t *testing.T, errs []error, logs string) {
				require.NoError(t, errs[0])
				assert.Contains(t, logs, "max_cost=12")
			},
		},
		{
			name:   "a provisioner error quoting a hash is redacted and still reaches the original",
			logins: []oidc.ExternalIdentity{passwordClaimIdentity("s-1", hashCost12)},
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errHashInProvision)
			},
			assert: func(t *testing.T, errs []error, _ string) {
				require.ErrorIs(t, errs[0], errHashInProvision)
				assert.NotErrorIs(t, errs[0], authenticate.ErrAuthenticationFailed)
				assert.NotContains(t, errs[0].Error(), hashCost12)
				assert.Contains(t, errs[0].Error(), "[redacted]")
				assert.Contains(t, errs[0].Error(), "scan failed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			prov := NewMockUserProvisioner(ctrl)
			tc.expect(prov)

			var logs bytes.Buffer
			opts := append([]oidc.BrokerOption{
				oidc.WithBrokerProvisioner(prov),
				oidc.WithBrokerJIT("corp"),
				oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
				oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
				oidc.WithBrokerLogger(testTextLogger(&logs)),
				oidc.WithBrokerClock(clockwork.NewFakeClockAt(provisionClock)),
			}, tc.opts...)
			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), opts...)
			require.NoError(t, err)

			errs := make([]error, 0, len(tc.logins))
			for _, ext := range tc.logins {
				_, err := b.Broker(t.Context(), ext)
				errs = append(errs, err)
			}
			tc.assert(t, errs, logs.String())
		})
	}
}

// errHashInProvision is a provisioner error whose text quotes a mapped hash,
// as a driver's scan error can.
var errHashInProvision = errors.New("scan failed on password " + hashCost12)

func TestBrokerPasswordClaimOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []oidc.BrokerOption
		assert func(t *testing.T, b *oidc.Broker, err error)
	}

	refused := func(fragments ...string) func(t *testing.T, b *oidc.Broker, err error) {
		return func(t *testing.T, b *oidc.Broker, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, b)
			for _, f := range fragments {
				assert.Contains(t, err.Error(), f)
			}
		}
	}
	claimed := func(t *testing.T, more ...oidc.BrokerOption) []oidc.BrokerOption {
		return append([]oidc.BrokerOption{
			oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
			oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
		}, more...)
	}

	cases := []testCase{
		{
			name: "a password claim with a bcrypt encoder is accepted",
			opts: func(t *testing.T) []oidc.BrokerOption { return claimed(t) },
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corp"}, b.ConfiguredProviders())
			},
		},
		{
			name: "a password claim without an encoder is refused",
			opts: func(*testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash")}
			},
			assert: refused("password encoder"),
		},
		{
			name: "an encoder that does not produce bcrypt is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				enc, err := password.NewArgon2idEncoder()
				require.NoError(t, err)
				return []oidc.BrokerOption{
					oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithBrokerPasswordEncoder(enc),
				}
			},
			assert: refused("bcrypt"),
		},
		{
			name: "a nil encoder is refused",
			opts: func(*testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerPasswordEncoder(nil)}
			},
			assert: refused("WithBrokerPasswordEncoder"),
		},
		{
			name: "a band below bcrypt's minimum is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerPasswordClaimCostRange(3, 15))
			},
			assert: refused("WithBrokerPasswordClaimCostRange"),
		},
		{
			name: "a band above bcrypt's maximum is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerPasswordClaimCostRange(10, 32))
			},
			assert: refused("WithBrokerPasswordClaimCostRange"),
		},
		{
			name: "an inverted band is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerPasswordClaimCostRange(12, 10))
			},
			assert: refused("WithBrokerPasswordClaimCostRange"),
		},
		{
			name: "a band up to the record ceiling of 16 is accepted",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerPasswordClaimCostRange(4, 16))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.NoError(t, err) },
		},
		{
			name: "a band beyond the record ceiling is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerPasswordClaimCostRange(10, 20))
			},
			assert: refused("WithBrokerPasswordClaimCostRange"),
		},
		{
			name: "a band one above the record ceiling is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerPasswordClaimCostRange(10, 17))
			},
			assert: refused("WithBrokerPasswordClaimCostRange"),
		},
		{
			name: "an empty provider key is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{
					oidc.WithBrokerPasswordClaim("", "credentials.password_hash"),
					oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
				}
			},
			assert: refused("WithBrokerPasswordClaim"),
		},
		{
			name: "an empty claim path is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerPasswordClaim("corp", ""), oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t))}
			},
			assert: refused("WithBrokerPasswordClaim"),
		},
		{
			name: "a display-name path equal to the password path is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerNameClaim("corp", "credentials.password_hash"))
			},
			assert: refused("corp", "display-name"),
		},
		{
			name: "the same path for another provider's display name is accepted",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithBrokerNameClaim("social", "credentials.password_hash"))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			opts := append([]oidc.BrokerOption{oidc.WithBrokerProvisioner(NewMockUserProvisioner(ctrl))}, tc.opts(t)...)
			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), opts...)
			tc.assert(t, b, err)
		})
	}
}
