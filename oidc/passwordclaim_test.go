package oidc_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/password"
)

// bcryptShapedHash returns a well-formed bcrypt hash string at cost, whose
// 53-character salt-and-digest is fill repeated. bcrypt.Cost reads only the
// prefix, so the digest need not verify anything.
func bcryptShapedHash(cost string, fill byte) string {
	return "$2a$" + cost + "$" + strings.Repeat(string(fill), 53)
}

// Hashes the password-claim rows present. They are distinct so a row can tell
// which one reached a call or a log.
var (
	hashCost12 = bcryptShapedHash("12", 'a')
	hashCost04 = bcryptShapedHash("04", 'b')
	hashCost31 = bcryptShapedHash("31", 'c')
	hashCost13 = bcryptShapedHash("13", 'd')
)

// fastBcryptEncoder returns a real bcrypt encoder at the password package's
// floor, cost 10, which keeps the construction probe cheap.
func fastBcryptEncoder(t *testing.T) password.Encoder {
	t.Helper()
	enc, err := password.NewBcryptEncoder(password.WithBcryptCost(10))
	require.NoError(t, err)
	return enc
}

// passwordClaimIdentity is an unlinked, verified corp identity carrying hash
// at credentials.password_hash, or no such claim when hash is nil.
func passwordClaimIdentity(subject string, hash any) oidc.ExternalIdentity {
	ext := provisionIdentity("corp", "bob@corp.example")
	ext.Subject = subject
	if hash != nil {
		ext.Claims = map[string]any{"credentials": map[string]any{"password_hash": hash}}
	}
	return ext
}

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
			opts:   []oidc.BrokerOption{oidc.WithPasswordClaimCostRange(4, 15)},
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
			opts:   []oidc.BrokerOption{oidc.WithPasswordClaimCostRange(10, 12)},
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
				oidc.WithProvisioner(prov),
				oidc.WithJIT("corp"),
				oidc.WithPasswordClaim("corp", "credentials.password_hash"),
				oidc.WithPasswordEncoder(fastBcryptEncoder(t)),
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

// linesContaining returns the lines of logs that contain s.
func linesContaining(logs, s string) []string {
	var out []string
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, s) {
			out = append(out, line)
		}
	}
	return out
}

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
			oidc.WithPasswordClaim("corp", "credentials.password_hash"),
			oidc.WithPasswordEncoder(fastBcryptEncoder(t)),
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
				return []oidc.BrokerOption{oidc.WithPasswordClaim("corp", "credentials.password_hash")}
			},
			assert: refused("password encoder"),
		},
		{
			name: "an encoder that does not produce bcrypt is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				enc, err := password.NewArgon2idEncoder()
				require.NoError(t, err)
				return []oidc.BrokerOption{
					oidc.WithPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithPasswordEncoder(enc),
				}
			},
			assert: refused("bcrypt"),
		},
		{
			name: "a nil encoder is refused",
			opts: func(*testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithPasswordEncoder(nil)}
			},
			assert: refused("WithPasswordEncoder"),
		},
		{
			name: "a band below bcrypt's minimum is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithPasswordClaimCostRange(3, 15))
			},
			assert: refused("WithPasswordClaimCostRange"),
		},
		{
			name: "a band above bcrypt's maximum is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithPasswordClaimCostRange(10, 32))
			},
			assert: refused("WithPasswordClaimCostRange"),
		},
		{
			name: "an inverted band is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithPasswordClaimCostRange(12, 10))
			},
			assert: refused("WithPasswordClaimCostRange"),
		},
		{
			name: "bcrypt's whole range is an accepted band",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithPasswordClaimCostRange(4, 31))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.NoError(t, err) },
		},
		{
			name: "an empty provider key is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{
					oidc.WithPasswordClaim("", "credentials.password_hash"),
					oidc.WithPasswordEncoder(fastBcryptEncoder(t)),
				}
			},
			assert: refused("WithPasswordClaim"),
		},
		{
			name: "an empty claim path is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithPasswordClaim("corp", ""), oidc.WithPasswordEncoder(fastBcryptEncoder(t))}
			},
			assert: refused("WithPasswordClaim"),
		},
		{
			name: "a display-name path equal to the password path is refused",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithNameClaim("corp", "credentials.password_hash"))
			},
			assert: refused("corp", "display-name"),
		},
		{
			name: "the same path for another provider's display name is accepted",
			opts: func(t *testing.T) []oidc.BrokerOption {
				return claimed(t, oidc.WithNameClaim("social", "credentials.password_hash"))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			opts := append([]oidc.BrokerOption{oidc.WithProvisioner(NewMockUserProvisioner(ctrl))}, tc.opts(t)...)
			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), opts...)
			tc.assert(t, b, err)
		})
	}
}
