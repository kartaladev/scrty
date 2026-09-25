package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// mirrorStored is the stored record of u-1, the user brokerSeededLinks links
// (corp, s-1) to: display name Alice, hash hashCost12, primary role editor.
func mirrorStored() *identity.Details {
	return &identity.Details{
		ID: "u-1", Username: "alice", Name: "Alice", Password: []byte(hashCost12), Active: true,
		Roles: []*identity.AssignedRole{{Name: "editor", Primary: true}},
	}
}

// mirrorIdentity is the linked corp identity presenting name and hash.
func mirrorIdentity(name, hash string) oidc.ExternalIdentity {
	ext := brokerCorpIdentity()
	ext.Claims = map[string]any{
		"name":        name,
		"credentials": map[string]any{"password_hash": hash},
	}
	return ext
}

// errMirrorUpdate is an update error quoting the username and a hash, as a
// driver's error can.
var errMirrorUpdate = errors.New("update of alice failed near " + hashCost13)

func TestBrokerClaimMirroring(t *testing.T) {
	t.Parallel()

	mirrorCorp := oidc.WithClaimMirror("corp", true)

	type testCase struct {
		name   string
		opts   []oidc.BrokerOption
		ext    oidc.ExternalIdentity
		expect func(prov *MockUserProvisioner)
		assert func(t *testing.T, p *identity.Principal, err error, logs string)
	}

	cases := []testCase{
		{
			name: "a changed hash is refreshed naming only the password",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext:  mirrorIdentity("Alice", hashCost13),
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "alice", provisionedWith(identity.WithUserPassword([]byte(hashCost13)))).
					DoAndReturn(func(_ context.Context, _ string, opts ...identity.UserOption) (*identity.Details, error) {
						u := identity.ApplyUserOptions(opts...)
						// The same fact the matcher states, spelled as the spec's IsSet reading.
						if !u.IsSet(identity.FieldPassword) || u.IsSet(identity.FieldName) {
							return nil, errors.New("the update named the wrong fields")
						}
						d := mirrorStored()
						d.Password = []byte(hashCost13)
						return d, nil
					})
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), p.ID)
				assert.NotContains(t, logs, "level=ERROR")
				assert.NotContains(t, logs, hashCost13)
			},
		},
		{
			name: "a changed display name is refreshed naming only the name",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext:  mirrorIdentity("Alice B.", hashCost12),
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "alice", provisionedWith(identity.WithUserName("Alice B."))).
					Return(&identity.Details{ID: "u-1", Username: "alice", Name: "Alice B.", Active: true}, nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, "Alice B.", p.Name)
			},
		},
		{
			name:   "unchanged claims write nothing",
			opts:   []oidc.BrokerOption{mirrorCorp},
			ext:    mirrorIdentity("Alice", hashCost12),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, "Alice", p.Name)
			},
		},
		{
			name: "nothing resolving writes nothing",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext: func() oidc.ExternalIdentity {
				e := brokerCorpIdentity()
				e.Claims = map[string]any{}
				return e
			}(),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name:   "an ignored hash is not mirrored",
			opts:   []oidc.BrokerOption{mirrorCorp},
			ext:    mirrorIdentity("Alice", "hunter2"),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, _ *identity.Principal, err error, logs string) {
				require.NoError(t, err)
				assert.NotContains(t, logs, "hunter2")
			},
		},
		{
			name: "an update failure does not fail the login and is logged scrubbed",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext:  mirrorIdentity("Alice B.", hashCost13),
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).Return(nil, errMirrorUpdate)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				require.NoError(t, err)
				assert.Equal(t, "Alice", p.Name, "the login proceeds with the stored name")
				require.Len(t, p.Roles, 1, "the login proceeds with the values loaded before the update")
				assert.Equal(t, "editor", p.Roles[0].Name)
				require.NotNil(t, p.ActiveRole)
				assert.Equal(t, "editor", p.ActiveRole.Name)
				errorLines := linesContaining(logs, "level=ERROR")
				require.Len(t, errorLines, 1)
				assert.Contains(t, errorLines[0], "provider=corp")
				assert.Contains(t, errorLines[0], "update of")
				assert.NotContains(t, logs, hashCost13)
				assert.NotContains(t, logs, "alice")
			},
		},
		{
			name: "an update returning no user does not fail the login",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext:  mirrorIdentity("Alice B.", hashCost12),
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).Return(nil, nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				require.NoError(t, err)
				assert.Equal(t, "Alice", p.Name)
				assert.Len(t, linesContaining(logs, "level=ERROR"), 1)
			},
		},
		{
			name: "a partial update result does not strip roles",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext:  mirrorIdentity("Alice B.", hashCost12),
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).
					Return(&identity.Details{ID: "u-1", Username: "alice", Name: "Alice B."}, nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, "Alice B.", p.Name)
				require.Len(t, p.Roles, 1)
				assert.Equal(t, "editor", p.Roles[0].Name)
				require.NotNil(t, p.ActiveRole)
				assert.Equal(t, "editor", p.ActiveRole.Name)
			},
		},
		{
			name: "only mirrored fields are copied back, whatever the update returned",
			opts: []oidc.BrokerOption{mirrorCorp},
			ext:  mirrorIdentity("Alice B.", hashCost12),
			expect: func(prov *MockUserProvisioner) {
				prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).Return(&identity.Details{
					ID: "u-2", Username: "mallory", Name: "Someone Else", Active: true,
					Roles: []*identity.AssignedRole{{Name: "admin", Primary: true, SuperRole: true}},
				}, nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), p.ID)
				assert.Equal(t, "alice", p.Username)
				assert.Equal(t, "Alice B.", p.Name, "the mirrored value, not the returned one")
				require.Len(t, p.Roles, 1)
				assert.Equal(t, "editor", p.Roles[0].Name)
			},
		},
		{
			name:   "mirroring is off by default",
			ext:    mirrorIdentity("Alice", hashCost13),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name:   "mirroring turned off explicitly writes nothing",
			opts:   []oidc.BrokerOption{oidc.WithClaimMirror("corp", false)},
			ext:    mirrorIdentity("Alice B.", hashCost13),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name:   "mirroring for another provider does not mirror corp",
			opts:   []oidc.BrokerOption{oidc.WithClaimMirror("social", true), oidc.WithNameClaim("social", "name")},
			ext:    mirrorIdentity("Alice B.", hashCost13),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(mirrorStored(), nil)
			prov := NewMockUserProvisioner(ctrl)
			tc.expect(prov)

			var logs bytes.Buffer
			opts := append([]oidc.BrokerOption{
				oidc.WithProvisioner(prov),
				oidc.WithNameClaim("corp", "name"),
				oidc.WithPasswordClaim("corp", "credentials.password_hash"),
				oidc.WithPasswordEncoder(fastBcryptEncoder(t)),
				oidc.WithBrokerLogger(testTextLogger(&logs)),
			}, tc.opts...)
			b, err := oidc.NewBroker(brokerSeededLinks(t), users, opts...)
			require.NoError(t, err)

			p, err := b.Broker(t.Context(), tc.ext)
			tc.assert(t, p, err, logs.String())
		})
	}
}

func TestBrokerClaimMirroringOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(prov identity.UserProvisioner) []oidc.BrokerOption
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

	cases := []testCase{
		{
			name: "mirroring without a provisioner is a missing port",
			opts: func(identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithNameClaim("corp", "name"), oidc.WithClaimMirror("corp", true)}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				refused("user provisioner", "WithClaimMirror")(t, b, err)
				require.ErrorIs(t, err, identity.ErrMissingPort)
			},
		},
		{
			name: "mirroring without a claim path is refused naming the provider",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithClaimMirror("corp", true)}
			},
			assert: refused(`"corp"`),
		},
		{
			name: "mirroring with only a name claim is accepted",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{
					oidc.WithProvisioner(p), oidc.WithNameClaim("corp", "name"), oidc.WithClaimMirror("corp", true),
				}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corp"}, b.ConfiguredProviders())
			},
		},
		{
			name: "mirroring turned off needs neither a provisioner nor a path",
			opts: func(identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithClaimMirror("corp", false)}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corp"}, b.ConfiguredProviders())
			},
		},
		{
			name: "an empty provider is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithClaimMirror("", true)}
			},
			assert: refused("WithClaimMirror"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), tc.opts(NewMockUserProvisioner(ctrl))...)
			tc.assert(t, b, err)
		})
	}
}
