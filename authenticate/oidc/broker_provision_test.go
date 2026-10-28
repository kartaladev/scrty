package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// provisionHarness is what one provisioning row runs against.
type provisionHarness struct {
	links oidc.LinkStore
	users *MockUserLoader
	prov  *MockUserProvisioner
	b     *oidc.Broker
	logs  *bytes.Buffer
}

// linkOf returns the link stored for ext, or fails the row.
func (h provisionHarness) linkOf(t *testing.T, ext oidc.ExternalIdentity) *oidc.Link {
	t.Helper()
	l, err := h.links.FindByExternal(t.Context(), ext.Provider, ext.Issuer, ext.Subject)
	require.NoError(t, err)
	require.NotNil(t, l)
	return l
}

// assertNoLink fails the row when ext was linked.
func (h provisionHarness) assertNoLink(t *testing.T, ext oidc.ExternalIdentity) {
	t.Helper()
	_, err := h.links.FindByExternal(t.Context(), ext.Provider, ext.Issuer, ext.Subject)
	assert.ErrorIs(t, err, oidc.ErrLinkNotFound, "no link is created")
}

func TestBrokerProvisioning(t *testing.T) {
	t.Parallel()

	created := func(id identity.UserID, username string) *identity.Details {
		return &identity.Details{ID: id, Username: username, Active: true}
	}
	refusedProvisioning := func(t *testing.T, p *identity.Principal, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrProvisioningRefused)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Nil(t, p)
	}
	jitCorp := []oidc.BrokerOption{oidc.WithBrokerJIT("corp")}
	// jitCorpDomains enables provisioning for corp, limited to the allowed
	// email domains.
	jitCorpDomains := func(allowed ...string) []oidc.BrokerOption {
		return []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITEmailDomains("corp", allowed...)}
	}
	refusedFolded := func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
		t.Helper()

		require.ErrorIs(t, err, oidc.ErrProvisioningRefused)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Nil(t, p)
	}

	type testCase struct {
		name   string
		ext    oidc.ExternalIdentity
		opts   []oidc.BrokerOption
		links  func(t *testing.T, ctrl *gomock.Controller) oidc.LinkStore // nil means an empty memory store
		expect func(h provisionHarness)
		assert func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error)
	}

	cases := []testCase{
		{
			name:   "provisioning is off by default",
			ext:    provisionIdentity("corp", "bob@corp.example"),
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "enabled for corp: a corp identity is provisioned and linked",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWith(
					identity.WithUserName("bob@corp.example"),
					identity.WithUserEmail("bob@corp.example"),
					identity.WithUserRoles(),
				)).Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-9"), p.ID)

				l := h.linkOf(t, ext)
				assert.Equal(t, identity.UserID("u-9"), l.UserID)
				assert.Equal(t, "bob@corp.example", l.Username)
				assert.Equal(t, "bob@corp.example", l.Email)
				assert.Equal(t, "corp", l.Provider)
				assert.Equal(t, "https://corp.example", l.Issuer)
				assert.Equal(t, "s-new", l.Subject)
				assert.False(t, l.ID.IsZero(), "the link has an identifier")
				assert.Equal(t, provisionClock, l.CreatedAt)
			},
		},
		{
			name:   "enabled for corp only: a social identity is not provisioned",
			ext:    provisionIdentity("social", "bob@social.example"),
			opts:   jitCorp,
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				assert.Nil(t, p)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "a pre-created link resolves with provisioning off",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			links: func(t *testing.T, _ *gomock.Controller) oidc.LinkStore {
				s := oidc.NewMemoryLinkStore()
				require.NoError(t, s.Insert(t.Context(), oidc.Link{
					Provider: "corp", Issuer: "https://corp.example", Subject: "s-new", UserID: "u-1", Username: "bob",
				}))
				return s
			},
			expect: func(h provisionHarness) {
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(created("u-1", "bob"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), p.ID)
			},
		},
		{
			name: "an unverified email is refused",
			ext: func() oidc.ExternalIdentity {
				e := provisionIdentity("corp", "bob@corp.example")
				e.EmailVerified = false
				return e
			}(),
			opts:   jitCorp,
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "a consumer can allow unverified email",
			ext: func() oidc.ExternalIdentity {
				e := provisionIdentity("corp", "bob@corp.example")
				e.EmailVerified = false
				return e
			}(),
			opts: []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITAllowUnverifiedEmail("corp")},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", gomock.Any()).
					Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-9"), p.ID)
			},
		},
		{
			name: "allowing unverified email does not bypass the domain allowlist",
			ext: func() oidc.ExternalIdentity {
				e := provisionIdentity("corp", "bob@other.example")
				e.EmailVerified = false
				return e
			}(),
			opts: []oidc.BrokerOption{
				oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITAllowUnverifiedEmail("corp"),
				oidc.WithBrokerJITEmailDomains("corp", "example.com"),
			},
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
			},
		},
		{
			name:   "a subdomain does not match its parent",
			ext:    provisionIdentity("corp", "bob@mail.example.com"),
			opts:   []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITEmailDomains("corp", "example.com")},
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
			},
		},
		{
			name: "the domain matches case-insensitively and the email is passed as presented",
			ext:  provisionIdentity("corp", "Bob@EXAMPLE.com"),
			opts: []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITEmailDomains("corp", "example.com")},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "Bob@EXAMPLE.com", provisionedWith(
					identity.WithUserName("Bob@EXAMPLE.com"),
					identity.WithUserEmail("Bob@EXAMPLE.com"),
					identity.WithUserRoles(),
				)).Return(created("u-9", "Bob@EXAMPLE.com"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-9"), p.ID)
			},
		},
		{
			name:   "an allowlist configured empty admits no one",
			ext:    provisionIdentity("corp", "bob@corp.example"),
			opts:   []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITEmailDomains("corp")},
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
			},
		},
		{
			name:   "an identity with no email is refused",
			ext:    provisionIdentity("corp", ""),
			opts:   jitCorp,
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "a taken username is refused and nothing is linked",
			ext:  provisionIdentity("corp", "alice@corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "alice@corp.example", gomock.Any()).
					Return(nil, identity.ErrUserExists)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "a provisioner that normalizes the username yields a resolvable link",
			ext:  provisionIdentity("corp", "Bob@Corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "Bob@Corp.example", gomock.Any()).
					Return(created("u-9", "bob@corp.example"), nil)
				h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-9")).
					Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-9"), p.ID)
				assert.Equal(t, "bob@corp.example", h.linkOf(t, ext).Username)

				again, err := h.b.Broker(t.Context(), ext)
				require.NoError(t, err, "the next login resolves through the link")
				assert.Equal(t, identity.UserID("u-9"), again.ID)
			},
		},
		{
			name: "a consumer display-name claim names the user",
			ext: func() oidc.ExternalIdentity {
				e := provisionIdentity("corp", "bob@corp.example")
				e.Claims = map[string]any{"name": "Bob B."}
				return e
			}(),
			opts: []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerNameClaim("corp", "name")},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWith(
					identity.WithUserName("Bob B."),
					identity.WithUserEmail("bob@corp.example"),
					identity.WithUserRoles(),
				)).Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, _ *identity.Principal, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a nested display-name claim path resolves through objects",
			ext: func() oidc.ExternalIdentity {
				e := provisionIdentity("corp", "bob@corp.example")
				e.Claims = map[string]any{"profile": map[string]any{"display": "Robert"}}
				return e
			}(),
			opts: []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerNameClaim("corp", "profile.display")},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWith(
					identity.WithUserName("Robert"),
					identity.WithUserEmail("bob@corp.example"),
					identity.WithUserRoles(),
				)).Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, _ *identity.Principal, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a display-name claim that does not resolve to a string falls back to the email",
			ext: func() oidc.ExternalIdentity {
				e := provisionIdentity("corp", "bob@corp.example")
				e.Claims = map[string]any{"name": 42}
				return e
			}(),
			opts: []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerNameClaim("corp", "name")},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWith(
					identity.WithUserName("bob@corp.example"),
					identity.WithUserEmail("bob@corp.example"),
					identity.WithUserRoles(),
				)).Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, _ *identity.Principal, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "the default role is the provisioned user's role",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: []oidc.BrokerOption{oidc.WithBrokerJIT("corp"), oidc.WithBrokerDefaultRole("member")},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", provisionedWith(
					identity.WithUserName("bob@corp.example"),
					identity.WithUserEmail("bob@corp.example"),
					identity.WithUserRoles("member"),
				)).Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, _ *identity.Principal, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a provisioner outage is not an authentication failure",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errDBDown)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, errDBDown)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "a provisioner returning no user is a failure and nothing is linked",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				h.assertNoLink(t, ext)
			},
		},
		{
			name: "a failed link insert after the user was created fails the login and says so",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			links: func(_ *testing.T, ctrl *gomock.Controller) oidc.LinkStore {
				s := NewMockLinkStore(ctrl)
				s.EXPECT().FindByExternal(gomock.Any(), "corp", "https://corp.example", "s-new").
					Return(nil, oidc.ErrLinkNotFound)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errDiskFull)
				return s
			},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, h provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, errDiskFull)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				logs := h.logs.String()
				assert.Contains(t, logs, "level=ERROR")
				assert.Contains(t, logs, "provider=corp")
				assert.Contains(t, logs, "operator")
				assert.NotContains(t, logs, "bob@", "the email is logged only as its domain")
				assert.NotContains(t, logs, "u-9")
				assert.NotContains(t, logs, "s-new")
			},
		},
		{
			name: "a provisioner returning an inactive user is refused and nothing is linked",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&identity.Details{ID: "u-9", Username: "bob@corp.example", Active: false}, nil)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				h.assertNoLink(t, ext)
				assert.Contains(t, h.logs.String(), "level=DEBUG")
				assert.NotContains(t, h.logs.String(), "bob@")
			},
		},
		{
			name: "a link store error naming the identity is redacted in the log and the returned error",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			links: func(_ *testing.T, ctrl *gomock.Controller) oidc.LinkStore {
				s := NewMockLinkStore(ctrl)
				s.EXPECT().FindByExternal(gomock.Any(), "corp", "https://corp.example", "s-new").
					Return(nil, oidc.ErrLinkNotFound)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errIdentifyingInsert)
				return s
			},
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(created("u-9", "bob@corp.example"), nil)
			},
			assert: func(t *testing.T, h provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, errIdentifyingInsert, "the original is still reachable")
				assert.Nil(t, p)
				for _, text := range []string{h.logs.String(), err.Error()} {
					assert.NotContains(t, text, "s-new")
					assert.NotContains(t, text, "bob@corp.example")
					assert.Contains(t, text, "duplicate key", "the rest of the text survives")
					assert.Contains(t, text, "corp.example", "the email keeps its domain")
				}
			},
		},
		{
			name: "a provisioner error naming the identity is redacted",
			ext:  provisionIdentity("corp", "bob@corp.example"),
			opts: jitCorp,
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, errIdentifyingProvision)
			},
			assert: func(t *testing.T, h provisionHarness, ext oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.ErrorIs(t, err, errIdentifyingProvision)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
				assert.NotContains(t, err.Error(), "bob@corp.example")
				assert.Contains(t, err.Error(), "insert failed")
				h.assertNoLink(t, ext)
			},
		},
		{
			name:   "the Kelvin sign in the email domain is not a k in the allowlist",
			ext:    provisionIdentity("corp", "bob@K.example"),
			opts:   jitCorpDomains("k.example"),
			expect: func(provisionHarness) {},
			assert: refusedFolded,
		},
		{
			name:   "the Kelvin sign in the allowlist is not a k in the email domain",
			ext:    provisionIdentity("corp", "bob@k.example"),
			opts:   jitCorpDomains("K.example"),
			expect: func(provisionHarness) {},
			assert: refusedFolded,
		},
		{
			name:   "the long s in the email domain is not an s in the allowlist",
			ext:    provisionIdentity("corp", "bob@ſ.example"),
			opts:   jitCorpDomains("s.example"),
			expect: func(provisionHarness) {},
			assert: refusedFolded,
		},
		{
			name:   "a no-break space around the allowlist entry is not trimmed",
			ext:    provisionIdentity("corp", "bob@corp.example"),
			opts:   jitCorpDomains("corp.example "),
			expect: func(provisionHarness) {},
			assert: refusedFolded,
		},
		{
			name: "ASCII letter case is still ignored",
			ext:  provisionIdentity("corp", "Bob@CORP.example"),
			opts: jitCorpDomains("Corp.Example"),
			expect: func(h provisionHarness) {
				h.prov.EXPECT().Provision(gomock.Any(), "Bob@CORP.example", gomock.Any()).
					Return(&identity.Details{ID: "u-9", Username: "Bob@CORP.example", Active: true}, nil)
			},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-9"), p.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			h := provisionHarness{
				users: NewMockUserLoader(ctrl),
				prov:  NewMockUserProvisioner(ctrl),
				logs:  &bytes.Buffer{},
			}
			h.links = oidc.LinkStore(oidc.NewMemoryLinkStore())
			if tc.links != nil {
				h.links = tc.links(t, ctrl)
			}
			tc.expect(h)

			log := testTextLogger(h.logs)
			opts := append([]oidc.BrokerOption{
				oidc.WithBrokerProvisioner(h.prov),
				oidc.WithBrokerLogger(log),
				oidc.WithBrokerClock(clockwork.NewFakeClockAt(provisionClock)),
			}, tc.opts...)

			b, err := oidc.NewBroker(h.links, h.users, opts...)
			require.NoError(t, err)
			h.b = b

			p, err := b.Broker(t.Context(), tc.ext)
			tc.assert(t, h, tc.ext, p, err)
		})
	}
}

// Consumer-port errors whose text names the identity being provisioned.
var (
	errDiskFull             = errors.New("disk full")
	errIdentifyingInsert    = errors.New("duplicate key (subject, email)=(s-new, bob@corp.example)")
	errIdentifyingProvision = errors.New("insert failed for username bob@corp.example")
)

func TestBrokerProvisioningOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(prov identity.UserProvisioner) []oidc.BrokerOption
		assert func(t *testing.T, b *oidc.Broker, err error)
	}

	refused := func(fragments ...string) func(t *testing.T, b *oidc.Broker, err error) {
		return func(t *testing.T, b *oidc.Broker, err error) {
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, b)
			for _, f := range fragments {
				assert.Contains(t, err.Error(), f)
			}
		}
	}

	cases := []testCase{
		{
			name: "provisioning without a provisioner is a missing port",
			opts: func(identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerJIT("corp")}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				refused("user provisioner")(t, b, err)
				require.ErrorIs(t, err, identity.ErrMissingPort)
			},
		},
		{
			name: "a nil provisioner is refused",
			opts: func(identity.UserProvisioner) []oidc.BrokerOption {
				var p *MockUserProvisioner
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p)}
			},
			assert: refused("WithBrokerProvisioner"),
		},
		{
			name: "an empty provider name is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerJIT("")}
			},
			assert: refused("WithBrokerJIT"),
		},
		{
			name: "an empty allowlist entry is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITEmailDomains("corp", "")}
			},
			assert: refused("WithBrokerJITEmailDomains"),
		},
		{
			name: "allowing unverified email for a provider without provisioning is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITAllowUnverifiedEmail("social")}
			},
			assert: refused("social"),
		},
		{
			name: "an allowlist for a provider without provisioning is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerJITEmailDomains("social", "example.com")}
			},
			assert: refused("social"),
		},
		{
			name: "an empty provider for the name claim is refused",
			opts: func(_ identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerNameClaim("", "name")}
			},
			assert: refused("WithBrokerNameClaim"),
		},
		{
			name: "an empty name claim path is refused",
			opts: func(_ identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerNameClaim("corp", "")}
			},
			assert: refused("WithBrokerNameClaim"),
		},
		{
			name: "an empty default role is refused",
			opts: func(_ identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerDefaultRole("")}
			},
			assert: refused("WithBrokerDefaultRole"),
		},
		{
			name: "an unregistered provider is listed for the manager to refuse",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerJIT("corpp")}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corpp"}, b.ConfiguredProviders())
			},
		},
		{
			name: "configured providers are deduplicated in the order first named",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{
					oidc.WithBrokerProvisioner(p), oidc.WithBrokerJIT("corp"), oidc.WithBrokerJITEmailDomains("corp", "corp.example"),
					oidc.WithBrokerNameClaim("social", "name"), oidc.WithBrokerJITAllowUnverifiedEmail("corp"),
				}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				got := b.ConfiguredProviders()
				require.Equal(t, []string{"corp", "social"}, got)
				got[0] = "changed"
				assert.Equal(t, []string{"corp", "social"}, b.ConfiguredProviders(), "the slice is the caller's own")
			},
		},
		{
			name: "mirroring without a provisioner is a missing port",
			opts: func(identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerNameClaim("corp", "name"), oidc.WithBrokerClaimMirror("corp", true)}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				refused("user provisioner", "WithBrokerClaimMirror")(t, b, err)
				require.ErrorIs(t, err, identity.ErrMissingPort)
			},
		},
		{
			name: "mirroring without a claim path is refused naming the provider",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerClaimMirror("corp", true)}
			},
			assert: refused(`"corp"`),
		},
		{
			name: "mirroring with only a name claim is accepted",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{
					oidc.WithBrokerProvisioner(p), oidc.WithBrokerNameClaim("corp", "name"), oidc.WithBrokerClaimMirror("corp", true),
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
				return []oidc.BrokerOption{oidc.WithBrokerClaimMirror("corp", false)}
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"corp"}, b.ConfiguredProviders())
			},
		},
		{
			name: "an empty provider is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithBrokerProvisioner(p), oidc.WithBrokerClaimMirror("", true)}
			},
			assert: refused("WithBrokerClaimMirror"),
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

// Standalone from TestBrokerProvisioning: every row resolves a seeded link with mirroring wired.
func TestBrokerClaimMirroring(t *testing.T) {
	t.Parallel()

	mirrorCorp := oidc.WithBrokerClaimMirror("corp", true)

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
			opts:   []oidc.BrokerOption{oidc.WithBrokerClaimMirror("corp", false)},
			ext:    mirrorIdentity("Alice B.", hashCost13),
			expect: func(*MockUserProvisioner) {},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name:   "mirroring for another provider does not mirror corp",
			opts:   []oidc.BrokerOption{oidc.WithBrokerClaimMirror("social", true), oidc.WithBrokerNameClaim("social", "name")},
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
				oidc.WithBrokerProvisioner(prov),
				oidc.WithBrokerNameClaim("corp", "name"),
				oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
				oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
				oidc.WithBrokerLogger(testTextLogger(&logs)),
			}, tc.opts...)
			b, err := oidc.NewBroker(brokerSeededLinks(t), users, opts...)
			require.NoError(t, err)

			p, err := b.Broker(t.Context(), tc.ext)
			tc.assert(t, p, err, logs.String())
		})
	}
}

// recordedUsers collects what each provisioner call named, so a row can read
// the options the broker passed rather than trusting a matcher to see them.
type recordedUsers struct {
	mu    sync.Mutex
	users []*identity.UserChange
}

func (r *recordedUsers) record(opts []identity.UserOption) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users = append(r.users, identity.ApplyUserOptions(opts...))
}

func (r *recordedUsers) all() []*identity.UserChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*identity.UserChange(nil), r.users...)
}

// TestFederatedLoginNeverNamesPasswordChangedAt pins that both federated-login
// paths that write a mapped password — mirroring onto a linked user, and
// just-in-time provisioning — name the password alone. A password mirrored on
// every login must never move the password-changed time, or a user whose
// identity provider re-sends the same hash would stay fresh forever.
// Standalone from TestBrokerProvisioning: each row builds its own broker and records every provisioner call.
func TestFederatedLoginNeverNamesPasswordChangedAt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// broker builds the broker under test, wiring prov and recording every
		// provisioner call it expects into rec.
		broker func(t *testing.T, ctrl *gomock.Controller, prov *MockUserProvisioner, rec *recordedUsers) *oidc.Broker
		ext    oidc.ExternalIdentity
		assert func(t *testing.T, err error, got []*identity.UserChange)
	}

	namesPasswordAlone := func(t *testing.T, err error, got []*identity.UserChange) {
		t.Helper()
		require.NoError(t, err)
		require.Len(t, got, 1, "exactly one provisioner call writes the mapped password")
		assert.True(t, got[0].IsSet(identity.FieldPassword), "the mapped password is written")
		assert.False(t, got[0].IsSet(identity.FieldPasswordChangedAt),
			"a federated login must never name the password-changed time")
	}

	cases := []testCase{
		{
			name: "mirroring a changed hash onto a linked user",
			broker: func(t *testing.T, ctrl *gomock.Controller, prov *MockUserProvisioner, rec *recordedUsers) *oidc.Broker {
				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(mirrorStored(), nil)
				prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, opts ...identity.UserOption) (*identity.Details, error) {
						rec.record(opts)
						d := mirrorStored()
						d.Password = []byte(hashCost13)
						return d, nil
					})

				var logs bytes.Buffer
				b, err := oidc.NewBroker(brokerSeededLinks(t), users,
					oidc.WithBrokerProvisioner(prov),
					oidc.WithBrokerClaimMirror("corp", true),
					oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
					oidc.WithBrokerLogger(testTextLogger(&logs)),
				)
				require.NoError(t, err)
				return b
			},
			ext:    mirrorIdentity("Alice", hashCost13),
			assert: namesPasswordAlone,
		},
		{
			name: "just-in-time provisioning with a mapped hash",
			broker: func(t *testing.T, ctrl *gomock.Controller, prov *MockUserProvisioner, rec *recordedUsers) *oidc.Broker {
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", gomock.Any()).
					DoAndReturn(func(_ context.Context, username string, opts ...identity.UserOption) (*identity.Details, error) {
						rec.record(opts)
						return &identity.Details{ID: "u-9", Username: username, Active: true}, nil
					})

				var logs bytes.Buffer
				b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl),
					oidc.WithBrokerProvisioner(prov),
					oidc.WithBrokerJIT("corp"),
					oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
					oidc.WithBrokerLogger(testTextLogger(&logs)),
					oidc.WithBrokerClock(clockwork.NewFakeClockAt(provisionClock)),
				)
				require.NoError(t, err)
				return b
			},
			ext:    passwordClaimIdentity("s-1", hashCost12),
			assert: namesPasswordAlone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			prov := NewMockUserProvisioner(ctrl)
			rec := &recordedUsers{}
			b := tc.broker(t, ctrl, prov, rec)

			_, err := b.Broker(t.Context(), tc.ext)
			tc.assert(t, err, rec.all())
		})
	}
}
