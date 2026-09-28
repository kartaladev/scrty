package oidc_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// provisionClock is the broker's clock in every provisioning row.
var provisionClock = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)

// allProvisionFields is every field a Provision or Update option can name.
// The matcher loops over it rather than restating the list. A field listed
// here without a case in provisionFieldValue panics; a new identity.Field
// constant that is never added here is not compared at all, because the
// identity package exports no list of every field to check this one against.
var allProvisionFields = []identity.Field{
	identity.FieldName,
	identity.FieldEmail,
	identity.FieldRoles,
	identity.FieldOrganization,
	identity.FieldPassword,
	identity.FieldPasswordChangedAt,
}

// provisionFieldValue returns u's value for f, in the shape the matcher
// compares. Roles is clipped to a fresh backing array so two equal-content
// slices with different capacities still compare equal.
func provisionFieldValue(u *identity.NewUser, f identity.Field) any {
	switch f {
	case identity.FieldName:
		return u.Name
	case identity.FieldEmail:
		return u.Email
	case identity.FieldRoles:
		return slices.Clip(append([]string{}, u.Roles...))
	case identity.FieldOrganization:
		return u.Organization
	case identity.FieldPassword:
		return u.Password
	case identity.FieldPasswordChangedAt:
		return u.PasswordChangedAt
	default:
		panic(fmt.Sprintf("provisionFieldValue: unhandled field %d", f))
	}
}

// brokerUserOptionsMatcher matches the variadic options of a Provision call
// by what they name: it applies both sides with identity.ApplyUserOptions and
// compares every field's IsSet flag and, where set, its value.
type brokerUserOptionsMatcher struct{ want *identity.NewUser }

// provisionedWith matches Provision options naming exactly opts.
func provisionedWith(opts ...identity.UserOption) gomock.Matcher {
	return brokerUserOptionsMatcher{want: identity.ApplyUserOptions(opts...)}
}

func (m brokerUserOptionsMatcher) Matches(x any) bool {
	opts, ok := x.([]identity.UserOption)
	if !ok {
		return false
	}
	got := identity.ApplyUserOptions(opts...)
	for _, f := range allProvisionFields {
		if got.IsSet(f) != m.want.IsSet(f) {
			return false
		}
		if m.want.IsSet(f) && !reflect.DeepEqual(provisionFieldValue(got, f), provisionFieldValue(m.want, f)) {
			return false
		}
	}
	return true
}

func (m brokerUserOptionsMatcher) String() string {
	return fmt.Sprintf("names name=%q email=%q roles=%q (and only the fields set on %+v)",
		m.want.Name, m.want.Email, m.want.Roles, *m.want)
}

// provisionIdentity is an unlinked, verified identity from provider.
func provisionIdentity(provider, email string) oidc.ExternalIdentity {
	return oidc.ExternalIdentity{
		Provider: provider, Issuer: "https://" + provider + ".example", Subject: "s-new",
		Email: email, EmailVerified: true, Claims: map[string]any{},
	}
}

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
	jitCorp := []oidc.BrokerOption{oidc.WithJIT("corp")}

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
			opts: []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithJITAllowUnverifiedEmail("corp")},
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
				oidc.WithJIT("corp"), oidc.WithJITAllowUnverifiedEmail("corp"),
				oidc.WithJITEmailDomains("corp", "example.com"),
			},
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
			},
		},
		{
			name:   "a subdomain does not match its parent",
			ext:    provisionIdentity("corp", "bob@mail.example.com"),
			opts:   []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithJITEmailDomains("corp", "example.com")},
			expect: func(provisionHarness) {},
			assert: func(t *testing.T, _ provisionHarness, _ oidc.ExternalIdentity, p *identity.Principal, err error) {
				refusedProvisioning(t, p, err)
			},
		},
		{
			name: "the domain matches case-insensitively and the email is passed as presented",
			ext:  provisionIdentity("corp", "Bob@EXAMPLE.com"),
			opts: []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithJITEmailDomains("corp", "example.com")},
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
			opts:   []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithJITEmailDomains("corp")},
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
			opts: []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithNameClaim("corp", "name")},
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
			opts: []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithNameClaim("corp", "profile.display")},
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
			opts: []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithNameClaim("corp", "name")},
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
			opts: []oidc.BrokerOption{oidc.WithJIT("corp"), oidc.WithDefaultRole("member")},
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
				oidc.WithProvisioner(h.prov),
				oidc.WithBrokerLogger(log),
				oidc.WithBrokerClock(func() time.Time { return provisionClock }),
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
			opts: func(identity.UserProvisioner) []oidc.BrokerOption { return []oidc.BrokerOption{oidc.WithJIT("corp")} },
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				refused("user provisioner")(t, b, err)
				require.ErrorIs(t, err, identity.ErrMissingPort)
			},
		},
		{
			name: "a nil provisioner is refused",
			opts: func(identity.UserProvisioner) []oidc.BrokerOption {
				var p *MockUserProvisioner
				return []oidc.BrokerOption{oidc.WithProvisioner(p)}
			},
			assert: refused("WithProvisioner"),
		},
		{
			name: "an empty provider name is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithJIT("")}
			},
			assert: refused("WithJIT"),
		},
		{
			name: "an empty allowlist entry is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithJIT("corp"), oidc.WithJITEmailDomains("corp", "")}
			},
			assert: refused("WithJITEmailDomains"),
		},
		{
			name: "allowing unverified email for a provider without provisioning is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithJIT("corp"), oidc.WithJITAllowUnverifiedEmail("social")}
			},
			assert: refused("social"),
		},
		{
			name: "an allowlist for a provider without provisioning is refused",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithJITEmailDomains("social", "example.com")}
			},
			assert: refused("social"),
		},
		{
			name: "an empty provider for the name claim is refused",
			opts: func(_ identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithNameClaim("", "name")}
			},
			assert: refused("WithNameClaim"),
		},
		{
			name: "an empty name claim path is refused",
			opts: func(_ identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithNameClaim("corp", "")}
			},
			assert: refused("WithNameClaim"),
		},
		{
			name: "an empty default role is refused",
			opts: func(_ identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithDefaultRole("")}
			},
			assert: refused("WithDefaultRole"),
		},
		{
			name: "an unregistered provider is listed for the manager to refuse",
			opts: func(p identity.UserProvisioner) []oidc.BrokerOption {
				return []oidc.BrokerOption{oidc.WithProvisioner(p), oidc.WithJIT("corpp")}
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
					oidc.WithProvisioner(p), oidc.WithJIT("corp"), oidc.WithJITEmailDomains("corp", "corp.example"),
					oidc.WithNameClaim("social", "name"), oidc.WithJITAllowUnverifiedEmail("corp"),
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
