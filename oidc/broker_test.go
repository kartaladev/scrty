package oidc_test

//go:generate mockgen -destination=broker_mocks_test.go -package=oidc_test -typed github.com/kartaladev/scrty/identity UserLoader,UserProvisioner

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/id"
)

// The broker's interfaces the Manager discovers by assertion.
var (
	_ oidc.IdentityBroker                         = (*oidc.Broker)(nil)
	_ interface{ ConfiguredProviders() []string } = (*oidc.Broker)(nil)
	_ interface{ Links() oidc.LinkStore }         = (*oidc.Broker)(nil)
	_ interface{ RoleSyncProviders() []string }   = (*oidc.Broker)(nil)
)

const (
	brokerCorpIssuer   = "https://corp.example"
	brokerSocialIssuer = "https://social.example"
)

// brokerCorpIdentity is the verified identity linked to u-1 in every
// linked-resolution row.
func brokerCorpIdentity() oidc.ExternalIdentity {
	return oidc.ExternalIdentity{
		Provider: "corp", Issuer: brokerCorpIssuer, Subject: "s-1",
		Email: "alice@corp.example", EmailVerified: true,
	}
}

// brokerSeededLinks returns a memory link store holding (corp, corp issuer,
// s-1) → u-1 / alice.
func brokerSeededLinks(t *testing.T) *oidc.MemoryLinkStore {
	t.Helper()

	s := oidc.NewMemoryLinkStore()
	require.NoError(t, s.Insert(t.Context(), oidc.Link{
		Provider: "corp", Issuer: brokerCorpIssuer, Subject: "s-1",
		UserID: "u-1", Username: "alice", Email: "alice@corp.example",
	}))
	return s
}

func TestBrokerLinkedResolution(t *testing.T) {
	t.Parallel()

	const hash = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

	type testCase struct {
		name   string
		ext    oidc.ExternalIdentity
		expect func(users *MockUserLoader)
		assert func(t *testing.T, p *identity.Principal, err error, logs string)
	}

	refused := func(t *testing.T, p *identity.Principal, err error, _ string) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Nil(t, p)
	}
	details := func(id identity.UserID, active bool) *identity.Details {
		return &identity.Details{ID: id, Username: "alice", Active: active}
	}

	cases := []testCase{
		{
			name: "a linked identity resolves by reference",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(details("u-1", true), nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("u-1"), p.ID)
			},
		},
		{
			name: "a dangling link is an authentication failure",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, identity.ErrUserNotFound)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				refused(t, p, err, logs)
				assert.Contains(t, logs, "level=WARN")
				assert.Contains(t, logs, "provider=corp")
				assert.Contains(t, logs, "email_domain=corp.example")
				assert.NotContains(t, logs, "alice")
				assert.NotContains(t, logs, "u-1")
				assert.NotContains(t, logs, "s-1")
			},
		},
		{
			name: "a recycled username never reaches the loader",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				// u-1 was deleted and alice now names u-2; only the reference is asked for.
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, identity.ErrUserNotFound)
			},
			assert: refused,
		},
		{
			name: "a non-conforming loader returning another user is refused",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(details("u-2", true), nil)
			},
			assert: refused,
		},
		{
			name: "nil details are refused",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, nil)
			},
			assert: refused,
		},
		{
			name: "a disabled user is refused",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(details("u-1", false), nil)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, logs string) {
				refused(t, p, err, logs)
				assert.Contains(t, logs, "level=DEBUG")
			},
		},
		{
			name: "a loader outage is not an authentication failure",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errDBDown)
			},
			assert: func(t *testing.T, p *identity.Principal, err error, _ string) {
				require.ErrorIs(t, err, errDBDown)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, p)
			},
		},
		{
			name: "a loader error's bcrypt-shaped text is redacted",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					Return(nil, errors.New("row with password "+hash+" failed"))
			},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), hash)
				assert.Contains(t, err.Error(), "[redacted]")
			},
		},
		{
			name: "a loader error naming the identity is redacted",
			ext:  brokerCorpIdentity(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errIdentifyingLoad)
			},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.ErrorIs(t, err, errIdentifyingLoad, "the original is still reachable")
				assert.NotContains(t, err.Error(), "s-1")
				assert.NotContains(t, err.Error(), "alice")
				assert.Contains(t, err.Error(), "row locked", "the rest of the text survives")
				assert.Contains(t, err.Error(), "corp.example", "the email keeps its domain")
			},
		},
		{
			name: "an identity with no email does not redact the whole error",
			ext: func() oidc.ExternalIdentity {
				e := brokerCorpIdentity()
				e.Email = ""
				return e
			}(),
			expect: func(users *MockUserLoader) {
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errDBDown)
			},
			assert: func(t *testing.T, _ *identity.Principal, err error, _ string) {
				require.ErrorIs(t, err, errDBDown)
				assert.Contains(t, err.Error(), "db down")
				assert.NotContains(t, err.Error(), "[redacted]")
			},
		},
		{
			name: "the same email at another issuer does not resolve",
			ext: oidc.ExternalIdentity{
				Provider: "social", Issuer: brokerSocialIssuer, Subject: "s-2",
				Email: "alice@corp.example", EmailVerified: true,
			},
			expect: func(*MockUserLoader) {},
			assert: refused,
		},
		{
			name: "the same subject at another issuer does not resolve",
			ext: oidc.ExternalIdentity{
				Provider: "corp", Issuer: "https://other.example", Subject: "s-1",
				Email: "alice@corp.example", EmailVerified: true,
			},
			expect: func(*MockUserLoader) {},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			users := NewMockUserLoader(ctrl)
			tc.expect(users)

			var logs bytes.Buffer
			log := testTextLogger(&logs)

			b, err := oidc.NewBroker(brokerSeededLinks(t), users, oidc.WithBrokerLogger(log))
			require.NoError(t, err)

			p, err := b.Broker(t.Context(), tc.ext)
			tc.assert(t, p, err, logs.String())
		})
	}
}

var (
	// errDBDown is a loader outage.
	errDBDown = errors.New("db down")
	// errIdentifyingLoad is a loader error whose text names the identity.
	errIdentifyingLoad = errors.New("row locked: (s-1, alice@corp.example, alice)")
)

func TestNewBroker(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(ctrl *gomock.Controller) (*oidc.Broker, error)
		assert func(t *testing.T, b *oidc.Broker, err error)
	}

	missing := func(port string) func(t *testing.T, b *oidc.Broker, err error) {
		return func(t *testing.T, b *oidc.Broker, err error) {
			require.ErrorIs(t, err, oidc.ErrConfig)
			require.ErrorIs(t, err, identity.ErrMissingPort)
			assert.Contains(t, err.Error(), port)
			assert.Nil(t, b)
		}
	}

	cases := []testCase{
		{
			name: "a nil link store is a missing port",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(nil, NewMockUserLoader(ctrl))
			},
			assert: missing("link store"),
		},
		{
			name: "a typed-nil link store is a missing port",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				var s *oidc.MemoryLinkStore
				return oidc.NewBroker(s, NewMockUserLoader(ctrl))
			},
			assert: missing("link store"),
		},
		{
			name: "a nil user loader is a missing port",
			build: func(*gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), nil)
			},
			assert: missing("user loader"),
		},
		{
			name: "a typed-nil user loader is a missing port",
			build: func(*gomock.Controller) (*oidc.Broker, error) {
				var u *MockUserLoader
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), u)
			},
			assert: missing("user loader"),
		},
		{
			name: "a nil logger is refused",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), oidc.WithBrokerLogger(nil))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.ErrorIs(t, err, oidc.ErrConfig) },
		},
		{
			name: "a nil clock is refused",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), oidc.WithBrokerClock(nil))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.ErrorIs(t, err, oidc.ErrConfig) },
		},
		{
			name: "a typed-nil clock is refused like an untyped one",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), oidc.WithBrokerClock((*nilClock)(nil)))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.ErrorIs(t, err, oidc.ErrConfig) },
		},
		{
			name: "a consumer clock with only Now is accepted",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl),
					oidc.WithBrokerClock(fixedClock{at: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}))
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.NotNil(t, b)
			},
		},
		{
			name: "a nil identifier generator is refused",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), oidc.WithBrokerIDGenerator(nil))
			},
			assert: func(t *testing.T, _ *oidc.Broker, err error) { require.ErrorIs(t, err, oidc.ErrConfig) },
		},
		{
			name: "a typed-nil identifier generator is refused",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				var g *id.V7Generator
				return oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl), oidc.WithBrokerIDGenerator(g))
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				assert.Contains(t, err.Error(), "WithBrokerIDGenerator")
				assert.Nil(t, b)
			},
		},
		{
			name: "the broker exposes the link store it was built with",
			build: func(ctrl *gomock.Controller) (*oidc.Broker, error) {
				return oidc.NewBroker(brokerLinksMarker, NewMockUserLoader(ctrl), nil)
			},
			assert: func(t *testing.T, b *oidc.Broker, err error) {
				require.NoError(t, err)
				assert.Same(t, brokerLinksMarker, b.Links())
				assert.Empty(t, b.ConfiguredProviders())
				assert.Empty(t, b.RoleSyncProviders())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, err := tc.build(gomock.NewController(t))
			tc.assert(t, b, err)
		})
	}
}

// brokerLinksMarker is a link store whose identity a test compares.
var brokerLinksMarker = oidc.NewMemoryLinkStore()
