package oidc_test

//go:generate mockgen -destination=broker_mocks_test.go -package=oidc_test -typed github.com/kartaladev/scrty/identity UserLoader,UserProvisioner

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// The broker's interfaces the RelyingParty discovers by assertion.
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

// errIdentifyingLoad is a loader error whose text names the identity.
var errIdentifyingLoad = errors.New("row locked: (s-1, alice@corp.example, alice)")

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

// TestBrokerFlushRefusalLogs pins spec oidc-login "OIDC components flush
// their refusal logs" for the identity broker: FlushRefusalLogs reports what
// its sampler is holding back, reports nothing when there is nothing
// pending, and leaves the broker usable afterward.
func TestBrokerFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	// buildBroker returns a broker with no links seeded and no provisioning
	// enabled, so every Broker call for corpIdentity refuses with the same
	// reason, and the identity itself, under one sampling key. The clock
	// never advances, so repeated refusals land in the same window.
	buildBroker := func(t *testing.T) (b *oidc.Broker, ext oidc.ExternalIdentity, logs *bytes.Buffer) {
		t.Helper()

		logs = &bytes.Buffer{}
		b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
			oidc.WithBrokerClock(flushFixedClock()), oidc.WithBrokerLogger(testTextLogger(logs)))
		require.NoError(t, err)

		return b, brokerCorpIdentity(), logs
	}

	refuse := func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity) {
		t.Helper()

		_, err := b.Broker(t.Context(), ext)
		require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
	}

	refuseThrice := func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity) {
		t.Helper()
		for range 3 {
			refuse(t, b, ext)
		}
	}

	type testCase struct {
		name string
		act  func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity)

		// afterFlush runs after FlushRefusalLogs, only for the row proving the
		// broker still works afterward; nil for every other row.
		afterFlush func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity)

		assert func(t *testing.T, err error, logs string)
	}

	cases := []testCase{
		{
			name: "records suppressed within a window are reported by the flush with their count",
			act:  refuseThrice,
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc broker refusals suppressed")
				require.Len(t, sums, 1, "three refusals of one reason must flush to exactly one summary record")
				assert.Equal(t, 2, sums[0], "the first refusal was already written; the flush owes the other two")
			},
		},
		{
			name: "a flush with nothing pending reports nothing",
			act:  func(*testing.T, *oidc.Broker, oidc.ExternalIdentity) {},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)
				assert.Empty(t, flushSummaries(t, logs, "oidc broker refusals suppressed"))
			},
		},
		{
			name: "the component still works after a flush",
			act:  refuseThrice,
			afterFlush: func(t *testing.T, b *oidc.Broker, ext oidc.ExternalIdentity) {
				t.Helper()

				// The flush forgot the key, so a refusal for the same reason
				// afterward is written again, not held back.
				refuse(t, b, ext)
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc broker refusals suppressed")
				require.Len(t, sums, 1)
				assert.Equal(t, 2, sums[0])

				assert.Equal(t, 2, strings.Count(logs, `msg="oidc: no link for the external identity"`),
					"the refusal after the flush must be written again, not suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, ext, logs := buildBroker(t)
			tc.act(t, b, ext)
			err := b.FlushRefusalLogs()

			if tc.afterFlush != nil {
				tc.afterFlush(t, b, ext)
			}

			tc.assert(t, err, logs.String())
		})
	}
}
