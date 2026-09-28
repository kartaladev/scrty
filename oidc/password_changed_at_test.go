package oidc_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// recordedUsers collects what each provisioner call named, so a row can read
// the options the broker passed rather than trusting a matcher to see them.
type recordedUsers struct {
	mu    sync.Mutex
	users []*identity.NewUser
}

func (r *recordedUsers) record(opts []identity.UserOption) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users = append(r.users, identity.ApplyUserOptions(opts...))
}

func (r *recordedUsers) all() []*identity.NewUser {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*identity.NewUser(nil), r.users...)
}

// TestFederatedLoginNeverNamesPasswordChangedAt pins that both federated-login
// paths that write a mapped password — mirroring onto a linked user, and
// just-in-time provisioning — name the password alone. A password mirrored on
// every login must never move the password-changed time, or a user whose
// identity provider re-sends the same hash would stay fresh forever.
func TestFederatedLoginNeverNamesPasswordChangedAt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// broker builds the broker under test, wiring prov and recording every
		// provisioner call it expects into rec.
		broker func(t *testing.T, ctrl *gomock.Controller, prov *MockUserProvisioner, rec *recordedUsers) *oidc.Broker
		ext    oidc.ExternalIdentity
		assert func(t *testing.T, err error, got []*identity.NewUser)
	}

	namesPasswordAlone := func(t *testing.T, err error, got []*identity.NewUser) {
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
					oidc.WithProvisioner(prov),
					oidc.WithClaimMirror("corp", true),
					oidc.WithPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithPasswordEncoder(fastBcryptEncoder(t)),
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
					oidc.WithProvisioner(prov),
					oidc.WithJIT("corp"),
					oidc.WithPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithPasswordEncoder(fastBcryptEncoder(t)),
					oidc.WithBrokerLogger(testTextLogger(&logs)),
					oidc.WithBrokerClock(func() time.Time { return provisionClock }),
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
