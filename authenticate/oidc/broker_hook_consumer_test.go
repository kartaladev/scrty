package oidc_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
)

// consumerLinkStore is a consumer's own link store, written against the
// LinkStore port alone: it wraps a memory store and counts the listings.
type consumerLinkStore struct {
	inner *oidc.MemoryLinkStore
	lists atomic.Int32
}

func (s *consumerLinkStore) FindByExternal(ctx context.Context, provider, issuer, subject string) (*oidc.Link, error) {
	return s.inner.FindByExternal(ctx, provider, issuer, subject)
}

func (s *consumerLinkStore) Insert(ctx context.Context, l oidc.Link) error {
	return s.inner.Insert(ctx, l)
}

func (s *consumerLinkStore) DeleteByUser(ctx context.Context, u identity.UserID) (int, error) {
	return s.inner.DeleteByUser(ctx, u)
}

func (s *consumerLinkStore) ListByUser(ctx context.Context, u identity.UserID) ([]oidc.Link, error) {
	s.lists.Add(1)
	return s.inner.ListByUser(ctx, u)
}

func (s *consumerLinkStore) DeleteLink(ctx context.Context, l oidc.Link) (bool, error) {
	return s.inner.DeleteLink(ctx, l)
}

// A sign-in hook over a consumer's link store, with several links per user
// not allowed, builds, and its one-link rule lists through that store.
func TestNewBroker_HookOverConsumerLinkStore(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	links := &consumerLinkStore{inner: oidc.NewMemoryLinkStore()}
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, u identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: u, Username: "user-" + string(u), Active: true}, nil
		}).AnyTimes()
	hook := func(context.Context, oidc.ExternalIdentity, oidc.Upstream, identity.UserID) (oidc.SignInDecision, error) {
		return oidc.SignInDecision{User: "u-1"}, nil
	}

	b, err := oidc.NewBroker(links, users, oidc.WithBrokerSignInHook("corp", hook))
	require.NoError(t, err)

	p, err := b.BrokerUpstream(t.Context(), brokerCorpIdentity(), oidc.NewUpstreamForTest("at", "s-1", nil, nil))
	require.NoError(t, err)
	assert.Equal(t, identity.UserID("u-1"), p.ID)
	assert.Positive(t, links.lists.Load(), "the one-link rule lists through the consumer's store")
}
