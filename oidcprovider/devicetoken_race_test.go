package oidcprovider_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// These tests race device-code polls on one record. Each has its own setup shape (a barrier,
// or a held write), so they are standalone tests rather than rows.

func TestToken_DeviceConcurrentExchange(t *testing.T) {
	t.Parallel()

	f := newDeviceTokenFixture(t)
	code, record := f.seed(t, tvRefresh, approved("openid", "offline_access"))
	// Every poll reads the approved record before any spends it, so each reaches the spend.
	const polls = 8
	f.barrier = &sync.WaitGroup{}
	f.barrier.Add(polls)

	type answer struct {
		res *oidcprovider.TokenResponse
		err error
	}
	answers := make(chan answer, polls)
	var wg sync.WaitGroup
	for range polls {
		wg.Go(func() {
			res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
			answers <- answer{res: res, err: err}
		})
	}
	wg.Wait()
	close(answers)

	issued, refused := 0, 0
	for a := range answers {
		if a.err == nil {
			require.NotNil(t, a.res)
			issued++

			continue
		}
		assert.Nil(t, a.res)
		assertRefused(t, a.err, oidcprovider.CodeInvalidGrant)
		refused++
	}
	assert.Equal(t, 1, issued, "exactly one poll is answered with tokens")
	assert.Equal(t, polls-1, refused, "every other poll is answered invalid_grant")

	assert.Equal(t, oidcprovider.DeviceSpent, f.stored(t, record).State)
	g := f.grantRow(t, record.Approval.GrantFamily)
	require.NotNil(t, g, "the winner's grant is stored")
	assert.False(t, g.Revoked, "a lost spend is no replay, and revokes nothing")
	assert.Equal(t, 1, f.p.LineageHeldForTest(), "one refresh lineage is stored")
}

// TestToken_DeviceReplayRacesExchange holds the exchange between its spend and its grant write,
// replays the code there, and lets the exchange finish: the grant is created over the replay's
// revocation, and the exchange hands nothing out.
func TestToken_DeviceReplayRacesExchange(t *testing.T) {
	t.Parallel()

	f := newDeviceTokenFixture(t)
	code, record := f.seed(t, tvRefresh, approved("openid", "offline_access"))
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.grantCreating = func() {
		once.Do(func() {
			close(reached)
			<-release
		})
	}

	type answer struct {
		res *oidcprovider.TokenResponse
		err error
	}
	exchanged := make(chan answer, 1)
	go func() {
		res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
		exchanged <- answer{res: res, err: err}
	}()
	<-reached

	res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
	assert.Nil(t, res)
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)

	close(release)
	first := <-exchanged
	assert.Nil(t, first.res, "the exchange hands nothing out over the replay's revocation")
	assertRefused(t, first.err, oidcprovider.CodeInvalidGrant)

	g := f.grantRow(t, record.Approval.GrantFamily)
	require.NotNil(t, g)
	assert.True(t, g.Revoked)
	assert.Equal(t, oidcprovider.CauseCodeReplay, g.RevokeCause)
	assert.Equal(t, 0, f.p.LineageHeldForTest(), "no refresh token is stored")
}
