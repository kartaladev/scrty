package oidcprovider_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
)

// deadContextConsents refuses a dead context on Revoke, as every SQL adapter's call does.
type deadContextConsents struct{ oidcprovider.ConsentStore }

func (c deadContextConsents) Revoke(ctx context.Context, user identity.UserID, clientID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	return c.ConsentStore.Revoke(ctx, user, clientID)
}

// A sink that outlasts the revocation budget spends the report's time, and the consent's own write
// has a budget of its own, so the answer and the consent do not depend on the sink.
func TestProvider_RevokeConsent_SlowSinkLeavesTheWriteItsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		consents, err := oidcprovider.NewMemoryConsentStore()
		require.NoError(t, err)
		sink := func(_ context.Context, e event.Event) {
			if e.Name == event.GrantRevoked {
				time.Sleep(11 * time.Second)
			}
		}
		f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink), oidcprovider.WithConsentStore(deadContextConsents{consents}))
		require.NoError(t, consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile", "offline_access"}, true, exchangeFixtureStart))
		startBilling(t, f)

		require.NoError(t, f.p.RevokeConsent(t.Context(), "u-1", "billing-web"))
		_, err = consents.Load(t.Context(), "u-1", "billing-web")
		assert.Error(t, err, "the consent is forgotten")
	})
}

// A consumer may spell its cause as the provider's own. Its revocation was reported when it happened,
// and a later end finds the grant revoked at another time, so it reports nothing.
func TestProvider_Events_ConsumerCauseSpelledAsSignInEndedReportsOnce(t *testing.T) {
	log := &eventLog{}
	e := newEndFixture(t, oidcprovider.WithSecurityEvents(log.sink))
	e.online(t, e.signInOf("u-1", "https://x.example.com", "one"))
	require.NoError(t, e.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseSignInEnded)))
	e.clk.Advance(time.Minute)
	_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{User: "u-1"})
	require.NoError(t, err)

	assert.Len(t, named(log.all(), event.GrantRevoked), 1)
}

// panicsOnFirstRecord is a log handler that panics on the first record it is given.
type panicsOnFirstRecord struct {
	slog.Handler
	done *atomic.Bool
}

func (h panicsOnFirstRecord) Handle(ctx context.Context, r slog.Record) error {
	if h.done.CompareAndSwap(false, true) {
		panic("handler")
	}

	return h.Handler.Handle(ctx, r)
}

// A failure whose line a panicking handler lost is counted in lost_records, so that lines and the
// count together account for every failure.
func TestProvider_BackChannelDelivery_LineLostToAPanicIsCounted(t *testing.T) {
	logs := &lockedBuffer{}
	delivery := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error { return errors.New("no") })
	x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(delivery),
		oidcprovider.WithLogger(slog.New(panicsOnFirstRecord{Handler: slog.NewTextHandler(logs, nil), done: &atomic.Bool{}})))
	x.end(t.Context(), t, "billing-web")
	drained(t, x.p)

	records, _ := countsOf(t, logs.String())
	assert.Equal(t, 1, strings.Count(logs.String(), aFailedDelivery)+records, "the line, or a count of it")
}

// onSayingLost is a log handler running act on each record saying how much found no room.
type onSayingLost struct {
	slog.Handler
	said *atomic.Int32
	act  func(n int32)
}

func (h onSayingLost) Handle(ctx context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "found no room") {
		h.act(h.said.Add(1))
	}

	return h.Handler.Handle(ctx, r)
}

// heldUntil holds every record until release is closed.
type heldUntil struct {
	slog.Handler
	release <-chan struct{}
}

func (h heldUntil) Handle(ctx context.Context, r slog.Record) error {
	<-h.release

	return h.Handler.Handle(ctx, r)
}

// Failures that lost their line are counted, and a log handler panicking on the saying of that count
// does not lose it: it is offered again, so the lines and the count still add up to the failures.
func TestProvider_BackChannelDelivery_LostRecordsSurviveAPanicOnTheCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const failures = 1 + reportsWaiting + 3 // One held at the handler, the lane's room, and three over.
		release := make(chan struct{})
		var said atomic.Int32
		logs := &lockedBuffer{}
		counted := onSayingLost{Handler: slog.NewTextHandler(logs, nil), said: &said, act: func(n int32) {
			if n == 1 {
				panic("in the handler")
			}
		}}
		delivery := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error { return errors.New("no") })
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(delivery),
			oidcprovider.WithLogger(slog.New(heldUntil{Handler: counted, release: release})))
		for range failures {
			x.end(t.Context(), t, "billing-web")
			synctest.Wait()
		}
		close(release)
		require.NoError(t, x.p.Shutdown(t.Context()))

		records, _ := countsOf(t, logs.String())
		assert.Positive(t, records, "some lines found no room")
		assert.Equal(t, failures, strings.Count(logs.String(), aFailedDelivery)+records)
		assert.Equal(t, int32(2), said.Load(), "the count was offered again after the panic")
	})
}

// A nil from Shutdown does not stay true past a later drop: the drop's report is something to wait for
// again, so a second Shutdown waits for a log handler that holds it.
func TestProvider_BackChannelDelivery_ShutdownWaitsForALaterDropsReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		logs := &lockedBuffer{}
		x := newEnding(t, oneClient(), nil, oidcprovider.WithLogoutDelivery(&logoutRecorder{}),
			oidcprovider.WithLogger(slog.New(heldUntil{Handler: slog.NewTextHandler(logs, nil), release: release})))
		require.NoError(t, x.p.Shutdown(t.Context()), "nothing was queued")

		x.end(t.Context(), t, "billing-web") // Dropped, and its line is what the handler holds.
		synctest.Wait()

		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		require.ErrorIs(t, x.p.Shutdown(bounded), context.DeadlineExceeded, "the drop's report is still being made")

		close(release)
		require.NoError(t, x.p.Shutdown(t.Context()))
		assert.Contains(t, logs.String(), aFailedDelivery)
	})
}
