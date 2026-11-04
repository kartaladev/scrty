package oidcprovider_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// eventLog is a sink that remembers what it was given.
type eventLog struct {
	mu  sync.Mutex
	got []event.Event
}

// sink implements event.Sink.
func (l *eventLog) sink(_ context.Context, e event.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.got = append(l.got, e)
}

func (l *eventLog) all() []event.Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]event.Event(nil), l.got...)
}

// named is the events with this name, in the order they arrived.
func named(got []event.Event, name string) []event.Event {
	var out []event.Event
	for _, e := range got {
		if e.Name == name {
			out = append(out, e)
		}
	}

	return out
}

// namesOf is each event's name, in the order they arrived.
func namesOf(got []event.Event) []string {
	out := make([]string, 0, len(got))
	for _, e := range got {
		out = append(out, e.Name)
	}

	return out
}

// awaitEvent waits for n events with this name, for those reported on a goroutine of their own.
func awaitEvent(t *testing.T, l *eventLog, name string, n int) {
	t.Helper()

	require.Eventually(t, func() bool { return len(named(l.all(), name)) >= n }, 10*time.Second, time.Millisecond,
		"%d %s events", n, name)
}

// reportsOf asserts the event names the client and user it concerns, and the outcome.
func reportsOf(t *testing.T, e event.Event, client string, user identity.UserID, outcome string) {
	t.Helper()

	assert.Equal(t, client, e.Client, "%s: client", e.Name)
	assert.Equal(t, user, e.User, "%s: user", e.Name)
	assert.Equal(t, outcome, e.Outcome, "%s: outcome", e.Name)
	assert.False(t, e.At.IsZero(), "%s: when", e.Name)
}

// TestProvider_Events pins one event per outcome the security-events spec lists, what each names, and
// that nothing is reported twice. Each row builds its own provider over the sink it is handed, does
// what the row is about, and waits for what a worker reports.
func TestProvider_Events(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, sink event.Sink)
		assert func(t *testing.T, got []event.Event)
	}

	// pastGrace is a refresh whose old token is presented after its window: reuse.
	pastGrace := func(t *testing.T, f *refreshFixture) (*refreshScene, string) {
		t.Helper()

		s := startBilling(t, f)
		stale := s.first.RefreshToken
		s.newest = assertRefreshWorks(t, f, s, stale).RefreshToken
		f.clk.Advance(30 * time.Second)

		return s, stale
	}
	wrongSecret := func(client string) oidcprovider.ClientCredentials {
		return oidcprovider.ClientCredentials{Authorization: basic(client, "not-the-secret-0123456789abcdef")}
	}
	// authenticate presents creds to a provider that holds the fixture's clients.
	authenticate := func(creds oidcprovider.ClientCredentials) func(*testing.T, event.Sink) {
		return func(t *testing.T, sink event.Sink) {
			t.Helper()

			f := newExchangeFixture(t, oidcprovider.WithSecurityEvents(sink))
			_, _ = f.p.AuthenticateClient(t.Context(), creds)
		}
	}
	answered := func(answer func(*oidcprovider.ResumeInput)) func(*testing.T, event.Sink) {
		return func(t *testing.T, sink event.Sink) {
			t.Helper()

			f := newExchangeFixture(t, oidcprovider.WithSecurityEvents(sink))
			signIn := testSignIn(f.parkFixture, "u-1")
			r, _ := atConsent(t, f.parkFixture, nil, signIn)
			in := r.input(&signIn)
			answer(&in)
			_, err := f.p.Resume(t.Context(), in)
			require.NoError(t, err)
		}
	}
	// revokedBy ends the grants with the cause its call names.
	onlyRevoked := func(t *testing.T, got []event.Event, cause string) {
		t.Helper()

		require.Equal(t, []string{event.GrantCreated, event.GrantRevoked}, namesOf(got))
		reportsOf(t, got[1], "billing-web", "u-1", event.OutcomeSuccess)
		assert.Equal(t, cause, got[1].Cause)
	}

	cases := []testCase{
		{
			name: "a grant created for an exchanged code",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				startBilling(t, f)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.GrantCreated}, namesOf(got), "remembered consent asks nothing")
				reportsOf(t, got[0], "billing-web", "u-1", event.OutcomeSuccess)
				assert.True(t, got[0].At.Equal(exchangeFixtureStart), "read from the provider's clock")
				assert.Empty(t, got[0].Cause)
			},
		},
		{
			name: "consent given",
			run:  answered(func(in *oidcprovider.ResumeInput) { answerWith(in, "openid") }),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.ConsentGiven}, namesOf(got))
				reportsOf(t, got[0], "billing-web", "u-1", event.OutcomeSuccess)
			},
		},
		{
			name: "consent denied",
			run:  answered(func(in *oidcprovider.ResumeInput) { in.Answer = &oidcprovider.ConsentAnswer{Deny: true} }),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.ConsentDenied}, namesOf(got))
				reportsOf(t, got[0], "billing-web", "u-1", event.OutcomeFailure)
			},
		},
		{
			name: "consent revoked, with the grants it ended",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				startBilling(t, f)
				require.NoError(t, f.p.RevokeConsent(t.Context(), "u-1", "billing-web"))
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.ElementsMatch(t, []string{event.GrantCreated, event.GrantRevoked, event.ConsentRevoked}, namesOf(got))
				reportsOf(t, named(got, event.ConsentRevoked)[0], "billing-web", "u-1", event.OutcomeSuccess)
				revoked := named(got, event.GrantRevoked)[0]
				reportsOf(t, revoked, "billing-web", "u-1", event.OutcomeSuccess)
				assert.Equal(t, string(oidcprovider.CauseConsentRevoked), revoked.Cause)
			},
		},
		{
			name: "a consent revocation that finds nothing reports nothing",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				require.ErrorIs(t, f.p.RevokeConsent(t.Context(), "u-1", "billing-web"), oidcprovider.ErrForeignConsent)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Empty(t, got)
			},
		},
		{
			name: "a wrong secret refuses the client authentication, naming the client the registry holds",
			run:  authenticate(wrongSecret("billing-web")),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.ClientAuthRefused}, namesOf(got))
				reportsOf(t, got[0], "billing-web", "", event.OutcomeFailure)
			},
		},
		{
			name: "an unknown client is refused, and named nowhere",
			run:  authenticate(wrongSecret("stranger")),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.ClientAuthRefused}, namesOf(got))
				reportsOf(t, got[0], "", "", event.OutcomeFailure)
			},
		},
		{
			name: "credentials that name no client are refused",
			run:  authenticate(oidcprovider.ClientCredentials{}),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.ClientAuthRefused}, namesOf(got))
				reportsOf(t, got[0], "", "", event.OutcomeFailure)
			},
		},
		{
			name: "a credential in the query is a malformed request, and reports nothing",
			run: authenticate(oidcprovider.ClientCredentials{
				Authorization: basic("billing-web", exchangeSecret), Query: url.Values{"client_secret": {"x"}},
			}),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Empty(t, got)
			},
		},
		{
			name: "a client that authenticates reports nothing",
			run:  authenticate(credsOf("billing-web")),
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Empty(t, got)
			},
		},
		{
			name: "a code replayed reports the replay and the revocation for it",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issue(t)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				_, err = f.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.ElementsMatch(t, []string{event.GrantCreated, event.CodeReplayed, event.GrantRevoked}, namesOf(got))
				reportsOf(t, named(got, event.CodeReplayed)[0], "billing-web", "u-1", event.OutcomeFailure)
				revoked := named(got, event.GrantRevoked)[0]
				reportsOf(t, revoked, "billing-web", "u-1", event.OutcomeSuccess)
				assert.Equal(t, string(oidcprovider.CauseCodeReplay), revoked.Cause)
			},
		},
		{
			name: "a refresh token reused past its grace reports the reuse and the revocation for it, once each",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s, stale := pastGrace(t, f)
				assertRefreshRefused(t, f, s, stale)
				assertRefreshRefused(t, f, s, stale)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.ElementsMatch(t, []string{event.GrantCreated, event.RefreshReused, event.GrantRevoked}, namesOf(got),
					"the second presentation finds the grant revoked, and is no new reuse")
				reportsOf(t, named(got, event.RefreshReused)[0], "billing-web", "u-1", event.OutcomeFailure)
				revoked := named(got, event.GrantRevoked)[0]
				reportsOf(t, revoked, "billing-web", "u-1", event.OutcomeSuccess)
				assert.Equal(t, string(oidcprovider.CauseReuse), revoked.Cause)
			},
		},
		{
			name: "a reuse only the lineage manager sees, a successor having moved on inside the grace, is reported once",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := startBilling(t, f)
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				assertRefreshWorks(t, f, s, second)
				f.clk.Advance(defaultSuccessorWindow)
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.ElementsMatch(t, []string{event.GrantCreated, event.RefreshReused, event.GrantRevoked}, namesOf(got))
				reportsOf(t, named(got, event.RefreshReused)[0], "billing-web", "u-1", event.OutcomeFailure)
			},
		},
		{
			name: "a reuse whose family cannot be deleted is still reported once",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s, stale := pastGrace(t, f)
				f.lineage.failDelete.Store(true)
				_, err := f.p.Token(t.Context(), s.again(stale))
				assertDependencyFailure(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.ElementsMatch(t, []string{event.GrantCreated, event.RefreshReused, event.GrantRevoked}, namesOf(got))
			},
		},
		{
			name: "a reuse whose row cannot be marked reports nothing, as nothing was revoked",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s, stale := pastGrace(t, f)
				f.grants.failRevoke.Store(true)
				_, err := f.p.Token(t.Context(), s.again(stale))
				assertDependencyFailure(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated}, namesOf(got))
			},
		},
		{
			name: "a grant revoked by its client",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := startBilling(t, f)
				require.NoError(t, f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)))
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				onlyRevoked(t, got, string(oidcprovider.CauseRevokedByClient))
			},
		},
		{
			name: "a grant revoked for a user, with the cause the consumer named",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				startBilling(t, f)
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", "recovery"))
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", "recovery"), "the second changes nothing")
			},
			assert: func(t *testing.T, got []event.Event) { t.Helper(); onlyRevoked(t, got, "recovery") },
		},
		{
			name: "a grant revoked because its user is gone",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := startBilling(t, f)
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				onlyRevoked(t, got, string(oidcprovider.CauseUserDisabled))
			},
		},
		{
			name: "the grants a sign-in's end revokes, and not the offline one that survives",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				e := newEndFixture(t, oidcprovider.WithSecurityEvents(sink))
				online := e.signInOf("u-1", "https://x.example.com", "one")
				e.online(t, online)
				e.offline(t, e.signInOf("u-1", "https://x.example.com", "two"))
				_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{User: "u-1"})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Len(t, named(got, event.GrantCreated), 2)
				require.Len(t, named(got, event.GrantRevoked), 1, "only the grant that ends with its sign-in")
				revoked := named(got, event.GrantRevoked)[0]
				reportsOf(t, revoked, "billing-web", "u-1", event.OutcomeSuccess)
				assert.Equal(t, string(oidcprovider.CauseSignInEnded), revoked.Cause)
			},
		},
		{
			name: "a failed delivery names the client, the user and the reason, and none of its text",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				delivery := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
					return errors.New("the relying party's own text")
				})
				x := newEnding(t, oneClient(), nil, oidcprovider.WithSecurityEvents(sink), oidcprovider.WithLogoutDelivery(delivery))
				x.end(t.Context(), t, "billing-web")
				drained(t, x.p)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				failed := named(got, event.LogoutDeliveryFailed)
				require.Len(t, failed, 1)
				reportsOf(t, failed[0], "billing-web", "u-1", event.OutcomeFailure)
				assert.Equal(t, "delivery", failed[0].Cause)
				assert.NotContains(t, fmt.Sprintf("%+v", failed[0]), "the relying party's own text")
			},
		},
		{
			name: "a delivery that succeeds reports no failure",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				delivery := oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error { return nil })
				x := newEnding(t, oneClient(), nil, oidcprovider.WithSecurityEvents(sink), oidcprovider.WithLogoutDelivery(delivery))
				x.end(t.Context(), t, "billing-web")
				drained(t, x.p)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Empty(t, named(got, event.LogoutDeliveryFailed))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var log eventLog
			tc.run(t, log.sink)
			tc.assert(t, log.all())
		})
	}
}

// TestProvider_Events_Delivery pins that a drop reports a failed delivery without holding the logout,
// whatever the sink does, and reports only a client that had someone to tell.
func TestProvider_Events_Delivery(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// sink wraps the recording sink, and release lets go of what it holds.
		sink func(log *eventLog) (event.Sink, func())
	}

	cases := []testCase{
		{
			name: "a drop reports a client with a URI, and a client with none is not reported",
			sink: func(log *eventLog) (event.Sink, func()) { return log.sink, func() {} },
		},
		{
			name: "a sink that never returns cannot hold the logout",
			sink: func(log *eventLog) (event.Sink, func()) {
				held := make(chan struct{})

				return func(ctx context.Context, e event.Event) {
					log.sink(ctx, e)
					if e.Name == event.LogoutDeliveryFailed {
						<-held
					}
				}, func() { close(held) }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var log eventLog
			sink, release := tc.sink(&log)
			g := newGate(true)
			clients := append(oneClient(), listeningClient("quiet", ""))
			x := newEnding(t, clients, nil,
				oidcprovider.WithSecurityEvents(sink), oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 1))
			ctx := context.WithoutCancel(t.Context())

			x.end(ctx, t, "billing-web") // takes the worker
			require.Eventually(t, func() bool { return g.entered.Load() == 1 }, 10*time.Second, time.Millisecond)
			x.end(ctx, t, "billing-web") // takes the queue's one place

			// The two that follow are dropped, and run where a sink that held them would show.
			end := func(client string) error {
				family, err := id.NewV7Generator().NewID()
				if err != nil {
					return err
				}
				x.grants.push(family, []oidcprovider.Grant{{ClientID: client, User: "u-1", SignInFamily: family}})
				_, err = x.p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: family})

				return err
			}
			ended := make(chan error, 1)
			go func() {
				ended <- errors.Join(end("quiet"), end("billing-web"))
			}()
			select {
			case err := <-ended:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("the logouts were held by the sink")
			}

			awaitEvent(t, &log, event.LogoutDeliveryFailed, 1)
			release()
			close(g.open)
			drained(t, x.p)

			failed := named(log.all(), event.LogoutDeliveryFailed)
			require.Len(t, failed, 1, "the quiet client's drop says nothing")
			reportsOf(t, failed[0], "billing-web", "u-1", event.OutcomeFailure)
			assert.Equal(t, "queue_full", failed[0].Cause)
		})
	}
}

// TestProvider_Events_Wiring pins how the sink is wired and what it cannot change.
func TestProvider_Events_Wiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	panics := func(context.Context, event.Event) { panic("the sink's own secret panic value") }
	// replay is a code presented twice, and what became of the grant.
	replay := func(t *testing.T, f *refreshFixture) (*oidcprovider.Grant, error) {
		t.Helper()

		c := f.issue(t)
		_, err := f.p.Token(t.Context(), billingExchange(c, nil))
		require.NoError(t, err)
		_, err = f.p.Token(t.Context(), billingExchange(c, nil))

		return grantOf(t, f.exchangeFixture, c), err
	}

	cases := []testCase{
		{
			name: "with no sink a replayed code is still refused, and still revokes",
			assert: func(t *testing.T) {
				t.Helper()
				f := newRefreshFixture(t)
				grant, err := replay(t, f)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grant.Revoked)
				assert.Equal(t, oidcprovider.CauseCodeReplay, grant.RevokeCause)
			},
		},
		{
			name: "a sink that panics changes no outcome, and is logged without what it panicked with",
			assert: func(t *testing.T) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(panics))
				grant, err := replay(t, f)
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.True(t, grant.Revoked)
				assert.Equal(t, oidcprovider.CauseCodeReplay, grant.RevokeCause)
				assert.Contains(t, f.logs.String(), eventsink.MsgSinkPanicked)
				assert.NotContains(t, f.logs.String(), "the sink's own secret panic value")
			},
		},
		{
			name: "a nil sink is a configuration error",
			assert: func(t *testing.T) {
				t.Helper()
				_, err := oidcprovider.New(validDeps(t), oidcprovider.WithSecurityEvents(nil))
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.Contains(t, err.Error(), "WithSecurityEvents")
			},
		},
		{
			name: "the option given twice is a configuration error",
			assert: func(t *testing.T) {
				t.Helper()
				var log eventLog
				_, err := oidcprovider.New(validDeps(t), oidcprovider.WithSecurityEvents(log.sink), oidcprovider.WithSecurityEvents(log.sink))
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.Contains(t, err.Error(), "WithSecurityEvents")
			},
		},
		{
			name: "on a request a chain reports for, the chain's delivery gets the event and the provider's own sink none",
			assert: func(t *testing.T) {
				t.Helper()
				var own, chain eventLog
				f := newExchangeFixture(t, oidcprovider.WithSecurityEvents(own.sink))
				ctx := eventsink.With(t.Context(), chain.sink)
				_, err := f.p.AuthenticateClient(ctx, oidcprovider.ClientCredentials{Authorization: basic("billing-web", "wrong")})
				require.Error(t, err)
				assert.Equal(t, []string{event.ClientAuthRefused}, namesOf(chain.all()))
				assert.Empty(t, own.all())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// capture is everything the provider says where a consumer could read it: its log lines, its events
// and the text of what it returns.
type capture struct {
	logs   *lockedBuffer
	events eventLog

	mu   sync.Mutex
	errs []error
}

func newCapture() *capture { return &capture{logs: &lockedBuffer{}} }

// logger logs everything, debug included, to the capture.
func (c *capture) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(c.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// saw keeps what an error says.
func (c *capture) saw(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.errs = append(c.errs, err)
}

// refused runs a call that must fail, and keeps what it says.
func (c *capture) refused(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	c.saw(err)
}

// texts is what was captured, by where it was said.
func (c *capture) texts() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs strings.Builder
	for _, err := range c.errs {
		fmt.Fprintf(&errs, "%v\n%+v\n", err, err)
	}
	var events strings.Builder
	for _, e := range c.events.all() {
		fmt.Fprintf(&events, "%+v\n%#v\n", e, e)
	}

	return map[string]string{"logs": c.logs.String(), "events": events.String(), "errors": errs.String()}
}

// leaks lists each secret found, and where.
func (c *capture) leaks(secrets map[string]string) []string {
	var found []string
	for where, text := range c.texts() {
		for what, secret := range secrets {
			if secret != "" && strings.Contains(text, secret) {
				found = append(found, what+" in "+where)
			}
		}
	}

	return found
}

// TestProvider_NoSecretsInLogs runs the whole happy path and every refusal over a capturing log
// handler and sink, and finds no code, handle, flow secret, token, assertion or secret in anything
// captured, in a log line, an event or an error's text.
func TestProvider_NoSecretsInLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		run  func(t *testing.T, c *capture) map[string]string
		// assert judges what was captured against the secrets run reported.
		assert func(t *testing.T, c *capture, secrets map[string]string)
	}

	cases := []testCase{
		{
			name: "the scan finds a secret planted in a log line, an event and an error",
			run: func(t *testing.T, c *capture) map[string]string {
				t.Helper()
				const planted = "planted-secret-9f3a"
				c.logger().Error("a log line", "value", planted)
				c.events.sink(t.Context(), event.Event{Name: event.GrantCreated, Client: planted})
				c.saw(fmt.Errorf("an error saying %s", planted))

				return map[string]string{"planted": planted}
			},
			assert: func(t *testing.T, c *capture, secrets map[string]string) {
				t.Helper()
				assert.ElementsMatch(t,
					[]string{"planted in logs", "planted in events", "planted in errors"}, c.leaks(secrets),
					"a scan that cannot see a planted secret proves nothing")
			},
		},
		{
			name: "the happy path and every refusal say none of what is secret",
			run:  everythingOnce,
			assert: func(t *testing.T, c *capture, secrets map[string]string) {
				t.Helper()
				require.NotEmpty(t, c.logs.String(), "the run logged, so the scan had text to read")
				require.NotEmpty(t, c.events.all(), "and reported, and failed")
				for _, name := range []string{
					event.GrantCreated, event.ConsentGiven, event.ClientAuthRefused, event.CodeReplayed,
					event.RefreshReused, event.GrantRevoked, event.LogoutDeliveryFailed,
				} {
					assert.NotEmpty(t, named(c.events.all(), name), "the run reached %s", name)
				}
				for _, what := range []string{"flow secret", "handle secret", "code", "second refresh token", "access token", "id token", "logout token"} {
					assert.NotEmpty(t, secrets[what], "the run held a %s to look for", what)
				}
				assert.Empty(t, c.leaks(secrets))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newCapture()
			secrets := tc.run(t, c)
			tc.assert(t, c, secrets)
		})
	}
}

// everythingOnce drives the authorization flow to its tokens, and each way it refuses, over one
// capture, and returns every secret it handled. It is the body of the no-secrets row.
func everythingOnce(t *testing.T, c *capture) map[string]string {
	t.Helper()

	secrets := map[string]string{"client secret": exchangeSecret, errOutage.Error(): errOutage.Error()}
	opts := []oidcprovider.Option{oidcprovider.WithLogger(c.logger()), oidcprovider.WithSecurityEvents(c.events.sink)}
	f := newRefreshFixture(t, opts...)

	// The authorization flow: a parked request, a login, a consent, a code.
	signIn := testSignIn(f.parkFixture, "u-1")
	r := park(t, f.parkFixture, nil)
	secrets["flow secret"] = r.flow
	_, handleSecret := handleParts(t, r.handle)
	secrets["handle secret"], secrets["handle"] = handleSecret, r.handle

	stranger := r.input(&signIn)
	stranger.FlowSecret = "not-the-flow-secret-0123456789"
	secrets["wrong flow secret"] = stranger.FlowSecret
	_, err := f.p.Resume(t.Context(), stranger)
	c.refused(t, err)

	_, err = f.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)
	require.Equal(t, oidcprovider.StageConsent, stageOf(t, f.parkFixture, r))
	in := r.input(&signIn)
	answerWith(&in, "openid", "profile")
	res, err := f.p.Resume(t.Context(), in)
	require.NoError(t, err)
	code := queryOf(t, res.RedirectTo).Get("code")
	require.NotEmpty(t, code)
	_, codeSecret, _ := strings.Cut(code, ".")
	secrets["code"], secrets["code secret"] = code, codeSecret

	// The exchange: refused for a wrong verifier and a wrong client secret, then granted.
	spent := issuedCode{code: code}
	_, err = f.p.Token(t.Context(), billingExchange(spent, func(v url.Values) { v.Set("code_verifier", strings.Repeat("a", 43)) }))
	c.refused(t, err)
	wrong := billingExchange(spent, nil)
	wrong.Credentials = oidcprovider.ClientCredentials{Authorization: basic("billing-web", "wrong-client-secret-0123456789ab")}
	secrets["wrong client secret"] = "wrong-client-secret-0123456789ab"
	_, err = f.p.Token(t.Context(), wrong)
	c.refused(t, err)

	tokens, err := f.p.Token(t.Context(), billingExchange(spent, nil))
	require.NoError(t, err)
	secrets["access token"], secrets["id token"] = tokens.AccessToken, tokens.IDToken

	// A replay of the spent code, which revokes the grant it made.
	_, err = f.p.Token(t.Context(), billingExchange(spent, nil))
	c.refused(t, err)

	// Another grant, for the refresh paths, and reuse.
	s := startBilling(t, f)
	secrets["second refresh token"] = s.first.RefreshToken
	secrets["second refresh secret"] = s.secretOf(t, s.first.RefreshToken)
	stale := s.first.RefreshToken
	next, err := f.p.Token(t.Context(), s.again(stale))
	require.NoError(t, err)
	secrets["rotated refresh token"] = next.RefreshToken
	secrets["rotated access token"] = next.AccessToken
	f.clk.Advance(30 * time.Second)
	_, err = f.p.Token(t.Context(), s.again(stale))
	c.refused(t, err)

	// A dependency failing with text of its own, and a client revoking what is not its own.
	third := startBilling(t, f)
	secrets["third refresh token"] = third.first.RefreshToken
	f.lineage.failLoad.Store(true)
	_, err = f.p.Token(t.Context(), third.again(third.first.RefreshToken))
	c.refused(t, err)
	f.lineage.failLoad.Store(false)
	c.refused(t, f.p.Revoke(t.Context(), credsOf("code-only"), tokenForm(third.first.RefreshToken)))
	c.saw(f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(third.first.RefreshToken)))
	_, err = f.p.AuthenticateClient(t.Context(), oidcprovider.ClientCredentials{Authorization: basic("billing-web", "another-wrong-secret-0123456789")})
	c.refused(t, err)
	secrets["another wrong secret"] = "another-wrong-secret-0123456789"

	// A consent denied.
	denied := park(t, f.parkFixture, func(v url.Values) { v.Set("prompt", "consent") })
	secrets["denied flow secret"] = denied.flow
	_, err = f.p.Resume(t.Context(), denied.input(&signIn))
	require.NoError(t, err)
	require.Equal(t, oidcprovider.StageConsent, stageOf(t, f.parkFixture, denied))
	deny := denied.input(&signIn)
	deny.Answer = &oidcprovider.ConsentAnswer{Deny: true}
	_, err = f.p.Resume(t.Context(), deny)
	require.NoError(t, err)

	// A back-channel logout whose delivery fails with the token in its own error text.
	var told atomic.Value
	delivery := oidcprovider.LogoutDeliveryFunc(func(_ context.Context, uri, raw string) error {
		told.Store(raw)

		return fmt.Errorf("the relying party at %s refused %s", uri, raw)
	})
	x := newEnding(t, oneClient(), nil,
		append(opts, oidcprovider.WithLogoutDelivery(delivery), oidcprovider.WithLogoutDeliveryPool(1, 1))...)
	x.end(t.Context(), t, "billing-web")
	drained(t, x.p)
	raw, _ := told.Load().(string)
	secrets["logout token"] = raw

	return secrets
}
