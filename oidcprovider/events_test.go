package oidcprovider_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
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

	// movedOn is a grant whose first token, still inside its grace, has a successor that moved on, so
	// presenting it again is a reuse only the lineage manager can see.
	movedOn := func(t *testing.T, f *refreshFixture) *refreshScene {
		t.Helper()

		s := startBilling(t, f)
		second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
		assertRefreshWorks(t, f, s, second)
		f.clk.Advance(defaultSuccessorWindow)

		return s
	}
	// revokeFirst is a store hook: another caller revokes the grant, once, just ahead of the first
	// revocation this request tries.
	revokeFirst := func(t *testing.T, f *refreshFixture, family id.ID, cause oidcprovider.RevocationCause) func() {
		t.Helper()

		var once sync.Once

		return func() {
			once.Do(func() { revokeGrantDirectly(t, f.grants.GrantStore, family, cause, f.clk.Now()) })
		}
	}
	noEvents := func(t *testing.T, got []event.Event) {
		t.Helper()
		assert.Empty(t, got)
	}
	// unspent answers at consent, on a provider whose spend of that stage fails.
	unspent := func(answer func(*oidcprovider.ResumeInput)) func(*testing.T, event.Sink) {
		return func(t *testing.T, sink event.Sink) {
			t.Helper()

			memory, err := oidcprovider.NewMemoryPendingRequestStore()
			require.NoError(t, err)
			f := newExchangeFixture(t, oidcprovider.WithSecurityEvents(sink),
				oidcprovider.WithPendingRequestStore(&consentSpendFailing{MemoryPendingRequestStore: memory}))
			f.store = memory
			signIn := testSignIn(f.parkFixture, "u-1")
			r, _ := atConsent(t, f.parkFixture, nil, signIn)
			in := r.input(&signIn)
			answer(&in)
			_, err = f.p.Resume(t.Context(), in)
			assertDependencyFailure(t, err)
		}
	}
	// assertionRefused runs a refusal against a provider holding a key client, a secret client and a
	// public one.
	assertionRefused := func(refuse func(*testing.T, *oidcprovider.Provider)) func(*testing.T, event.Sink) {
		return func(t *testing.T, sink event.Sink) {
			t.Helper()

			refuse(t, assertionProvider(t, clientKeys(t), oidcprovider.WithSecurityEvents(sink)))
		}
	}
	refusedClientNamed := func(client string) func(*testing.T, []event.Event) {
		return func(t *testing.T, got []event.Event) {
			t.Helper()

			require.Equal(t, []string{event.ClientAuthRefused}, namesOf(got))
			reportsOf(t, got[0], client, "", event.OutcomeFailure)
		}
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
		{
			name: "a public client refused at introspection is reported by the name the registry holds",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				_, err := f.p.Introspect(t.Context(), oidcprovider.ClientCredentials{}, url.Values{"client_id": {nativeClient}})
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.ClientAuthRefused}, namesOf(got))
				reportsOf(t, got[0], nativeClient, "", event.OutcomeFailure)
			},
		},
		{
			name: "no grant is reported created when its row could not be stored",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				failing := &grantsFailingCreate{}
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink), oidcprovider.WithGrantStore(failing.over(t)))
				_, err := f.p.Token(t.Context(), billingExchange(f.issue(t), nil))
				assertDependencyFailure(t, err)
			},
			assert: noEvents,
		},
		{
			name: "no grant is reported created when its lineage could not be stored",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issue(t)
				f.lineage.failCreate.Store(true)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				assertDependencyFailure(t, err)
			},
			assert: noEvents,
		},
		{
			name: "no grant is reported created when its opaque access token could not be stored",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := issueOpaque(t, f.exchangeFixture)
				f.access.failCreate.Store(true)
				_, err := f.p.Token(t.Context(), opaqueExchange(c))
				assertDependencyFailure(t, err)
			},
			assert: noEvents,
		},
		{
			name: "a second replay is a second replay, and the grant is revoked once",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issue(t)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				for range 2 {
					_, err = f.p.Token(t.Context(), billingExchange(c, nil))
					assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				}
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated, event.CodeReplayed, event.GrantRevoked, event.CodeReplayed}, namesOf(got))
			},
		},
		{
			name: "replays racing one another report the revocation once",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issue(t)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				var racers sync.WaitGroup
				for range 16 {
					racers.Go(func() {
						_, err := f.p.Token(t.Context(), billingExchange(c, nil))
						assertRefused(t, err, oidcprovider.CodeInvalidGrant)
					})
				}
				racers.Wait()
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Len(t, named(got, event.CodeReplayed), 16, "each is a presentation of its own")
				assert.Len(t, named(got, event.GrantRevoked), 1, "and one of them revoked the grant")
			},
		},
		{
			name: "a replay of a grant revoked for another cause states only the replay, and the first cause stands",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issue(t)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseRecovery)))
				_, err = f.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Equal(t, oidcprovider.CauseRecovery, grantOf(t, f.exchangeFixture, c).RevokeCause)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.GrantCreated, event.GrantRevoked, event.CodeReplayed}, namesOf(got))
				assert.Equal(t, string(oidcprovider.CauseRecovery), got[1].Cause)
			},
		},
		{
			name: "a replay whose row is stored and whose family cannot be deleted reports the revocation, and a retry does not",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issueOffline(t)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				f.lineage.failDelete.Store(true)
				_, err = f.p.Token(t.Context(), billingExchange(c, nil))
				assertDependencyFailure(t, err)
				assert.True(t, grantOf(t, f.exchangeFixture, c).Revoked, "the row is what ends the grant")
				f.lineage.failDelete.Store(false)
				_, err = f.p.Token(t.Context(), billingExchange(c, nil))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated, event.CodeReplayed, event.GrantRevoked, event.CodeReplayed}, namesOf(got))
			},
		},
		{
			name: "a replay whose row cannot be marked reports nothing, as nothing was revoked",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				c := f.issue(t)
				_, err := f.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err)
				f.grants.failRevoke.Store(true)
				_, err = f.p.Token(t.Context(), billingExchange(c, nil))
				assertDependencyFailure(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated}, namesOf(got))
			},
		},
		{
			name: "a client's retried revocation reports the revocation once",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := startBilling(t, f)
				f.lineage.failDelete.Store(true)
				require.Error(t, f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)))
				f.lineage.failDelete.Store(false)
				require.NoError(t, f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)))
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				onlyRevoked(t, got, string(oidcprovider.CauseRevokedByClient))
			},
		},
		{
			name: "a client revoking a grant already revoked for another cause reports nothing of its own",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := startBilling(t, f)
				require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseRecovery)))
				require.NoError(t, f.p.Revoke(t.Context(), credsOf("billing-web"), tokenForm(s.first.RefreshToken)))
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				onlyRevoked(t, got, string(oidcprovider.CauseRecovery))
			},
		},
		{
			name: "a user gone, with the grant revoked since it was read, states the first cause alone",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := startBilling(t, f)
				f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
				f.grants.beforeRevoke = revokeFirst(t, f, s.grant.Family, oidcprovider.CauseUserRequest)
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated}, namesOf(got), "nothing here revoked it, and the store did not say it had")
			},
		},
		{
			name: "a reuse of a grant revoked since it was read is a reuse, and no revocation of its own",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s, stale := pastGrace(t, f)
				f.grants.beforeRevoke = revokeFirst(t, f, s.grant.Family, oidcprovider.CauseUserRequest)
				assertRefreshRefused(t, f, s, stale)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated, event.RefreshReused}, namesOf(got))
			},
		},
		{
			name: "a reuse only the lineage manager sees, of a grant revoked since it was read, is no revocation of its own",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := movedOn(t, f)
				f.grants.beforeRevoke = revokeFirst(t, f, s.grant.Family, oidcprovider.CauseUserRequest)
				assertRefreshRefused(t, f, s, s.first.RefreshToken)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated, event.RefreshReused}, namesOf(got))
			},
		},
		{
			name: "a reuse whose family cannot be deleted, of a grant revoked since it was read, is no revocation of its own",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := movedOn(t, f)
				f.lineage.failDelete.Store(true)
				f.grants.beforeRevoke = revokeFirst(t, f, s.grant.Family, oidcprovider.CauseUserRequest)
				_, err := f.p.Token(t.Context(), s.again(s.first.RefreshToken))
				assertDependencyFailure(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated, event.RefreshReused}, namesOf(got))
			},
		},
		{
			name: "a reuse only the lineage manager sees, whose family cannot be deleted, is still reported once",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := movedOn(t, f)
				f.lineage.failDelete.Store(true)
				_, err := f.p.Token(t.Context(), s.again(s.first.RefreshToken))
				assertDependencyFailure(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.GrantCreated, event.RefreshReused, event.GrantRevoked}, namesOf(got))
				assert.Equal(t, string(oidcprovider.CauseReuse), got[2].Cause)
			},
		},
		{
			name: "a reuse only the lineage manager sees, where neither write lands, reports nothing",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				s := movedOn(t, f)
				f.lineage.failDelete.Store(true)
				f.grants.failRevoke.Store(true)
				_, err := f.p.Token(t.Context(), s.again(s.first.RefreshToken))
				assertDependencyFailure(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				assert.Equal(t, []string{event.GrantCreated}, namesOf(got), "the grant still stands")
			},
		},
		{
			name: "a sign-in's end does not report a grant already revoked for another cause",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				e := newEndFixture(t, oidcprovider.WithSecurityEvents(sink))
				e.online(t, e.signInOf("u-1", "https://x.example.com", "one"))
				require.NoError(t, e.p.RevokeUserGrants(t.Context(), "u-1", string(oidcprovider.CauseRecovery)))
				_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{User: "u-1"})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				onlyRevoked(t, got, string(oidcprovider.CauseRecovery))
			},
		},
		{
			name: "a sign-in's end reports the offline grant of a client tied to its sign-in",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				e := newEndFixture(t, oidcprovider.WithSecurityEvents(sink))
				e.grantFrom(t, e.signInOf("u-1", "https://x.example.com", "one"), tiedClient, tiedRedirect, "openid", "offline_access")
				_, err := e.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{User: "u-1"})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				require.Equal(t, []string{event.GrantCreated, event.GrantRevoked}, namesOf(got))
				reportsOf(t, got[1], tiedClient, "u-1", event.OutcomeSuccess)
				assert.Equal(t, string(oidcprovider.CauseSignInEnded), got[1].Cause)
			},
		},
		{
			name:   "consent given is not reported when the stage could not be spent",
			run:    unspent(func(in *oidcprovider.ResumeInput) { answerWith(in, "openid") }),
			assert: noEvents,
		},
		{
			name:   "consent denied is not reported when the stage could not be spent",
			run:    unspent(func(in *oidcprovider.ResumeInput) { in.Answer = &oidcprovider.ConsentAnswer{Deny: true} }),
			assert: noEvents,
		},
		{
			name: "grants ended with no consent to forget report no consent revoked",
			run: func(t *testing.T, sink event.Sink) {
				t.Helper()
				f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(sink))
				startBilling(t, f)
				_, err := f.consents.Revoke(t.Context(), "u-1", "billing-web")
				require.NoError(t, err)
				require.NoError(t, f.p.RevokeConsent(t.Context(), "u-1", "billing-web"))
			},
			assert: func(t *testing.T, got []event.Event) {
				t.Helper()
				onlyRevoked(t, got, string(oidcprovider.CauseConsentRevoked))
			},
		},
		{
			name: "an assertion for a client registered for another method names that client",
			run: assertionRefused(func(t *testing.T, p *oidcprovider.Provider) {
				t.Helper()
				_, err := p.AuthenticateClient(t.Context(), presenting(es256(t, claimsFor("billing-web"))))
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
			}),
			assert: refusedClientNamed("billing-web"),
		},
		{
			name: "an assertion a stranger signed names the client it claims, as the registry holds it",
			run: assertionRefused(func(t *testing.T, p *oidcprovider.Provider) {
				t.Helper()
				forged := signed(t, "ES256", strangerECKey(), map[string]any{"kid": esKid}, claimsFor(keyClientID))
				_, err := p.AuthenticateClient(t.Context(), presenting(forged))
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
			}),
			assert: refusedClientNamed(keyClientID),
		},
		{
			name: "an assertion replayed names its client",
			run: assertionRefused(func(t *testing.T, p *oidcprovider.Provider) {
				t.Helper()
				once := es256(t, claimsFor(keyClientID))
				_, err := p.AuthenticateClient(t.Context(), presenting(once))
				require.NoError(t, err)
				_, err = p.AuthenticateClient(t.Context(), presenting(once))
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
			}),
			assert: refusedClientNamed(keyClientID),
		},
		{
			name: "an assertion claiming a client no registry holds names no one",
			run: assertionRefused(func(t *testing.T, p *oidcprovider.Provider) {
				t.Helper()
				_, err := p.AuthenticateClient(t.Context(), presenting(es256(t, claimsFor("stranger"))))
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
			}),
			assert: refusedClientNamed(""),
		},
		{
			name: "a confidential client naming itself alone, as a public one does, is named",
			run: assertionRefused(func(t *testing.T, p *oidcprovider.Provider) {
				t.Helper()
				_, err := p.AuthenticateClient(t.Context(), oidcprovider.ClientCredentials{Form: url.Values{"client_id": {"billing-web"}}})
				assertRefused(t, err, oidcprovider.CodeInvalidClient)
			}),
			assert: refusedClientNamed("billing-web"),
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

// consentSpendFailing is a pending store whose spend of the consent stage fails.
type consentSpendFailing struct {
	*oidcprovider.MemoryPendingRequestStore
}

// Advance implements oidcprovider.PendingRequestStore.
func (s *consentSpendFailing) Advance(
	ctx context.Context, handleDigest []byte, from, to oidcprovider.Stage, signIn *oidcprovider.SignIn,
) error {
	if from == oidcprovider.StageConsent {
		return errOutage
	}

	return s.MemoryPendingRequestStore.Advance(ctx, handleDigest, from, to, signIn)
}

// grantsFailingCreate is a grant store that cannot store a grant.
type grantsFailingCreate struct {
	oidcprovider.GrantStore
}

// over wraps a fresh in-memory store.
func (g *grantsFailingCreate) over(t *testing.T) oidcprovider.GrantStore {
	t.Helper()

	memory, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	g.GrantStore = memory

	return g
}

// Create implements oidcprovider.GrantStore.
func (g *grantsFailingCreate) Create(context.Context, *oidcprovider.Grant) error { return errOutage }

// revokeGrantDirectly revokes family through store, as another caller would.
func revokeGrantDirectly(t *testing.T, store oidcprovider.GrantStore, family id.ID, cause oidcprovider.RevocationCause, at time.Time) {
	t.Helper()

	require.NoError(t, revokeErr(store.Revoke(context.WithoutCancel(t.Context()), family, cause, at)))
}

// TestProvider_Events_ThroughChain pins that one reuse is reported as one reuse and one revocation on a
// request a real chain reports for, whichever path finds it: the provider's own two, with what the chain
// adds, and nothing from the session manager the lineage is kept by.
func TestProvider_Events_ThroughChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// reused arranges a grant and returns the request that presents a token already reused.
		reused func(t *testing.T, f *refreshFixture) oidcprovider.TokenRequest
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		assertRefused(t, err, oidcprovider.CodeInvalidGrant)
	}
	cases := []testCase{
		{
			name: "a token presented past its grace",
			reused: func(t *testing.T, f *refreshFixture) oidcprovider.TokenRequest {
				t.Helper()
				s := startBilling(t, f)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(30 * time.Second)

				return s.again(s.first.RefreshToken)
			},
			assert: refused,
		},
		{
			name: "a token whose successor moved on inside its grace",
			reused: func(t *testing.T, f *refreshFixture) oidcprovider.TokenRequest {
				t.Helper()
				s := startBilling(t, f)
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				assertRefreshWorks(t, f, s, second)
				f.clk.Advance(defaultSuccessorWindow)

				return s.again(s.first.RefreshToken)
			},
			assert: refused,
		},
		{
			name: "a token found past its grace when a rotation that lost reads it again",
			reused: func(t *testing.T, f *refreshFixture) oidcprovider.TokenRequest {
				t.Helper()
				s := startBilling(t, f)
				assertRefreshWorks(t, f, s, s.first.RefreshToken)
				f.clk.Advance(defaultSuccessorWindow)
				var once sync.Once
				f.lineage.conflict.Store(true)
				f.lineage.beforeSupersede = func() { once.Do(func() { f.clk.Advance(30 * time.Second) }) }

				return s.again(s.first.RefreshToken)
			},
			assert: refused,
		},
		{
			name: "a token whose family cannot be deleted",
			reused: func(t *testing.T, f *refreshFixture) oidcprovider.TokenRequest {
				t.Helper()
				s := startBilling(t, f)
				second := assertRefreshWorks(t, f, s, s.first.RefreshToken).RefreshToken
				assertRefreshWorks(t, f, s, second)
				f.clk.Advance(defaultSuccessorWindow)
				f.lineage.failDelete.Store(true)

				return s.again(s.first.RefreshToken)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var own, chained eventLog
			f := newRefreshFixture(t, oidcprovider.WithSecurityEvents(own.sink))
			request := tc.reused(t, f)
			already := len(own.all())

			chain, err := httpsec.New(httpsec.WithClock(f.clk), httpsec.EnableSecurityEvents(chained.sink))
			require.NoError(t, err)
			var answered error
			run := chain.Assemble(func(ex *httpsec.Exchange) error {
				_, answered = f.p.Token(ex.Context(), request) //nolint:contextcheck // the exchange carries the request's context

				return nil
			})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example.com/token", http.NoBody)
			req.RemoteAddr = "192.0.2.7:4711"
			require.NoError(t, run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))))
			tc.assert(t, answered)

			got := chained.all()
			require.Equal(t, []string{event.RefreshReused, event.GrantRevoked}, namesOf(got), "the session manager's report of the same reuse stays out")
			reportsOf(t, got[0], "billing-web", "u-1", event.OutcomeFailure)
			reportsOf(t, got[1], "billing-web", "u-1", event.OutcomeSuccess)
			assert.Equal(t, string(oidcprovider.CauseReuse), got[1].Cause)
			for _, e := range got {
				assert.Equal(t, "192.0.2.7", e.ClientIP, "%s went through the chain's own emitter", e.Name)
			}
			assert.Len(t, own.all(), already, "the provider's own sink is not called on a request a chain reports for")
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

// registryAnswering is a registry that, once armed, answers as a row says.
type registryAnswering struct {
	oidcprovider.ClientRegistry

	armed  atomic.Bool
	answer func(ctx context.Context) error
}

// Client implements oidcprovider.ClientRegistry.
func (r *registryAnswering) Client(ctx context.Context, clientID string) (*oidcprovider.RegisteredClient, error) {
	if r.armed.Load() {
		return nil, r.answer(ctx)
	}

	return r.ClientRegistry.Client(ctx, clientID)
}

// causesOf is each event's Cause, in the order they arrived.
func causesOf(got []event.Event) []string {
	out := make([]string, 0, len(got))
	for _, e := range got {
		out = append(out, e.Cause)
	}

	return out
}

// TestProvider_Events_DropReadsTheClient pins what a drop's report does with the registry it must ask
// whether the client had anyone to tell: only an answer that it has not stops the report, and the
// question has the delivery's own bound.
func TestProvider_Events_DropReadsTheClient(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		answer func(ctx context.Context, release <-chan struct{}) error
		// reported says the drop is reported.
		reported bool
		// lost is how many events are counted as lost.
		lost int
	}

	cases := []testCase{
		{
			name:     "a registry that cannot answer leaves it unknown, and unknown is reported",
			answer:   func(context.Context, <-chan struct{}) error { return errOutage },
			reported: true,
		},
		{
			name: "a registry that does not answer is asked within the delivery's bound, and is reported",
			answer: func(ctx context.Context, release <-chan struct{}) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-release:
					return errOutage
				}
			},
			reported: true,
		},
		{
			name:   "a client the registry no longer holds has no one to tell",
			answer: func(context.Context, <-chan struct{}) error { return oidcprovider.ErrClientNotFound },
		},
		{
			name:     "a registry that panics has not answered, so that too is unknown, and is reported",
			answer:   func(context.Context, <-chan struct{}) error { panic("in the registry") },
			reported: true,
		},
		{
			name: "a registry that ends the goroutine takes the event with it, and it is counted",
			answer: func(context.Context, <-chan struct{}) error {
				runtime.Goexit()

				return nil
			},
			lost: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			memory, err := oidcprovider.NewMemoryRegistry(oneClient())
			require.NoError(t, err)
			release := make(chan struct{})
			registry := &registryAnswering{ClientRegistry: memory, answer: func(ctx context.Context) error { return tc.answer(ctx, release) }}
			var log eventLog
			g := newGate(true)
			x := newEnding(t, nil, registry, oidcprovider.WithSecurityEvents(log.sink), oidcprovider.WithLogoutDelivery(g),
				oidcprovider.WithLogoutDeliveryPool(1, 1), oidcprovider.WithLogoutDeliveryTimeout(2*time.Second))
			var opened sync.Once
			finish := func() {
				opened.Do(func() {
					close(release)
					close(g.open)
				})
			}
			t.Cleanup(finish)
			ctx := context.WithoutCancel(t.Context())
			dropReported := func() bool {
				return slices.Contains(causesOf(named(log.all(), event.LogoutDeliveryFailed)), "queue_full")
			}

			x.end(ctx, t, "billing-web") // takes the worker
			require.Eventually(t, func() bool { return g.entered.Load() == 1 }, 10*time.Second, time.Millisecond)
			x.end(ctx, t, "billing-web") // takes the queue's one place
			registry.armed.Store(true)
			x.end(ctx, t, "billing-web") // dropped, with the registry as the row has it

			if tc.reported {
				// Before anything is let go, so that nothing but the delivery's bound can end a registry that holds on.
				assert.Eventually(t, dropReported, 10*time.Second, time.Millisecond)
			}
			finish()
			drained(t, x.p)
			assert.Equal(t, tc.reported, dropReported())
			_, lost := countsOf(t, x.logs.String())
			assert.Equal(t, tc.lost, lost)
		})
	}
}

// TestProvider_Events_DropsOfEachKind pins that every failure leaving before a client is read asks whether
// it had anyone to tell, whichever kind of failure it is.
func TestProvider_Events_DropsOfEachKind(t *testing.T) {
	t.Parallel()

	clients := append(oneClient(), listeningClient("quiet", ""))

	t.Run("no room, as calls left behind take every place", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			var log eventLog
			g := newGate(false)
			x := newEnding(t, clients, nil,
				oidcprovider.WithSecurityEvents(log.sink), oidcprovider.WithLogoutDelivery(g), oidcprovider.WithLogoutDeliveryPool(1, 16))

			for _, client := range []string{"billing-web", "billing-web", "quiet", "billing-web"} {
				x.end(t.Context(), t, client)
			}
			time.Sleep(10 * time.Second)
			synctest.Wait()

			assert.Equal(t, []string{"timeout", "timeout", "busy", "busy"}, x.reasons(), "the quiet client took a place too")
			failed := named(log.all(), event.LogoutDeliveryFailed)
			assert.Equal(t, []string{"timeout", "timeout", "busy"}, causesOf(failed), "and is not reported")

			close(g.open)
			synctest.Wait()
			require.NoError(t, x.p.Shutdown(t.Context()))
		})
	})

	t.Run("after Shutdown", func(t *testing.T) {
		t.Parallel()

		var log eventLog
		x := newEnding(t, clients, nil, oidcprovider.WithSecurityEvents(log.sink), oidcprovider.WithLogoutDelivery(newGate(true)))
		drained(t, x.p)
		ctx := context.WithoutCancel(t.Context())

		x.end(ctx, t, "quiet")
		x.end(ctx, t, "billing-web")
		awaitEvent(t, &log, event.LogoutDeliveryFailed, 1)
		drained(t, x.p)

		failed := named(log.all(), event.LogoutDeliveryFailed)
		require.Len(t, failed, 1, "the quiet client's says nothing")
		reportsOf(t, failed[0], "billing-web", "u-1", event.OutcomeFailure)
		assert.Equal(t, "shutdown", failed[0].Cause)
	})
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
		{name: "a client assertion, whatever it is refused for", run: assertionRefusals, assert: saidNoneOf(event.ClientAuthRefused)},
		{name: "malformed client credentials", run: malformedCredentials, assert: saidNoneOf(event.ClientAuthRefused)},
		{name: "an access token VerifyAccessToken refuses", run: verifyRefusals, assert: saidNoneOf()},
		{name: "a token UserInfo refuses", run: userInfoRefusals, assert: saidNoneOf()},
		{name: "a token introspection refuses to look at", run: introspectionRefusals, assert: saidNoneOf(event.ClientAuthRefused)},
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

// saidNoneOf judges a row of refusals: what it reported holds those events, and nothing captured holds
// any secret the row handled.
func saidNoneOf(reached ...string) func(*testing.T, *capture, map[string]string) {
	return func(t *testing.T, c *capture, secrets map[string]string) {
		t.Helper()

		for _, name := range reached {
			assert.NotEmpty(t, named(c.events.all(), name), "the row reached %s", name)
		}
		assert.Empty(t, c.leaks(secrets))
	}
}

// watching are the options that capture what a provider says.
func (c *capture) watching() []oidcprovider.Option {
	return []oidcprovider.Option{oidcprovider.WithLogger(c.logger()), oidcprovider.WithSecurityEvents(c.events.sink)}
}

// assertionRefusals presents a client assertion created for each way one is refused.
func assertionRefusals(t *testing.T, c *capture) map[string]string {
	t.Helper()

	p := assertionProvider(t, clientKeys(t), c.watching()...)
	once := es256(t, claimsFor(keyClientID))
	_, err := p.AuthenticateClient(t.Context(), presenting(once))
	require.NoError(t, err)

	assertions := map[string]string{
		"replayed":             once,
		"for another method":   es256(t, claimsFor("billing-web")),
		"a stranger's":         signed(t, "ES256", strangerECKey(), map[string]any{"kid": esKid}, claimsFor(keyClientID)),
		"of an unknown client": es256(t, claimsFor("stranger")),
		"expired":              es256(t, withClaims(map[string]any{"exp": authNow.Add(-time.Minute).Unix()})),
		"unsigned":             unsigned(t, map[string]any{"alg": "HS256", "kid": esKid}, claimsFor(keyClientID), hs256([]byte("x"))),
		"of no shape":          "not-a-jwt-but-the-clients-own-text-0123456789",
	}
	secrets := map[string]string{}
	for what, raw := range assertions {
		secrets["assertion "+what] = raw
		if i := strings.LastIndexByte(raw, '.'); i >= 0 {
			secrets["signature of the assertion "+what] = raw[i+1:]
		}
		_, err := p.AuthenticateClient(t.Context(), presenting(raw))
		c.refused(t, err)
	}
	_, err = p.AuthenticateClient(t.Context(), oidcprovider.ClientCredentials{
		Form: url.Values{"client_assertion_type": {"urn:of:another:kind"}, "client_assertion": {assertions["expired"]}},
	})
	c.refused(t, err)

	return secrets
}

// malformedCredentials presents credentials of each shape that is refused before any client is read.
func malformedCredentials(t *testing.T, c *capture) map[string]string {
	t.Helper()

	const (
		inQuery      = "secret-in-the-query-0123456789abcdef"
		assertion    = "assertion-in-the-query-0123456789abc"
		undecodable  = "undecodable-header-text-0123456789a"
		noColon      = "header-with-no-colon-0123456789abcd"
		badEscape    = "secret-after-a-bad-escape-012345678"
		otherScheme  = "another-schemes-credential-01234567"
		twoMethods   = "secret-beside-a-header-0123456789ab"
		twoMethods2  = "header-beside-a-secret-0123456789ab"
		repeated     = "secret-given-twice-0123456789abcdef"
		repeated2    = "secret-given-again-0123456789abcdef"
		otherClient  = "header-naming-another-client-012345"
		repeatedCode = "code-given-twice-0123456789abcdef01"
	)
	encode := func(text string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(text)) }
	headers := map[string]string{"no colon": encode(noColon), "bad escape": encode("%zz:" + badEscape)}
	refused := []oidcprovider.ClientCredentials{
		{Authorization: basic("billing-web", exchangeSecret), Query: url.Values{"client_secret": {inQuery}}},
		{Query: url.Values{"client_assertion": {assertion}}},
		{Authorization: "Basic !" + undecodable},
		{Authorization: headers["no colon"]},
		{Authorization: headers["bad escape"]},
		{Authorization: "Bearer " + otherScheme},
		{Authorization: basic("billing-web", twoMethods2), Form: url.Values{"client_secret": {twoMethods}}},
		{Form: url.Values{"client_id": {"billing-web"}, "client_secret": {repeated, repeated2}}},
		{Authorization: basic("billing-web", otherClient), Form: url.Values{"client_id": {"code-only"}}},
	}

	f := newRefreshFixture(t, c.watching()...)
	for _, creds := range refused {
		_, err := f.p.AuthenticateClient(t.Context(), creds)
		c.refused(t, err)
	}
	_, err := f.p.Token(t.Context(), oidcprovider.TokenRequest{
		Credentials: credsOf("billing-web"), Form: url.Values{"grant_type": {"authorization_code"}, "code": {repeatedCode, repeatedCode}},
	})
	c.refused(t, err)

	return map[string]string{
		"secret in the query": inQuery, "assertion in the query": assertion, "undecodable header": undecodable,
		"header of no colon": noColon, "its encoding": headers["no colon"], "secret after a bad escape": badEscape,
		"its header": headers["bad escape"], "another scheme's credential": otherScheme, "secret beside a header": twoMethods,
		"header beside a secret": twoMethods2, "secret given twice": repeated, "given again": repeated2,
		"header naming another client": otherClient, "code given twice": repeatedCode,
	}
}

// heldTokens is one JWT and one opaque access token of the fixture's user, and what is secret of each.
func heldTokens(t *testing.T, f *refreshFixture) (jwtToken, opaqueToken string, secrets map[string]string) {
	t.Helper()

	s := startBilling(t, f)
	opaque, err := f.p.Token(t.Context(), opaqueExchange(issueOpaque(t, f.exchangeFixture)))
	require.NoError(t, err)
	_, opaqueSecret := opaqueParts(t, opaque.AccessToken)

	return s.first.AccessToken, opaque.AccessToken, map[string]string{
		"access token": s.first.AccessToken, "signature": s.first.AccessToken[strings.LastIndexByte(s.first.AccessToken, '.')+1:],
		"refresh token": s.first.RefreshToken, "opaque token": opaque.AccessToken, "opaque secret": opaqueSecret,
		errOutage.Error(): errOutage.Error(),
	}
}

// verifyRefusals presents access tokens of each kind VerifyAccessToken refuses, or cannot judge.
func verifyRefusals(t *testing.T, c *capture) map[string]string {
	t.Helper()

	f := newRefreshFixture(t, c.watching()...)
	jwtToken, opaque, secrets := heldTokens(t, f)
	tampered := jwtToken[:len(jwtToken)-6] + "AAAAAA"
	wrongSecret := opaque[:strings.LastIndexByte(opaque, '.')+1] + "not-its-secret-0123456789abcdefghijklmnop"
	shapeless := "neither-a-jwt-nor-opaque-0123456789"
	secrets["tampered"], secrets["wrong secret"], secrets["shapeless"] = tampered, wrongSecret, shapeless

	for _, raw := range []string{tampered, wrongSecret, shapeless} {
		_, err := f.p.VerifyAccessToken(t.Context(), raw)
		c.refused(t, err)
	}
	f.access.failLoad.Store(true)
	_, err := f.p.VerifyAccessToken(t.Context(), opaque)
	c.refused(t, err)
	f.access.failLoad.Store(false)

	require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", "recovery"))
	for _, raw := range []string{jwtToken, opaque} {
		_, err := f.p.VerifyAccessToken(t.Context(), raw)
		c.refused(t, err)
	}

	return secrets
}

// userInfoRefusals asks UserInfo of tokens it refuses, and of a claim source and a store that fail with
// text of their own. A token that reaches it was read already, so these are what it can carry.
func userInfoRefusals(t *testing.T, c *capture) map[string]string {
	t.Helper()

	const claimsText = "the claim source's own text-0123456789"
	source := NewMockClaimSource(gomock.NewController(t))
	source.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New(claimsText)).AnyTimes()

	f := newRefreshFixture(t, append(c.watching(), oidcprovider.WithClaimSource(source))...)
	jwtToken, _, secrets := heldTokens(t, f)
	secrets["claim source's text"] = claimsText
	at, err := f.p.VerifyAccessToken(t.Context(), jwtToken)
	require.NoError(t, err)

	_, err = f.p.UserInfo(t.Context(), at)
	c.refused(t, err)
	_, err = f.p.UserInfo(t.Context(), nil)
	c.refused(t, err)
	for _, change := range []func(*oidcprovider.AccessToken){
		func(a *oidcprovider.AccessToken) { a.Scopes = nil },
		func(a *oidcprovider.AccessToken) { a.Audience = nil },
		func(a *oidcprovider.AccessToken) { a.ExpiresAt = exchangeFixtureStart },
	} {
		changed := *at
		change(&changed)
		_, err = f.p.UserInfo(t.Context(), &changed)
		c.refused(t, err)
	}
	f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })
	_, err = f.p.UserInfo(t.Context(), at)
	c.refused(t, err)
	f.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = false })
	require.NoError(t, f.p.RevokeUserGrants(t.Context(), "u-1", "recovery"))
	_, err = f.p.UserInfo(t.Context(), at)
	c.refused(t, err)

	return secrets
}

// introspectionRefusals names real tokens to introspection, from callers it refuses to answer, and with
// what it answers as inactive.
func introspectionRefusals(t *testing.T, c *capture) map[string]string {
	t.Helper()

	f := newRefreshFixture(t, c.watching()...)
	jwtToken, opaque, secrets := heldTokens(t, f)
	const wrong = "wrong-secret-at-introspection-012345"
	secrets["wrong secret"] = wrong
	forged := "rt." + strings.Repeat("0", 36) + ".not-a-secret-0123456789abcdefghijklmnopqrs"
	secrets["forged"] = forged

	for _, form := range []url.Values{tokenForm(jwtToken), tokenForm(opaque)} {
		for _, creds := range []oidcprovider.ClientCredentials{
			{},
			{Authorization: basic("billing-web", wrong)},
			{Form: url.Values{"client_id": {nativeClient}}},
		} {
			_, err := f.p.Introspect(t.Context(), creds, form)
			c.refused(t, err)
		}
	}
	_, err := f.p.Introspect(t.Context(), credsOf("billing-web"), url.Values{"token": {jwtToken, opaque}})
	c.refused(t, err)
	_, err = f.p.Introspect(t.Context(), credsOf("billing-web"), url.Values{})
	c.refused(t, err)
	for _, raw := range []string{forged, jwtToken[:len(jwtToken)-6] + "AAAAAA"} {
		answer, err := f.p.Introspect(t.Context(), credsOf("billing-web"), tokenForm(raw))
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"active": false}, answer)
	}
	f.access.failLoad.Store(true)
	_, err = f.p.Introspect(t.Context(), credsOf("billing-web"), tokenForm(opaque))
	c.refused(t, err)

	return secrets
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

// revokeErr is what a call to GrantStore.Revoke failed with, for a row that does not ask whether the
// call is what revoked the grant.
func revokeErr(_ bool, err error) error { return err }
