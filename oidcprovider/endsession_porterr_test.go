package oidcprovider_test

// TestPortErrors_LogoutDelivery and TestPortErrors_EndSessionAndLoads replace
// slog.Default() for their duration, so they do not run in parallel, and they
// restore the logger they found. They are two tables because their setups
// differ in shape: a back-channel delivery runs on the provider's pool and is
// observed through its failure seam, the end-session and load rows through the
// flows' answers.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// pe7kRowEnv names the row a child process runs. It is empty in the parent.
const pe7kRowEnv = "SCRTY_OIDCPROVIDER_PE7K_PORTERR_ROW"

// pe7kRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7kRanMarker = "SCRTY_OIDCPROVIDER_PE7K_PORTERR_RAN: "

// errPe7kNoRecord is not returned: a load site given it answers (nil, nil), a
// port breaking its contract.
var errPe7kNoRecord = errors.New("pe7k: answer no record and no error")

// pe7kDeliveryFailed is the record a failed back-channel delivery writes.
const pe7kDeliveryFailed = "oidcprovider: a logout token was not delivered"

// pe7kSpendFailed is the record SpendLogout writes for a handle it could not spend.
const pe7kSpendFailed = "oidcprovider: an answered logout's handle could not be spent"

const (
	// The id_token_hint of an end-session request, judged against the keys
	// the provider publishes.
	pe7kHintKeys pe7eSite = "EndSession's hint KeySource.VerificationKeys"

	// Every entry point that reads a parked request through one load.
	pe7kViewLoad          pe7eSite = "PendingRequest's PendingRequestStore.Load"
	pe7kResumeLoginLoad   pe7eSite = "Resume's login-stage PendingRequestStore.Load"
	pe7kResumeConsentLoad pe7eSite = "Resume's consent-stage PendingRequestStore.Load"
	pe7kConfirmLoad       pe7eSite = "ConfirmLogout's PendingRequestStore.Load"
	pe7kSpendLoad         pe7eSite = "SpendLogout's PendingRequestStore.Load"

	// Every entry point that asks the browser's session which sign-in to end.
	pe7kEndSessionBrowser pe7eSite = "EndSession's BrowserSessionStore.Load"
	pe7kConfirmBrowser    pe7eSite = "ConfirmLogout's BrowserSessionStore.Load"
)

// pe7kPendingSites are the sites whose port is the pending-request store's load.
var pe7kPendingSites = []pe7eSite{pe7kViewLoad, pe7kResumeLoginLoad, pe7kResumeConsentLoad, pe7kConfirmLoad, pe7kSpendLoad}

// pe7kBrowserSites are the sites whose port is the browser-session store's load.
var pe7kBrowserSites = []pe7eSite{pe7kEndSessionBrowser, pe7kConfirmBrowser}

// pe7kDeliveryOutcome is what one ended sign-in's delivery produced through a
// failing delivery, and what the provider logged.
type pe7kDeliveryOutcome struct {
	endErr      error
	shutdownErr error
	reasons     []string
	panicTypes  []string
	unwalkable  []bool
	failureLogs int
	aborts      []map[string]any
	failures    []map[string]any
	logText     string
}

// pe7kDeliverRun ends one sign-in whose client listens on its back channel,
// while the consumer's delivery answers portErr, and waits for the pool to
// finish. It fails the test when the end or its delivery hangs, lets a panic
// escape, or never reaches the delivery.
//
// With viaTransport, portErr is what the default delivery's HTTP transport
// answers, so the library's own delivery wraps it; otherwise it is what a
// consumer's delivery answers.
func pe7kDeliverRun(ctx context.Context, t *testing.T, portErr error, viaTransport bool) pe7kDeliveryOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var hits atomic.Int32

	var deliveryOpt oidcprovider.Option
	if viaTransport {
		deliveryOpt = oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(&http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				hits.Add(1)

				return nil, portErr
			}),
		}))
	} else {
		deliveryOpt = oidcprovider.WithLogoutDelivery(oidcprovider.LogoutDeliveryFunc(func(context.Context, string, string) error {
			hits.Add(1)

			return portErr
		}))
	}

	x := newEnding(t, []oidcprovider.Client{listeningClient("billing-web", billingBackChannel)}, nil,
		deliveryOpt, oidcprovider.WithLogger(logger))

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	x.grants.push(family, []oidcprovider.Grant{{ClientID: "billing-web", User: "u-1", SignInFamily: family}})

	out := pe7eBounded(t, func() pe7kDeliveryOutcome {
		var o pe7kDeliveryOutcome

		_, o.endErr = x.p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: family})

		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer cancel()

		o.shutdownErr = x.p.Shutdown(shutdown)

		return o
	})

	require.Positive(t, hits.Load(), "the delivery was reached")

	for _, f := range x.failed() {
		out.reasons = append(out.reasons, f.Reason)
		out.panicTypes = append(out.panicTypes, f.PanicType)
		out.unwalkable = append(out.unwalkable, errors.Is(f.Err, porterr.ErrUnwalkable))
	}

	aborts, failures := pe7eAbortsAndLogs(t, logs.String(), pe7kDeliveryFailed)
	out.aborts, out.failureLogs, out.failures, out.logText = aborts, len(failures), failures, logs.String()

	return out
}

// TestPortErrors_LogoutDelivery pins that a consumer's back-channel delivery
// failing with an error whose chain cannot be walked is reported exactly as a
// plain failing delivery is: one failure, reason "delivery", one record of it,
// never a panic, a hang or a fatal stack overflow on the pool's worker. The
// sanitizer writes one record, to the provider's logger, and none to
// slog.Default().
func TestPortErrors_LogoutDelivery(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7kRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	const site pe7eSite = "the back channel's LogoutDelivery.Deliver"

	type testCase struct {
		name string
		err  error
		// transport says err is what the default delivery's HTTP transport
		// answers, and the reason a plain failure there is reported with.
		transport bool
		child     bool
		ctx       func(ctx context.Context) context.Context
		assert    func(t *testing.T, plain, got pe7kDeliveryOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pe7kDeliveryOutcome) {
		t.Helper()

		require.NoError(t, got.endErr, "whatever becomes of its delivery, an end succeeds")
		require.NoError(t, got.shutdownErr, "the pool finished")
		assert.Equal(t, plain.reasons, got.reasons, "the same failures, for the same reason")
		assert.Equal(t, plain.panicTypes, got.panicTypes, "no failure read as a panic")
		assert.Equal(t, plain.failureLogs, got.failureLogs, "the same failure records")
	}

	asOutage := func(reason string) func(*testing.T, pe7kDeliveryOutcome, pe7kDeliveryOutcome) {
		return func(t *testing.T, plain, got pe7kDeliveryOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			pe7eOneAbort(t, got.aborts, got.failures, reason)
			assert.Equal(t, []bool{true}, got.unwalkable, "the failure carries the sanitizer's fault")
			assert.NotContains(t, got.logText, pe7bSecret, "the provider's log never carries the hostile error's text")
		}
	}

	// asTransportOutage is asOutage for the default delivery: the failure is
	// reported as a plain transport error is, with reason "post".
	asTransportOutage := func(reason string) func(*testing.T, pe7kDeliveryOutcome, pe7kDeliveryOutcome) {
		return func(t *testing.T, plain, got pe7kDeliveryOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			pe7eOneAbort(t, got.aborts, got.failures, reason)
			assert.NotContains(t, got.logText, pe7bSecret, "the provider's log never carries the hostile error's text")
		}
	}

	walked := func(t *testing.T, plain, got pe7kDeliveryOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	cases := make([]testCase, 0, len(pe7eRows())+6)

	const transportSite = "the default delivery's transport"

	cases = append(cases,
		testCase{
			name: transportSite + ": a cycle through Unwrap() error is reported as a failed post",
			err:  &pe7bCycleOne{}, transport: true, assert: asTransportOutage("budget"),
		},
		testCase{
			name: transportSite + ": a link whose Unwrap panics is reported as a failed post",
			err:  pe7bPanicUnwrap{}, transport: true, assert: asTransportOutage("panic"),
		},
		testCase{
			name: transportSite + ": a cycle through Unwrap() []error is reported as a failed post",
			err:  &pe7bCycleMany{}, transport: true, child: true, assert: asTransportOutage("budget"),
		},
		testCase{name: transportSite + ": a plain failure, against itself", err: errPe7bDown, transport: true, assert: walked},
	)

	for _, row := range pe7eRows() {
		tc := testCase{name: string(site) + ": " + row.name, err: row.err(site), child: row.child, assert: asOutage(row.reason)}
		if row.cancel {
			tc.ctx = pe7eCancelled
		}

		cases = append(cases, tc)
	}

	cases = append(cases,
		testCase{
			name: string(site) + ": a typed-nil root walks to the end and is reported as a failed delivery",
			err:  (*pe7bTypedNil)(nil), assert: walked,
		},
		testCase{name: string(site) + ": a plain failure, against itself", err: errPe7bDown, assert: walked},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7kInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7kDeliverRun(ctx, t, errPe7bDown, tc.transport)
			wantReason := "delivery"
			if tc.transport {
				wantReason = "post"
			}
			require.Equal(t, []string{wantReason}, plain.reasons, "precondition: a plain failure is reported by where it failed")
			require.Equal(t, 1, plain.failureLogs, "precondition: a plain failure is logged once")
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")

			got := pe7kDeliverRun(ctx, t, tc.err, tc.transport)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7kRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7kOutcome is what one end-session or parked-request call produced through
// a failing port, the state it left, and what the provider logged.
type pe7kOutcome struct {
	errText           string
	failed            bool
	dependency        bool
	notFound          bool
	unknownHandle     bool
	invalidEndSession bool
	canceled          bool

	// What the call answered.
	location string
	hasFlow  bool
	viewed   bool
	ended    bool

	// The state afterwards.
	grantEnded  bool
	sessionHeld bool
	spendLogs   int

	aborts []map[string]any
}

// pe7kRun calls site's flow on ctx while site's port call fails with portErr,
// or answers (nil, nil) for errPe7kNoRecord. It fails the test when the call
// hangs, lets a panic escape, or never reaches site.
func pe7kRun(ctx context.Context, t *testing.T, site pe7eSite, portErr error) pe7kOutcome { //nolint:gocyclo,cyclop // one fixture, every entry point
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		hits  atomic.Int32
		now   = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
		user  = identity.UserID("u-1")
		clk   = clockwork.NewFakeClockAt(now)
	)

	// fail reports whether the port call at is the one a row breaks, counting
	// that it was reached.
	fail := func(at ...pe7eSite) bool {
		if armed.Load() && slices.Contains(at, site) {
			hits.Add(1)

			return true
		}

		return false
	}

	memPending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	memGrants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	grantFamily, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	digest := digestOf(t, pe7eSessionSecret)

	require.NoError(t, memSessions.Put(t.Context(), &oidcprovider.BrowserSession{ //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		Digest: digest,
		SignIn: oidcprovider.SignIn{
			User: user, Family: family, AuthenticatedAt: now.Add(-time.Minute), AMR: []string{"pwd"},
			AbsoluteExpiresAt: now.Add(time.Hour),
		},
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, memGrants.Create(t.Context(), &oidcprovider.Grant{ //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		Family: grantFamily, User: user, ClientID: "billing-web", Scopes: []string{"openid"},
		SignInFamily: family, AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	ctrl := gomock.NewController(t)

	pending := NewMockPendingRequestStore(ctrl)
	pending.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memPending.Create).AnyTimes()
	pending.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, d []byte) (*oidcprovider.PendingRequest, error) {
			if fail(pe7kPendingSites...) {
				if portErr == errPe7kNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					return nil, nil
				}

				return nil, portErr
			}

			return memPending.Load(context.WithoutCancel(ctx), d)
		}).AnyTimes()
	pending.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memPending.Advance).AnyTimes()
	pending.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memPending.DeleteExpired).AnyTimes()

	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Put).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, d []byte, at time.Time) (*oidcprovider.BrowserSession, error) {
			if fail(pe7kBrowserSites...) {
				if portErr == errPe7kNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					return nil, nil
				}

				return nil, portErr
			}

			return memSessions.Load(context.WithoutCancel(ctx), d, at)
		}).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Touch).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	signing := logoutSigningKeys()
	keys := NewMockKeySource(ctrl)
	keys.EXPECT().Signer(gomock.Any(), gomock.Any()).DoAndReturn(signing.Signer).AnyTimes()
	keys.EXPECT().VerificationKeys(gomock.Any()).DoAndReturn(
		func(ctx context.Context) ([]signingkey.PublicKey, error) {
			if fail(pe7kHintKeys) {
				return nil, portErr
			}

			return signing.VerificationKeys(ctx)
		}).AnyTimes()

	registry, err := oidcprovider.NewMemoryRegistry(authzClients())
	require.NoError(t, err)

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         keys,
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithLogger(logger),
		oidcprovider.WithPendingRequestStore(pending),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithGrantStore(memGrants),
	)
	require.NoError(t, err)

	// The hint is an ID token of this provider naming the browser's sign-in.
	issuerOf, err := token.NewIssuer(signing, signingkey.RS256, issuer, token.WithClock(clk))
	require.NoError(t, err)
	hint, err := issuerOf.Issue(t.Context(), token.Issue{ //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		Type: token.TypeIDToken, Subject: string(user), ID: "j-1", Audience: []string{"billing-web"},
		Lifetime: 5 * time.Minute, Claims: map[string]any{"sid": family.String()},
	})
	require.NoError(t, err)

	signIn := &oidcprovider.SignIn{
		User: user, Family: family, AuthenticatedAt: now.Add(-time.Minute), AMR: []string{"pwd"},
		AbsoluteExpiresAt: now.Add(time.Hour),
	}

	// parkedAt reads the handle and flow secret a parking answered with.
	parkedAt := func(location, flow string) (string, string) {
		loc, err := url.Parse(location)
		require.NoError(t, err)

		return loc.Query().Get(oidcprovider.HandleParam), flow
	}

	// Whatever a flow needs parked first is parked while every port works.
	var handle, flow string

	switch site {
	case pe7kViewLoad, pe7kResumeLoginLoad, pe7kResumeConsentLoad:
		res, err := p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()}) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		require.NoError(t, err)

		handle, flow = parkedAt(res.Location, res.FlowSecret)

		if site == pe7kResumeConsentLoad {
			_, err := p.Resume(t.Context(), oidcprovider.ResumeInput{ //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
				Handle: handle, FlowSecret: flow, SignIn: signIn, IdleTimeout: sessionIdle,
			})
			require.NoError(t, err, "precondition: the login stage is answered, and consent is asked")
		}
	case pe7kConfirmLoad, pe7kSpendLoad, pe7kConfirmBrowser:
		res, err := p.EndSession(t.Context(), oidcprovider.EndSessionInput{Params: url.Values{}}) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		require.NoError(t, err)

		handle, flow = parkedAt(res.Location, res.FlowSecret)
	}

	armed.Store(true)

	out := pe7eBounded(t, func() pe7kOutcome {
		var (
			o   pe7kOutcome
			err error
		)

		switch site {
		case pe7kHintKeys, pe7kEndSessionBrowser:
			var res *oidcprovider.EndSessionResult

			res, err = p.EndSession(ctx, oidcprovider.EndSessionInput{
				Params:               url.Values{"id_token_hint": {hint}},
				BrowserSessionSecret: pe7eSessionSecret,
			})
			if res != nil {
				o.location, o.hasFlow, o.ended = res.Location, res.FlowSecret != "", res.Ended != nil
			}
		case pe7kViewLoad:
			var view *oidcprovider.PendingView

			view, err = p.PendingRequest(ctx, handle, flow)
			o.viewed = view != nil
		case pe7kResumeLoginLoad:
			var res oidcprovider.ResumeResult

			res, err = p.Resume(ctx, oidcprovider.ResumeInput{
				Handle: handle, FlowSecret: flow, SignIn: signIn, IdleTimeout: sessionIdle,
			})
			o.location = res.RedirectTo
		case pe7kResumeConsentLoad:
			var res oidcprovider.ResumeResult

			res, err = p.Resume(ctx, oidcprovider.ResumeInput{
				Handle: handle, FlowSecret: flow, SignIn: signIn, IdleTimeout: sessionIdle,
				Answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}},
			})
			o.location = res.RedirectTo
		case pe7kConfirmLoad, pe7kConfirmBrowser:
			var res *oidcprovider.LogoutResult

			res, err = p.ConfirmLogout(ctx, handle, flow, pe7eSessionSecret, true)
			if res != nil {
				o.location, o.ended = res.RedirectTo, res.Ended != nil
			}
		case pe7kSpendLoad:
			p.SpendLogout(ctx, handle, flow)
		}

		if err != nil {
			o.failed = true
			o.errText = err.Error()
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, oidcprovider.ErrNotFound)
			o.unknownHandle = errors.Is(err, oidcprovider.ErrUnknownHandle)
			o.invalidEndSession = errors.Is(err, oidcprovider.ErrInvalidEndSession)
			o.canceled = errors.Is(err, context.Canceled)
		}

		return o
	})

	armed.Store(false)
	require.Positive(t, hits.Load(), "the call reached %s", site)

	g, err := memGrants.Load(t.Context(), grantFamily) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)
	out.grantEnded = !g.SignInEndedAt.IsZero()

	_, err = memSessions.Load(t.Context(), digest, now) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.sessionHeld = err == nil

	var spends []map[string]any

	out.aborts, spends = pe7eAbortsAndLogs(t, logs.String(), pe7kSpendFailed)
	out.spendLogs = len(spends)

	return out
}

// pe7kSameAsPlain asserts a row is answered and leaves state exactly as the
// plain outage of the same call did, and never as a not-found reading.
func pe7kSameAsPlain(t *testing.T, plain, got pe7kOutcome) {
	t.Helper()

	assert.Equal(t, plain.failed, got.failed)
	assert.Equal(t, plain.errText, got.errText, "the same returned error")
	assert.Equal(t, plain.dependency, got.dependency, "answered as a dependency failure")
	assert.Equal(t, plain.canceled, got.canceled)
	assert.False(t, got.notFound, "never answered as the port's not-found sentinel")
	assert.False(t, got.unknownHandle, "never answered as an unknown handle")
	assert.False(t, got.invalidEndSession, "never answered as an invalid hint")
	assert.Equal(t, plain.location, got.location, "answered at the same place")
	assert.Equal(t, plain.hasFlow, got.hasFlow, "nothing parked a page could answer")
	assert.Equal(t, plain.viewed, got.viewed)
	assert.Equal(t, plain.ended, got.ended, "no sign-in ended")
	assert.Equal(t, plain.grantEnded, got.grantEnded, "the same grants ended")
	assert.Equal(t, plain.sessionHeld, got.sessionHeld, "the browser session kept as after a plain outage")
	assert.Equal(t, plain.spendLogs, got.spendLogs, "the same failure records")
	assert.NotContains(t, got.errText, pe7bSecret)
}

// TestPortErrors_EndSessionAndLoads pins three things.
//
// An end-session request's id_token_hint judged while the key source fails
// with an error whose chain cannot be walked is answered exactly as a plain
// key outage is: a dependency failure, never a valid hint that ends a sign-in
// and never an invalid one. The sanitizer writes one record, to the
// provider's logger, and none to slog.Default().
//
// A pending-request store whose load answers no record and no error, at every
// entry point that reads a parked request, is answered as that store failing:
// a dependency failure (SpendLogout's logged failure), never an unknown handle
// and never a panic. A plain ErrNotFound keeps its answer.
//
// A browser-session store whose load answers no record and no error, at every
// entry point that asks it which sign-in to end, is answered as that store
// failing: the grant is not ended and the session is kept. A plain ErrNotFound
// keeps its answer: no session, nothing ended.
func TestPortErrors_EndSessionAndLoads(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7kRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		site   pe7eSite
		err    error
		child  bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, plain, got pe7kOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7kOutcome, pe7kOutcome) {
		return func(t *testing.T, plain, got pe7kOutcome) {
			t.Helper()

			pe7kSameAsPlain(t, plain, got)
			pe7eOneAbort(t, got.aborts, nil, reason)
		}
	}

	walked := func(t *testing.T, plain, got pe7kOutcome) {
		t.Helper()

		pe7kSameAsPlain(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	// The hint's key read: every hostile row.
	prefix := string(pe7kHintKeys) + ": "
	for _, row := range pe7eRows() {
		tc := testCase{name: prefix + row.name, site: pe7kHintKeys, err: row.err(pe7kHintKeys), child: row.child, assert: asOutage(row.reason)}
		if row.cancel {
			tc.ctx = pe7eCancelled
		}

		cases = append(cases, tc)
	}

	cases = append(cases, testCase{
		name: prefix + "a typed-nil root walks to the end and is answered as an outage",
		site: pe7kHintKeys, err: (*pe7bTypedNil)(nil), assert: walked,
	})

	// The loads: no record and no error, and the store's honest not-found.
	for _, site := range append(append([]pe7eSite{}, pe7kPendingSites...), pe7kBrowserSites...) {
		cases = append(cases, testCase{
			name: string(site) + ": a store answering no record and no error is answered as an outage",
			site: site, err: errPe7kNoRecord, assert: walked,
		})
	}

	notFoundIsUnknownHandle := func(t *testing.T, _, got pe7kOutcome) {
		t.Helper()

		assert.True(t, got.failed)
		assert.True(t, got.unknownHandle, "an unknown handle")
		assert.False(t, got.dependency)
		assert.Empty(t, got.aborts)
	}

	cases = append(cases,
		testCase{
			name: string(pe7kViewLoad) + ": a plain ErrNotFound is an unknown handle",
			site: pe7kViewLoad, err: oidcprovider.ErrNotFound, assert: notFoundIsUnknownHandle,
		},
		testCase{
			name: string(pe7kResumeLoginLoad) + ": a plain ErrNotFound is an unknown handle",
			site: pe7kResumeLoginLoad, err: oidcprovider.ErrNotFound, assert: notFoundIsUnknownHandle,
		},
		testCase{
			name: string(pe7kResumeConsentLoad) + ": a plain ErrNotFound is an unknown handle",
			site: pe7kResumeConsentLoad, err: oidcprovider.ErrNotFound, assert: notFoundIsUnknownHandle,
		},
		testCase{
			name: string(pe7kConfirmLoad) + ": a plain ErrNotFound is an unknown handle",
			site: pe7kConfirmLoad, err: oidcprovider.ErrNotFound, assert: notFoundIsUnknownHandle,
		},
		testCase{
			name: string(pe7kSpendLoad) + ": a plain ErrNotFound is an unknown handle, which is no failure to log",
			site: pe7kSpendLoad, err: oidcprovider.ErrNotFound,
			assert: func(t *testing.T, _, got pe7kOutcome) {
				t.Helper()

				assert.Zero(t, got.spendLogs, "an unknown handle is no failure")
				assert.Empty(t, got.aborts)
			},
		},
		testCase{
			name: string(pe7kEndSessionBrowser) + ": a plain ErrNotFound is no session, so the request is parked to ask",
			site: pe7kEndSessionBrowser, err: oidcprovider.ErrNotFound,
			assert: func(t *testing.T, _, got pe7kOutcome) {
				t.Helper()

				assert.False(t, got.failed, "no session is an answer")
				assert.True(t, strings.HasPrefix(got.location, issuer+"/logout?"), "the logout page asks: %s", got.location)
				assert.True(t, got.hasFlow)
				assert.False(t, got.ended)
				assert.False(t, got.grantEnded)
				assert.True(t, got.sessionHeld)
				assert.Empty(t, got.aborts)
			},
		},
		testCase{
			name: string(pe7kConfirmBrowser) + ": a plain ErrNotFound is no session, and ends nothing",
			site: pe7kConfirmBrowser, err: oidcprovider.ErrNotFound,
			assert: func(t *testing.T, _, got pe7kOutcome) {
				t.Helper()

				assert.False(t, got.failed, "no session is an answer")
				assert.False(t, got.ended)
				assert.False(t, got.grantEnded)
				assert.True(t, got.sessionHeld)
				assert.Empty(t, got.aborts)
			},
		},
	)

	// Every site's plain outage, against itself.
	for _, site := range append([]pe7eSite{pe7kHintKeys}, append(append([]pe7eSite{}, pe7kPendingSites...), pe7kBrowserSites...)...) {
		cases = append(cases, testCase{name: string(site) + ": a plain outage, against itself", site: site, err: errPe7bDown, assert: walked})
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7kInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7kRun(ctx, t, tc.site, errPe7bDown)
			if tc.site == pe7kSpendLoad {
				require.Equal(t, 1, plain.spendLogs, "precondition: a plain outage is logged once")
			} else {
				require.True(t, plain.failed && plain.dependency, "precondition: a plain outage is a dependency failure")
			}
			require.False(t, plain.grantEnded, "precondition: a plain outage ends no grant")
			require.True(t, plain.sessionHeld, "precondition: a plain outage keeps the browser session")
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7kRun(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7kRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7kInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7kInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7kRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7kRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
