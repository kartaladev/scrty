package httpsec_test

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The summary records each component writes when a flush reports what it held
// back. A row reads its own component's summaries by these, so a row passes
// only when the flush reached that component, not merely some sampler.
const (
	summaryChain     = "httpsec: refusal logs suppressed"
	summaryGuard     = "ratelimit: refusal records suppressed"
	summaryThrottle  = "mfa: verification refusals suppressed"
	summaryAuthn     = "authentication refusals suppressed"
	summaryOIDC      = "oidc refusals suppressed"
	summaryHandoff   = "oidc handoff refusals suppressed"
	summaryMFAPolicy = "policy: second-factor records suppressed"
)

// flushSource is the client address every guarded refusal in these tests comes
// from, so one source's refusals share one sampling key.
const flushSource = "198.51.100.23"

// summaries returns the suppressed count of every record in recs written with
// msg and, when attr is non-empty, whose attribute attr equals value.
func summaries(t *testing.T, recs []slog.Record, msg, attr, value string) []int64 {
	t.Helper()

	var counts []int64

	for _, r := range recs {
		if r.Message != msg {
			continue
		}

		if attr != "" {
			v, ok := attrValue(r, attr)
			if !ok || v.String() != value {
				continue
			}
		}

		counts = append(counts, suppressedCount(t, r))
	}

	return counts
}

// exceededLimiter is a consumer limiter reporting every source over its limit,
// so every attempt through a guard built over it is refused and sampled.
func exceededLimiter(t *testing.T) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return l
}

// refusingAuthenticator is the library's password authenticator over a user
// store that knows nobody, logging through log under a window no test outlives.
// It has already refused three logins, so it holds two suppressed refusals.
func refusingAuthenticator(t *testing.T, log *slog.Logger) authenticate.Authenticator {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
		Return(nil, identity.ErrUserNotFound).AnyTimes()

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordAuthenticatorLogger(log),
		authenticate.WithPasswordAuthenticatorLogInterval(time.Hour))
	require.NoError(t, err)

	for range 3 {
		_, err := authn.Authenticate(t.Context(), identity.NewUsernamePassword("nobody", []byte("wrong")))
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	}

	return authn
}

// flushOIDCRegistry registers testOIDCProvider with pinned endpoints, so
// nothing built over it sends a request.
func flushOIDCRegistry(t *testing.T) *oidc.Registry {
	t.Helper()

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                "https://idp.example.com",
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider,
		RedirectURL:           "https://app.example.com/login/oauth2/callback/" + testOIDCProvider,
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "https://idp.example.com/jwks",
	})
	require.NoError(t, err)

	return registry
}

// oidcChain builds a chain with federated login over m and handoffs, logging
// through log, with a session manager and token generator no row exercises.
func oidcChain(
	t *testing.T,
	log *slog.Logger,
	m *oidc.Manager,
	handoffs *oidc.HandoffManager,
	opts ...httpsec.OIDCOption,
) *httpsec.Chain {
	t.Helper()

	sessions, err := session.NewManager()
	require.NoError(t, err)

	base := []httpsec.OIDCOption{httpsec.WithOIDCSessions(sessions)}
	if handoffs != nil {
		base = append(base, httpsec.WithOIDCTokens(NewMockGenerator(gomock.NewController(t))))
	}

	c, err := httpsec.New(
		httpsec.WithLogger(log),
		httpsec.EnableOIDCLogin(m, handoffs, append(base, opts...)...),
	)
	require.NoError(t, err)

	return c
}

// redeemGarbage posts a malformed handoff code to c from flushSource n times.
func redeemGarbage(t *testing.T, c *httpsec.Chain, n int) {
	t.Helper()

	for range n {
		out := serve(t, c, handoffRequest(t.Context(), flushSource, "not-a-code"))
		require.Error(t, out.err)
	}
}

// TestFlushRefusalLogsReachesComponents pins spec http-security-chain "Chain
// refusal logs are sampled and summarised", scenarios "One flush reaches the
// components" and "Registered policy flushed": one FlushRefusalLogs call
// reports what every component the chain holds is still holding back, each
// through its own reporter.
//
// Every row drives one component until it has suppressed records under a
// window no test outlives, then flushes the chains it built, once each, and
// reads the summaries that flush alone wrote.
func TestFlushRefusalLogsReachesComponents(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange builds the chains under test, every one logging through
		// log, and leaves the row's component holding suppressed records.
		arrange func(t *testing.T, log *slog.Logger) []*httpsec.Chain

		// assert reads the records the flush wrote, and nothing earlier.
		assert func(t *testing.T, flushed []slog.Record)
	}

	cases := []testCase{
		{
			name: "the chain's own sampler",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				c, err := httpsec.New(httpsec.WithLogger(log))
				require.NoError(t, err)

				for range 3 {
					httpsec.LogSampledForTest(t.Context(), httpsec.SamplerForTest(c), log,
						slog.LevelWarn, time.Now(), "login|"+flushSource, "httpsec: source throttled")
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryChain, "", ""))
			},
		},
		{
			name: "the verification throttle EnableMFA built",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
				h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).Times(3)

				s := h.pendingSession(t, factor.Password)

				c, err := httpsec.New(
					httpsec.WithLogger(log),
					h.carries(s),
					httpsec.EnableMFA(h.method,
						httpsec.WithMFAVerifyLimiter(h.limiter),
						httpsec.WithMFATokens(h.tokens),
						httpsec.WithMFALogInterval(time.Hour)),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
				)
				require.NoError(t, err)

				for range 3 {
					out := serve(t, c, postCode(t.Context(), httpsec.DefaultMFAVerifyPath))
					require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryThrottle, "", ""))
			},
		},
		{
			name: "a source guard the chain built over its default limiter",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				c := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithHandoffRateLimit(1, time.Hour))

				// The first failure spends the allowance; the three after it
				// are throttled, one written and two held back.
				redeemGarbage(t, c, 4)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "oidc.handoff"))
			},
		},
		{
			name: "a source guard over a consumer-supplied limiter",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				c := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithHandoffLimiter(exceededLimiter(t)))
				redeemGarbage(t, c, 3)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "oidc.handoff"))
			},
		},
		{
			name: "the API key source guard",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAPIKeyHarness(t)

				c, err := httpsec.New(
					httpsec.WithLogger(log),
					httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(exceededLimiter(t))),
				)
				require.NoError(t, err)

				for range 3 {
					// A throttled source is refused with the same error as a
					// wrong key, so the refusal itself is all a row can see.
					out := h.withKey(t, c, flushSource, h.valid)
					require.Error(t, out.err)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "api-key"))
			},
		},
		{
			name: "the magic-link source guard",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newMagicLinkHarness(t)
				h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter(exceededLimiter(t))}
				h.chainOpts = []httpsec.Option{httpsec.WithLogger(log)}
				c := h.chain(t)

				for range 3 {
					out := h.redeemFrom(t, c, flushSource, "not-a-token", "")
					require.Error(t, out.err)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "magic-link-redeem"))
			},
		},
		{
			// Review Focus 4: a limiter the consumer shares between two
			// chains shares its counts, never the guards' samplers, so both
			// chains flushing reports the pending count once.
			name: "a consumer limiter shared by two chains, both flushed",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				shared := exceededLimiter(t)
				a := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithHandoffLimiter(shared))
				b := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithHandoffLimiter(shared))
				redeemGarbage(t, a, 3)

				return []*httpsec.Chain{a, b}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "oidc.handoff"),
					"the pending count was reported other than exactly once")
			},
		},
		{
			name: "the password authenticator of form login",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAuthHarness(t)
				deps := h.formLoginDeps()
				deps.Authenticator = refusingAuthenticator(t, log)

				c, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableFormLogin(deps))
				require.NoError(t, err)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""))
			},
		},
		{
			name: "the password authenticator of basic authentication",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAuthHarness(t)
				deps := h.basicAuthDeps()
				deps.Authenticator = refusingAuthenticator(t, log)

				c, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableBasicAuth(deps))
				require.NoError(t, err)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""))
			},
		},
		{
			// Review Focus 4 again, for a component the consumer hands to
			// two chains: each chain reaches it, and the second flush finds
			// nothing new pending.
			name: "one authenticator given to two chains, both flushed",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				authn := refusingAuthenticator(t, log)

				login := newAuthHarness(t).formLoginDeps()
				login.Authenticator = authn
				a, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableFormLogin(login))
				require.NoError(t, err)

				basic := newAuthHarness(t).basicAuthDeps()
				basic.Authenticator = authn
				b, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableBasicAuth(basic))
				require.NoError(t, err)

				return []*httpsec.Chain{a, b}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""),
					"the pending count was reported other than exactly once")
			},
		},
		{
			name: "a policy registered on the chain's engine",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				// A magic-link login whose only second factor arrives by email
				// is two factors on one channel, so the policy refuses it.
				method := NewMockMFAMethodLookup(gomock.NewController(t))
				method.EXPECT().Channel().Return(factor.Email).AnyTimes()
				method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				p, err := policy.NewMFAPolicy(method,
					policy.WithMFAPolicyLogger(log),
					policy.WithMFAPolicyLogInterval(time.Hour))
				require.NoError(t, err)

				engine, err := policy.NewEngine(p)
				require.NoError(t, err)

				c, err := httpsec.New(
					httpsec.WithLogger(log),
					httpsec.WithPolicyEngine(engine),
					httpsec.EnableGateForTest(policy.ChallengeMFA),
				)
				require.NoError(t, err)

				login := &policy.Input{User: "u-1", FirstFactor: factor.MagicLink, Now: time.Now()}
				for range 3 {
					d := engine.EvaluatePhase(t.Context(), policy.PostAuthentication, login)
					require.Equal(t, policy.Deny, d.Outcome, "the policy under test stopped refusing")
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryMFAPolicy, "", ""))
			},
		},
		{
			name: "the OIDC manager given to EnableOIDCLogin",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				// A flow-store fault is a refusal the manager samples itself.
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, errFlushFlowFault).Times(3)

				m, err := oidc.NewManager(flushOIDCRegistry(t),
					NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithLogger(log))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), testOIDCProvider, "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				return []*httpsec.Chain{oidcChain(t, log, m, newTestHandoffManager(t))}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryOIDC, "", ""))
			},
		},
		{
			name: "the OIDC handoff manager given to EnableOIDCLogin",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(),
					NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffLogger(log))
				require.NoError(t, err)

				for range 3 {
					_, err := handoffs.Redeem(t.Context(), "not-a-code")
					require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
				}

				return []*httpsec.Chain{oidcChain(t, log, newTestOIDCManager(t), handoffs)}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryHandoff, "", ""))
			},
		},
		{
			// Review Focus 5: a login conveyed by WithCallbackSuccess has no
			// handoff manager and no redemption guard to flush; the manager
			// is still reached.
			name: "an OIDC chain with WithCallbackSuccess and no handoff manager",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, errFlushFlowFault).Times(3)

				m, err := oidc.NewManager(flushOIDCRegistry(t),
					NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithLogger(log))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), testOIDCProvider, "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				conveyed := func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil }

				return []*httpsec.Chain{oidcChain(t, log, m, nil, httpsec.WithCallbackSuccess(conveyed))}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryOIDC, "", ""))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &capturingHandler{}
			chains := tc.arrange(t, slog.New(logs))
			before := len(logs.records())

			require.NotPanics(t, func() {
				for _, c := range chains {
					c.FlushRefusalLogs()
				}
			})

			tc.assert(t, logs.records()[before:])
		})
	}
}

// TestFlushRefusalLogsReachesEveryComponentOnOneChain pins spec
// http-security-chain "Chain refusal logs are sampled and summarised",
// scenario "One flush reaches the components", against the chain the
// scenario actually names: ONE chain carrying form login, the second-factor
// verify endpoint, a magic-link source guard and OIDC login, with a policy
// registered on its engine — not one chain built per component, as
// TestFlushRefusalLogsReachesComponents does. A chain.go that stopped after
// flushing the first component it reached would still pass every row of that
// table, because each row's chain holds only one; this test is the one that
// would catch it.
//
// It is a standalone test rather than another row of that table, because
// assembling six collaborators onto one chain and driving each into a
// refusal is not the "one component, one chain" shape the other rows share.
func TestFlushRefusalLogsReachesEveryComponentOnOneChain(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}
	log := slog.New(logs)

	// The password authenticator of form login. It already holds two
	// suppressed refusals by the time it is handed over: refusingAuthenticator
	// drives them itself.
	loginDeps := newAuthHarness(t).formLoginDeps()
	loginDeps.Authenticator = refusingAuthenticator(t, log)

	// The verification throttle EnableMFA builds: the method's channel
	// differs from the session's first factor, so the same-channel exemption
	// never applies and every attempt reaches the throttle.
	mh := newMFAHarness(t)
	mh.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
	mh.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).Times(3)
	pending := mh.pendingSession(t, factor.Password)

	// The magic-link source guard, built over a consumer limiter reporting
	// every source exceeded.
	lh := newMagicLinkHarness(t)
	lh.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter(exceededLimiter(t))}

	// The OIDC manager and the handoff manager EnableOIDCLogin is given.
	flows := NewMockFlowStore(gomock.NewController(t))
	flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(oidc.Flow{}, errFlushFlowFault).Times(3)

	m, err := oidc.NewManager(flushOIDCRegistry(t), NewMockIdentityBroker(gomock.NewController(t)),
		oidc.WithFlowStore(flows), oidc.WithLogger(log))
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(),
		NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffLogger(log))
	require.NoError(t, err)

	oidcSessions, err := session.NewManager()
	require.NoError(t, err)

	// A second-factor policy registered on the chain's engine: a magic-link
	// login whose only second factor arrives by email is two factors on one
	// channel, so the policy refuses it. EnableMFA below is what enforces the
	// challenge this policy raises, so no separate gate is needed.
	method := NewMockMFAMethodLookup(gomock.NewController(t))
	method.EXPECT().Channel().Return(factor.Email).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	p, err := policy.NewMFAPolicy(method,
		policy.WithMFAPolicyLogger(log), policy.WithMFAPolicyLogInterval(time.Hour))
	require.NoError(t, err)

	engine, err := policy.NewEngine(p)
	require.NoError(t, err)

	c, err := httpsec.New(
		httpsec.WithLogger(log),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableFormLogin(loginDeps),
		mh.carries(pending),
		httpsec.EnableMFA(mh.method,
			httpsec.WithMFAVerifyLimiter(mh.limiter),
			httpsec.WithMFATokens(mh.tokens),
			httpsec.WithMFALogInterval(time.Hour)),
		httpsec.EnableMagicLink(lh.manager, lh.options()...),
		httpsec.EnableOIDCLogin(m, handoffs,
			httpsec.WithOIDCSessions(oidcSessions),
			httpsec.WithOIDCTokens(NewMockGenerator(gomock.NewController(t)))),
	)
	require.NoError(t, err)

	// Drive every component but the authenticator — already refused above —
	// into holding suppressed refusals, all under one window no test outlives.
	for range 3 {
		out := serve(t, c, postCode(t.Context(), httpsec.DefaultMFAVerifyPath))
		require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
	}

	for range 3 {
		out := lh.redeemFrom(t, c, flushSource, "not-a-token", "")
		require.Error(t, out.err)
	}

	for range 3 {
		_, err := m.Callback(t.Context(), testOIDCProvider, "the-code", "the-state", "the-handle")
		require.Error(t, err)
	}

	for range 3 {
		_, err := handoffs.Redeem(t.Context(), "not-a-code")
		require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
	}

	login := &policy.Input{User: "u-1", FirstFactor: factor.MagicLink, Now: time.Now()}
	for range 3 {
		d := engine.EvaluatePhase(t.Context(), policy.PostAuthentication, login)
		require.Equal(t, policy.Deny, d.Outcome, "the policy under test stopped refusing")
	}

	before := len(logs.records())

	require.NotPanics(t, func() { c.FlushRefusalLogs() })

	flushed := logs.records()[before:]

	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""),
		"the form login authenticator was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryThrottle, "", ""),
		"the verification throttle was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "magic-link-redeem"),
		"the magic-link source guard was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryOIDC, "", ""),
		"the OIDC manager was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryHandoff, "", ""),
		"the OIDC handoff manager was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryMFAPolicy, "", ""),
		"the registered policy was not reached by the one flush")
}

// errFlushFlowFault is a flow-store failure, which the OIDC manager samples
// under its own window, unlike an invalid state, which it never logs.
var errFlushFlowFault = errors.New("flush_test: flow store fault fixture")
