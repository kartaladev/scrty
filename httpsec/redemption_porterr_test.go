package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// redemptionPortErrRowEnv names the row a child process runs. It is empty in
// the parent.
const redemptionPortErrRowEnv = "SCRTY_HTTPSEC_REDEMPTION_PORTERR_ROW"

// redemptionPortErrRan is what a child prints, as a line of its own followed
// by the row's name, once it has run its row to the end.
const redemptionPortErrRan = "redemption-porterr-row-ran:"

// redemptionPortOutcome is what one magic-link redemption produced that a
// client or the source's allowance can observe, and the records each logger
// received.
type redemptionPortOutcome struct {
	status int
	header http.Header
	body   string

	// charged is the flow limiter's RecordFailure calls: what was counted
	// against the source.
	charged int

	chainLogs, linkLogs []slog.Record
}

// redemptionPortSite is one consumer dependency a magic-link redemption runs
// before the spend, failing with portErr. countsUnderOptOut is whether its
// plain failure is counted against the source under the count-refusals
// opt-out.
type redemptionPortSite struct {
	name string

	// configure wires h so the redemption meets portErr at the site.
	configure func(t *testing.T, h *magicLinkHarness, portErr error)

	assert func(t *testing.T, plain, got redemptionPortOutcome, reason string)

	// skip, when set, names the reason a kind of error is not run at the
	// site, and "" for every kind that is.
	skip func(kind string) string
}

// redeemMagicLinkThrough requests one link and redeems it once on ctx through
// the chain's net/http middleware, with the count-refusals opt-out on and the
// flow's limiter counting what is charged. The chain logs to one capturing
// logger, the manager to another.
func redeemMagicLinkThrough(
	ctx context.Context,
	t *testing.T,
	configure func(t *testing.T, h *magicLinkHarness),
) redemptionPortOutcome {
	t.Helper()

	chainLogs, linkLogs := &capturingHandler{}, &capturingHandler{}

	var charged atomic.Int32

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string) error {
			charged.Add(1)

			return nil
		}).AnyTimes()

	h := newMagicLinkHarness(t, magiclink.WithLogger(slog.New(linkLogs)))
	h.linkOpts = append(h.linkOpts,
		httpsec.WithMagicLinkCountRefusals(false), httpsec.WithMagicLinkLimiter(limiter))
	h.chainOpts = append(h.chainOpts, httpsec.WithLogger(slog.New(chainLogs)))
	configure(t, h)

	c := h.chain(t)
	link, nonce := h.link(t, c) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()

	req := postValues(ctx, httpsec.DefaultMagicLinkConsumePath, magicLinkSource, url.Values{"token": {link}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	rec := loginServeWithin(t, c, req)

	return redemptionPortOutcome{
		status:    rec.Code,
		header:    rec.Header(),
		body:      rec.Body.String(),
		charged:   int(charged.Load()),
		chainLogs: chainLogs.records(),
		linkLogs:  linkLogs.records(),
	}
}

// assertRedemptionParity is the outcome every hostile row shares: the plain
// failure's response, byte for byte, and its charge to the source.
func assertRedemptionParity(t *testing.T, plain, got redemptionPortOutcome) {
	t.Helper()

	assert.Equal(t, plain.status, got.status, "status")
	assert.Equal(t, plain.header, got.header, "headers")
	assert.Equal(t, plain.body, got.body, "body")
	assert.Equal(t, plain.charged, got.charged, "charges to the source")
	assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
}

// assertOneAbortOnChain asserts the one abort record a hostile row writes is
// on the chain's logger, and none is on the manager's.
func assertOneAbortOnChain(t *testing.T, got redemptionPortOutcome, reason string) {
	t.Helper()

	assert.Empty(t, abortRecords(got.linkLogs), "none on the manager's logger")

	aborts := abortRecords(got.chainLogs)
	if reason == "" {
		assert.Empty(t, aborts, "a walk that completes writes no abort record")

		return
	}

	require.Len(t, aborts, 1, "one abort record, on the chain's logger")
	assertAbortRecord(t, aborts[0], reason)
}

func redemptionPortSites() []redemptionPortSite {
	// sessionLogs is the session manager's logger of the row being run, set by
	// that site's configure. Rows run one after another.
	var sessionLogs *capturingHandler

	return []redemptionPortSite{
		{
			name: "the consumer's refusal check",
			configure: func(_ *testing.T, h *magicLinkHarness, portErr error) {
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkChecks(
					func(context.Context, identity.Principal, time.Time) error { return portErr }))
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Zero(t, plain.charged, "the opt-out exempts the consumer's own refusal")
				assertRedemptionParity(t, plain, got)
				assertOneAbortOnChain(t, got, reason)
			},
		},
		{
			name: "the policy's deny reason",
			configure: func(t *testing.T, h *magicLinkHarness, portErr error) {
				h.engine = denyingEngine(t, portErr)
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Zero(t, plain.charged, "the opt-out exempts the policy's denial")
				assertRedemptionParity(t, plain, got)
				assertOneAbortOnChain(t, got, reason)
			},
		},
		{
			// The issuing step's failure is recorded on the outcome too, and
			// is never counted, plain or hostile.
			name: "the token generator, beside a consumer check that passes",
			configure: func(t *testing.T, h *magicLinkHarness, portErr error) {
				h.tokens = newMockGenerator(gomock.NewController(t))
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", portErr).AnyTimes()
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkChecks(
					func(context.Context, identity.Principal, time.Time) error { return nil }))
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Zero(t, plain.charged, "an issuing failure is never counted")
				assertRedemptionParity(t, plain, got)
				// Sanitized where the generator returns, onto the chain's
				// logger.
				assertOneAbortOnChain(t, got, reason)
			},
		},
		{
			// The session the issuing step builds draws its identifier from
			// the session manager's random source, a consumer port the
			// session package returns unsanitized. Its failure is recorded
			// on the outcome as the issuing step's, so the record must be the
			// very value the redeemer hands back, walkable or not.
			name: "the session manager's random source, beside a consumer check that passes",
			configure: func(t *testing.T, h *magicLinkHarness, portErr error) {
				sessionLogs = &capturingHandler{}

				sessions, err := session.New(
					session.WithRandom(failingRandom{err: portErr}),
					session.WithLogger(slog.New(sessionLogs)))
				require.NoError(t, err)

				h.sessions = sessions
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkChecks(
					func(context.Context, identity.Principal, time.Time) error { return nil }))
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Zero(t, plain.charged, "a failure to build the session is never counted")
				assertRedemptionParity(t, plain, got)
				assert.Empty(t, abortRecords(got.chainLogs), "none on the chain's logger")
				assert.Empty(t, abortRecords(got.linkLogs), "none on the link manager's logger")

				aborts := abortRecords(sessionLogs.records())
				if reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")

					return
				}

				require.Len(t, aborts, 1, "one abort record, on the session manager's logger")
				assertAbortRecord(t, aborts[0], reason)
			},
		},
		{
			// The consumer's Redeemer is a port too: whatever it returns goes
			// into the charge decision, which walks the error whenever a
			// check, the policy or the issuing step recorded one. The
			// redeemer here runs the checks, a consumer check refuses with a
			// plain error, and it then answers with portErr.
			name: "the consumer's redeemer, beside a refusing check it ran",
			configure: func(_ *testing.T, h *magicLinkHarness, portErr error) {
				h.linkOpts = append(h.linkOpts,
					httpsec.WithMagicLinkChecks(func(context.Context, identity.Principal, time.Time) error {
						return errors.New("redemption_porterr_test: refused")
					}),
					httpsec.WithMagicLinkRedeemer(redeemerFunc(func(
						ctx context.Context, _, _ string, checks ...magiclink.Check,
					) (magiclink.Redemption, error) {
						p := identity.Principal{ID: magicLinkUserID, Username: magicLinkKnown}
						for _, check := range checks {
							if err := check(ctx, p, time.Time{}); err != nil {
								break
							}
						}

						return magiclink.Redemption{}, portErr
					})))
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assertRedemptionParity(t, plain, got)
				assertOneAbortOnChain(t, got, reason)
			},
		},
		{
			// Another port's fault in the same redemption: it is never taken for
			// the consumer's refusal, so it is counted as its plain outage is.
			name: "the enrolment lookup of a raised challenge, beside a consumer check that passes",
			configure: func(t *testing.T, h *magicLinkHarness, portErr error) {
				method := NewMockMethod(gomock.NewController(t))
				method.EXPECT().Name().Return("totp").AnyTimes()
				method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
				method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
				method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, portErr).AnyTimes()

				h.engine = engineOf(t, policyAnswering(t, policy.Decision{
					Outcome: policy.Challenge, Challenge: policy.ChallengeMFA,
				}))
				h.chainOpts = append(h.chainOpts,
					httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens)))
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkChecks(
					func(context.Context, identity.Principal, time.Time) error { return nil }))
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Equal(t, 1, plain.charged, "an enrolment outage is counted under the opt-out")
				assertRedemptionParity(t, plain, got)

				aborts := append(abortRecords(got.chainLogs), abortRecords(got.linkLogs)...)
				if reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")

					return
				}

				require.Len(t, aborts, 1, "one abort record")
				assertAbortRecord(t, aborts[0], reason)
			},
		},
	}
}

func redemptionPortErrKinds() []loginPortErrKind {
	return []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain error of the port.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}
}

// TestPortErrors_Redemption pins that an error the magic-link redemption meets
// at a consumer dependency before the spend is classified the same whether or
// not its chain can be walked: a hostile consumer check error, or policy deny
// reason, is exempted from the source count under the opt-out exactly as a
// plain one is, and answered with the same response, byte for byte; a hostile
// error from another dependency of the same redemption is never taken for the
// consumer's refusal, and is counted as its plain outage is. Each abort is
// reported once, and none to slog.Default().
func TestPortErrors_Redemption(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(redemptionPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live"},
		{name: "cancelled", ctx: func(ctx context.Context) context.Context {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			return cctx
		}},
	}

	plainOutage := errors.New("redemption_porterr_test: dependency unavailable")

	for _, site := range redemptionPortSites() {
		for _, c := range contexts {
			for _, kind := range redemptionPortErrKinds() {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if site.skip != nil {
						if reason := site.skip(kind.name); reason != "" {
							t.Skip(reason)
						}
					}

					if kind.child && childRow == "" {
						redemptionPortErrInChild(t, row)

						return
					}

					defaults := swapDefaultLogger(t)

					ctx := t.Context()
					if c.ctx != nil {
						ctx = c.ctx(ctx)
					}

					serve := func(portErr error) redemptionPortOutcome {
						return redeemMagicLinkThrough(ctx, t, func(t *testing.T, h *magicLinkHarness) {
							site.configure(t, h, portErr)
						})
					}

					plain := serve(plainOutage)
					require.Empty(t, abortRecords(plain.chainLogs), "the plain error writes no abort record")
					require.Empty(t, abortRecords(plain.linkLogs), "the plain error writes no abort record")

					got := serve(kind.err)
					site.assert(t, plain, got, kind.reason)
					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						_, _ = fmt.Fprintln(os.Stdout, redemptionPortErrRan+row)
					}
				})
			}
		}
	}
}

// redemptionPortErrInChild re-runs the current top-level test in a child
// process limited to row, and fails unless it exits 0 within a minute having
// printed the row's marker as a whole line: a stack overflow is fatal and only
// a child can watch for one, and a row name that matched nothing would
// otherwise pass without running.
func redemptionPortErrInChild(t *testing.T, row string) {
	limiterPortErrInChild(t, redemptionPortErrRowEnv, redemptionPortErrRan, row)
}

// failingRandom is an entropy source that fails every read with err.
type failingRandom struct{ err error }

func (r failingRandom) Read([]byte) (int, error) { return 0, r.err }

// redeemOIDCHandoffThrough issues one handoff code and redeems it once on ctx
// through the chain's net/http middleware, with the count-refusals opt-out on
// and the flow's limiter counting what is charged. The chain logs to one
// capturing logger; the handoff manager logs to slog.Default(), which the
// caller watches.
func redeemOIDCHandoffThrough(
	ctx context.Context,
	t *testing.T,
	configure func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption,
) redemptionPortOutcome {
	t.Helper()

	chainLogs := &capturingHandler{}

	var charged atomic.Int32

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string) error {
			charged.Add(1)

			return nil
		}).AnyTimes()

	h := newOIDCHarness(t) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()
	extra := configure(t, h)

	code := h.issueHandoff(t, "") //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()

	opts := append([]httpsec.Option{
		httpsec.WithLogger(slog.New(chainLogs)),
		httpsec.WithRefusalLogInterval(0),
	}, h.chainOpts...)
	opts = append(opts, httpsec.EnableOIDCLogin(
		httpsec.OIDCDeps{RelyingParty: h.manager, Handoff: h.handoffs},
		append([]httpsec.OIDCOption{
			httpsec.WithOIDCTokens(h.tokens),
			httpsec.WithOIDCSessions(h.sessions),
			httpsec.WithOIDCHandoffCountRefusals(false),
			httpsec.WithOIDCHandoffLimiter(limiter),
		}, extra...)...,
	))

	c, err := httpsec.New(opts...)
	require.NoError(t, err)

	rec := loginServeWithin(t, c, handoffRequest(ctx, oidcTestSource, code))

	return redemptionPortOutcome{
		status:    rec.Code,
		header:    rec.Header(),
		body:      rec.Body.String(),
		charged:   int(charged.Load()),
		chainLogs: chainLogs.records(),
	}
}

// oidcRedemptionPortSite is one consumer dependency the OIDC handoff
// redemption runs before the spend, failing with portErr.
type oidcRedemptionPortSite struct {
	name string

	// configure wires h so the redemption meets portErr at the site.
	configure func(t *testing.T, h *oidcHarness, portErr error)

	// options, when set, are the OIDC options the site adds for portErr.
	options func(h *oidcHarness, portErr error) []httpsec.OIDCOption

	assert func(t *testing.T, plain, got redemptionPortOutcome, reason string)
}

// handoffRedeemerFunc adapts a function to httpsec.HandoffRedeemer.
type handoffRedeemerFunc func(context.Context, string, ...oidc.RedeemCheck) (oidc.HandoffResult, error)

func (f handoffRedeemerFunc) Redeem(
	ctx context.Context, code string, checks ...oidc.RedeemCheck,
) (oidc.HandoffResult, error) {
	return f(ctx, code, checks...)
}

func oidcRedemptionPortSites() []oidcRedemptionPortSite {
	return []oidcRedemptionPortSite{
		{
			name: "the policy's deny reason",
			configure: func(t *testing.T, h *oidcHarness, portErr error) {
				h.issueTokens()
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(denyingEngine(t, portErr)))
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Zero(t, plain.charged, "the opt-out exempts the policy's denial")
				assertRedemptionParity(t, plain, got)
				assertOneAbortOnChain(t, got, reason)
			},
		},
		{
			// The consumer's HandoffRedeemer is a port: it runs the checks,
			// the policy denies with a plain reason, and it answers with
			// portErr, which the charge decision then walks.
			name: "the consumer's redeemer, beside a denying policy it ran",
			configure: func(t *testing.T, h *oidcHarness, _ error) {
				h.issueTokens()
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(
					denyingEngine(t, errors.New("redemption_porterr_test: denied"))))
			},
			options: func(h *oidcHarness, portErr error) []httpsec.OIDCOption {
				res := h.handoffResult()

				return []httpsec.OIDCOption{httpsec.WithOIDCHandoffRedeemer(handoffRedeemerFunc(func(
					ctx context.Context, _ string, checks ...oidc.RedeemCheck,
				) (oidc.HandoffResult, error) {
					c := oidc.RedeemCandidate{Principal: *res.Principal, Provider: res.Provider}
					for _, check := range checks {
						if err := check(ctx, c); err != nil {
							break
						}
					}

					return oidc.HandoffResult{}, portErr
				}))}
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assertRedemptionParity(t, plain, got)
				assertOneAbortOnChain(t, got, reason)
			},
		},
		{
			name: "the token generator",
			configure: func(_ *testing.T, h *oidcHarness, portErr error) {
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", portErr).AnyTimes()
			},
			assert: func(t *testing.T, plain, got redemptionPortOutcome, reason string) {
				t.Helper()

				assert.Equal(t, http.StatusInternalServerError, plain.status, "an issuing failure is an outage")
				assert.Zero(t, plain.charged, "an issuing failure is never counted")
				assertRedemptionParity(t, plain, got)
				assertOneAbortOnChain(t, got, reason)
			},
		},
	}
}

// TestPortErrors_OIDCRedemption pins, for the OIDC handoff redemption, what
// TestPortErrors_Redemption pins for the magic link: a hostile policy deny
// reason, or token generator error, met before the code is spent is answered
// exactly as its plain counterpart, byte for byte and charge for charge, with
// one abort record on the chain's logger and none on slog.Default().
func TestPortErrors_OIDCRedemption(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(redemptionPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live"},
		{name: "cancelled", ctx: func(ctx context.Context) context.Context {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			return cctx
		}},
	}

	plainOutage := errors.New("redemption_porterr_test: dependency unavailable")

	for _, site := range oidcRedemptionPortSites() {
		for _, c := range contexts {
			for _, kind := range redemptionPortErrKinds() {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						redemptionPortErrInChild(t, row)

						return
					}

					defaults := swapDefaultLogger(t)

					ctx := t.Context()
					if c.ctx != nil {
						ctx = c.ctx(ctx)
					}

					serve := func(portErr error) redemptionPortOutcome {
						return redeemOIDCHandoffThrough(ctx, t, func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption {
							site.configure(t, h, portErr)

							if site.options == nil {
								return nil
							}

							return site.options(h, portErr)
						})
					}

					plain := serve(plainOutage)
					require.Empty(t, abortRecords(plain.chainLogs), "the plain error writes no abort record")

					got := serve(kind.err)
					site.assert(t, plain, got, kind.reason)
					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						_, _ = fmt.Fprintln(os.Stdout, redemptionPortErrRan+row)
					}
				})
			}
		}
	}
}
