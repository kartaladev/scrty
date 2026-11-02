package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
)

//go:generate mockgen -destination=challengeverifier_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec ChallengeVerifier

// ErrChallengeRequired refuses a request the automation-challenge verifier
// refused (EnableAutomationChallenge). StatusForError answers it 403: the
// client must pass the challenge, not present other credentials. It is
// returned before any account is looked up, so it says nothing about one.
var ErrChallengeRequired = errors.New("httpsec: automation challenge required")

// ErrChallengeUnavailable is matched by the error a request fails with when
// the automation-challenge verifier returned an error, or an answer that is
// none of the three decisions. It is a dependency failure, not a refusal:
// StatusForError answers it 500 whatever the verifier's own error wraps, and
// it is charged to no throttle. Its text is fixed library text; the
// verifier's error stays reachable through errors.Is and errors.As.
var ErrChallengeUnavailable = errors.New("httpsec: automation challenge verifier unavailable")

// ChallengeDecision is a ChallengeVerifier's answer about one request.
//
// The zero value is no decision. A verifier that answers it, or any other
// value not declared here, has not let the request through: the request fails
// as a dependency failure (ErrChallengeUnavailable), so a verifier that
// forgot to set its answer is seen at once rather than read as a pass.
type ChallengeDecision int

// The answers a ChallengeVerifier gives.
const (
	// ChallengePass is a request that presented a challenge response the
	// verifier accepted. It proceeds.
	ChallengePass ChallengeDecision = iota + 1

	// ChallengeRefuse is a request that must pass a challenge first: one
	// with no response, or one the verifier did not accept. It is refused
	// with ErrChallengeRequired.
	ChallengeRefuse

	// ChallengeNotNeeded is a request the verifier lets through without a
	// challenge, typically because ChallengeSignals reports nothing
	// suspicious. It proceeds, exactly as ChallengePass does.
	ChallengeNotNeeded
)

// ChallengeSignals is what the chain tells a verifier about a request, so it
// can ask only suspicious requests for a challenge and answer
// ChallengeNotNeeded for ordinary traffic.
//
// Each field is true whenever the chain cannot say the answer is false: a
// limiter or attempt store that fails, a limiter that cannot report recent
// failures (ratelimit.RecentFailureReporter), and an address that cannot be
// attributed to one source all read as having failures, so a verifier that
// asks only suspicious requests asks.
type ChallengeSignals struct {
	// SourceHasFailures reports at least one failure recorded for the
	// request's source, in the window of the flow's source limiter, however
	// far below the limit: a wrong password at form login and Basic, a refused
	// redemption for a magic-link request, a refused recovery for a recovery
	// start. The passwordless begin's limiter counts every begin, so there it
	// reports a source that has begun a ceremony in the window.
	SourceHasFailures bool

	// IdentifierHasFailures reports at least one failed login recorded in the
	// last 24 hours for the identifier the request names, in the chain's
	// password-login attempt store: the username at form login and Basic,
	// and the username at a recovery start. It is false for the flows that
	// read no identifier before their lookup, the passwordless begin, and the
	// magic-link request, whose address no lockout counts failures for.
	IdentifierHasFailures bool
}

// ChallengeVerifier decides whether a request has passed an automation
// challenge: a CAPTCHA, a managed challenge, a proof of work, or anything else
// the consumer chooses. It is the consumer's own, typically a client of a
// third-party service; scrty bundles none, and there is no default.
//
// Verify reads the challenge response from r wherever the consumer's client
// side put it (a header, a form field, a cookie); reading the body with
// r.Body is safe, since the flow reads it again from the same buffer. It
// answers with a ChallengeDecision.
//
// An error is an outage of the verifier, not a refusal: the request fails as
// a dependency failure (ErrChallengeUnavailable, 500), charged to no throttle.
// An error that is ctx's own end is a client that left. Its text never reaches
// the client or a log record, so it may name what the verifier saw.
//
// An implementation must be safe for concurrent use, and should bound its own
// I/O: it runs on the request path, in front of the flow.
type ChallengeVerifier interface {
	Verify(ctx context.Context, r Request, s ChallengeSignals) (ChallengeDecision, error)
}

// ChallengeFlow names an unauthenticated flow the challenge verifier can stand
// in front of (WithChallengeFlows).
type ChallengeFlow string

// The flows EnableAutomationChallenge covers, every one selected by default.
const (
	// ChallengeFlowFormLogin is form login (EnableFormLogin).
	ChallengeFlowFormLogin ChallengeFlow = "form-login"

	// ChallengeFlowBasicAuth is Basic authentication (EnableBasicAuth).
	ChallengeFlowBasicAuth ChallengeFlow = "basic-auth"

	// ChallengeFlowMagicLinkRequest is the magic-link request endpoint
	// (EnableMagicLink), not its redemption.
	ChallengeFlowMagicLinkRequest ChallengeFlow = "magic-link-request"

	// ChallengeFlowPasswordlessBegin is the passwordless passkey login's
	// begin endpoint (WithPasskeyPasswordlessLogin), not its finish.
	ChallengeFlowPasswordlessBegin ChallengeFlow = "passwordless-begin"

	// ChallengeFlowRecoveryStart is the account-recovery start endpoint
	// (EnableAccountRecovery), not its completion.
	ChallengeFlowRecoveryStart ChallengeFlow = "recovery-start"
)

// challengeFlowsAll is every flow the seam covers, the default selection.
var challengeFlowsAll = []ChallengeFlow{
	ChallengeFlowFormLogin,
	ChallengeFlowBasicAuth,
	ChallengeFlowMagicLinkRequest,
	ChallengeFlowPasswordlessBegin,
	ChallengeFlowRecoveryStart,
}

// ChallengeOption configures EnableAutomationChallenge. Each replaces one of
// the defaults named there.
type ChallengeOption func(*challengeGate) error

// challengeIdentifierWindow is how far back an identifier's recorded login
// failures count as recent for ChallengeSignals.IdentifierHasFailures: the
// account-lockout policy's default window, so an identifier the lockout still
// counts failures for reads as suspicious.
const challengeIdentifierWindow = 24 * time.Hour

// challengeGate is the configured verifier, shared by every flow it was
// selected for.
type challengeGate struct {
	verifier ChallengeVerifier
	flows    map[ChallengeFlow]bool

	// countRefusals charges a refusal to the flow's source limit
	// (WithoutChallengeRefusalCounting turns it off).
	countRefusals bool

	// attempts is the chain's password-login attempt store, read for the
	// identifier signal of a flow that has none of its own (recovery start),
	// settled at assembly, and nil on a chain without password login.
	attempts policy.AttemptStore

	// log and sampler are the chain's, handed over once it exists, and now
	// is the chain's clock.
	log     *slog.Logger
	sampler *logsample.Sampler
	now     func() time.Time
}

// EnableAutomationChallenge puts v, a consumer's automation challenge such as
// a CAPTCHA, a managed challenge or a proof of work, in front of the chain's
// unauthenticated flows, so an automated attack on them costs more.
//
// Default: off. No flow asks for a challenge until this option is given, and
// scrty bundles no verifier for any third-party service: v is the consumer's,
// and decides on its own what a challenge is and where its answer travels (a
// header, a form field, a cookie).
//
// Once enabled, v is asked in every selected flow, after the flow's source
// limit and before its guarded work and any account lookup:
//
//   - form login (ChallengeFlowFormLogin), after the password-login source
//     limit and before the pre-authentication phase;
//   - Basic authentication (ChallengeFlowBasicAuth), likewise;
//   - the magic-link request (ChallengeFlowMagicLinkRequest), before the
//     address is looked up or anything is sent; this endpoint has no source
//     limit of its own;
//   - the passwordless passkey begin (ChallengeFlowPasswordlessBegin), after
//     its source limit and before the begin is counted or a challenge issued;
//   - the account-recovery start (ChallengeFlowRecoveryStart), after its
//     source limit and before the start is counted or the username looked up.
//
// All five are selected by default; WithChallengeFlows narrows them. A source
// the source limit refuses never reaches v.
//
// v answers each request with a ChallengeDecision:
//
//   - ChallengePass and ChallengeNotNeeded let the request through, unchanged;
//   - ChallengeRefuse refuses it with ErrChallengeRequired, answered 403,
//     before any account is looked up and without recording a lockout
//     failure. The refusal counts against the flow's source limit like a
//     failed attempt, by default (WithoutChallengeRefusalCounting), and never
//     against the identifier's lockout.
//
// A v that returns an error fails the request as a dependency failure:
// ErrChallengeUnavailable behind fixed library text, answered 500, with v's
// error reachable through errors.Is and errors.As but never in the text,
// recorded at ERROR by the error's type, sampled per flow, and charged to no
// throttle. So is an answer that is none of the three decisions. An error v
// returns because the request's own context ended is a client that left, not
// an outage: the request fails with an error matching that context's error,
// recorded at debug and charged to nothing.
//
// v is told, through ChallengeSignals, whether the request's source and its
// identifier have recent failures, so it can answer ChallengeNotNeeded for
// ordinary traffic and ask only suspicious requests.
//
// A nil v, or an interface holding a nil pointer, fails New with a
// configuration error naming the verifier; a second EnableAutomationChallenge
// is refused with one too.
func EnableAutomationChallenge(v ChallengeVerifier, opts ...ChallengeOption) Option {
	const option = "EnableAutomationChallenge"

	return func(c *config) error {
		if c.challenge != nil {
			return newConfigError("%s was given twice; one chain has one challenge verifier", option)
		}

		g := &challengeGate{
			verifier:      v,
			flows:         flowSet(challengeFlowsAll),
			countRefusals: true,
			now:           c.now,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}

			if err := opt(g); err != nil {
				return err
			}
		}

		c.challenge = g
		c.enable(option, func() error { return requireDep(option, "challenge verifier", v) })
		c.wire(func(ch *Chain) {
			g.log = ch.logger
			g.sampler = ch.sampler
		})

		return nil
	}
}

// WithChallengeFlows asks the verifier in the given flows only.
//
// Default: every flow, ChallengeFlowFormLogin, ChallengeFlowBasicAuth,
// ChallengeFlowMagicLinkRequest, ChallengeFlowPasswordlessBegin and
// ChallengeFlowRecoveryStart. A flow selected here that the chain does not
// enable asks nothing. Selecting no flow, or a value that names none of the
// five, is a configuration error: a verifier no flow asks would read as
// protection the chain does not have.
func WithChallengeFlows(flows ...ChallengeFlow) ChallengeOption {
	return func(g *challengeGate) error {
		if len(flows) == 0 {
			return newConfigError("WithChallengeFlows selected no flow, so the verifier would never be asked; " +
				"leave the option out to select every flow")
		}

		for _, f := range flows {
			if !slices.Contains(challengeFlowsAll, f) {
				return newConfigError("WithChallengeFlows was given %q, which names no flow the challenge "+
					"seam covers", f)
			}
		}

		g.flows = flowSet(flows)

		return nil
	}
}

// WithoutChallengeRefusalCounting stops a challenge refusal from counting
// against the flow's per-source rate limit.
//
// Default: a refusal counts against the source limit like a failed attempt,
// so a source refused as often as the limit allows is then refused by the
// limit, before the verifier is asked again. Opted out, such a source keeps
// reaching the verifier, which then carries the whole cost of an automated
// source; it suits a verifier that throttles on its own. A refusal never
// counts against the identifier's lockout, either way. The passwordless begin
// and the recovery start count every request that passes against their source
// limits whatever this option says, because those limits bound how often a
// source makes the library write.
func WithoutChallengeRefusalCounting() ChallengeOption {
	return func(g *challengeGate) error {
		g.countRefusals = false

		return nil
	}
}

// flowSet is flows as a set.
func flowSet(flows []ChallengeFlow) map[ChallengeFlow]bool {
	set := make(map[ChallengeFlow]bool, len(flows))
	for _, f := range flows {
		set[f] = true
	}

	return set
}

// forFlow is the gate when it was selected for flow, and nil otherwise, which
// asks nothing.
func (g *challengeGate) forFlow(flow ChallengeFlow) *challengeGate {
	if g == nil || !g.flows[flow] {
		return nil
	}

	return g
}

// wireChallenge hands the gate to every selected flow on the chain, once every
// option has been applied, whichever order the flows' options and
// EnableAutomationChallenge came in. The recovery start's identifier signal
// reads the chain's password-login attempt store: form login's, or Basic's
// when there is no form login.
func (c *config) wireChallenge() {
	g := c.challenge
	if g == nil {
		return
	}

	_ = eachInterceptor(c, func(l *formLogin) error {
		l.automation = g.forFlow(ChallengeFlowFormLogin)

		if g.attempts == nil {
			g.attempts = l.attempts
		}

		return nil
	})
	_ = eachInterceptor(c, func(b *basicAuth) error {
		b.automation = g.forFlow(ChallengeFlowBasicAuth)

		if g.attempts == nil {
			g.attempts = b.attempts
		}

		return nil
	})
	_ = eachInterceptor(c, func(i *magicLinkInterceptor) error {
		i.automation = g.forFlow(ChallengeFlowMagicLinkRequest)

		return nil
	})
	_ = eachInterceptor(c, func(i *passwordlessInterceptor) error {
		i.automation = g.forFlow(ChallengeFlowPasswordlessBegin)

		return nil
	})
	_ = eachInterceptor(c, func(i *recoveryInterceptor) error {
		i.automation = g.forFlow(ChallengeFlowRecoveryStart)

		return nil
	})
}

// What a verifier that failed is recorded and returned with. The text is
// fixed: a consumer's verifier may word its failure with a site key, a
// response token or the address it could not reach.
const (
	reasonChallengeVerifier = "challenge-verifier"
	msgChallengeFailed      = "httpsec: an automation challenge could not be verified; the verifier failed"
	textChallengeFailed     = "httpsec: automation challenge verifier unavailable"
	msgChallengeEnded       = "httpsec: the request ended while its automation challenge was verified"
	textChallengeEnded      = "httpsec: the request ended while its automation challenge was verified"
	msgChallengeUndecided   = "httpsec: the automation challenge verifier answered with no known decision"
	challengeSampleSuffix   = sampleKeySeparator + reasonChallengeVerifier
)

// errChallengeUndecided is the cause of the dependency failure a verifier
// answering none of the three decisions is refused with.
var errChallengeUndecided = errors.New("httpsec: the challenge verifier answered with no known decision")

// challengeQuery is what one flow hands the gate about one request.
type challengeQuery struct {
	flow ChallengeFlow

	// source is the guard whose recorded failures for clientIP answer
	// ChallengeSignals.SourceHasFailures.
	source   sourceGuard
	clientIP string

	// identifier and attempts answer ChallengeSignals.IdentifierHasFailures;
	// an empty identifier or a nil store reads none.
	identifier string
	attempts   policy.AttemptStore

	// charge counts a refusal against the flow's source limit, and is nil
	// for a flow that has none.
	charge func()
}

// loginAttempts is the chain's password-login attempt store, nil on a nil
// gate or a chain without password login.
func (g *challengeGate) loginAttempts() policy.AttemptStore {
	if g == nil {
		return nil
	}

	return g.attempts
}

// recentFailureReader is the part of ratelimit.SourceGuard the signals read.
// It is asked for with a type assertion, so the throttle seam's own doubles
// need not implement it; a guard without it cannot say, and is reported as
// having failures.
type recentFailureReader interface {
	HasRecentFailures(ctx context.Context, clientAddr string) bool
}

// signals reads what the verifier is told about q's request. Whatever cannot
// say a source or an identifier is clean, a limiter or an attempt store that
// fails among it, reports it as having failures, so a verifier that asks only
// suspicious requests asks.
func (g *challengeGate) signals(ctx context.Context, q challengeQuery) ChallengeSignals {
	var s ChallengeSignals

	if r, ok := q.source.(recentFailureReader); ok {
		s.SourceHasFailures = r.HasRecentFailures(ctx, q.clientIP)
	} else {
		s.SourceHasFailures = true
	}

	if q.identifier != "" && q.attempts != nil {
		n, err := q.attempts.FailureCount(ctx, q.identifier, g.now().Add(-challengeIdentifierWindow))
		s.IdentifierHasFailures = err != nil || n > 0
	}

	return s
}

// ask asks the verifier about r, for the flow q describes. A nil gate asks
// nothing and lets the request through.
//
// ChallengePass and ChallengeNotNeeded let the request through, and
// ChallengeRefuse refuses it with ErrChallengeRequired, charged to the
// flow's source limit unless the consumer opted out. A verifier error is a
// dependency failure: ErrChallengeUnavailable behind fixed text, with the
// verifier's error reachable, recorded at ERROR by type, sampled per flow, and
// charged to nothing. So is an answer that is none of the three: a verifier
// that cannot say what it decided has not let the request through. A
// verifier error that is the request's own context ending (hangup.ByCaller)
// is a hang-up: the context's error, recorded at debug, charged to nothing.
func (g *challengeGate) ask(ctx context.Context, r Request, q challengeQuery) error {
	if g == nil {
		return nil
	}

	decision, err := g.verifier.Verify(ctx, r, g.signals(ctx, q))
	if err != nil {
		attrs := append([]slog.Attr{slog.String("flow", string(q.flow))},
			diag.Failure(reasonChallengeVerifier, err)...)

		if hangup.ByCaller(ctx, err) {
			g.log.LogAttrs(ctx, slog.LevelDebug, msgChallengeEnded, attrs...)

			return diag.Wrap(err, textChallengeEnded, ctx.Err())
		}

		logSampled(ctx, g.sampler, g.log, slog.LevelError, g.now(),
			string(q.flow)+challengeSampleSuffix, msgChallengeFailed, attrs...)

		return diag.Wrap(err, textChallengeFailed, ErrChallengeUnavailable)
	}

	switch decision {
	case ChallengePass, ChallengeNotNeeded:
		return nil
	case ChallengeRefuse:
		if g.countRefusals && q.charge != nil {
			q.charge()
		}

		return ErrChallengeRequired
	default:
		logSampled(ctx, g.sampler, g.log, slog.LevelError, g.now(),
			string(q.flow)+challengeSampleSuffix, msgChallengeUndecided,
			slog.String("flow", string(q.flow)), slog.Int("decision", int(decision)))

		return diag.Wrap(errChallengeUndecided, textChallengeFailed, ErrChallengeUnavailable)
	}
}
