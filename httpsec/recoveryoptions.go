package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The paths the recovery endpoints answer on when the consumer names none.
// They are constants so a consumer who follows the convention elsewhere — a
// client, a test, a reverse proxy rule — names the same thing this package
// does.
const (
	// DefaultRecoveryStartPath is where a recovery is started: an issued code
	// is emailed to the account.
	DefaultRecoveryStartPath = "/recovery/start"

	// DefaultRecoveryCompletePath is where a recovery is completed with two
	// proofs.
	DefaultRecoveryCompletePath = "/recovery/complete"

	// DefaultRecoveryFinishPath is where a held recovery is finished once its
	// hold is over.
	DefaultRecoveryFinishPath = "/recovery/finish"

	// DefaultRecoveryCancelPath is where a held recovery is cancelled.
	DefaultRecoveryCancelPath = "/recovery/cancel"

	// DefaultRecoveryCodesPath is where a user's saved codes are regenerated
	// and counted.
	DefaultRecoveryCodesPath = "/recovery/codes"
)

// The form fields the complete endpoint reads, and the start endpoint's
// username field. They are fixed rather than configurable: they are the
// documented contract a client posts to.
const (
	// RecoveryUsernameParam names the account. The start endpoint reads it
	// from a form field or a JSON member of this name.
	RecoveryUsernameParam = "username"

	// RecoverySavedCodeParam carries a saved recovery code.
	RecoverySavedCodeParam = "saved_code"

	// RecoveryIssuedCodeParam carries a code a start emailed.
	RecoveryIssuedCodeParam = "issued_code"

	// RecoveryPasswordParam carries the user's password.
	RecoveryPasswordParam = "password"

	// RecoveryMFAMethodParam names the MFA method whose code
	// RecoveryMFACodeParam carries.
	RecoveryMFAMethodParam = "mfa_method"

	// RecoveryMFACodeParam carries a code for the named MFA method.
	RecoveryMFACodeParam = "mfa_code"

	// RecoveryLostParam names an authenticator the user reports lost, as
	// "kind:id". It is the one field that may be given more than once.
	RecoveryLostParam = "lost"

	// RecoveryCompletionTokenParam carries the completion token a held
	// recovery answered with, posted to the finish endpoint.
	RecoveryCompletionTokenParam = "completion_token"

	// RecoveryCancelTokenParam carries the cancel token a held recovery's
	// notice linked to, posted to the cancel endpoint. It is the same name as
	// recovery.CancelLinkParam, the query parameter the link carries it in, so
	// the consumer's page posts back what it read.
	RecoveryCancelTokenParam = recovery.CancelLinkParam
)

// recoveryBodyLimit is how many request body bytes a recovery endpoint reads.
// The endpoints are unauthenticated, and nothing a client legitimately posts
// to them comes near it.
const recoveryBodyLimit int64 = 16 << 10

// The flows the two unauthenticated recovery endpoints are guarded under, each
// with an allowance of its own.
const (
	recoveryFlow      = "account-recovery"
	recoveryStartFlow = "account-recovery-start"
)

// The allowances a source gets before the recovery endpoints refuse it.
const (
	defaultRecoveryFailureLimit  = 10
	defaultRecoveryFailureWindow = 15 * time.Minute

	defaultRecoveryStartLimit  = 10
	defaultRecoveryStartWindow = time.Hour
)

// defaultRecoveryLogInterval is the window the recovery endpoints' own records
// are sampled over when the consumer names none.
const defaultRecoveryLogInterval = time.Minute

// RecoveryDeps are the ports the chain builds its account recovery over: the
// user loader, the session manager, the record store, the sender and the
// saved-code manager, exactly as recovery.Deps documents each of them.
type RecoveryDeps recovery.Deps

// RecoveryResult is what a completed recovery produced, handed to whatever
// writes the response.
type RecoveryResult struct {
	// Token is the access token issued for the recovery-pending session.
	Token string

	// Recovery is what the recovery produced: the recovery-pending session,
	// the user's new saved codes when a saved code was spent, the count of
	// saved codes the user holds, and the user's details.
	Recovery *recovery.Result
}

// RecoveryResponder writes the response to a completed recovery.
//
// With none supplied, the library writes the JSON document
// {"access_token","expires_at","recovery_codes","remaining","low"}; a consumer
// replaces that whole response with WithRecoveryResponder.
//
// It is called instead of the downstream handler, because the complete
// endpoint is the library's own. The endpoint sets Cache-Control: no-store
// before calling it, since the response carries a credential and possibly
// codes shown once; a responder may replace that header. An error it returns
// leaves the chain as the request's refusal, and the recovery it answers
// stands.
type RecoveryResponder func(ex *Exchange, result RecoveryResult) error

// RecoveryHoldResponder writes the response to a recovery that is held rather
// than completed.
//
// With none supplied, the library answers 202 with the JSON document
// {"completion_token","completable_at"}; a consumer replaces that whole
// response with WithRecoveryHoldResponder. The completion token is the only
// way to finish the recovery, so a responder that drops it leaves the user
// with nothing to finish it with.
type RecoveryHoldResponder func(ex *Exchange, hold recovery.Hold) error

// RecoveryOption configures account recovery. Each replaces one of the
// defaults named on EnableAccountRecovery.
type RecoveryOption func(*recoveryInterceptor) error

// EnableAccountRecovery answers the account-recovery endpoints at the
// OrderAccountRecoveryEndpoints slot, and confines the session a recovery
// produces with the recovery gate at OrderAccountRecovery.
//
// Recovery is off until this option is given: without it no recovery endpoint
// exists, and a request to one of its paths reaches the application like any
// other.
//
// The chain builds the recovery.Recoverer itself, from deps and the core's own
// options (WithRecoveryCore). Which proofs a recovery accepts, how it resets
// the account and whether it holds are the core's settings, and a mistake in
// them fails New with an error wrapping both ErrConfig and recovery.ErrConfig.
//
// The password proof is always checked by this chain's form login: its
// pre-authentication policy phase first, so a locked account is refused
// before its password is tested, then FormLoginDeps.Authenticator, recording
// a failure in FormLoginDeps.Attempts exactly as a failed login does. A
// consumer never supplies that check through the chain; a
// recovery.WithPasswordCheck given through WithRecoveryCore is replaced by the
// chain's own. Enabling recovery.ProofPassword without EnableFormLogin on the
// same chain fails New. One limit is stated: on a chain without form login,
// the chain cannot see which proofs the core enables, so a
// recovery.WithPasswordCheck given through WithRecoveryCore there is used as
// given.
//
// Defaults:
//   - the complete endpoint answers POST on DefaultRecoveryCompletePath
//     (WithRecoveryCompletePath), reading only a URL-encoded body of at most
//     16 KiB, never the query; a single-valued field given more than once is
//     recovery.ErrMalformed;
//   - the start endpoint answers POST on DefaultRecoveryStartPath
//     (WithRecoveryStartPath), reading the username from a form or JSON body,
//     and always answers 202 with an empty body. It exists only when the core
//     enables recovery.ProofIssued (recovery.Recoverer.Enabled), since issued
//     codes are the one thing it sends; otherwise a POST to its path reaches
//     the application like any other, though the path is still checked
//     against the others;
//   - the finish endpoint answers POST on DefaultRecoveryFinishPath
//     (WithRecoveryFinishPath), reading the completion token from a
//     URL-encoded body by the complete endpoint's rules, and answers a
//     finished recovery exactly as a completed one; the cancel endpoint
//     answers POST on DefaultRecoveryCancelPath (WithRecoveryCancelPath) and
//     always answers 204 with an empty body. Both exist only when the core may
//     hold a recovery (recovery.Recoverer.Holds); otherwise their paths reach
//     the application like any other, though they are still checked against
//     the others. With a hold, every login that ends through the chain's login
//     completion — form login, magic link, OIDC — cancels the user's held
//     recoveries as soon as its first factor has authenticated, before the
//     policy phase and before its session is created, so a login the policy
//     then denies has still cancelled them; a cancellation the record store
//     cannot record refuses the login;
//   - the saved-code endpoints answer on DefaultRecoveryCodesPath
//     (WithRecoveryCodesPath), served by the recovery gate for a full session
//     only, and exist only when the core enables recovery.ProofSaved;
//     otherwise their path reaches the application like any other. A POST
//     regenerates the set through recovery.Recoverer.Regenerate, which
//     notifies the user, when the session's latest authentication — the
//     later of its creation and its second factor's satisfaction — is within
//     15 minutes (WithRegenerationFreshness), and is refused with
//     recovery.ErrReauthenticationRequired (403) otherwise; it answers 200
//     with {"recovery_codes":[…]} and Cache-Control: no-store
//     (WithRecoveryCodesResponder). A GET answers 200 with
//     {"remaining":n,"low":bool} and never a code
//     (WithRecoveryCountResponder). A request with no session is
//     ErrAuthenticationRequired, and a session with another challenge
//     pending is passed on to the gate enforcing it;
//   - the complete endpoint counts failures per source at 10 per 15 minutes
//     (WithRecoveryLimiter), and a refusal of a request whose recovery codes
//     passed counts too (WithRecoveryCountRefusals);
//   - the start endpoint counts every start per source at 10 per hour
//     (WithRecoveryStartLimiter);
//   - the access token is issued by FormLoginDeps.Tokens (WithRecoveryTokens);
//   - a completed recovery is answered with the JSON document
//     {"access_token","expires_at","recovery_codes","remaining","low"}
//     (WithRecoveryResponder), and a held one with 202 and
//     {"completion_token","completable_at"} (WithRecoveryHoldResponder);
//   - the endpoints' own records are sampled once per minute per key
//     (WithRecoveryLogInterval).
//
// New fails when the chain has no way to bind the recovered session — neither
// EnableMFAEnrolment nor a password-change resolve endpoint
// (WithChangePasswordEndpoint) — since a recovery-pending session could then
// never become a full one. It fails too when any recovery path is empty, lacks
// a leading "/", or equals another recovery path, the login path or the logout
// path. One chain has one recovery; a second EnableAccountRecovery is refused.
func EnableAccountRecovery(deps RecoveryDeps, opts ...RecoveryOption) Option {
	const option = "EnableAccountRecovery"

	return func(c *config) error {
		i := &recoveryInterceptor{
			deps:          deps,
			now:           time.Now,
			completePath:  DefaultRecoveryCompletePath,
			startPath:     DefaultRecoveryStartPath,
			finishPath:    DefaultRecoveryFinishPath,
			cancelPath:    DefaultRecoveryCancelPath,
			codesPath:     DefaultRecoveryCodesPath,
			countRefusals: true,
			logInterval:   defaultRecoveryLogInterval,
			respond:       writeRecoveryResult,
			respondHold:   writeRecoveryHold,
			freshness:     defaultRegenerationFreshness,
			respondCodes:  writeRecoveryCodes,
			respondCount:  writeRecoveryCount,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		if err := eachInterceptor(c, func(*recoveryInterceptor) error {
			return newConfigError("%s was given twice; one chain has one account recovery", option)
		}); err != nil {
			return err
		}

		c.enable(option, func() error { return i.check(c, option) })

		c.useSessions(deps.Sessions)
		c.register(i, OrderAccountRecoveryEndpoints)
		c.enableRecoveryGate(i)
		c.wire(i.wire)

		return nil
	}
}

// WithRecoveryCore passes the core's own options to the recovery.Recoverer the
// chain builds: the proof kinds, the reset, holds, messages, the issued-code
// and saved-code settings, and every other recovery.Option.
//
// Default: none, and the core has required settings of its own
// (recovery.WithProofs, recovery.WithRepudiationContact,
// recovery.WithAuthenticatorKinds), so a chain enabling recovery passes at
// least those. Repeated calls accumulate, in order. The core's logger defaults
// to the chain's (WithLogger) rather than slog.Default; a recovery.WithLogger
// given here replaces it.
func WithRecoveryCore(opts ...recovery.Option) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.coreOpts = append(i.coreOpts, opts...)

		return nil
	}
}

// WithRecoveryCompletePath answers the complete endpoint on path instead.
//
// Default: DefaultRecoveryCompletePath. The path must start with "/" and
// differ from every other recovery path, the login path and the logout path;
// New refuses it otherwise.
func WithRecoveryCompletePath(path string) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.completePath = path

		return nil
	}
}

// WithRecoveryStartPath answers the start endpoint on path instead.
//
// Default: DefaultRecoveryStartPath, with the same rules as
// WithRecoveryCompletePath.
func WithRecoveryStartPath(path string) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.startPath = path

		return nil
	}
}

// WithRecoveryFinishPath answers the finish endpoint of held recoveries on
// path instead.
//
// Default: DefaultRecoveryFinishPath, with the same rules as
// WithRecoveryCompletePath.
func WithRecoveryFinishPath(path string) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.finishPath = path

		return nil
	}
}

// WithRecoveryCancelPath answers the cancel endpoint of held recoveries on
// path instead.
//
// Default: DefaultRecoveryCancelPath, with the same rules as
// WithRecoveryCompletePath.
func WithRecoveryCancelPath(path string) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.cancelPath = path

		return nil
	}
}

// WithRecoveryCodesPath answers the saved-code endpoints on path instead.
//
// Default: DefaultRecoveryCodesPath, with the same rules as
// WithRecoveryCompletePath.
func WithRecoveryCodesPath(path string) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.codesPath = path

		return nil
	}
}

// WithRecoveryLimiter counts the complete endpoint's failures per source
// through l.
//
// Default: an in-memory limiter of 10 failures per source per 15 minutes, used
// by this flow alone, under the flow "account-recovery". A deployment running
// more than one replica supplies one its replicas share. One limiter may be
// shared with other flows: every key carries its flow, so the allowances stay
// separate.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithRecoveryLimiter(l ratelimit.Limiter) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if err := requireDep("WithRecoveryLimiter", "limiter", l); err != nil {
			return err
		}

		i.limiter = l

		return nil
	}
}

// WithRecoveryStartLimiter counts starts per source through l.
//
// Default: an in-memory limiter of 10 starts per source per hour, used by this
// flow alone, under the flow "account-recovery-start". Every start is counted,
// whatever it did, and a source over its limit is still answered 202 and sends
// nothing.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithRecoveryStartLimiter(l ratelimit.Limiter) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if err := requireDep("WithRecoveryStartLimiter", "limiter", l); err != nil {
			return err
		}

		i.startLimiter = l

		return nil
	}
}

// WithRecoveryUserLimiter counts failed recoveries per user through l. It is
// recovery.WithUserLimiter, passed to the core; giving that through
// WithRecoveryCore is the same.
//
// Default: the core's, an in-memory limiter of 5 failures per user per 15
// minutes, per process, under recovery.UserThrottleKey.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithRecoveryUserLimiter(l ratelimit.Limiter) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if err := requireDep("WithRecoveryUserLimiter", "limiter", l); err != nil {
			return err
		}

		i.coreOpts = append(i.coreOpts, recovery.WithUserLimiter(l))

		return nil
	}
}

// WithRecoveryCountRefusals decides whether a refusal of a recovery whose
// recovery codes passed their check counts against the source's allowance
// (see recovery.RefusedAfterValidCode): a wrong or locked password, a wrong MFA
// code, a consumer check's refusal, and the like.
//
// Default: true. A presenter holding one valid code could otherwise keep
// trying the other proof from one source for as long as the per-user limit
// allows. Passing false exempts exactly those refusals; every other failure
// is still counted. A malformed request is counted nowhere either way.
func WithRecoveryCountRefusals(count bool) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.countRefusals = count

		return nil
	}
}

// WithRecoveryTokens issues the recovered session's access token through g.
//
// Default: the token generator form login was given (FormLoginDeps.Tokens).
// A chain without form login must supply one, or New refuses it: a recovery
// that produced a session the caller holds no credential for would spend both
// proofs for nothing. A nil generator is refused.
func WithRecoveryTokens(g token.Generator) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if err := requireDep("WithRecoveryTokens", "token generator", g); err != nil {
			return err
		}

		i.tokens = g

		return nil
	}
}

// WithRecoveryResponder writes the response to a completed recovery through
// fn.
//
// Default: 200 with the JSON document {"access_token","expires_at",
// "recovery_codes","remaining","low"}, where remaining and low are the
// core's count (recovery.Result.Remaining). Whichever responder runs, the
// endpoint has already set Cache-Control: no-store, which fn may replace. A nil
// responder is refused: a recovery that succeeded and wrote nothing would
// leave the caller with no credential and no new codes.
func WithRecoveryResponder(fn RecoveryResponder) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if fn == nil {
			return newConfigError("WithRecoveryResponder was given no responder; omit it to " +
				"keep the default JSON response")
		}

		i.respond = fn

		return nil
	}
}

// WithRecoveryHoldResponder writes the response to a held recovery through
// fn.
//
// Default: 202 with the JSON document {"completion_token","completable_at"}.
// Whichever responder runs, the endpoint has already set Cache-Control:
// no-store, which fn may replace. A nil responder is refused.
func WithRecoveryHoldResponder(fn RecoveryHoldResponder) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		if fn == nil {
			return newConfigError("WithRecoveryHoldResponder was given no responder; omit it " +
				"to keep the default JSON response")
		}

		i.respondHold = fn

		return nil
	}
}

// WithRecoveryLogInterval writes at most one of the recovery endpoints' own
// records per key per d: an unattributable or throttled source.
//
// Default: one minute. It governs those records and nothing else; the chain's
// own records keep the window WithRefusalLogInterval sets. An interval of zero
// or less writes every record.
func WithRecoveryLogInterval(d time.Duration) RecoveryOption {
	return func(i *recoveryInterceptor) error {
		i.logInterval = d

		return nil
	}
}

// recoverySession is the session a responder's result carries, or nil.
func recoverySession(res *recovery.Result) *session.Session {
	if res == nil {
		return nil
	}

	return res.Session
}
