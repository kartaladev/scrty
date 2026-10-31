package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// DefaultAPIKeyScheme is the Authorization prefix a presented key is matched
// under when the consumer names none, trailing space included.
//
// It is matched exactly, case and all. A case-insensitive match here would also
// claim headers meant for another scheme registered at a nearby slot, and this
// interceptor answers every header it claims — one claimed by mistake is a
// request refused rather than one passed on.
const DefaultAPIKeyScheme = "ApiKey "

// apiKeyFlow names this flow's rate-limit buckets and sampler keys, so a source
// that exhausts its key-guessing allowance still has its own at every other
// endpoint.
const apiKeyFlow = "api-key"

// The allowance a source gets before presented keys stop being checked. A
// machine client retries, so the window is short and the count is generous
// compared with a human's password attempts.
const (
	defaultAPIKeyFailureLimit  = 20
	defaultAPIKeyFailureWindow = time.Minute
)

// apiKeyInterceptor authenticates a machine caller by key and establishes no
// session.
type apiKeyInterceptor struct {
	keys *apikey.Keys

	engine  *policy.Engine
	log     *slog.Logger
	sampler *logsample.Sampler
	guard   sourceGuard

	limiter ratelimit.Limiter

	// owners loads a verified key's principal reference as a user; nil means
	// no owner is looked up.
	owners identity.UserLoader

	now func() time.Time

	scheme string
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (i *apiKeyInterceptor) wire(c *Chain) {
	i.engine = c.engine
	i.log = c.logger
	i.sampler = c.sampler
}

// wireAPIKey settles the limiter and the source guard against the assembled
// configuration, once every option has been applied.
func (c *config) wireAPIKey() error {
	return eachInterceptor(c, func(i *apiKeyInterceptor) error {
		guard, err := c.resolveSourceGuard("EnableAPIKey", apiKeyFlow, i.limiter,
			defaultAPIKeyFailureLimit, defaultAPIKeyFailureWindow, c.refusalInterval)
		if err != nil {
			return err
		}

		i.guard = guard

		return nil
	})
}

// flushRefusalLogs reports what the source guard is holding back.
func (i *apiKeyInterceptor) flushRefusalLogs() {
	if i.guard != nil {
		i.guard.Flush()
	}
}

// Intercept authenticates a machine caller by the key in the Authorization
// header.
//
// The order matters at each step:
//
//  1. Match the scheme first. A request that carries no key is not an attempt,
//     so it must not consult the limiter — otherwise ordinary unauthenticated
//     traffic would fill the buckets that exist to catch guessing.
//  2. Check the source before verifying, so a throttled scanner costs one
//     bucket read rather than a store round trip.
//  3. Verify. A failure records against the source and returns the same error a
//     throttled source gets, so the two cannot be told apart.
//  4. Check the key's owner, when the consumer gave a user loader. A missing or
//     inactive owner is refused and recorded as a wrong key is; a loader that
//     could not answer, or a caller that left, is not recorded.
//  5. The stateless phase. A deny here is not recorded: the credential was
//     valid, and counting it would let a policy misconfiguration lock out the
//     caller's own machines.
//  6. Publish the caller with no session. A machine has nobody to prompt and
//     nothing to keep between requests.
func (i *apiKeyInterceptor) Intercept(ex *Exchange, next Next) error {
	presented, claimed := strings.CutPrefix(ex.Request.Header("Authorization"), i.scheme)
	if !claimed {
		return next(ex)
	}

	ctx := ex.Context()
	now := i.now()

	src, err := sourceThrottled(ctx, i.guard, ex.Request.ClientIP(), apiKeyFlow,
		i.sampler, i.log, now)
	if err != nil {
		return refusedAPIKey()
	}

	p, _, err := i.keys.Verify(ctx, presented)
	if err != nil {
		recordSourceFailure(ctx, i.guard, src)

		// The manager already answers every cause — wrong shape, unknown
		// identifier, wrong secret, expired, revoked, store outage — with one
		// error, and this adds only the chain's own vocabulary for "this
		// request did not authenticate".
		return refusedAPIKey()
	}

	if err := i.checkOwner(ctx, p.ID, src, now); err != nil {
		return err
	}

	auth := &authenticate.Authentication{Principal: &p, Time: now}

	// Stateless: there is no later request in which this caller could answer a
	// challenge, so the phase decides outright and its challenge carries
	// nothing to come back to.
	d := evaluatePhase(ctx, i.engine, policy.StatelessAuthentication, postAuthenticationInput(
		&p, factor.APIKey, p.Username, time.Time{}, now))

	switch d.Outcome {
	case policy.Deny:
		// Not recorded against the source: the key was valid, and counting a
		// policy refusal would let a misconfiguration lock out the very
		// machines it was meant to govern.
		return policyDenyReason(d)
	case policy.Challenge:
		return &ChallengeError{Kind: d.Challenge}
	case policy.Allow:
	}

	ex.Authentication = auth
	ex.SetContext(WithCaller(ctx, auth))

	return next(ex)
}

// The sampler keys and messages of the owner check's records.
const (
	reasonOwnerUnavailable = "owner-unavailable"
	reasonOwnerCallerEnded = "owner-caller-ended"
	reasonOwnerMismatch    = "owner-mismatch"

	msgAPIKeyOwnerUnavailable = "httpsec: an API key's owner could not be loaded"
	msgAPIKeyOwnerCallerEnded = "httpsec: the caller left while an API key's owner was loaded"
	msgAPIKeyOwnerMismatch    = "httpsec: the user loader answered for another user than an API key's owner"
)

// checkOwner refuses a verified key whose owner the consumer's user loader
// does not hold as an active user. With no loader it checks nothing.
//
// A missing or inactive owner writes no record of its own and records a
// failure against the source, as a wrong key does, so nothing on either side
// of the chain tells the two apart. A loader that answers for another user
// than the one asked about is refused and recorded the same way, and logged
// at error level under a reason of its own, naming neither user, since the
// loader is the consumer's to fix. An outage is logged, since an operator has
// something to fix, and a caller that left is logged at debug under a key of
// its own, so a burst of hang-ups cannot crowd the outage records out of the
// sampled window. Neither is recorded against the source: the key verified.
func (i *apiKeyInterceptor) checkOwner(
	ctx context.Context,
	owner identity.UserID,
	src ratelimit.Source,
	now time.Time,
) error {
	if i.owners == nil {
		return nil
	}

	details, err := i.owners.LoadByUserID(ctx, owner)

	switch {
	case err == nil && details != nil && details.ID != owner:
		recordSourceFailure(ctx, i.guard, src)

		logSampled(ctx, i.sampler, i.log, slog.LevelError, now,
			apiKeyFlow+sampleKeySeparator+reasonOwnerMismatch, msgAPIKeyOwnerMismatch,
			slog.String("flow", apiKeyFlow), slog.String("reason", reasonOwnerMismatch))

		return refusedAPIKey()

	case err == nil && details != nil && details.Active:
		return nil

	case err == nil || errors.Is(err, identity.ErrUserNotFound):
		recordSourceFailure(ctx, i.guard, src)

		return refusedAPIKey()

	case ownerLoadEndedByCaller(ctx, err):
		logSampled(ctx, i.sampler, i.log, slog.LevelDebug, now,
			apiKeyFlow+sampleKeySeparator+reasonOwnerCallerEnded, msgAPIKeyOwnerCallerEnded,
			append([]slog.Attr{slog.String("flow", apiKeyFlow)},
				diag.Failure(reasonOwnerCallerEnded, err)...)...)

		return callerEndedAPIKey(ctx)

	default:
		// diag.Failure names the error's Go type, never its text: a store's
		// error can quote a row or an address, and a consumer who wants that
		// detail logs it inside their own user loader.
		logSampled(ctx, i.sampler, i.log, slog.LevelError, now,
			apiKeyFlow+sampleKeySeparator+reasonOwnerUnavailable, msgAPIKeyOwnerUnavailable,
			append([]slog.Attr{slog.String("flow", apiKeyFlow)},
				diag.Failure(reasonOwnerUnavailable, err)...)...)

		// Bare: the loader's text stays out of the error as it stays out of
		// the log.
		return authenticate.ErrUnavailable
	}
}

// ownerLoadEndedByCaller reports whether err is the request's own context
// ending rather than the user loader failing on its own: ctx has ended, and
// err is or wraps ctx's error or its cause. A deadline the loader met on a
// context of its own is an outage, since the caller was still waiting.
func ownerLoadEndedByCaller(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()

	return ctxErr != nil &&
		(errors.Is(err, ctxErr) || errors.Is(err, context.Cause(ctx)))
}

// callerEndedAPIKey is the refusal of a request whose client left while its
// key's owner was loaded: the wrong-key refusal, joined with the request
// context's error and, when it differs, that context's cause, so a consumer can
// tell that the client left.
func callerEndedAPIKey(ctx context.Context) error {
	ctxErr := ctx.Err()
	errs := []error{refusedAPIKey(), ctxErr}

	if cause := context.Cause(ctx); !errors.Is(cause, ctxErr) {
		errs = append(errs, cause)
	}

	return errors.Join(errs...)
}

// refusedAPIKey is the one answer every refusal of a presented key gives.
//
// It joins rather than wraps, so a consumer matching the chain's own
// "authentication failed" and one matching apikey's verification failure both
// reach it, and neither learns which of the causes it was.
func refusedAPIKey() error {
	return errors.Join(authenticate.ErrAuthenticationFailed, apikey.ErrVerificationFailed)
}

// APIKeyOption configures API key authentication. Each replaces one of the
// defaults named on EnableAPIKey.
type APIKeyOption func(*apiKeyInterceptor) error

// EnableAPIKey authenticates machine callers by key at the API key slot.
//
// Defaults: a key is read from the Authorization header after the literal
// DefaultAPIKeyScheme prefix (WithAPIKeyScheme); a source that presents wrong
// keys is cut off after 20 failures a minute by a limiter this flow alone uses
// (WithAPIKeyLimiter); and no owner is looked up (WithAPIKeyOwners).
//
// Without WithAPIKeyOwners, a key's principal reference is taken as the
// consumer's own and never loaded, so deactivating a user stops none of the
// keys issued for that user's reference: each must be revoked, or the flow
// given a user loader with WithAPIKeyOwners.
//
// A request that does not carry the scheme passes through untouched and
// consults nothing: ordinary unauthenticated traffic is not a failed attempt,
// and counting it would fill the buckets that exist to catch guessing.
//
// The caller a key resolves is published with no session. A machine has nobody
// to prompt and nothing to keep between requests, so a policy that challenges
// in the stateless phase refuses outright rather than raising a prompt nothing
// can answer.
func EnableAPIKey(m *apikey.Keys, opts ...APIKeyOption) Option {
	const option = "EnableAPIKey"

	return func(c *config) error {
		if m == nil {
			return newConfigError("%s needs an API key manager", option)
		}

		i := &apiKeyInterceptor{keys: m, now: c.now, scheme: DefaultAPIKeyScheme}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		c.register(i, OrderAPIKey)
		c.wire(i.wire)

		return nil
	}
}

// WithAPIKeyScheme matches presented keys under scheme instead.
//
// Default: DefaultAPIKeyScheme. The scheme is matched exactly, case and
// trailing space included, so include the separating space: "Service " matches
// "Service sk_...", while "Service" would also claim "Servicex".
//
// An empty scheme is refused: it would claim every Authorization header on the
// chain, including the ones another interceptor answers.
func WithAPIKeyScheme(scheme string) APIKeyOption {
	return func(i *apiKeyInterceptor) error {
		if scheme == "" {
			return newConfigError("WithAPIKeyScheme was given no scheme, which would claim " +
				"every Authorization header, including another interceptor's")
		}

		i.scheme = scheme

		return nil
	}
}

// WithAPIKeyLimiter counts failed key verifications through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "api-key", or else an in-memory limiter of 20 failures per source
// per minute, used by this flow alone. A deployment running more than one
// replica supplies a factory or a limiter its replicas share, or the limit is
// per process and a scanner simply spreads its guesses.
//
// One limiter may be handed to several flows. That shares the store and the
// limit it was built with, not the allowance: every key carries the flow it
// belongs to, so a source that exhausts its key guesses still has its whole
// allowance at every other endpoint.
// A limiter handed to several flows shares its key cap among them, so a flood
// on one refuses new sources on all.
//
// The flow's IPv6 aggregate (WithIPv6Aggregate) is sized from l: the
// aggregate's multiplier, 4 by default, times the limit l reports, over the
// window l reports, read through ratelimit.PolicyReporter, which the in-memory
// limiter and the shared limiters scrty ships implement. A limiter that does
// not implement it gets no default aggregate for this flow, and one warning
// when the chain is built; under an explicit WithIPv6Aggregate it is a
// configuration error.
//
// It counts wrong keys and nothing else: a policy refusal of a valid key is not
// a failed guess, and a request carrying no key at all never reaches it.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithAPIKeyLimiter(l ratelimit.Limiter) APIKeyOption {
	return func(i *apiKeyInterceptor) error {
		if err := requireDep("WithAPIKeyLimiter", "limiter", l); err != nil {
			return err
		}

		i.limiter = l

		return nil
	}
}

// WithAPIKeyOwners requires the owner of every verified key to be an active
// user that users holds.
//
// Default: no lookup. A key's principal reference is the consumer's own and
// need not name a user, so without this option deactivating a user stops none
// of the keys issued for that user's reference.
//
// With it, a key that verifies has its principal reference loaded with
// users.LoadByUserID, before the stateless policy phase:
//
//   - an owner the loader does not find (identity.ErrUserNotFound), or finds
//     not active, is refused exactly as a wrong key is, with the same error,
//     and counted against the source the same way;
//   - a loader that answers with a user other than the one asked for is
//     refused the same way and counted as a missing owner is, and is logged
//     at error level under the reason "owner-mismatch", since the loader is
//     what needs fixing; the record names neither user;
//   - an active owner leaves the request authenticated as the key's service
//     principal, unchanged;
//   - any other loader failure is refused with authenticate.ErrUnavailable,
//     which carries none of the loader's text and which StatusForError
//     answers 503. It is logged at error level, naming the error's Go type,
//     and not counted against the source: the key was not refused;
//   - a load the request's own context ended, when the loader's error is or
//     wraps that context's error or its cause, is refused with the wrong-key
//     error joined with that context's error, not ErrUnavailable. It is not
//     counted either: the key was verified, and the client has left.
//
// Every request that presents a valid key then costs one load. A loader that
// caches decides for itself how soon a deactivation takes effect.
//
// The key's verification stamps its last-use time before the owner is loaded,
// so a key refused for its owner keeps that stamp.
//
// A nil loader, including an interface holding a nil pointer, is refused.
func WithAPIKeyOwners(users identity.UserLoader) APIKeyOption {
	return func(i *apiKeyInterceptor) error {
		if err := requireDep("WithAPIKeyOwners", "user loader", users); err != nil {
			return err
		}

		i.owners = users

		return nil
	}
}
