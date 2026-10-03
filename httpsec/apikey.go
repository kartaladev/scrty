package httpsec

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
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
	keys *apikey.Manager

	engine  *policy.Engine
	log     *slog.Logger
	sampler *logsample.Sampler
	guard   sourceGuard

	limiter ratelimit.Limiter

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
//  4. The stateless phase. A deny here is not recorded: the credential was
//     valid, and counting it would let a policy misconfiguration lock out the
//     caller's own machines.
//  5. Publish the caller with no session. A machine has nobody to prompt and
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

// refusedAPIKey is the one answer every refusal on this path gives.
//
// It joins rather than wraps, so a consumer matching the chain's own
// "authentication failed" and one matching apikey's verification failure both
// reach it, and neither learns which of the causes it was.
func refusedAPIKey() error {
	return errors.Join(authenticate.ErrAuthenticationFailed, apikey.ErrVerificationFailed)
}
