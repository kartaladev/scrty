package httpsec

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// DefaultBasicAuthRealm is the realm named in the WWW-Authenticate header when
// the consumer names none. It is deliberately uninformative: a realm is shown
// to whoever is being refused, and naming the system behind it tells a prober
// what they have found.
const DefaultBasicAuthRealm = "Restricted"

// basicPrefix is matched exactly, with its trailing space and its case.
//
// A case-insensitive match here would also claim headers meant for another
// scheme registered at a nearby slot, and this interceptor answers every header
// it claims — a header it claimed by mistake is a request refused rather than
// one passed on.
const basicPrefix = "Basic "

// basicAuth authenticates a Basic credential and establishes no session.
type basicAuth struct {
	authn    authenticate.Authenticator
	attempts policy.AttemptStore

	engine *policy.Engine
	log    *slog.Logger

	// enforced holds the challenge kinds something on the chain enforces,
	// handed over by wire; a raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	// limiter is the consumer's own (WithBasicAuthLimiter), and nil means the
	// password-login limiter the chain shares with form login.
	limiter ratelimit.Limiter

	// guard is the password-login source guard, settled at assembly
	// (wirePasswordLogin), and sampler the chain's, handed over by wire.
	guard   sourceGuard
	sampler *logsample.Sampler

	// discloseLocks is the chain's WithLockDisclosure, settled at assembly.
	discloseLocks bool

	now func() time.Time

	realm string
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *basicAuth) wire(c *Chain) {
	b.engine = c.engine
	b.log = c.logger
	b.enforced = c.enforced
	b.sampler = c.sampler
}

// flushRefusalLogs reports what the source guard and the authenticator are
// holding back; an authenticator that keeps no refusal logs of its own has
// nothing to report.
func (b *basicAuth) flushRefusalLogs() {
	if b.guard != nil {
		b.guard.Flush()
	}

	if f, ok := b.authn.(authenticate.RefusalLogFlusher); ok {
		_ = f.FlushRefusalLogs() // documented never to fail: its reporter only logs
	}
}

// Intercept authenticates a Basic credential and establishes no session.
func (b *basicAuth) Intercept(ex *Exchange, next Next) error {
	header := ex.Request.Header("Authorization")
	if !strings.HasPrefix(header, basicPrefix) {
		return next(ex)
	}

	ctx := ex.Context()
	now := b.now()

	username, password, ok := decodeBasic(strings.TrimPrefix(header, basicPrefix))
	if !ok {
		// A malformed header is reported as a failed authentication, not as a
		// malformed request: telling the two apart tells a prober which of its
		// guesses was even parsed.
		b.challenge(ex)

		return authenticate.ErrAuthenticationFailed
	}

	// The source is checked only once the header has decoded, so a malformed
	// header spends nothing, and before the pre-authentication phase, as at
	// the login form. A throttled refusal is still a 401, and every 401 names
	// the realm (RFC 9110 §15.5.2); one without it would also single the
	// throttled response out.
	src, err := sourceThrottled(ctx, b.guard, ex.Request.ClientIP(), passwordLoginFlow,
		b.sampler, b.log, now)
	if err != nil {
		b.challenge(ex)

		return err
	}

	// Before the credential is checked, for the same reason as at the login
	// form: a locked account must not answer differently for a right guess.
	pre := evaluatePhase(ctx, b.engine, policy.PreAuthentication, &policy.Input{
		Username: username,
		Now:      now,
	})
	if err := refusePreAuthentication(pre, b.enforced); err != nil {
		if !errors.Is(err, policy.ErrAccountLocked) {
			return err
		}

		// A source hammering a locked account spends its own allowance.
		recordSourceFailure(ctx, b.guard, src)

		// A concealed lock is a 401 and carries the challenge every 401
		// carries; a disclosed one is a 429, which has none.
		if !b.discloseLocks {
			b.challenge(ex)
		}

		return refuseLocked(ctx, b.authn, b.discloseLocks,
			identity.NewUsernamePassword(username, password), err)
	}

	auth, err := b.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	if err != nil {
		// The record carries a fixed reason and the attempt store's error
		// type, never its text: a consumer who wants that detail logs it
		// inside their own policy.AttemptStore.
		// The client's cancellation is not passed on: a client that hangs up after
		// sending its guess must still be charged for it, and an attempt store
		// that honours cancellation would otherwise drop the failure. Reset is
		// different, and stays on the request's context: nobody is owed a
		// clearing the client did not wait for.
		if recErr := b.attempts.RecordFailure(context.WithoutCancel(ctx), username, now); recErr != nil {
			b.log.LogAttrs(ctx, slog.LevelError, msgAttemptNotRecorded,
				diag.Failure("attempt-store", recErr)...)
		}

		recordSourceFailure(ctx, b.guard, src)

		b.challenge(ex)

		// The authenticator's own refusal, not a restatement of it: it already
		// carries no detail that would tell one refusal from another.
		return err
	}

	// Stateless: there is no later request in which this caller could answer a
	// challenge, so the phase decides outright and its challenge carries
	// nothing to come back to.
	d := evaluatePhase(ctx, b.engine, policy.StatelessAuthentication, postAuthenticationInput(
		auth.Principal, factor.Basic, username, auth.PasswordChangedAt, now))

	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		return &ChallengeError{Kind: d.Challenge}
	case policy.Allow:
	}

	ex.Authentication = auth
	ex.SetContext(WithCaller(ctx, auth))

	return next(ex)
}

// decodeBasic reads the user-id and password out of the credential.
//
// Standard base64 with padding, and the first colon separates: a password may
// itself hold colons, and cutting at the last one would refuse a password the
// user actually set.
func decodeBasic(credential string) (username string, password []byte, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		return "", nil, false
	}

	name, secret, found := bytes.Cut(decoded, []byte(":"))
	if !found {
		return "", nil, false
	}

	return string(name), secret, true
}

// challenge names the realm a client is being asked to answer for.
//
// It is set before the refusal is returned, so the consumer's error handling —
// which writes a status and, by default, no body — still sends it.
func (b *basicAuth) challenge(ex *Exchange) {
	ex.Writer.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", b.realm))
}
