package oidcprovider

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

//go:generate mockgen -destination=limiter_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/ratelimit Limiter

// entryState holds the entry throttle. current is read without a lock on every entry, and
// mu serialises UseUserCodeEntryLimiter, so that of concurrent calls one decides.
type entryState struct {
	mu      sync.Mutex
	current atomic.Pointer[entryThrottle]
}

// entryThrottle is the guard user-code entry is checked against, with the limiter it
// counts in.
type entryThrottle struct {
	guard   *ratelimit.SourceGuard
	limiter ratelimit.Limiter
	// consumer says the limiter came from WithUserCodeEntryLimiter, and handedOver that it
	// came from UseUserCodeEntryLimiter. The default is neither.
	consumer, handedOver bool
}

// DeviceEntryInput is a user code entered on the code-entry page, with what the browser
// holds. It holds the code and the browser's secrets, so it prints and logs redacted; read
// its fields to use it.
type DeviceEntryInput struct {
	// UserCode is the code as the user typed it.
	UserCode string
	// FlowSecret is the value of the browser's flow cookie, or empty when it sent none.
	FlowSecret string
	// BrowserSessionSecret is the value of the browser-session cookie, or empty.
	BrowserSessionSecret string
	// Source is the client address the entry came from, which the throttle counts by.
	Source string
	// IdleTimeout is how long a browser session lives without use, as in AuthorizeInput.
	IdleTimeout time.Duration
}

// Format writes the redacted form under every verb.
func (DeviceEntryInput) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (DeviceEntryInput) LogValue() slog.Value { return slog.StringValue(redacted) }

// userCodeEntryFlow names the entry throttle's counts in its limiter, which is the namespace
// the chain asks its limiter factory for.
const userCodeEntryFlow = "oidc-device-entry"

// maxEnteredUserCode bounds the bytes of an entered code that are read at all: four times
// the longest code a format may have, which leaves room for any grouping and spacing a
// person types. A longer entry is refused unread, as a malformed one is.
const maxEnteredUserCode = 4 * maxUserCodeLength

// entryRefused is the refusal of a throttled entry. Its text is ErrUserCodeThrottled's
// alone, and it matches ErrUserCodeThrottled, ratelimit.ErrThrottled and what the guard
// answered, which may be the caller's own context error or ratelimit.ErrSourceUnattributable.
type entryRefused struct{ cause error }

func (e *entryRefused) Error() string { return userCodeThrottledText }

func (e *entryRefused) Unwrap() []error {
	return []error{ErrUserCodeThrottled, ratelimit.ErrThrottled, e.cause}
}

// newEntryThrottle builds the guard over limiter, logging through the provider's logger
// and sampling by its clock.
func newEntryThrottle(limiter ratelimit.Limiter, clk clock.Clock, logger *slog.Logger) (*entryThrottle, error) {
	guard, err := ratelimit.NewSourceGuard(userCodeEntryFlow, limiter,
		ratelimit.WithSourceGuardLogger(logger), ratelimit.WithSourceGuardClock(clk))
	if err != nil {
		return nil, err
	}

	return &entryThrottle{guard: guard, limiter: limiter}, nil
}

// resolveEntry checks the limiter WithUserCodeEntryLimiter gave, or builds the default, and
// the throttle over it.
func (d *deviceConfig) resolveEntry(clk clock.Clock, logger *slog.Logger) error {
	limiter := d.entryLimiter
	if d.entryLimiterSet {
		if nilcheck.IsNil(limiter) {
			return fmt.Errorf("%w: WithUserCodeEntryLimiter: must not be nil", ErrConfig)
		}
	} else {
		memory, err := ratelimit.NewMemoryLimiter(DefaultUserCodeEntryLimit, DefaultUserCodeEntryWindow,
			ratelimit.WithMemoryLimiterClock(clk), ratelimit.WithMemoryLimiterLogger(logger))
		if err != nil {
			return fmt.Errorf("%w: WithUserCodeEntryLimiter: the default limiter: %w", ErrConfig, err)
		}
		limiter = memory
	}
	throttle, err := newEntryThrottle(limiter, clk, logger)
	if err != nil {
		return fmt.Errorf("%w: WithUserCodeEntryLimiter: %w", ErrConfig, err)
	}
	throttle.consumer = d.entryLimiterSet
	d.entry = &entryState{}
	d.entry.current.Store(throttle)

	return nil
}

// sameLimiter reports whether a and b are one limiter, without panicking on a limiter that
// cannot be compared: such a limiter is never the same as another value. Its type alone does
// not say so, because a comparable struct may hold a map, slice or func in an interface field;
// reflect.Value.Comparable looks at the values.
func sameLimiter(a, b ratelimit.Limiter) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if !va.IsValid() || !vb.IsValid() || va.Type() != vb.Type() || !va.Comparable() || !vb.Comparable() {
		return false
	}

	return a == b
}

// EnterUserCode enters a user code typed on the code-entry page (RFC 8628 section 3.3), for
// the chain's code-entry endpoint or a consumer's own handler, which apply the same rules
// through it. In order, it:
//
//  1. checks the source against the entry throttle (WithUserCodeEntryLimiter), and charges
//     the entry to it, both before the code is read, so a throttled source learns nothing of
//     whether its code is valid and a concurrent burst from one source is looked up no more
//     often than the limit allows;
//  2. reads the code back to its raw form, with whitespace and dashes dropped and upper-cased
//     for an alphabet with no lower-case letter (WithUserCodeFormat);
//  3. looks up the unexpired device authorization holding it;
//  4. claims it for this browser with one conditional write, bound to the browser's flow
//     secret, minted when the browser holds none;
//  5. parks a pending request for it, and answers like Authorize: the consumer's login page
//     with the handle, or the consent page when the browser's session answers the login
//     stage, with status 303, and the flow secret to set.
//
// The browser that claimed a code may enter it again with the same flow secret while it has
// not expired and has not been answered: a new pending request is parked for it, and the
// browser goes to the login page, or to the consent page when its session answers. Two
// entries of one code by that browser at once are both handed off: the one whose claim
// loses reads the record again, finds the claim bound to its own flow secret, and is charged
// nothing.
//
// A refusal of the code is ErrInvalidUserCode, one error with one text, whatever the
// reason: malformed, longer than any code could be, unknown, expired (at ExpiresAt and
// after, by the provider's clock), claimed by another browser, answered or exchanged, or for
// a client no longer registered for the grant. Each keeps the charge made before the code
// was read, and leaves the device authorization as it was. A source that has failed too
// often, that names no single address, or that the limiter cannot answer or charge for is
// refused before anything is read, with an error matching ErrUserCodeThrottled and
// ratelimit.ErrThrottled; with the default, that is the sixth failure in 10 minutes.
//
// Any other outcome is no verdict on the code, and its charge is refunded: a claim, a
// re-entry, and every error below. A refund the limiter cannot make is logged and changes no
// answer. A failing store,
// registry, user loader or random source matches ErrDependency behind fixed text, and a caller
// who left matches its own context's error. When the claim may have been written, because
// the store reported a failure for it or the request could not be parked after it, the result
// still carries the FlowSecret the claim is bound to and no Location: the caller sets the cookie, so that the same browser's re-entry recovers the
// claim, which no other browser can. A negative IdleTimeout, and a provider without
// WithDeviceAuthorization, are refused with an error matching ErrConfig.
//
// Its errors and logs carry no code, digest, handle or secret. EnterUserCode does not judge
// TLS, CSRF or the flow cookie's rules, and renders nothing: those are the caller's.
func (p *Provider) EnterUserCode(ctx context.Context, in DeviceEntryInput) (AuthorizeResult, error) {
	cfg := p.cfg.device
	if cfg == nil {
		return AuthorizeResult{}, fmt.Errorf("%w: EnterUserCode: the device grant is off; enable it with WithDeviceAuthorization", ErrConfig)
	}
	if in.IdleTimeout < 0 {
		return AuthorizeResult{}, fmt.Errorf("%w: DeviceEntryInput.IdleTimeout: must not be negative", ErrConfig)
	}

	// One load: the check, the charge and the refund all reach the same limiter, whatever
	// UseUserCodeEntryLimiter does meanwhile.
	throttle := cfg.entry.current.Load()
	source, err := throttle.guard.Check(ctx, in.Source)
	if err != nil {
		p.entryThrottled(ctx)

		return AuthorizeResult{}, &entryRefused{cause: err}
	}
	receipt, err := p.chargeEntry(ctx, throttle, source)
	if err != nil {
		p.entryThrottled(ctx)

		return AuthorizeResult{}, err
	}

	res, err := p.enterCode(ctx, cfg, in)
	if !errors.Is(err, ErrInvalidUserCode) {
		p.refundEntry(ctx, throttle, receipt)
	}

	return res, err
}

// Log messages of the entry throttle's own failures. They carry the error's type, never its
// text, and never the source.
const (
	msgEntryChargeFailed = "oidcprovider: the user-code entry limiter could not charge an entry, which is refused"
	msgEntryRefundFailed = "oidcprovider: the user-code entry limiter could not refund an entry that was no failure"
)

// errEntryChargeText is the fixed text a charge the limiter could not decide is wrapped in.
const errEntryChargeText = "oidcprovider: the user-code entry limiter could not charge the entry"

// chargeEntry charges the entry to its source before anything of the code is read, so a
// concurrent burst from one source cannot all pass the check before any of it is counted:
// once the limit is reached, every further charge is refused in the limiter's one step. The
// charge is made with the caller's cancellation stripped, so a client that hangs up cannot
// slip past the limit. A charge refused, or one the limiter could not decide, refuses the
// entry as throttled, failing closed; the limiter's own failure stays reachable beneath the
// fixed text, and is logged by its type alone.
//
// Only the source is charged. The entry guard is built with no IPv6 aggregate, so there is no
// aggregate count to charge.
func (p *Provider) chargeEntry(ctx context.Context, throttle *entryThrottle, source ratelimit.Source) (ratelimit.Receipt, error) {
	receipt, exceeded, err := throttle.limiter.Charge(context.WithoutCancel(ctx), source.Key())
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	if err != nil {
		p.cfg.logger.LogAttrs(ctx, slog.LevelError, msgEntryChargeFailed, diag.Failure("limiter", err)...)

		return ratelimit.Receipt{}, &entryRefused{cause: diag.Wrap(err, errEntryChargeText)}
	}
	if exceeded {
		return ratelimit.Receipt{}, &entryRefused{cause: ratelimit.ErrThrottled}
	}

	return receipt, nil
}

// refundEntry takes back the charge of an entry that was no failure of the code: a claim, a
// re-entry, a failing dependency, a configuration error or a caller who left. It runs with the
// caller's cancellation stripped, and a refund that fails is logged by the error's type alone
// and changes no answer: the entry then stays counted until it leaves the window.
func (p *Provider) refundEntry(ctx context.Context, throttle *entryThrottle, receipt ratelimit.Receipt) {
	err := throttle.limiter.Refund(context.WithoutCancel(ctx), receipt)
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		p.cfg.logger.LogAttrs(ctx, slog.LevelError, msgEntryRefundFailed, diag.Failure("limiter", err)...)
	}
}

// entryThrottled is where a throttled entry is reported. It is the one place a throttled
// entry passes, and reports nothing yet.
func (p *Provider) entryThrottled(context.Context) {}

// enterCode is EnterUserCode past the throttle. Every refusal of the code it answers is
// ErrInvalidUserCode itself, whose charge the caller keeps.
func (p *Provider) enterCode(ctx context.Context, cfg *deviceConfig, in DeviceEntryInput) (AuthorizeResult, error) {
	if len(in.UserCode) > maxEnteredUserCode {
		return AuthorizeResult{}, ErrInvalidUserCode
	}
	raw, ok := cfg.format.normalise(in.UserCode)
	if !ok {
		return AuthorizeResult{}, ErrInvalidUserCode
	}

	record, err := p.deviceByUserCode(ctx, cfg, raw)
	if err != nil {
		return AuthorizeResult{}, err
	}
	// The record's own state and claim are judged before the registry is read, so a code that
	// is refused for them costs no registry call, and answers no slower than an unknown one.
	switch record.State {
	case DeviceIssued:
	case DeviceClaimed:
		if !claimedBy(record, in.FlowSecret) {
			return AuthorizeResult{}, ErrInvalidUserCode
		}
	default:
		return AuthorizeResult{}, ErrInvalidUserCode
	}
	if err := p.deviceClientAllowed(ctx, record.ClientID); err != nil {
		return AuthorizeResult{}, err
	}

	flow := in.FlowSecret
	if record.State == DeviceIssued {
		if flow, err = p.claimDevice(ctx, cfg, record, raw, in.FlowSecret); err != nil {
			if errors.Is(err, ErrInvalidUserCode) {
				return AuthorizeResult{}, err
			}
			// The claim may have been written, bound to flow: the browser keeps it, so its
			// re-entry recovers. flow is empty when none could be minted.
			return AuthorizeResult{FlowSecret: flow}, err
		}
	}

	res, err := p.parkDevice(ctx, cfg, in, record, raw, flow)
	if err != nil {
		// The claim stands, bound to flow: the browser keeps it, so its re-entry recovers.
		return AuthorizeResult{FlowSecret: flow}, err
	}

	return res, nil
}

// claimedBy reports whether record's claim is bound to the browser holding flow: its flow
// secret's digest is the one the claim stored.
func claimedBy(record *DeviceAuthorization, flow string) bool {
	given, ok := digestEncoded(flow)

	return ok && hmac.Equal(given, record.ClaimFlowDigest)
}

// deviceClientAllowed checks that the client a code was issued to is still registered for the
// grant. A client gone or no longer allowed it is ErrInvalidUserCode; a failing registry is
// the registry's error.
func (p *Provider) deviceClientAllowed(ctx context.Context, clientID string) error {
	rc, err := p.client(ctx, clientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return ErrInvalidUserCode
	case err != nil:
		return err
	case !slices.Contains(rc.GrantTypes, GrantDeviceCode):
		return ErrInvalidUserCode
	}

	return nil
}

// deviceByUserCode returns the unexpired record holding raw, or ErrInvalidUserCode. A record
// is judged again here, by the provider's clock and against the digest asked for, so a store
// that answers an expired record, or another code's, cannot let it through.
func (p *Provider) deviceByUserCode(ctx context.Context, cfg *deviceConfig, raw string) (*DeviceAuthorization, error) {
	digest := cfg.userCodeDigest(raw)
	now := p.cfg.clock.Now()

	record, err := cfg.store.LoadByUserCode(ctx, digest, now)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, ErrInvalidUserCode
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: look up the user code")
	case record == nil:
		return nil, dependencyFailure(ctx, errNoRecord, "oidcprovider: look up the user code")
	case !hmac.Equal(record.UserCodeDigest, digest) || record.expiredAt(now):
		return nil, ErrInvalidUserCode
	}

	return record, nil
}

// claimDevice claims an issued record for the browser, minting it a flow secret when it
// holds none it could have been given, and returns that secret, also with an error once the
// claim has been attempted, since it may have been written. A claim lost to another browser,
// or to expiry, is ErrInvalidUserCode. A claim lost to the same browser's other entry, found
// by reading the record again, is this entry's too.
func (p *Provider) claimDevice(ctx context.Context, cfg *deviceConfig, record *DeviceAuthorization, raw, given string) (string, error) {
	flow, flowDigest, err := p.flowFor(ctx, given)
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: mint a flow secret")
	}

	err = cfg.store.Claim(ctx, record.ID, flowDigest, p.cfg.clock.Now())
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return p.claimLost(ctx, cfg, record, raw, flow, flowDigest)
	case err != nil:
		return flow, dependencyFailure(ctx, err, "oidcprovider: claim the device authorization")
	}

	return flow, nil
}

// claimLost reads the record a lost claim was for once more. When the same record is now
// claimed with this entry's flow digest and has not expired, the claim was won by the same
// browser's concurrent entry, and is this entry's too; anything else is ErrInvalidUserCode.
func (p *Provider) claimLost(
	ctx context.Context, cfg *deviceConfig, record *DeviceAuthorization, raw, flow string, flowDigest []byte,
) (string, error) {
	again, err := p.deviceByUserCode(ctx, cfg, raw)
	switch {
	case errors.Is(err, ErrInvalidUserCode):
		return "", ErrInvalidUserCode
	case err != nil:
		return flow, err
	case again.ID != record.ID || again.State != DeviceClaimed || !hmac.Equal(again.ClaimFlowDigest, flowDigest):
		return "", ErrInvalidUserCode
	}

	return flow, nil
}

// parkDevice parks a request for the claimed record, bound to flow, and sends the browser to
// the login page, or to the consent page when its session answers the login stage. Consent
// is always asked for a device request, so a session never answers with a code here.
func (p *Provider) parkDevice(
	ctx context.Context, cfg *deviceConfig, in DeviceEntryInput, record *DeviceAuthorization, raw, flow string,
) (AuthorizeResult, error) {
	req := &PendingRequest{
		ClientID:              record.ClientID,
		Scopes:                slices.Clone(record.Scopes),
		Resources:             slices.Clone(record.Resources),
		DeviceAuthorizationID: record.ID,
		DeviceUserCode:        cfg.format.display(raw),
	}

	now := p.cfg.clock.Now()
	s, digest, err := p.sessionSignIn(ctx, in.BrowserSessionSecret, req, now)
	switch {
	case err != nil:
		return AuthorizeResult{}, err
	case digest == nil:
		return p.park(ctx, req, flow)
	default:
		return p.parkAtConsent(ctx, AuthorizeInput{FlowSecret: flow, IdleTimeout: in.IdleTimeout}, req, s, digest, now)
	}
}

// errDeviceGone says the device authorization a pending request names is no longer live: no
// unexpired record holds its user code, or the one that does is another record. A store
// releases a user code only once its record has expired, and sweeps only expired records, so
// either way the authorization the request answers has expired.
var errDeviceGone = errors.New("oidcprovider: device authorization expired")

// liveDevice reads the device authorization a pending request answers, by the user code it
// was parked with, which must still be held by the record the request names, unexpired by the
// provider's clock. A record gone, expired or replaced is errDeviceGone, and a provider
// without the grant, or a code that no longer reads, ErrUnknownHandle. A failing store is a
// dependency failure. The record's state and claim are the caller's to judge.
func (p *Provider) liveDevice(ctx context.Context, r *PendingRequest) (*DeviceAuthorization, error) {
	cfg := p.cfg.device
	if cfg == nil {
		return nil, ErrUnknownHandle
	}
	raw, ok := cfg.format.normalise(r.DeviceUserCode)
	if !ok {
		return nil, ErrUnknownHandle
	}
	record, err := p.deviceByUserCode(ctx, cfg, raw)
	switch {
	case errors.Is(err, ErrInvalidUserCode):
		return nil, errDeviceGone
	case err != nil:
		return nil, err
	case record.ID != r.DeviceAuthorizationID:
		return nil, errDeviceGone
	}

	return record, nil
}

// deviceView is the device part of a pending request's view, read from the record it
// answers, which must still be live and the one the request names. A record gone, expired
// or replaced is ErrUnknownHandle: there is nothing left for the page to answer.
func (p *Provider) deviceView(ctx context.Context, r *PendingRequest) (*DeviceView, error) {
	record, err := p.liveDevice(ctx, r)
	switch {
	case errors.Is(err, errDeviceGone):
		return nil, ErrUnknownHandle
	case err != nil:
		return nil, err
	}

	return &DeviceView{UserCode: r.DeviceUserCode, RequestedAt: record.IssuedAt}, nil
}
