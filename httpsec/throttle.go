package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/ratelimit"
)

//go:generate mockgen -destination=limiter_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/ratelimit Limiter

// The reasons an address cannot key a bucket. Each is the tail of the sampler
// key its refusal is recorded under, so an operator reading one record sees
// which of the three is happening without opening the message.
const (
	reasonNoClientAddress = "no-client-address"
	reasonNotSingleIP     = "not-single-ip"
	reasonUnspecified     = "unspecified-address"
)

// sampleKeySeparator joins a sampler key's parts. Every key this package builds
// starts with the flow, so a burst against one flow never holds another flow's
// window open.
const sampleKeySeparator = "|"

// sourceGuard is the part of ratelimit.SourceGuard the throttle seam uses.
//
// It is an interface so the seam's own guarantee — that a recording is made on
// a context the client's disconnect cannot reach — is observable at this
// package's boundary rather than only inside the guard. A consumer never sees
// it: every chain is wired with a real *ratelimit.SourceGuard.
type sourceGuard interface {
	Check(ctx context.Context, clientAddr string) (ratelimit.Source, error)
	RecordFailure(ctx context.Context, s ratelimit.Source)
}

// The real guard satisfies the seam, so a change to either is a compile error
// here rather than a surprise where an interceptor is wired.
var _ sourceGuard = (*ratelimit.SourceGuard)(nil)

// classifyAddress decides whether addr may key a rate-limit bucket, and names
// the reason when it may not.
//
// An address that is not exactly one IP names more than one client — a
// forwarding header's list, a hostname, a host and port — and an unspecified
// address is what a peer that is not a TCP client is reported as. Keying either
// pools unrelated clients into one bucket, where any one of them can spend the
// allowance all the others depend on, so both are refused outright instead. An
// empty address names nobody at all.
func classifyAddress(addr string) (reason string, ok bool) {
	if addr == "" {
		return reasonNoClientAddress, false
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return reasonNotSingleIP, false
	}

	// Unmapped first: IsUnspecified alone is false for ::ffff:0.0.0.0, which is
	// the same address written the other way and would otherwise be keyed on.
	if ip.Unmap().IsUnspecified() {
		return reasonUnspecified, false
	}

	return "", true
}

// sourceThrottled checks the request's source before the guarded work runs, and
// returns the source the failure is later recorded against.
//
// It refuses an address it cannot attribute before the limiter is asked, so
// such a request never reaches a bucket to be pooled in, and it refuses a check
// the limiter could not answer as well: a limiter that cannot answer has not
// said the source is within its limit, and admitting the request would lift
// every limit at exactly the moment something is wrong. Both read to the client
// as an ordinary failed attempt, so a client cannot tell a refused source from
// a wrong credential.
//
// A refused check returns the zero Source, which keys nothing, so no failure
// can be charged to a check that did not pass.
func sourceThrottled(
	ctx context.Context,
	g sourceGuard,
	clientAddr, flow string,
	s *logsample.Sampler,
	log *slog.Logger,
	now time.Time,
) (ratelimit.Source, error) {
	if reason, ok := classifyAddress(clientAddr); !ok {
		logSampled(ctx, s, log, slog.LevelError, now, flow+sampleKeySeparator+reason,
			"httpsec: refusing a request whose client address cannot be attributed",
			slog.String("flow", flow), slog.String("reason", reason))

		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed
	}

	src, err := g.Check(ctx, clientAddr)
	switch {
	case err == nil:
		return src, nil

	case overLimit(err):
		// Keyed on the address rather than on the source, because a refused
		// check carries no source: the guard returns the zero value with it.
		logSampled(ctx, s, log, slog.LevelWarn, now, flow+sampleKeySeparator+clientAddr,
			"httpsec: source throttled",
			slog.String("flow", flow), slog.String("source", clientAddr))

		return src, err

	case endedBeforeTheAnswer(ctx, err):
		// The client's own doing, not a refusal worth a sampled warning, and
		// sampling it would let ordinary disconnections consume the window a
		// real outage needs. So it is written every time, at debug.
		log.LogAttrs(ctx, slog.LevelDebug,
			"httpsec: the request ended before the rate limiter answered",
			slog.String("flow", flow), slog.String("error", err.Error()))

		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed

	default:
		// One key per flow: the limiter is either answering for that flow or it
		// is not, and one record per window says so.
		logSampled(ctx, s, log, slog.LevelError, now, flow,
			"httpsec: the rate limiter could not answer",
			slog.String("flow", flow), slog.String("error", err.Error()))

		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed
	}
}

// overLimit reports whether the guard refused because the source has spent its
// allowance, rather than because it could not ask at all.
//
// The guard answers both with ErrThrottled and tells them apart by what the
// refusal carries: a source over its limit is refused with the sentinel itself,
// while a check that could not be made carries the limiter's own failure
// underneath it. So the question is whether the refusal has anything underneath
// it at all, which reads the difference without this package having to know the
// wrapping's wording.
func overLimit(err error) bool {
	if !errors.Is(err, ratelimit.ErrThrottled) {
		return false
	}

	var (
		wrapped interface{ Unwrap() error }
		joined  interface{ Unwrap() []error }
	)

	return !errors.As(err, &wrapped) && !errors.As(err, &joined)
}

// endedBeforeTheAnswer reports whether the check failed because this request's
// own context ended, rather than because the limiter is unwell.
func endedBeforeTheAnswer(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()

	return ctxErr != nil && errors.Is(err, ctxErr)
}

// recordSourceFailure counts one failure against the source that made it.
//
// It records on a context the request's cancellation does not reach: a client
// that submits a wrong credential and hangs up before the response has still
// made the attempt, and a recording that went with it would let a guesser evade
// the limit simply by not waiting for the answer. The context is otherwise
// passed through, so a limiter reaching a remote store still sees its values.
func recordSourceFailure(ctx context.Context, g sourceGuard, s ratelimit.Source) {
	g.RecordFailure(context.WithoutCancel(ctx), s)
}
