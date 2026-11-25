package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// referenceTransport names how a session reference reached the chain. The
// pipeline judges a reference the same way whichever carried it; the
// transport is there so what differs by carrier, and only that, can be told
// apart.
type referenceTransport uint8

const (
	// transportHeader is a reference presented in the Authorization header,
	// under the session bearer's scheme.
	transportHeader referenceTransport = iota + 1

	// transportCookie is a reference presented in the session cookie.
	transportCookie
)

// referenceCheck is a transport's own check of a well-formed reference: it
// runs after the shape check and before the session is loaded, so a request it
// refuses costs no store read. Its error is the request's answer as it is, and
// is not counted against the source. The admit it returns, when not nil,
// judges the loaded session before its user is reloaded or anything is
// published (sessionResolver.admit).
type referenceCheck func(ex *Exchange) (admit func(*Exchange, *session.Session) (*identity.Details, error), err error)

// sessionReference is the pipeline a session reference is judged by, whatever
// carried it: the source check, the shape check, the transport's own check,
// then the resolution core (load by digest, reuse, user reload, publication
// and the per-request phase), with every refusal of the reference itself
// counted against its source.
type sessionReference struct {
	// resolver is the resolution core, built at assembly over the mode's own
	// session manager and user loader and the chain's engine, enforcer set and
	// enrolment lifetime: the same core the signed bearer joins.
	resolver sessionResolver

	now func() time.Time

	// flow names the transport's rate-limit namespace and its sampler and log
	// keys, so an operator can tell the refusals of one transport from the
	// other's: sessionReferenceFlow for the header, sessionCookieFlow for the
	// cookie.
	flow string

	limiter ratelimit.Limiter
	guard   sourceGuard
	sampler *refusalSampler
	log     *slog.Logger
}

// resolve judges the reference id, which reached the chain by transport t, and
// resolves its session and user onto ex. A reference that resolved is the
// caller's to record as presented once resolve returns nil; resolve itself
// records one only for a header credential whose caller it published and the
// per-request phase then throttled (Exchange.recordThrottledBearer). A cookie
// is never recorded: what is recorded is what a DPoP proof's ath is judged
// against, and a cookie is no access token.
//
// The source is checked first, before the value is even parsed, so a
// throttled scanner costs one bucket read. A value that cannot be a session
// identifier is then refused before the store is asked. check, when not nil,
// runs next. Every refusal of the reference (format, load, user reload) is
// recorded against the source; a policy decision about a valid session is
// not, and neither is a dependency failure or a request whose own context
// ended, which reach no verdict and so do not match ErrAuthenticationRequired.
//
// It returns nil when the request may go on, and otherwise the request's
// answer. rejected reports whether that answer is a verdict on the reference
// itself, and is true for exactly the refusals charged to the source: a
// malformed value, a missing, expired, unreadable or reused session, a user
// refused on reload, and a refusal an admit step returned matching
// ErrAuthenticationRequired. It is false for every answer reached without
// judging the reference, even one matching ErrAuthenticationRequired: a
// source over its allowance, a limiter that could not answer or an address
// that cannot be attributed, an error from check, and any error once the
// caller was published. A dependency failure and a request whose own context
// ended are never verdicts.
func (r *sessionReference) resolve(
	ex *Exchange, id string, t referenceTransport, check referenceCheck,
) (rejected bool, err error) {
	ctx := ex.Context()

	src, err := sourceThrottled(ctx, r.guard, ex.Request.ClientIP(), r.flow,
		r.sampler, r.log, r.now())
	if err != nil {
		return false, ErrAuthenticationRequired
	}

	if !session.ValidIdentifier(id) {
		recordSourceFailure(ctx, r.guard, src)

		return true, ErrAuthenticationRequired
	}

	resolver := r.resolver

	if check != nil {
		admit, err := check(ex)
		if err != nil {
			return false, err
		}

		resolver.admit = admit
	}

	if err := resolver.resolve(ex, id); err != nil {
		if t == transportHeader {
			ex.recordThrottledBearer(err, id)
		}

		// Only a refusal of the reference itself is a failed guess. Once the
		// session and its user are resolved the caller is published, so an
		// error after that point is a policy decision about a valid session,
		// and counting it would let a policy misconfiguration lock out the
		// very clients it governs.
		rejected := ex.Authentication == nil && errors.Is(err, ErrAuthenticationRequired)
		if rejected {
			recordSourceFailure(ctx, r.guard, src)
		}

		return rejected, err
	}

	if ex.renewal != "" {
		// A late credential let through to the renewal endpoint is judged
		// there, after the mode has gone by, so the endpoint is left the
		// means to charge the source this request came from when it refuses
		// the credential.
		ex.chargeRenewal = func(ctx context.Context) { recordSourceFailure(ctx, r.guard, src) }
	}

	return false, nil
}
