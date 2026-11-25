package guardauth

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

// Recency is the one judge of whether a guarded request's caller proved their
// identity recently enough, shared by the net/http, gin and fiber guards.
//
// It holds the guards-wide window, the clock it reads now from, where it
// finds the caller's authentication time, and the adapter's refusals. Each
// adapter keeps its own options and its own way of answering a refusal; the
// verdict and the choice of refusal (Refuse) live here, so the three adapters
// judge alike. It is safe for concurrent use.
type Recency struct {
	window   time.Duration
	clock    clock.Clock
	authTime func(ctx context.Context) (time.Time, bool)
	refusals Refusals
}

// AccessTokenCaller reports whether the caller of the request ctx belongs to
// was authenticated by an access token a resource server accepted, and the
// authentication time that token carries: the zero time when it carries none.
// Each adapter passes its own, reading the token httpsec publishes, since this
// package cannot import httpsec.
type AccessTokenCaller func(ctx context.Context) (authTime time.Time, ok bool)

// Refusals are how an adapter answers a caller the recency judge found stale.
// The judge chooses which (Recency.Refuse); the adapter builds it, since the
// refusal types are httpsec's. Every field is required.
type Refusals struct {
	// AccessTokenCaller tells an access-token caller apart from any other.
	AccessTokenCaller AccessTokenCaller

	// Session is the refusal of any caller that is no access-token caller,
	// carrying window: httpsec's *ReauthenticationRequiredError (403).
	Session func(window time.Duration) error

	// AccessToken is the refusal of an access-token caller, carrying window:
	// httpsec's *InsufficientUserAuthenticationError (401, with max_age).
	AccessToken func(window time.Duration) error
}

// NewRecency validates the recency settings and returns their judge.
//
// It refuses, with an empty judge and a reason naming the guard option as
// every adapter spells it, a window of zero or less, a nil clock or an
// interface holding a nil value, and a nil time source, judged in that order.
// The reason is the body of the adapter's configuration error: the adapter
// adds its own prefix and wraps its own sentinel. The reason is empty when
// the settings are usable.
//
// authTime is where the caller's authentication time comes from: the
// consumer's source when one was given, the request's access token or session
// otherwise (CallerAuthenticationTime). The adapter resolves which, since only it can
// tell a consumer's nil from no option at all.
//
// refusals are the adapter's own, and are judged last: a Refusals missing a
// field is the adapter's wiring mistake, never the consumer's, and is refused
// with a reason naming the recency refusals.
func NewRecency(
	window time.Duration, clk clock.Clock, authTime func(ctx context.Context) (time.Time, bool), refusals Refusals,
) (*Recency, string) {
	switch {
	case window <= 0:
		return nil, fmt.Sprintf("WithRecentAuthenticationWindow needs a window above zero, got %s", window)
	case nilcheck.IsNil(clk):
		return nil, "WithGuardClock was given no clock; omit the option to use the system clock"
	case authTime == nil:
		return nil, "WithAuthenticationTime was given no function; omit the option to read the session's"
	case refusals.AccessTokenCaller == nil || refusals.Session == nil || refusals.AccessToken == nil:
		return nil, "the guards' recency refusals are incomplete; this is a defect in the adapter"
	}

	return &Recency{window: window, clock: clk, authTime: authTime, refusals: refusals}, ""
}

// Refuse judges the request ctx belongs to as Judge does, and returns nil when
// its caller is recent. Otherwise it returns the adapter's refusal carrying the
// window judged: the access-token refusal for a caller a resource server
// authenticated, whatever time source judged it, and the session refusal for
// any other caller, an API key, HTTP Basic or a consumer's own first factor
// included.
func (r *Recency) Refuse(ctx context.Context, window time.Duration) error {
	recent, judged := r.Judge(ctx, window)
	if recent {
		return nil
	}

	if _, ok := r.refusals.AccessTokenCaller(ctx); ok {
		return r.refusals.AccessToken(judged)
	}

	return r.refusals.Session(judged)
}

// CallerAuthenticationTime is the default time source every adapter builds its
// guards with: for an access-token caller, the authentication time its token
// carries, and none when the token carries none, so such a token is never
// recent; for any other caller, the time of the session sessions finds on the
// request (SessionAuthenticationTime). An access-token caller is never judged
// by a session's time.
func CallerAuthenticationTime(
	sessions func(ctx context.Context) (*session.Session, bool), accessToken AccessTokenCaller,
) func(ctx context.Context) (time.Time, bool) {
	fromSession := SessionAuthenticationTime(sessions)

	return func(ctx context.Context) (time.Time, bool) {
		if at, ok := accessToken(ctx); ok {
			return at, !at.IsZero()
		}

		return fromSession(ctx)
	}
}

// Judge reports whether the caller of the request ctx belongs to proved their
// identity within window, and the window it judged against, which the
// adapter's refusal carries. A window of zero means the guards-wide window;
// the adapter refuses a route's window of zero or less at wiring, so a zero
// here is never the consumer's own.
//
// A caller with no authentication time is not recent. Otherwise the library's
// one freshness rule decides (session.AuthenticatedWithin, which the session's
// own method delegates to), so a consumer's time is judged exactly as a
// session's: the window's end inclusive, a time ahead of the clock recent, a
// zero time never.
func (r *Recency) Judge(ctx context.Context, window time.Duration) (recent bool, judged time.Duration) {
	if window == 0 {
		window = r.window
	}

	at, ok := r.authTime(ctx)
	if !ok {
		return false, window
	}

	return session.AuthenticatedWithin(at, r.clock.Now(), window), window
}

// SessionAuthenticationTime is the session half of the default time source
// (CallerAuthenticationTime): the authentication time of the session lookup
// finds on the request, and none when the request carries no session. Each adapter passes its own session lookup, since this
// package cannot import the one in httpsec.
func SessionAuthenticationTime(
	lookup func(ctx context.Context) (*session.Session, bool),
) func(ctx context.Context) (time.Time, bool) {
	return func(ctx context.Context) (time.Time, bool) {
		s, ok := lookup(ctx)
		if !ok {
			return time.Time{}, false
		}

		return s.AuthenticatedAt, true
	}
}
