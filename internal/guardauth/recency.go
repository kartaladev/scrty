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
// It holds the guards-wide window, the clock it reads now from, and where it
// finds the caller's authentication time. Each adapter keeps its own options,
// its own refusal error and its own way of answering one; only the verdict
// lives here. It is safe for concurrent use.
type Recency struct {
	window   time.Duration
	clock    clock.Clock
	authTime func(ctx context.Context) (time.Time, bool)
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
// consumer's source when one was given, the request's session otherwise
// (SessionAuthenticationTime). The adapter resolves which, since only it can
// tell a consumer's nil from no option at all.
func NewRecency(
	window time.Duration, clk clock.Clock, authTime func(ctx context.Context) (time.Time, bool),
) (*Recency, string) {
	switch {
	case window <= 0:
		return nil, fmt.Sprintf("WithRecentAuthenticationWindow needs a window above zero, got %s", window)
	case nilcheck.IsNil(clk):
		return nil, "WithGuardClock was given no clock; omit the option to use the system clock"
	case authTime == nil:
		return nil, "WithAuthenticationTime was given no function; omit the option to read the session's"
	}

	return &Recency{window: window, clock: clk, authTime: authTime}, ""
}

// Judge reports whether the caller of the request ctx belongs to proved their
// identity within window, and the window it judged against, which the
// adapter's refusal carries. A window of zero means the guards-wide window;
// the adapter refuses a route's window of zero or less at wiring, so a zero
// here is never the consumer's own.
//
// A caller with no authentication time is not recent. Otherwise the session's
// own rule decides (session.(*Session).AuthenticatedWithin), so a consumer's
// time is judged exactly as a session's: the window's end inclusive, a time
// ahead of the clock recent, a zero time never.
func (r *Recency) Judge(ctx context.Context, window time.Duration) (recent bool, judged time.Duration) {
	if window == 0 {
		window = r.window
	}

	at, ok := r.authTime(ctx)
	if !ok {
		return false, window
	}

	s := session.Session{AuthenticatedAt: at}

	return s.AuthenticatedWithin(r.clock.Now(), window), window
}

// SessionAuthenticationTime is the default time source: the authentication
// time of the session lookup finds on the request, and none when the request
// carries no session. Each adapter passes its own session lookup, since this
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
