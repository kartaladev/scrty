package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/token/onetime"
)

// DefaultMFABeginPrefix is the prefix the begin endpoint answers POST requests
// under when the consumer names none: a challenge method begins at the prefix
// followed by "/" and the method's name, so a method named "passkey" begins at
// "/mfa/begin/passkey" by default.
const DefaultMFABeginPrefix = "/mfa/begin"

// DefaultMFAChallengeTTL is how long a pending challenge may be answered when
// the consumer sets no lifetime: long enough for a person to complete a
// device ceremony, short enough that a challenge left lying about is soon
// worthless.
const DefaultMFAChallengeTTL = 5 * time.Minute

// DefaultMFAChallengeLimit is how many challenges begin issues one user for
// one method within the pending-challenge manager's issuance window, one hour,
// when the consumer sets no limit.
const DefaultMFAChallengeLimit = 10

// mfaChallengePurpose is the one-time purpose a method's pending challenges
// are issued under. The purpose is stored on every record, so the managers of
// two methods sharing one store never honour each other's challenges.
func mfaChallengePurpose(method string) string { return "mfa-challenge:" + method }

// msgChallengeNotIssued is the fixed text a begin that could not issue its
// challenge or build its data is refused with. The failure is a dependency's,
// and its own text stays out of the refusal.
const msgChallengeNotIssued = "httpsec: the MFA challenge could not be issued"

// MFABeginResponder writes the response to a successful begin. data is the
// document the method's BeginChallenge built around the issued challenge,
// unchanged.
//
// It is called instead of the downstream handler, because the begin endpoint
// is the library's own. An error it returns leaves the chain as the request's
// refusal; the challenge is issued by then and simply expires unanswered.
type MFABeginResponder func(ex *Exchange, data json.RawMessage) error

// writeMFABegin is the response a begin succeeds with when the consumer
// supplies no responder: 200, the method's document as the JSON body, marked
// Cache-Control: no-store because it carries a live challenge. A consumer's
// responder owns its headers and is not given this one.
func writeMFABegin(ex *Exchange, data json.RawMessage) error {
	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err := ex.Writer.Write(data)

	return err
}

// isBeginRequest reports whether r asks for a pending challenge: POST, under
// the begin prefix. Only POST, because issuing a challenge is a change a link
// must not be able to make; and every POST under the prefix, so one naming no
// challenge method is refused as unknown rather than passed to the gate or the
// application.
func (i *mfaInterceptor) isBeginRequest(r Request) bool {
	return r.Method() == http.MethodPost && underPrefix(r.Path(), i.beginPrefix)
}

// begin issues a pending challenge for a challenge method and answers with the
// method's begin data.
//
// It makes the same refusals verify does, in the same order and before the
// body is read — the body is never read here at all — with one difference: a
// path naming a method that has no begin step is refused as unknown, exactly
// as one naming no method is. None of them is counted. A user the verification
// throttle already refuses is refused here too, so a locked-out user cannot
// keep minting challenges.
//
// The challenge is a one-time token of the method's own purpose, whose subject
// is the user and which is bound to the session's handle, so it can be
// answered only on the session that asked for it. Its string is what the
// method builds its data around; the library keeps only its hash.
//
// Issuance is bounded, so a session past its first factor cannot grow the
// store without limit. A user already issued the challenge limit for the
// method within the manager's issuance window is refused as
// mfa.ErrVerifyThrottled, and nothing is issued. The count and the issue are
// one decision of the store's (onetime.Tokens.IssueWithin), so begins racing
// for one user never together exceed the limit. A store that cannot decide is
// a refusal too, behind fixed text, because a limit that lifted whenever the
// store was down would be no limit. And at most once per issuance window,
// begin sweeps the method's expired challenges out of the store, under the
// request's own context. A sweep that fails is logged, never refused: the
// begin in hand is not what failed. One that failed for any reason but the
// store's inability to purge is retried by the next begin.
func (i *mfaInterceptor) begin(ex *Exchange) error {
	s, method, err := i.admit(ex, i.beginPrefix, isChallengeMethod)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	if err := i.throttle.Check(ctx, s.UserID); err != nil {
		return err
	}

	cm := method.(mfa.ChallengeMethod) // admit checked it
	mgr := i.challenges[method.Name()]

	i.sweepExpired(ctx, method.Name(), mgr)

	// One bounded issue, not a count and then an issue: of begins racing for
	// one user, on this process or on another replica, no more than the limit
	// are issued a challenge.
	challenge, _, err := mgr.IssueWithin(ctx, string(s.UserID), i.challengeCap, onetime.WithBinding(s.ID))

	switch {
	case errors.Is(err, onetime.ErrIssueLimitReached):
		return mfa.ErrVerifyThrottled
	case err != nil:
		return diag.Wrap(err, msgChallengeNotIssued)
	}

	data, err := cm.BeginChallenge(ctx, s.UserID, challenge)
	if err != nil {
		return diag.Wrap(err, msgChallengeNotIssued)
	}

	return i.beginRespond(ex, data)
}

// msgChallengesNotPurged is what a sweep of a method's expired challenges
// that failed is logged as.
const msgChallengesNotPurged = "httpsec: expired MFA challenges could not be purged"

// Why a sweep failed, as its log record names it.
const (
	reasonPurgeUnsupported = "purge-unsupported"
	reasonStoreUnavailable = "store-unavailable"
)

// challengeSweepFlow names the sampler keys of failed sweeps.
const challengeSweepFlow = "mfa-challenge-sweep"

// sweepExpired purges method's expired challenges from the store, when a
// sweep is due. A sweep that fails is logged through the chain's sampler and
// otherwise ignored.
//
// It runs under the request's own context, so a store that stops answering
// holds the begin no longer than the request allows. A sweep that fails, or is
// cut short, gives its turn back, so a later begin sweeps again rather than
// waiting out the window; the exception is a store that cannot purge at all,
// which no retry would change, so its turn is kept and it is logged once per
// window.
func (i *mfaInterceptor) sweepExpired(ctx context.Context, method string, mgr *onetime.Tokens) {
	clock := i.sweeps[method]

	claimed, due := clock.claim(i.now(), mgr.IssuanceWindow())
	if !due {
		return
	}

	_, err := mgr.PurgeExpired(ctx)
	if err == nil {
		return
	}

	reason := reasonStoreUnavailable
	if errors.Is(err, onetime.ErrReapUnsupported) {
		reason = reasonPurgeUnsupported
	} else {
		clock.release(claimed)
	}

	logSampled(ctx, i.sampler, i.log, slog.LevelWarn, i.now(),
		challengeSweepFlow+sampleKeySeparator+method+sampleKeySeparator+reason, msgChallengesNotPurged,
		slog.String("method", method), slog.String("reason", reason))
}

// sweepClock spaces one method's sweeps of its expired challenges. It is safe
// for concurrent use.
type sweepClock struct {
	mu   sync.Mutex
	last time.Time
	prev time.Time
}

// claim reports whether a sweep is due at now, the first ever, one a window
// after the last, or the first after the clock has stepped back behind the
// last, and claims it if so: of several begins asking at once, exactly one is
// told to sweep. It returns the claim, which release takes. Without the
// backwards case, a clock set back would hold off every sweep for as long as
// it was set back by.
func (c *sweepClock) claim(now time.Time, window time.Duration) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.last.IsZero() && !now.Before(c.last) && now.Sub(c.last) < window {
		return time.Time{}, false
	}

	c.prev, c.last = c.last, now

	return now, true
}

// release gives back the claim made at claimed, so the next begin finds a
// sweep due. A claim a later one has already replaced is left alone.
func (c *sweepClock) release(claimed time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.last.Equal(claimed) {
		c.last = c.prev
	}
}

// isChallengeMethod reports whether m has a begin step.
func isChallengeMethod(m mfa.Method) bool {
	_, ok := m.(mfa.ChallengeMethod)

	return ok
}

// wireChallenges builds one pending-challenge manager per challenge method,
// all over one store, told apart by their purposes. It runs at assembly,
// because the managers log through the chain's logger and read the chain's
// clock. The default store reads that clock too, so expiry means the same on
// both sides; a store the consumer gave (WithMFAChallengeStore) keeps its own.
func (i *mfaInterceptor) wireChallenges(c *config) error {
	store := i.challengeStore
	if store == nil {
		store = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(c.clock))
	}

	i.challenges = make(map[string]*onetime.Tokens)
	i.sweeps = make(map[string]*sweepClock)

	for _, m := range i.methods {
		if !isChallengeMethod(m) {
			continue
		}

		mgr, err := onetime.New(mfaChallengePurpose(m.Name()),
			onetime.WithTTL(i.challengeTTL),
			onetime.WithStore(store),
			onetime.WithClock(c.clock),
			onetime.WithLogger(c.logger))
		if err != nil {
			return newConfigError("EnableMFA could not build the pending challenges of %q: %s", m.Name(), err)
		}

		i.challenges[m.Name()] = mgr
		i.sweeps[m.Name()] = &sweepClock{}
	}

	return nil
}

// WithMFABeginPrefix begins each challenge method under prefix instead: a
// method begins at prefix, "/" and its name.
//
// Default: DefaultMFABeginPrefix. Only POST under the prefix is a begin. A
// trailing slash is dropped. An empty prefix, one that does not start with "/"
// and the root "/" are refused, as they are for WithMFAVerifyPrefix; so is a
// prefix equal to, above or below the verify prefix, since one endpoint would
// then answer the other's requests, and one that claims the chain's logout
// path.
func WithMFABeginPrefix(prefix string) MFAOption {
	return func(i *mfaInterceptor) error {
		p, err := mfaPrefix("WithMFABeginPrefix", prefix)
		if err != nil {
			return err
		}

		i.beginPrefix = p

		return nil
	}
}

// WithMFAChallengeTTL lets a pending challenge be answered for d after it is
// issued, instead of DefaultMFAChallengeTTL.
//
// A lifetime of zero or less is refused: it would expire every challenge the
// moment it was issued, and a challenge method could never be verified.
func WithMFAChallengeTTL(d time.Duration) MFAOption {
	return func(i *mfaInterceptor) error {
		if d <= 0 {
			return newConfigError("WithMFAChallengeTTL was given %s; a challenge that expires as it "+
				"is issued could never be answered", d)
		}

		i.challengeTTL = d

		return nil
	}
}

// WithMFAChallengeStore keeps pending challenges in s instead.
//
// Default: an in-memory one-time store, which serves a single process. On
// several replicas a begin and the verify answering it may land on different
// ones, and the verify is then refused as an invalid code; a deployment
// running more than one supplies a store its replicas share, such as the
// durable one-time stores this module's adapters provide. The store is shared
// by every challenge method, and each method's challenges are issued under a
// purpose of its own, so no method honours another's.
//
// Begin counts each user's challenges in the store to enforce
// WithMFAChallengeLimit, and sweeps each method's expired challenges from it
// at most once per issuance window per method, and again whenever the clock
// has stepped back behind the last sweep. The window is kept by each
// process on its own, so replicas sharing a store each sweep it once a window.
// A sweep runs under the begin request's context; one that fails or is cut
// short is logged and retried by the next begin. A store that does not
// implement onetime.Reaper cannot be swept: begin still works, and each
// skipped sweep is logged, once a window, so a store whose records are removed
// some other way is a choice, not a surprise.
//
// A nil store, including an interface holding a nil pointer, is refused.
func WithMFAChallengeStore(s onetime.Store) MFAOption {
	return func(i *mfaInterceptor) error {
		if err := requireDep("WithMFAChallengeStore", "one-time store", s); err != nil {
			return err
		}

		i.challengeStore = s

		return nil
	}
}

// WithMFABeginResponder replaces the response written when a begin succeeds.
//
// Default: 200 with the method's begin data as an "application/json" body,
// unchanged. A nil function is refused; omit the option to keep the default.
func WithMFABeginResponder(fn MFABeginResponder) MFAOption {
	return func(i *mfaInterceptor) error {
		if fn == nil {
			return newConfigError("WithMFABeginResponder was given no function; omit the option to " +
				"keep the default document")
		}

		i.beginRespond = fn

		return nil
	}
}

// WithMFAChallengeLimit lets begin issue n challenges to one user for one
// method within the pending-challenge issuance window, one hour, instead of
// DefaultMFAChallengeLimit. A begin past the limit is refused as
// mfa.ErrVerifyThrottled and issues nothing.
//
// The limit is counted from the pending-challenge store, so it holds across
// replicas sharing a store and across a user's sessions. The count and the
// issue are one decision of the store's, so begins racing each other never
// together issue more than n.
//
// A limit of zero or less is refused: it would refuse every begin, and a
// challenge method could never be verified.
func WithMFAChallengeLimit(n int) MFAOption {
	return func(i *mfaInterceptor) error {
		if n <= 0 {
			return newConfigError("WithMFAChallengeLimit was given %d; a limit that refuses every "+
				"begin leaves no challenge to answer", n)
		}

		i.challengeCap = n

		return nil
	}
}

// methodSegment returns the method named by path under prefix. It is ok only
// for prefix, then "/", then one non-empty segment with no further "/": the
// bare prefix, an empty segment, a trailing slash and an extra segment all name
// no method, so none of them can match one by accident.
//
// prefix is as mfaPrefix returns it, with no trailing slash.
func methodSegment(path, prefix string) (name string, ok bool) {
	rest, found := strings.CutPrefix(path, prefix+"/")
	if !found || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}

	return rest, true
}

// underPrefix reports whether path is prefix itself or lies below it. Every
// such path is the endpoint's own, including one that names no method, so the
// endpoint refuses it as unknown rather than letting it through to the
// application or to the gate.
func underPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// mfaPrefix validates a second-factor endpoint prefix and returns it without
// a trailing slash, so "/auth/second-factor" and "/auth/second-factor/" name
// the same endpoints.
//
// An empty prefix is refused, because the consumer asked for an endpoint that
// would then silently not exist; so is one that does not start with "/", which
// matches no request path; and so is the root, which would claim every
// one-segment path of the application as a method name.
func mfaPrefix(option, prefix string) (string, error) {
	switch {
	case prefix == "":
		return "", newConfigError("%s was given no prefix, so a session owing a second factor "+
			"would have no way to resolve it", option)
	case !strings.HasPrefix(prefix, "/"):
		return "", newConfigError("%s was given %q, which does not start with \"/\" and so "+
			"matches no request path", option, prefix)
	}

	trimmed := strings.TrimRight(prefix, "/")
	if trimmed == "" {
		return "", newConfigError("%s was given the root path %q, which would claim every "+
			"one-segment path of the application", option, prefix)
	}

	return trimmed, nil
}
