package httpsec

import (
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/token"
)

// MFAOption configures the second factor. Each replaces one of the defaults
// named on EnableMFA.
type MFAOption func(*mfaInterceptor) error

// EnableMFA verifies a second factor at the MFA slot, on any of methods, and
// holds every session that owes one.
//
// Each method is verified by POST at its own path: the verify prefix, "/" and
// the method's name, so TOTP is verified at "/mfa/verify/totp" by default. The
// method is read from that path and never from a header, the URL query or the
// body. A POST under the prefix naming no configured method — an empty, extra
// or trailing segment included — is refused with ErrUnknownMFAMethod (404).
// Before the body is read the endpoint also refuses a method on the session's
// first-factor channel with mfa.ErrSameChannel, and a method the user may not
// use with ErrMFAMethodNotUsable (403), deciding "usable" with
// policy.UsableMFAMethods; a failed enrolment lookup is a refusal behind
// fixed text, with the lookup's error reachable through errors.Is and
// errors.As but not repeated in the text. None of these is counted against the
// verification limiter.
//
// A method that is an mfa.ChallengeMethod also has a begin step: a POST to
// the begin prefix, "/" and its name ("/mfa/begin/<name>" by default) makes
// the same refusals, is refused while the user's verification is throttled,
// and then issues a pending challenge — a one-time token of the method's own
// purpose, for the session's user, bound to the session's handle — whose
// string the method's BeginChallenge builds its data around. The data is
// written by the begin responder. A begin path naming a method with no begin
// step is refused with ErrUnknownMFAMethod. At verification of such a method,
// the challenge its response presents is checked against the ones issued for
// that session and spent before the method verifies anything, whether the
// attempt then succeeds or not; an absent, unknown, expired, spent or
// other-session challenge is refused with mfa.ErrInvalidCode and counted.
//
// The policies that raise the challenge must be built from the same methods,
// through mfa.LookupsFor(methods...), so the endpoint never refuses a method a
// policy offered or accepts one it did not.
//
// Defaults: the verify prefix is DefaultMFAVerifyPrefix
// (WithMFAVerifyPrefix); failed verifications are counted per user reference,
// across every method, by a limiter of 5 failures per 15 minutes from the
// chain's rate-limiter factory under namespace "mfa-verify", or else in memory
// (WithMFAVerifyLimiter); and the records those refusals write are sampled
// over one minute (WithMFALogInterval). A consumer who wires nothing else gets
// all three. For challenge methods: the begin prefix is DefaultMFABeginPrefix
// (WithMFABeginPrefix), a pending challenge lives DefaultMFAChallengeTTL
// (WithMFAChallengeTTL) in an in-memory store serving one process
// (WithMFAChallengeStore), a user is issued at most DefaultMFAChallengeLimit
// (10) challenges per method within the store's one-hour issuance window
// (WithMFAChallengeLimit), and a begin answers with the method's data as a
// JSON body (WithMFABeginResponder). Begin also sweeps each method's expired
// challenges out of the store, at most once per issuance window per method in
// each process, under the begin request's own context; a sweep that fails is
// logged and retried by a later begin, and never refuses the begin. A store
// that cannot purge at all (onetime.ErrReapUnsupported) is not retried, since
// a retry would not change that: it is tried and logged once per issuance
// window. The verify and begin prefixes must not overlap.
//
// The method-listing endpoint, a GET a pending session sends to learn which
// methods its user can use, is off unless WithMFAMethodListing turns it on.
//
// Each method's response is read by the library, the way the method's
// mfa.ResponseFormat declares: one field of an
// "application/x-www-form-urlencoded" POST body (TOTP reads "code", up to
// 4 KiB), or a whole JSON body, bounded at the method's declared limit. A
// response in the URL query is never read, because a URL reaches access logs,
// proxy logs and the Referer header the next page sends. A body that carries
// no response, is not of the declared type or does not parse is refused with
// ErrCredentialsMissing (400), and one over the limit with ErrRequestTooLarge
// (413); neither is counted against the verification limiter, because no
// response was presented. The limiter is still consulted first, so a user it
// already refuses gets its refusal rather than 400. The two readers are a
// limit, not a default: a method never reads the request itself, and a
// consumer who must accept another encoding puts an interceptor of their own
// in front of the endpoint.
//
// A chain has one MFA configuration: a second EnableMFA is refused whatever
// prefix or methods it carries, because the challenge a refused request
// carries lists the methods of one configuration, so give every method to one
// EnableMFA.
//
// The set is required and is checked by mfa.LookupsFor: an empty set, an
// absent method, a method reporting no channel, a name that is not one path
// segment, two methods sharing a name and a malformed response format are all
// refused here. An empty channel in particular equals the channel of an
// unrecorded first factor, so every session established without a recorded
// kind would be refused at verify as a same-channel attempt — a wiring mistake
// whose symptom appears far from its cause.
//
// The session manager is not a parameter: the handle is rotated in the one the
// chain already resolves sessions through, taken from the built-ins enabled
// alongside this one, exactly as the chain's own activity write-back takes it.
// A chain with no session manager at all is refused, because a second factor
// that could not rotate the handle would leave a pre-MFA handle live after the
// privilege change. A verify prefix that claims the chain's logout path is
// refused too, because a pending session could then not log out.
func EnableMFA(methods []mfa.Method, opts ...MFAOption) Option {
	const option = "EnableMFA"

	return func(c *config) error {
		// The challenge a refused request carries lists the methods of one
		// configuration, so a second would leave its methods unoffered.
		if err := eachInterceptor(c, func(*mfaInterceptor) error {
			return newConfigError("%s was given twice; one chain offers one set of second-factor "+
				"methods, so give every method to one EnableMFA", option)
		}); err != nil {
			return err
		}

		// LookupsFor is the one place a wrongly declared method is caught, so
		// the rules and their messages are stated once for the policy lookups
		// and for this endpoint rather than drifting apart.
		lookups, err := mfa.LookupsFor(methods...)
		if err != nil {
			return newConfigError("%s was given an unusable method: %s", option, err)
		}

		byName := make(map[string]mfa.Method, len(methods))
		for _, m := range methods {
			byName[m.Name()] = m
		}

		i := &mfaInterceptor{
			methods:      slices.Clone(methods),
			byName:       byName,
			lookups:      lookups,
			now:          c.now,
			verifyPrefix: DefaultMFAVerifyPrefix,
			respond:      writeMFAResult,
			beginPrefix:  DefaultMFABeginPrefix,
			beginRespond: writeMFABegin,
			challengeTTL: DefaultMFAChallengeTTL,
			challengeCap: DefaultMFAChallengeLimit,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		// Every POST under either prefix is that endpoint's own, so two
		// prefixes that overlap would leave one endpoint answering the
		// other's requests.
		if underPrefix(i.beginPrefix, i.verifyPrefix) || underPrefix(i.verifyPrefix, i.beginPrefix) {
			return newConfigError("%s's verify prefix %q and begin prefix %q overlap, so one "+
				"endpoint would answer the other's requests", option, i.verifyPrefix, i.beginPrefix)
		}

		if err := i.checkListing(option); err != nil {
			return err
		}

		c.enable(option, func() error {
			if c.sessions == nil {
				return newConfigError("%s needs a session manager to rotate the handle with, "+
					"and none of the built-ins enabled on this chain was wired to one", option)
			}

			if c.sessionBearer {
				return checkTokenGenerator(c, option, "WithMFATokens", i.tokens)
			}

			if i.tokens == nil {
				return newConfigError("%s needs a token generator: rotating the handle ends the "+
					"credential the caller arrived with, so the response has to hand back one "+
					"naming the rotated session (WithMFATokens)", option)
			}

			return nil
		})

		c.register(i, OrderMFAChallenge)
		c.enableGate(policy.ChallengeMFA)

		return nil
	}
}

// WithMFAVerifyPrefix verifies each method under prefix instead: a method is
// verified at prefix, "/" and its name.
//
// Default: DefaultMFAVerifyPrefix. Only POST under the prefix is a
// verification; every other request to it is judged like any other, which for
// a session that owes a second factor means the gate holds it. A trailing
// slash is dropped, so "/auth/2fa" and "/auth/2fa/" are the same prefix.
//
// An empty prefix is refused, because the endpoint the consumer asked for
// would silently not exist and the challenge could never be resolved; so is a
// prefix that does not start with "/", which matches no request path, and the
// root "/", which would claim every one-segment path of the application.
func WithMFAVerifyPrefix(prefix string) MFAOption {
	return func(i *mfaInterceptor) error {
		p, err := mfaPrefix("WithMFAVerifyPrefix", prefix)
		if err != nil {
			return err
		}

		i.verifyPrefix = p

		return nil
	}
}

// WithMFAVerifyLimiter counts failed code verifications through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "mfa-verify", or else an in-memory limiter of 5 failures per 15
// minutes; either way keyed by the user reference rather than by the request's
// source — by the time a second factor is being checked the attacker already
// holds the first and can present codes from as many addresses as they like. A
// deployment running more than one replica supplies a factory or a limiter its
// replicas share, or the limit is per process and the guesses are simply
// spread.
//
// It governs failed code verifications alone. The key is composed by mfa, and
// mfa.VerifyThrottleKey reports it, so a consumer sharing one limiter across
// flows can read or clear that bucket.
//
// For this second-factor flow, a shared limiter in ratelimit.UnavailableFallbackToLocal
// mode is the recommended choice: during an outage of the shared store each
// replica still bounds guessing on its own, and users are not locked out.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it
// would read as "no limit" while the consumer believed they had replaced one.
func WithMFAVerifyLimiter(l ratelimit.Limiter) MFAOption {
	return func(i *mfaInterceptor) error {
		if err := requireDep("WithMFAVerifyLimiter", "limiter", l); err != nil {
			return err
		}

		i.throttleOpts = append(i.throttleOpts, mfa.WithThrottleLimiter(l))

		return nil
	}
}

// WithMFATokens issues the rotated session's access token through g.
//
// There is no default, and it is required in the signed-token mode: rotation
// deletes the handle the caller arrived with, and the session identifier is
// the token's jti, so without a generator a caller who passed their second
// factor would hold a credential naming a session that no longer exists. With
// EnableSessionBearer on, it must not be given: the endpoint hands back the
// rotated session's identifier instead, and a generator is a configuration
// error from New. It is the same generator
// the first factors issue through, so a token from a login and one from a
// second factor are indistinguishable to whatever verifies them.
func WithMFATokens(g token.Generator) MFAOption {
	return func(i *mfaInterceptor) error {
		if err := requireDep("WithMFATokens", "token generator", g); err != nil {
			return err
		}

		i.tokens = g

		return nil
	}
}

// WithMFAResponder replaces the response written when a second factor
// succeeds.
//
// With none supplied, the library writes a JSON document carrying an access
// token for the rotated session and that session's validity, the same shape a
// successful login answers with, so a client handles both alike.
//
// It is called instead of the downstream handler, because the verify endpoint
// is the library's own and the application has no route behind it. The session
// it receives carries the handle rotation produced, which is the only place
// that handle is available: an error it returns leaves the chain as the
// request's refusal, and nothing else will hand the caller a usable
// credential.
func WithMFAResponder(fn MFAResponder) MFAOption {
	return func(i *mfaInterceptor) error {
		if fn == nil {
			return newConfigError("WithMFAResponder was given no function; omit the option to " +
				"keep the default document")
		}

		i.respond = fn

		return nil
	}
}

// WithMFALogInterval writes at most one second-factor throttle record per
// reason per d.
//
// Default: one minute. It governs the records MFA verification refusals write
// and nothing else, so a user being guessed at cannot drown out or silence any
// other part of the chain — the chain's own refusal records keep their own
// window, set by WithRefusalLogInterval.
//
// An interval of zero or less writes every record, which is the documented way
// to ask for the full stream: it is a choice about volume, not a fault.
func WithMFALogInterval(d time.Duration) MFAOption {
	return func(i *mfaInterceptor) error {
		i.throttleOpts = append(i.throttleOpts, mfa.WithThrottleLogInterval(d))

		return nil
	}
}
