package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -destination=enroller_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/mfa Enroller
//go:generate mockgen -destination=sender_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/notify Sender

// enrolmentInterceptor is the enrolment path: the gate that confines an
// enrolment-only session, and the endpoints that session may reach.
type enrolmentInterceptor struct {
	users  identity.UserLoader
	sender notify.Sender

	// methods, sessions, logoutPath and log are handed over at assembly,
	// never configured here. methods are the enrollable methods, keyed by the
	// path segment that names each.
	methods    map[string]mfa.Enroller
	sessions   *session.Manager
	logoutPath string
	log        *slog.Logger

	beginPrefix   string
	confirmPrefix string
	emailPrefix   string

	// names are the methods WithEnrolmentMethods named, nil when it was not
	// given.
	names []string

	// passkeys reports, from assembly on, that the passkey MFA method is
	// among the enrolling methods, so passkey registration serves the path;
	// passkeyPaths are then the registration endpoints' paths, which the gate
	// exempts. Neither is configured here: EnablePasskeys hands the paths
	// over.
	passkeys     bool
	passkeyPaths []string

	lifetime time.Duration

	// beginLimiter and confirmLimiter are nil until assembly when the
	// consumer supplied none, because the defaults write through the chain's
	// logger.
	beginLimiter   ratelimit.Limiter
	confirmLimiter ratelimit.Limiter

	emailConfirmation bool
	notification      bool
	acceptSync        bool

	contact  mfa.ContactResolver
	label    mfa.LabelResolver
	messages EnrolmentMessages

	now func() time.Time

	// logInterval is the window the path's own records are sampled over, and
	// sampler the sampler built from it at assembly, when the chain's logger
	// is known.
	logInterval time.Duration
	sampler     *logsample.Sampler
}

// check is the half of the construction checks that needs nothing but this
// option's own configuration: the user loader, the sender the defaults need,
// and that sender's delivery.
func (i *enrolmentInterceptor) check(option string) error {
	if err := requireDep(option, "user loader (EnrolmentDeps.Users)", i.users); err != nil {
		return err
	}

	if err := i.checkPrefixes(option); err != nil {
		return err
	}

	if !i.emailConfirmation && !i.notification {
		// Nothing is sent, so no sender is needed and none is judged.
		return nil
	}

	if nilcheck.IsNil(i.sender) {
		return newConfigError("%s needs a Sender (EnrolmentDeps.Sender) while email "+
			"confirmation or notification is on, which both are by default; turn each off "+
			"explicitly with WithoutEmailConfirmation and WithoutEnrolmentNotification rather "+
			"than leaving the sender out", option)
	}

	if i.acceptSync {
		return nil
	}

	if nb, ok := i.sender.(notify.NonBlocking); !ok || !nb.NonBlocking() {
		return newConfigError("%s was given a sender that waits for delivery, which puts the "+
			"mail server into the enrolment endpoints' response time; wrap it in "+
			"notify.NewQueuedSender, or accept it with WithEnrolmentSynchronousDelivery", option)
	}

	return nil
}

// checkPrefixes refuses two enrolment endpoints whose prefixes overlap: every
// POST under a prefix is that endpoint's, so whichever matched first would
// swallow the other's requests. The logout path and the MFA endpoints are
// compared at assembly, because they may be configured after this option.
func (i *enrolmentInterceptor) checkPrefixes(option string) error {
	prefixes := i.prefixes()

	for a := range prefixes {
		for b := a + 1; b < len(prefixes); b++ {
			if overlap(prefixes[a], prefixes[b]) {
				return newConfigError("%s was given the overlapping prefixes %q and %q for two "+
					"enrolment endpoints, so whichever matched first would swallow the other",
					option, prefixes[a], prefixes[b])
			}
		}
	}

	return nil
}

// overlap reports whether one of two prefixes is the other or lies below it.
func overlap(a, b string) bool {
	return underPrefix(a, b) || underPrefix(b, a)
}

// prefixes is every enrolment endpoint's prefix. The emailed-code endpoint's
// is among them only while email confirmation is on: without it that endpoint
// does not exist.
func (i *enrolmentInterceptor) prefixes() []string {
	if !i.emailConfirmation {
		return []string{i.beginPrefix, i.confirmPrefix}
	}

	return []string{i.beginPrefix, i.confirmPrefix, i.emailPrefix}
}

// wire takes the settings the chain resolved, once every option has been
// applied, and builds the path's own log sampler, whose reporter writes through
// that logger.
func (i *enrolmentInterceptor) wire(c *Chain) {
	i.log = c.logger
	i.sampler = logsample.New(i.logInterval, logsample.WithReporter(i.reportSuppressed))
}

// logSampled writes one of the path's records, unless the sampler is holding
// key's window open, in which case it is counted and reported later.
//
// Every record the path writes goes through here, and carries only fixed
// categories: which endpoint, which limiter, which reason. It is never given a
// code, a secret, a provisioning URI, an address or the user reference, so it
// cannot write one. The key is the category too, so one record stands for every
// user refused the same way in the window, and naming one user on it would
// read as though that user accounted for all of them.
func (i *enrolmentInterceptor) logSampled(ctx context.Context, level slog.Level, key, msg string, attrs ...slog.Attr) {
	logSampled(ctx, i.sampler, i.log, level, i.now(), key, msg, attrs...)
}

// flushRefusalLogs reports what the enrolment path's own sampler is holding
// back.
func (i *enrolmentInterceptor) flushRefusalLogs() {
	if i.sampler != nil {
		i.sampler.Flush()
	}
}

// reportSuppressed writes what the sampler held back for key and is about to
// forget. It runs on whichever request or flush evicted the key, and that
// request's context has nothing to do with the counts, so it is written
// without one.
func (i *enrolmentInterceptor) reportSuppressed(key string, suppressed int) {
	i.log.LogAttrs(context.Background(), slog.LevelWarn, msgEnrolmentLogsSuppressed,
		slog.String("key", key), slog.Int("suppressed", suppressed))
}

// msgEnrolmentLogsSuppressed is the record the path's reporter writes.
const msgEnrolmentLogsSuppressed = "httpsec: enrolment logs suppressed"

// wireMFAEnrolment hands the enrolment path what only the assembled
// configuration knows, and refuses a path that could not work.
//
// Each of these is checked here rather than by EnableMFAEnrolment, because
// each depends on an option that may be applied after it: the policy engine,
// EnableMFA, the session manager a built-in brings, and the logout path.
func (c *config) wireMFAEnrolment() error {
	const option = "EnableMFAEnrolment"

	return eachInterceptor(c, func(i *enrolmentInterceptor) error {
		if !c.declares(policy.ChallengeMFAEnrolment) {
			return newConfigError("%s is enabled, but no registered policy can raise "+
				"%s, so no session could ever reach the path: build the MFA requirement "+
				"policy with policy.WithMFAEnrolmentPath and register it through WithPolicyEngine",
				option, policy.ChallengeMFAEnrolment)
		}

		methods, passkeys, err := c.enrollableMethods(option, i.names)
		if err != nil {
			return err
		}

		if passkeys && c.passkeysOf() == nil {
			return newConfigError("%s counts the passkey method among its enrolling methods, "+
				"but passkey registration is not enabled, so the policy would send users to a "+
				"path that cannot enrol it: enable EnablePasskeys, or name the path's methods "+
				"without it (WithEnrolmentMethods)", option)
		}

		if err := i.checkClaims(option, c); err != nil {
			return err
		}

		if c.sessions == nil {
			return newConfigError("%s needs a session manager to confine and upgrade sessions "+
				"in, and none of the built-ins enabled on this chain was wired to one", option)
		}

		if limit := c.sessions.AbsoluteTimeout(); i.lifetime > limit {
			return newConfigError("WithEnrolmentSessionTTL was given %s, longer than the session "+
				"manager's absolute timeout of %s; an enrolment-only session never outlives "+
				"the deadline it already has", i.lifetime, limit)
		}

		beginLimiter, err := c.enrolmentLimiter(i.beginLimiter, namespaceEnrolmentBegin,
			defaultEnrolmentBeginLimit, defaultEnrolmentBeginWindow)
		if err != nil {
			return err
		}

		confirmLimiter, err := c.enrolmentLimiter(i.confirmLimiter, namespaceEnrolmentConfirm,
			defaultEnrolmentConfirmLimit, defaultEnrolmentConfirmWindow)
		if err != nil {
			return err
		}

		i.methods = methods
		i.passkeys = passkeys
		i.sessions = c.sessions
		i.logoutPath = c.logoutPath
		i.beginLimiter, i.confirmLimiter = beginLimiter, confirmLimiter

		return nil
	})
}

// declares reports whether a policy registered on the engine can raise kind.
func (c *config) declares(kind policy.ChallengeKind) bool {
	return c.engine != nil && slices.Contains(c.engine.DeclaredChallenges(), kind)
}

// checkClaims refuses an enrolment prefix that claims a path another endpoint
// of the chain answers: the logout path, which an enrolment-only session must
// always reach, and the MFA verify and begin prefixes, which it must never
// reach. The enrolment endpoints run ahead of both for such a session, so an
// overlap would hand one endpoint's requests to the other.
func (i *enrolmentInterceptor) checkClaims(option string, c *config) error {
	var others []struct{ name, prefix string }
	if m := c.mfaOf(); m != nil {
		others = append(others,
			struct{ name, prefix string }{"EnableMFA's verify prefix", m.verifyPrefix},
			struct{ name, prefix string }{"EnableMFA's begin prefix", m.beginPrefix})
	}

	for _, p := range i.prefixes() {
		if c.logoutPath != "" && underPrefix(c.logoutPath, p) {
			return newConfigError("%s's prefix %q claims the logout path %q, so an "+
				"enrolment-only session could not log out", option, p, c.logoutPath)
		}

		for _, o := range others {
			if overlap(p, o.prefix) {
				return newConfigError("%s's prefix %q overlaps %s %q, so whichever matched "+
					"first would swallow the other's requests", option, p, o.name, o.prefix)
			}
		}
	}

	return nil
}

// enrollableMethods are the MFA methods the enrolment path enrols, keyed by
// name: every method EnableMFA was given that can enrol through the path, or,
// when the consumer named some (WithEnrolmentMethods), exactly those.
//
// They are drawn from EnableMFA's methods and no others because the verify
// endpoint completes the upgrade by verifying one: a factor enrolled on a
// method it does not verify could never be verified, and the session would
// stay confined until it expired.
//
// The passkey method is not among them, since the path's own endpoints cannot
// enrol it, but it is counted: passkeys reports that it is one of the path's
// enrolling methods, served by passkey registration (see servedByPasskeys).
// It is counted by default, and when named.
func (c *config) enrollableMethods(option string, names []string) (map[string]mfa.Enroller, bool, error) {
	m := c.mfaOf()
	if m == nil {
		return nil, false, newConfigError("%s needs EnableMFA: the factors it enrols are the ones the "+
			"verify endpoint verifies", option)
	}

	out := make(map[string]mfa.Enroller, len(m.methods))
	passkeys := false

	if names == nil {
		var reasons []string

		for _, method := range m.methods {
			if servedByPasskeys(method) {
				passkeys = true

				continue
			}

			e, reason := enrollable(method)
			if e == nil {
				reasons = append(reasons, reason)

				continue
			}

			out[method.Name()] = e
		}

		if len(out) == 0 && !passkeys {
			return nil, false, newConfigError("%s needs a method EnableMFA was given that implements "+
				"mfa.Enroller over a store implementing mfa.DeviceProofStore, or the passkey method, "+
				"and none does: %s", option, strings.Join(reasons, "; "))
		}

		return out, passkeys, nil
	}

	named := make(map[string]bool, len(names))

	for _, name := range names {
		if named[name] {
			return nil, false, newConfigError("WithEnrolmentMethods names %q twice", name)
		}

		named[name] = true

		method, ok := m.byName[name]
		if !ok {
			return nil, false, newConfigError("WithEnrolmentMethods names %q, which is not among the "+
				"methods EnableMFA was given", name)
		}

		if servedByPasskeys(method) {
			passkeys = true

			continue
		}

		e, reason := enrollable(method)
		if e == nil {
			return nil, false, newConfigError("WithEnrolmentMethods names %q, which cannot enrol "+
				"through the path: %s", name, reason)
		}

		out[name] = e
	}

	return out, passkeys, nil
}

// enrollable is m as an mfa.Enroller that can serve the path, or nil and why
// it cannot.
func enrollable(m mfa.Method) (mfa.Enroller, string) {
	e, ok := m.(mfa.Enroller)
	if !ok {
		return nil, fmt.Sprintf("%q does not implement mfa.Enroller", m.Name())
	}

	if !e.SupportsEnrolmentPath() {
		return nil, fmt.Sprintf("the store of %q does not implement mfa.DeviceProofStore; it "+
			"still serves out-of-band enrolment", m.Name())
	}

	return e, ""
}

// enrolmentLimiter is l, or else one the chain's factory builds under
// namespace with the documented limit and window (rateLimiterFactory).
func (c *config) enrolmentLimiter(
	l ratelimit.Limiter, namespace string, limit int, window time.Duration,
) (ratelimit.Limiter, error) {
	if l != nil {
		return l, nil
	}

	built, err := c.rateLimiterFactory().NewLimiter(namespace, limit, window)
	if err != nil {
		return nil, newConfigError("EnableMFAEnrolment could not build its limiter for namespace %q: %s",
			namespace, err)
	}

	return built, nil
}

// Intercept is the gate and the endpoints behind it.
//
// They are one interceptor rather than several registrations because the
// endpoints are the gate's own exemptions. Split apart, a consumer or a later
// release could order the gate outside an endpoint and leave an
// enrolment-only session unable to reach the one request that ends its
// confinement.
//
// A request whose session is not enrolment-only passes untouched, the
// enrolment prefixes included: the endpoints serve that state alone, and for any
// other session their paths are routes like any other. A request carrying no
// session passes too; whether it may go on is the authentication
// interceptors' business.
//
// For an enrolment-only session, only POST under an enrolment prefix, the
// chain's logout and, when passkey registration serves the path, POST to the
// passkey registration endpoints pass. Every other request, whatever its method or path, is
// refused before anything behind the gate runs. Logout is exempt because the
// gate sits outside it, and a caller confined here must always be able to end
// the session — on a device that is not theirs, it is the one thing they most
// need to do. There is deliberately no way to exempt anything else: every
// further route would reopen a surface this state exists to close.
//
// A recovery-pending session is served on the same endpoints, on its own
// user, exactly as an enrolment-only session is. Every other request it makes
// passes on untouched: the recovery gate outside this one has already decided
// which requests such a session may make, and refusing here too would only
// restate that decision under the enrolment challenge's name.
func (i *enrolmentInterceptor) Intercept(ex *Exchange, next Next) error {
	s := ex.Session
	if s == nil || (s.MFA != session.MFAEnrolmentPending && s.MFA != session.MFARecoveryPending) {
		return next(ex)
	}

	if served, err := i.endpoint(ex, s); served {
		return err
	}

	if s.MFA == session.MFARecoveryPending || isLogoutPost(i.logoutPath, ex.Request) ||
		i.passkeyRegistration(ex.Request) {
		return next(ex)
	}

	// No token: the caller already holds the credential this session was
	// reached with, and a gate issues nothing.
	return &ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: s}
}

// passkeyRegistration reports whether r is a POST to one of the passkey
// registration endpoints, which an enrolment-only session reaches when passkey
// registration serves the path. The paths are handed over at assembly, and
// only then (wirePasskeys).
func (i *enrolmentInterceptor) passkeyRegistration(r Request) bool {
	return r.Method() == http.MethodPost && slices.Contains(i.passkeyPaths, r.Path())
}

// endpoint serves ex when it is a request to one of the path's endpoints. It
// reports whether it was one, and the endpoint's answer when it was.
func (i *enrolmentInterceptor) endpoint(ex *Exchange, s *session.Session) (bool, error) {
	r := ex.Request

	switch {
	case isPostUnder(r, i.beginPrefix):
		return true, i.serve(ex, s, endpointBegin, i.beginPrefix, i.begin)
	case isPostUnder(r, i.confirmPrefix):
		return true, i.serve(ex, s, endpointConfirm, i.confirmPrefix, i.confirm)
	case i.emailConfirmation && isPostUnder(r, i.emailPrefix):
		return true, i.serve(ex, s, endpointEmail, i.emailPrefix, i.redeemEmailCode)
	}

	return false, nil
}

// serve runs one enrolment endpoint on the method the request's path names
// under prefix, and records its refusal. A path naming no enrollable method —
// an unknown, empty or extra segment, or the bare prefix — is refused with
// ErrUnknownMFAMethod before anything else, so it neither reaches the
// endpoint's limiter nor stores anything. The method is read from the path and
// nowhere else.
func (i *enrolmentInterceptor) serve(
	ex *Exchange,
	s *session.Session,
	endpoint, prefix string,
	run func(*Exchange, *session.Session, mfa.Enroller) error,
) error {
	name, ok := methodSegment(ex.Request.Path(), prefix)
	method, known := i.methods[name]

	if !ok || !known {
		return i.refused(ex.Context(), endpoint, ErrUnknownMFAMethod)
	}

	return i.refused(ex.Context(), endpoint, run(ex, s, method))
}

// The names the path's records give its endpoints.
const (
	endpointBegin   = "begin"
	endpointConfirm = "confirm"
	endpointEmail   = "confirm-email"
)

// refused records err, an endpoint's refusal, and returns it unchanged. A nil
// err is a request the endpoint answered, and nothing is written.
//
// The record names the endpoint and the refusal's fixed reason, sampled per
// endpoint and reason. When err is an *enrolmentFault — always a dependency's
// answer, never the library's own decision — the record also carries
// diag.Failure's error_type, the dependency's Go type and never its text; a
// library refusal with no dependency behind it (a wrong code, an enrolled
// user, the same channel twice) carries neither. A gate refusal is not
// recorded here: it is the challenge the confined session is expected to
// meet, not a request an endpoint turned down.
func (i *enrolmentInterceptor) refused(ctx context.Context, endpoint string, err error) error {
	if err == nil {
		return nil
	}

	reason, level := refusalReason(err)

	attrs := []slog.Attr{slog.String("endpoint", endpoint)}

	// A record names its reason once: diag.Failure writes it for a
	// dependency's failure, and a plain attribute does for the rest.
	var fault *enrolmentFault
	if errors.As(err, &fault) {
		attrs = append(attrs, diag.Failure(reason, fault.err)...)
	} else {
		attrs = append(attrs, slog.String("reason", reason))
	}

	i.logSampled(ctx, level, "refused|"+endpoint+"|"+reason, msgEnrolmentRefused, attrs...)

	return err
}

// msgEnrolmentRefused is written when an enrolment endpoint refuses a request.
const msgEnrolmentRefused = "httpsec: an enrolment request was refused"

// refusalReason is the fixed category err is recorded by, and the level: an
// outage is an error, a user at their limit a warning, and any other refusal —
// a wrong code, an unreadable one — is what users do, and informational.
func refusalReason(err error) (string, slog.Level) {
	var fault *enrolmentFault
	if errors.As(err, &fault) {
		return fault.reason, slog.LevelError
	}

	for _, r := range refusalReasons {
		if errors.Is(err, r.err) {
			return r.reason, r.level
		}
	}

	return reasonUnknown, slog.LevelError
}

// refusalReasons are the library refusals an enrolment endpoint answers with,
// in the order they are matched: the emailed-code refusal wraps the
// invalid-code one, so it comes first.
var refusalReasons = []struct {
	err    error
	reason string
	level  slog.Level
}{
	{mfa.ErrEnrolmentThrottled, "throttled", slog.LevelWarn},
	{mfa.ErrEmailCodeInvalid, "email-code-invalid", slog.LevelInfo},
	{mfa.ErrInvalidCode, "invalid-code", slog.LevelInfo},
	{mfa.ErrSameChannel, "same-channel", slog.LevelInfo},
	{mfa.ErrAlreadyEnrolled, "already-enrolled", slog.LevelInfo},
	{ErrCredentialsMissing, "code-unread", slog.LevelInfo},
	{ErrRequestTooLarge, "too-large", slog.LevelInfo},
	{ErrUnknownMFAMethod, "unknown-method", slog.LevelInfo},
}

// isPostUnder reports whether r is a POST at or under prefix. Only POST: every
// enrolment endpoint changes something, and one a link could trigger is one
// another site could trigger for a caller who never asked. Every POST under
// the prefix is the endpoint's, including one naming no method, so that one is
// refused as unknown rather than challenged by the gate.
func isPostUnder(r Request, prefix string) bool {
	return r.Method() == http.MethodPost && underPrefix(r.Path(), prefix)
}

// begin begins a pending enrolment for the session's user, or begins it
// again, and answers with what the user needs to add it to an authenticator.
//
// The order is deliberate:
//
//  1. The limiter, before anything else, so a user over their budget costs
//     nothing. A limiter that cannot decide refuses.
//  2. The call is recorded — every call, not only a failed one. Each begin
//     generates a secret and can lead to an email, so this count is what
//     bounds both, and it is recorded under a context the caller cannot
//     cancel, since hanging up does not undo a request already made.
//  3. The same-channel refusal, before anything is generated: a factor that
//     would arrive the way the first one did is not a second factor, and a
//     required user enrolled only on it would be refused at the next login.
//  4. The label, from the user's records through the label resolver, never
//     from the request.
//  5. The begin itself, whose store decides the already-enrolled refusal.
//  6. The new generation is recorded on the session and saved before the
//     response, since every later step acts only on the generation this
//     session holds.
func (i *enrolmentInterceptor) begin(ex *Exchange, s *session.Session, method mfa.Enroller) error {
	ctx := ex.Context()
	key := EnrolmentBeginThrottleKey(s.UserID)

	if err := i.throttled(ctx, i.beginLimiter, key); err != nil {
		return err
	}

	i.record(ctx, i.beginLimiter, key, limiterBegin)

	if method.Channel() == s.FirstFactor.Channel() {
		return mfa.ErrSameChannel
	}

	details, err := i.users.LoadByUserID(ctx, s.UserID)
	if err != nil {
		return newEnrolmentFault(reasonUserUnloadable, msgUserUnloadable, err)
	}

	label, err := i.label(ctx, details)
	if err != nil {
		return newEnrolmentFault(reasonLabelUnresolved, msgLabelUnresolved, err)
	}

	provisioning, gen, err := method.BeginEnrolmentGeneration(ctx, s.UserID, label)
	if errors.Is(err, mfa.ErrAlreadyEnrolled) {
		// The store decides this refusal, and may word it itself.
		return refusedAs(mfa.ErrAlreadyEnrolled, textMFAAlreadyEnrolled, err)
	}

	if err != nil {
		// The method was handed the label, and its refusal may quote it —
		// TOTP's refusal of a ':' does.
		return newEnrolmentFault(reasonNotBegun, msgNotBegun, err)
	}

	s.EnrolmentGeneration = gen

	if err := i.sessions.Save(ctx, s); err != nil {
		return newEnrolmentFault(reasonSessionUnsaved, msgSessionUnsaved, err)
	}

	return writeEnrolmentDocument(ex, enrolmentBeginDocument{
		Secret: provisioning.Secret,
		URI:    provisioning.URI,
	})
}

// enrolmentBeginDocument is the begin endpoint's answer. Its member names are
// the documented contract of the endpoint.
type enrolmentBeginDocument struct {
	// Secret is the shared secret in base32, for a user typing it in.
	Secret string `json:"secret"`

	// URI is the provisioning URI, which the consumer's client renders as a
	// QR code; the library renders no image.
	URI string `json:"uri"`
}

// writeEnrolmentDocument answers with body as JSON that no cache may keep: the
// document carries a secret.
//
// A failure is an *enrolmentFault like every other: a transport's write error
// names the connection's addresses, and is not the library's text to return.
func writeEnrolmentDocument(ex *Exchange, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return newEnrolmentFault(reasonNotWritten, msgNotWritten, err)
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)

	if _, err := ex.Writer.Write(encoded); err != nil {
		return newEnrolmentFault(reasonNotWritten, msgNotWritten, err)
	}

	return nil
}

// throttled refuses a user at their limit on l, and refuses when l cannot say:
// a limiter that answered "under the limit" whenever its store was down would
// lift the limit exactly when something is wrong. That refusal's text is fixed,
// since a consumer's limiter may quote the bucket key, and with it the user
// reference, back.
func (i *enrolmentInterceptor) throttled(ctx context.Context, l ratelimit.Limiter, key string) error {
	exceeded, err := l.Exceeded(ctx, key)
	if err != nil {
		return newEnrolmentFault(reasonLimiterUnavailable, msgLimiterUndecided, err,
			mfa.ErrEnrolmentThrottled)
	}

	if exceeded {
		return mfa.ErrEnrolmentThrottled
	}

	return nil
}

// record counts one against key on l, under a context the caller cannot
// cancel: a caller who hangs up has still made the attempt. A limiter that
// cannot record is an outage, not a judgement on the request, so it is logged,
// sampled, and the request's outcome is unchanged.
//
// The record names which limiter failed, and a fixed reason, never the
// limiter's own error: a consumer's limiter may quote the bucket key back, and
// the key carries the user reference, which a deployment may have made the
// address.
func (i *enrolmentInterceptor) record(ctx context.Context, l ratelimit.Limiter, key, limiter string) {
	if err := l.RecordFailure(context.WithoutCancel(ctx), key); err != nil {
		i.logSampled(ctx, slog.LevelError, "not-recorded|"+limiter, msgEnrolmentNotRecorded,
			slog.String("limiter", limiter), slog.String("reason", reasonLimiterUnavailable))
	}
}

// The names record logs a limiter by.
const (
	limiterBegin   = "begin"
	limiterConfirm = "confirm"
)

// msgEnrolmentNotRecorded is written when an enrolment limiter cannot record:
// the count it keeps has stopped moving, and only this record says so.
const msgEnrolmentNotRecorded = "httpsec: an enrolment attempt could not be recorded"

// confirm proves the device with a code from the pending secret, on the
// generation this session began.
//
// The order is deliberate:
//
//  1. The limiter, before the code is read, so guessing costs attempts rather
//     than time. A limiter that cannot decide refuses. A code the endpoint
//     cannot read is then refused as missing credentials, and not counted:
//     only a code actually presented can be a wrong one.
//  2. With email confirmation on, the address the code will go to, resolved
//     before the proof is written: a proof whose code could not be addressed
//     would stand with nobody able to complete it.
//  3. The proof, decided by the store's conditional write on this session's
//     generation. A refused code is recorded against the user under a context
//     the caller cannot cancel; any other failure is an outage, not a guess,
//     and is not counted.
//  4. With email confirmation on, the code is queued to the user and nothing
//     more happens: a proven device does not make the enrolment count. A
//     sender that refuses to queue it fails the request, and the code is
//     voided by charging every attempt it has left, so the proof, whose code
//     nobody was meant to have received, can then never complete; the user
//     begins again. A synchronous sender may report a failure after its relay
//     accepted the mail, so a code that did arrive is refused too, as the
//     failed request told the user. The one exception: if the store fails
//     while voiding, the code keeps the attempts it has left, and the failure
//     is logged by the fixed reason "not-voided".
//  5. With it off, the enrolment is completed on the same generation, and the
//     session moves on to verification.
func (i *enrolmentInterceptor) confirm(ex *Exchange, s *session.Session, method mfa.Enroller) error {
	ctx := ex.Context()
	key := EnrolmentConfirmThrottleKey(s.UserID)

	if err := i.throttled(ctx, i.confirmLimiter, key); err != nil {
		return err
	}

	code, err := postedField(ex.Request, "code")
	if err != nil {
		return err
	}

	var to string

	if i.emailConfirmation {
		addr, err := i.contactOf(ctx, s.UserID)
		if err != nil {
			return err
		}

		to = addr
	}

	gen := s.EnrolmentGeneration

	emailed, err := method.ProveDevice(ctx, s.UserID, gen, code, i.emailConfirmation, enrolmentEmailCodeTTL)
	if err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			i.record(ctx, i.confirmLimiter, key, limiterConfirm)

			return refusedAs(mfa.ErrInvalidCode, textMFAInvalidCode, err)
		}

		return newEnrolmentFault(reasonNotProven, msgNotProven, err)
	}

	if i.emailConfirmation {
		subject, body := i.messages.Code(emailed, i.now().Add(enrolmentEmailCodeTTL))

		if err := i.sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body}); err != nil {
			i.voidEmailCode(ctx, method, s.UserID, gen)

			return newEnrolmentFault(reasonSendRefused, msgSendRefused, err)
		}

		ex.Writer.WriteHeader(http.StatusNoContent)

		return nil
	}

	if err := method.CompleteEnrolment(ctx, s.UserID, gen); err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			return refusedAs(mfa.ErrInvalidCode, textMFAInvalidCode, err)
		}

		return newEnrolmentFault(reasonNotCompleted, msgNotCompleted, err)
	}

	return i.completed(ex, s, method)
}

// voidEmailCode voids the emailed code of generation gen after the sender
// refused to queue it, so the proof that issued it can never complete and the
// user begins again. It runs under a context the caller cannot cancel: a
// client that hangs up must not leave the code redeemable.
//
// A voiding that fails does not replace the send failure the request answers
// with; it is logged, sampled, through [diag.Failure] — the fixed reason and
// the error's Go type, never the failure's own text, which a store may word
// with the user reference.
func (i *enrolmentInterceptor) voidEmailCode(ctx context.Context, method mfa.Enroller, user identity.UserID, gen id.ID) {
	if err := mfa.VoidEmailCode(context.WithoutCancel(ctx), method, user, gen); err != nil {
		i.logSampled(ctx, slog.LevelError, reasonNotVoided, msgEmailCodeNotVoided,
			diag.Failure(reasonNotVoided, err)...)
	}
}

// msgEmailCodeNotVoided is written when an emailed code the sender refused to
// queue could not be voided.
const msgEmailCodeNotVoided = "httpsec: an undelivered enrolment code could not be voided"

// completed moves a session whose enrolment has just completed on to
// verification, notifies the user, and answers with no body.
//
// The session becomes MFA pending, not satisfied: completing an enrolment is
// not a second factor, and the verify endpoint, with its own throttle,
// same-channel check and rotation, is the one place a challenge is resolved.
// The enrolment-origin marker and the lowered deadline stay until that
// verification restores them, and so does a recovery-pending session's
// recovery time, which is kept for good.
//
// The user is notified whether or not the session can then be saved. The
// binding is already written, and the owner is told of every binding: a save
// that fails does not undo it, so it must not silence it either. If the save
// fails, the session is left as it was in memory too, and the request fails;
// the enrolment stands, so a new login is challenged for the factor rather
// than for enrolment.
func (i *enrolmentInterceptor) completed(ex *Exchange, s *session.Session, method mfa.Enroller) error {
	ctx := ex.Context()

	was := s.MFA
	s.MFA = session.MFAPending

	saveErr := i.sessions.Save(ctx, s)

	i.notifyBound(ctx, s.UserID, method.Name())

	if saveErr != nil {
		s.MFA = was

		return newEnrolmentFault(reasonSessionUnsaved, msgSessionUnsaved, saveErr)
	}

	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}

// notifyBound tells the user a second factor was bound to their account, when
// notification is on. The enrolment is complete by then and is not undone: a
// notification that cannot be addressed or queued is logged, sampled, and the
// request succeeds. It is sent under a context the caller cannot cancel, since the
// binding it reports has already happened.
//
// The record names a fixed reason and never the failure's own text: a
// synchronous sender's refusal quotes the recipient back ("RCPT TO: 550
// <ana@example.com>"), and a loader's or resolver's may quote the username,
// which by default is the address.
func (i *enrolmentInterceptor) notifyBound(ctx context.Context, user identity.UserID, method string) {
	if !i.notification {
		return
	}

	ctx = context.WithoutCancel(ctx)

	reason := ""

	to, err := i.contactOf(ctx, user)
	if err != nil {
		// A failure is always logged, under the fault's own reason when it
		// names one.
		reason = reasonUnknown

		var fault *enrolmentFault
		if errors.As(err, &fault) {
			reason = fault.reason
		}
	} else {
		subject, body := i.messages.Bound(method, i.now())
		if err := i.sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body}); err != nil {
			reason = reasonSendRefused
		}
	}

	if reason != "" {
		i.logSampled(ctx, slog.LevelError, "not-notified|"+reason, msgEnrolmentNotNotified,
			slog.String("reason", reason))
	}
}

// msgEnrolmentNotNotified is written when the user could not be told of a
// completed enrolment.
const msgEnrolmentNotNotified = "httpsec: the user could not be notified of a completed enrolment"

// contactOf is the address the user's enrolment messages go to, from their
// loaded details through the contact resolver. A failure is an
// *enrolmentFault, whose text is fixed.
func (i *enrolmentInterceptor) contactOf(ctx context.Context, user identity.UserID) (string, error) {
	details, err := i.users.LoadByUserID(ctx, user)
	if err != nil {
		return "", newEnrolmentFault(reasonUserUnloadable, msgUserUnloadable, err)
	}

	to, err := i.contact(ctx, details)
	if err != nil {
		return "", newEnrolmentFault(reasonContactUnresolved, msgContactUnresolved, err)
	}

	return to, nil
}

// enrolmentFault is an enrolment refusal whose cause's text may carry the
// user's reference, username or address: a user loader's, a label or contact
// resolver's, the method's refusal of a label, a store's or a session store's
// failure, a store's own wording of a library refusal, or a sender's. Every
// error the enrolment path returns is either one of these or a bare library
// sentinel.
//
// Its text is fixed, so a consumer's error handler that logs a refusal by its
// text logs no address. The cause, and the library sentinel the refusal is
// answered as, are still reachable through errors.Is and errors.As, so its
// status and any mapping the consumer keeps are unchanged; a handler that
// unwraps it and prints the cause prints what the consumer's own dependency
// wrote.
//
// It is a thin wrapper around [diag.Fault], built by [diag.Wrap]: this
// path's own reason, logged by [refusalReason] and notifyBound, stays local
// to httpsec rather than joining diag's shared vocabulary.
type enrolmentFault struct {
	// reason is the fixed category the enrolment path logs the fault by.
	reason string

	// msg is the fixed text the fault always reads as. It is kept here, not
	// only in err, because diag.Wrap hands back a bare sentinel cause as it
	// is, and this path's text must not change to the sentinel's when a
	// dependency happens to fail with one.
	msg string

	// err is the *diag.Fault (or a bare library sentinel) that carries the
	// sentinel and the cause.
	err error
}

// newEnrolmentFault is reason's *enrolmentFault over diag.Wrap(cause, msg,
// kinds...): msg is the fixed text a consumer's error handler sees, and
// kinds, when given, are the library sentinels the refusal is answered as.
func newEnrolmentFault(reason, msg string, cause error, kinds ...error) *enrolmentFault {
	return &enrolmentFault{reason: reason, msg: msg, err: diag.Wrap(cause, msg, kinds...)}
}

func (f *enrolmentFault) Error() string { return f.msg }

func (f *enrolmentFault) Unwrap() error { return f.err }

// refusedAs is the refusal kind, with text matching kind's own words (given as
// a constant, never kind.Error(), so this path's fixed text is never a
// dependency's error rendered at runtime): err itself when it is the bare
// sentinel, and otherwise a fault that keeps err reachable, since a store
// that decides a refusal may word it with the user reference or the address.
func refusedAs(kind error, text string, err error) error {
	return diag.Wrap(err, text, kind)
}

// The reasons an enrolment fault is logged by, and the fixed text it is
// returned with.
const (
	reasonUserUnloadable     = "user-unloadable"
	reasonLabelUnresolved    = "label-unresolved"
	reasonNotBegun           = "not-begun"
	reasonContactUnresolved  = "contact-unresolved"
	reasonSendRefused        = "send-refused"
	reasonLimiterUnavailable = "limiter-unavailable"
	reasonSessionUnsaved     = "session-unsaved"
	reasonNotProven          = "not-proven"
	reasonNotCompleted       = "not-completed"
	reasonNotWritten         = "not-written"
	reasonNotVoided          = "not-voided"
	reasonUnknown            = "unknown"

	msgUserUnloadable    = "httpsec: the enrolling user could not be loaded"
	msgLabelUnresolved   = "httpsec: the enrolling user's account label could not be resolved"
	msgNotBegun          = "httpsec: the method could not begin the enrolment"
	msgContactUnresolved = "httpsec: the enrolling user's contact address could not be resolved"
	msgSendRefused       = "httpsec: the enrolment message could not be sent"
	msgLimiterUndecided  = "httpsec: the enrolment limiter could not decide, so the attempt is refused"
	msgSessionUnsaved    = "httpsec: the enrolling session could not be saved"
	msgNotProven         = "httpsec: the method could not record the device proof"
	msgNotCompleted      = "httpsec: the method could not complete the enrolment"
	msgNotWritten        = "httpsec: the enrolment response could not be written"

	// The words of the sentinels refusedAs is called with, kept as constants
	// so the fixed text a caller sees never comes from calling Error() on a
	// dependency's error at runtime (forbidigo forbids that, save for the
	// stated exceptions elsewhere): each string here must read exactly as
	// its sentinel's own Error() does.
	textMFAAlreadyEnrolled  = "mfa: this user already has a confirmed enrolment"
	textMFAInvalidCode      = "mfa: invalid code"
	textMFAEmailCodeInvalid = "mfa: invalid code: the emailed code is wrong or expired"
	textCredentialsMissing  = "httpsec: missing or unreadable login credentials"
)

// redeemEmailCode completes the enrolment with the code emailed when this
// session's device was proven.
//
// The order is deliberate:
//
//  1. The limiter, before the code is read, as confirm's. A code the endpoint
//     cannot read is refused as missing credentials, and not counted.
//  2. The redemption, which the method decides on this session's generation:
//     it charges an attempt on the enrolment before comparing, compares in
//     constant time, and completes last. A code emailed for another generation
//     — another session's, or this session's before a later begin — is
//     refused, as is a late, wrong, malformed or voided one; none completes
//     anything.
//  3. A refused code is also recorded against the user, under a context the
//     caller cannot cancel. Any other failure is an outage, not a guess, and
//     is not counted.
//  4. The session moves on to verification, and the user is notified.
func (i *enrolmentInterceptor) redeemEmailCode(ex *Exchange, s *session.Session, method mfa.Enroller) error {
	ctx := ex.Context()
	key := EnrolmentConfirmThrottleKey(s.UserID)

	if err := i.throttled(ctx, i.confirmLimiter, key); err != nil {
		return err
	}

	code, err := postedField(ex.Request, "code")
	if err != nil {
		return err
	}

	if err := method.RedeemEmailCode(ctx, s.UserID, s.EnrolmentGeneration, code); err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			i.record(ctx, i.confirmLimiter, key, limiterConfirm)

			return refusedAs(mfa.ErrEmailCodeInvalid, textMFAEmailCodeInvalid, err)
		}

		return newEnrolmentFault(reasonNotCompleted, msgNotCompleted, err)
	}

	return i.completed(ex, s, method)
}

// EnrolmentMessages renders the two plain-text messages the enrolment path
// sends. The library sets each message's recipient itself, from the contact
// resolver, so a renderer decides what a message says and never where it
// goes.
//
// The default, used when WithEnrolmentMessages is not given, is a short English
// message for each. A consumer replaces it to translate, to brand, or to add
// their own support contact.
type EnrolmentMessages interface {
	// Code renders the message that carries code, the one-time code emailed
	// when a device is proven, which is accepted until until. It must carry
	// the code, or the enrolment cannot complete.
	Code(code string, until time.Time) (subject, body string)

	// Bound renders the notification that method was bound to the account at
	// at. It is given no code, secret or provisioning URI, and must not need
	// one: the message tells the account's owner something happened, and a
	// credential in it would be one more place to steal it from.
	Bound(method string, at time.Time) (subject, body string)
}

// plainEnrolmentMessages is the default renderer: short plain-text messages
// that say what happened, when, and what to do if it was not the recipient.
type plainEnrolmentMessages struct{}

// enrolmentTimeLayout is how the default messages write an instant: in UTC,
// with the zone named, so a reader in any zone can tell when it was.
const enrolmentTimeLayout = "2 January 2006 15:04 MST"

// Code carries the code and when it stops being accepted.
func (plainEnrolmentMessages) Code(code string, until time.Time) (string, string) {
	return "Your verification code",
		"Your code to finish setting up two-step verification is " + code + ".\n\n" +
			"It can be used until " + until.UTC().Format(enrolmentTimeLayout) + ".\n\n" +
			"If you did not ask for it, someone may know your password: change it, " +
			"and contact your administrator.\n"
}

// Bound names the method and the time, and carries no code, secret or
// provisioning URI.
func (plainEnrolmentMessages) Bound(method string, at time.Time) (string, string) {
	return "Two-step verification was set up on your account",
		"Two-step verification (" + method + ") was set up on your account on " +
			at.UTC().Format(enrolmentTimeLayout) + ".\n\n" +
			"If this was not you, contact your administrator at once.\n"
}

// EnrolmentBeginThrottleKey is the bucket key the begin limiter counts user's
// begins under.
//
// It is exported because a consumer who supplies their own limiter, shared
// with other flows, needs to know which bucket these begins land in — to read
// it, to clear it after an administrative unlock, or to keep their own keys
// from colliding with it. The user reference travels through unparsed.
func EnrolmentBeginThrottleKey(user identity.UserID) string {
	return "mfa-enrol-begin:" + string(user)
}

// EnrolmentConfirmThrottleKey is the bucket key the confirmation limiter
// counts user's failed confirmations under, for the same reasons
// EnrolmentBeginThrottleKey is exported.
func EnrolmentConfirmThrottleKey(user identity.UserID) string {
	return "mfa-enrol-confirm:" + string(user)
}
