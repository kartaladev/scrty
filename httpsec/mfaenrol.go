package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/identity"
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

	// method, sessions, logoutPath and log are handed over at assembly,
	// never configured here.
	method     mfa.Enroller
	sessions   *session.Manager
	logoutPath string
	log        *slog.Logger

	beginPath   string
	confirmPath string
	emailPath   string

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

	if err := i.checkPaths(option); err != nil {
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

// checkPaths refuses two enrolment endpoints on one path: whichever matched
// first would swallow the other. The logout path is compared at assembly,
// because it may be configured after this option.
func (i *enrolmentInterceptor) checkPaths(option string) error {
	paths := i.paths()

	for a := range paths {
		for b := a + 1; b < len(paths); b++ {
			if paths[a] == paths[b] {
				return newConfigError("%s was given one path, %q, for two enrolment endpoints, "+
					"so whichever matched first would swallow the other", option, paths[a])
			}
		}
	}

	return nil
}

// paths is every enrolment endpoint's path. The emailed-code endpoint is
// among them only while email confirmation is on: without it that endpoint
// does not exist.
func (i *enrolmentInterceptor) paths() []string {
	if !i.emailConfirmation {
		return []string{i.beginPath, i.confirmPath}
	}

	return []string{i.beginPath, i.confirmPath, i.emailPath}
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

		method, err := c.enrolmentMethod(option)
		if err != nil {
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

		if c.logoutPath != "" && slices.Contains(i.paths(), c.logoutPath) {
			return newConfigError("%s was given the logout path, %q, for an enrolment endpoint, "+
				"so whichever matched first would swallow the other", option, c.logoutPath)
		}

		beginLimiter, err := c.enrolmentLimiter(i.beginLimiter,
			defaultEnrolmentBeginLimit, defaultEnrolmentBeginWindow)
		if err != nil {
			return err
		}

		confirmLimiter, err := c.enrolmentLimiter(i.confirmLimiter,
			defaultEnrolmentConfirmLimit, defaultEnrolmentConfirmWindow)
		if err != nil {
			return err
		}

		i.method = method
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

// enrolmentMethod is the MFA method the enrolment path enrols: the one
// EnableMFA was given, which must be able to enrol through the path.
//
// It is that method and no other because the verify endpoint completes the
// upgrade by verifying it: a factor enrolled on any other method could never
// be verified, and the session would stay confined until it expired.
func (c *config) enrolmentMethod(option string) (mfa.Enroller, error) {
	var method mfa.Method

	_ = eachInterceptor(c, func(i *mfaInterceptor) error {
		method = i.method

		return nil
	})

	if method == nil {
		return nil, newConfigError("%s needs EnableMFA: the factor it enrols is the one the "+
			"verify endpoint verifies", option)
	}

	enroller, ok := method.(mfa.Enroller)
	if !ok {
		return nil, newConfigError("%s needs the method EnableMFA was given to implement "+
			"mfa.Enroller, and %q does not", option, method.Name())
	}

	if !enroller.SupportsEnrolmentPath() {
		return nil, newConfigError("%s needs the store of the method EnableMFA was given to "+
			"implement mfa.DeviceProofStore, and the store of %q does not; it still serves "+
			"out-of-band enrolment", option, method.Name())
	}

	return enroller, nil
}

// enrolmentLimiter is l, or the documented in-memory default of limit per
// window when the consumer supplied none. The default is built here because it
// writes its per-replica warning through the chain's logger.
func (c *config) enrolmentLimiter(l ratelimit.Limiter, limit int, window time.Duration) (ratelimit.Limiter, error) {
	if l != nil {
		return l, nil
	}

	m, err := ratelimit.NewMemoryLimiter(limit, window, ratelimit.WithMemoryLimiterLogger(c.logger))
	if err != nil {
		return nil, newConfigError("the default enrolment limiter could not be built: %s", err)
	}

	return m, nil
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
// enrolment paths included: the endpoints serve that state alone, and for any
// other session their paths are routes like any other. A request carrying no
// session passes too; whether it may go on is the authentication
// interceptors' business.
//
// For an enrolment-only session, only POST on an enrolment path and the
// chain's logout pass. Every other request, whatever its method or path, is
// refused before anything behind the gate runs. Logout is exempt because the
// gate sits outside it, and a caller confined here must always be able to end
// the session — on a device that is not theirs, it is the one thing they most
// need to do. There is deliberately no way to exempt anything else: every
// further route would reopen a surface this state exists to close.
func (i *enrolmentInterceptor) Intercept(ex *Exchange, next Next) error {
	s := ex.Session
	if s == nil || s.MFA != session.MFAEnrolmentPending {
		return next(ex)
	}

	r := ex.Request

	switch {
	case isPost(r, i.beginPath):
		return i.refused(ex.Context(), endpointBegin, i.begin(ex, s))
	case isPost(r, i.confirmPath):
		return i.refused(ex.Context(), endpointConfirm, i.confirm(ex, s))
	case i.emailConfirmation && isPost(r, i.emailPath):
		return i.refused(ex.Context(), endpointEmail, i.redeemEmailCode(ex, s))
	case isLogoutPost(i.logoutPath, r):
		return next(ex)
	}

	// No token: the caller already holds the credential this session was
	// reached with, and a gate issues nothing.
	return &ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: s}
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
// The record names the endpoint and the refusal's fixed reason and nothing
// else, sampled per endpoint and reason. A gate refusal is not recorded here:
// it is the challenge the confined session is expected to meet, not a request
// an endpoint turned down.
func (i *enrolmentInterceptor) refused(ctx context.Context, endpoint string, err error) error {
	if err == nil {
		return nil
	}

	reason, level := refusalReason(err)

	i.logSampled(ctx, level, "refused|"+endpoint+"|"+reason, msgEnrolmentRefused,
		slog.String("endpoint", endpoint), slog.String("reason", reason))

	return err
}

// msgEnrolmentRefused is written when an enrolment endpoint refuses a request.
const msgEnrolmentRefused = "httpsec: an enrolment request was refused"

// refusalReason is the fixed category err is recorded by, and the level: an
// outage is an error, a user at their limit a warning, and any other refusal —
// a wrong code, an unreadable one — is what users do, and informational.
func refusalReason(err error) (string, slog.Level) {
	var fault *enrolmentFault
	if errors.As(err, &fault) && fault.reason != reasonRefused {
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
}

// isPost reports whether r is a POST on exactly path. Only POST: every
// enrolment endpoint changes something, and one a link could trigger is one
// another site could trigger for a caller who never asked.
func isPost(r Request, path string) bool {
	return r.Method() == http.MethodPost && r.Path() == path
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
func (i *enrolmentInterceptor) begin(ex *Exchange, s *session.Session) error {
	ctx := ex.Context()
	key := EnrolmentBeginThrottleKey(s.UserID)

	if err := i.throttled(ctx, i.beginLimiter, key); err != nil {
		return err
	}

	i.record(ctx, i.beginLimiter, key, limiterBegin)

	if i.method.Channel() == s.FirstFactor.Channel() {
		return mfa.ErrSameChannel
	}

	details, err := i.users.LoadByUserID(ctx, s.UserID)
	if err != nil {
		return &enrolmentFault{reason: reasonUserUnloadable, msg: msgUserUnloadable, cause: err}
	}

	label, err := i.label(ctx, details)
	if err != nil {
		return &enrolmentFault{reason: reasonLabelUnresolved, msg: msgLabelUnresolved, cause: err}
	}

	provisioning, gen, err := i.method.BeginEnrolmentGeneration(ctx, s.UserID, label)
	if errors.Is(err, mfa.ErrAlreadyEnrolled) {
		// The store decides this refusal, and may word it itself.
		return refusedAs(mfa.ErrAlreadyEnrolled, err)
	}

	if err != nil {
		// The method was handed the label, and its refusal may quote it —
		// TOTP's refusal of a ':' does.
		return &enrolmentFault{reason: reasonNotBegun, msg: msgNotBegun, cause: err}
	}

	s.EnrolmentGeneration = gen

	if err := i.sessions.Save(ctx, s); err != nil {
		return &enrolmentFault{reason: reasonSessionUnsaved, msg: msgSessionUnsaved, cause: err}
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
		return &enrolmentFault{reason: reasonNotWritten, msg: msgNotWritten, cause: err}
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)

	if _, err := ex.Writer.Write(encoded); err != nil {
		return &enrolmentFault{reason: reasonNotWritten, msg: msgNotWritten, cause: err}
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
		return &enrolmentFault{
			reason: reasonLimiterUnavailable, msg: msgLimiterUndecided,
			kind: mfa.ErrEnrolmentThrottled, cause: err,
		}
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
func (i *enrolmentInterceptor) confirm(ex *Exchange, s *session.Session) error {
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

	emailed, err := i.method.ProveDevice(ctx, s.UserID, gen, code, i.emailConfirmation, enrolmentEmailCodeTTL)
	if err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			i.record(ctx, i.confirmLimiter, key, limiterConfirm)

			return refusedAs(mfa.ErrInvalidCode, err)
		}

		return &enrolmentFault{reason: reasonNotProven, msg: msgNotProven, cause: err}
	}

	if i.emailConfirmation {
		subject, body := i.messages.Code(emailed, i.now().Add(enrolmentEmailCodeTTL))

		if err := i.sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body}); err != nil {
			i.voidEmailCode(ctx, s.UserID, gen)

			return &enrolmentFault{reason: reasonSendRefused, msg: msgSendRefused, cause: err}
		}

		ex.Writer.WriteHeader(http.StatusNoContent)

		return nil
	}

	if err := i.method.CompleteEnrolment(ctx, s.UserID, gen); err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			return refusedAs(mfa.ErrInvalidCode, err)
		}

		return &enrolmentFault{reason: reasonNotCompleted, msg: msgNotCompleted, cause: err}
	}

	return i.completed(ex, s)
}

// voidEmailCode voids the emailed code of generation gen after the sender
// refused to queue it, so the proof that issued it can never complete and the
// user begins again. It runs under a context the caller cannot cancel: a
// client that hangs up must not leave the code redeemable.
//
// A voiding that fails does not replace the send failure the request answers
// with; it is logged, sampled, by a fixed reason and never by the failure's own
// text, which a store may word with the user reference.
func (i *enrolmentInterceptor) voidEmailCode(ctx context.Context, user identity.UserID, gen id.ID) {
	if err := mfa.VoidEmailCode(context.WithoutCancel(ctx), i.method, user, gen); err != nil {
		i.logSampled(ctx, slog.LevelError, reasonNotVoided, msgEmailCodeNotVoided,
			slog.String("reason", reasonNotVoided))
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
// verification restores them.
//
// The user is notified whether or not the session can then be saved. The
// binding is already written, and the owner is told of every binding: a save
// that fails does not undo it, so it must not silence it either. If the save
// fails, the session is left as it was in memory too, and the request fails;
// the enrolment stands, so a new login is challenged for the factor rather
// than for enrolment.
func (i *enrolmentInterceptor) completed(ex *Exchange, s *session.Session) error {
	ctx := ex.Context()

	s.MFA = session.MFAPending

	saveErr := i.sessions.Save(ctx, s)

	i.notifyBound(ctx, s.UserID)

	if saveErr != nil {
		s.MFA = session.MFAEnrolmentPending

		return &enrolmentFault{reason: reasonSessionUnsaved, msg: msgSessionUnsaved, cause: saveErr}
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
func (i *enrolmentInterceptor) notifyBound(ctx context.Context, user identity.UserID) {
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
		subject, body := i.messages.Bound(i.method.Name(), i.now())
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
		return "", &enrolmentFault{reason: reasonUserUnloadable, msg: msgUserUnloadable, cause: err}
	}

	to, err := i.contact(ctx, details)
	if err != nil {
		return "", &enrolmentFault{reason: reasonContactUnresolved, msg: msgContactUnresolved, cause: err}
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
type enrolmentFault struct {
	// reason is the fixed category the enrolment path logs the fault by.
	reason string
	msg    string

	// kind is the library sentinel the refusal is, or nil.
	kind  error
	cause error
}

func (f *enrolmentFault) Error() string { return f.msg }

func (f *enrolmentFault) Unwrap() []error {
	if f.kind == nil {
		return []error{f.cause}
	}

	return []error{f.kind, f.cause}
}

// refusedAs is the refusal kind, which err is or wraps, with kind's own text:
// err itself when it is the bare sentinel, and otherwise a fault that keeps err
// reachable, since a store that decides a refusal may word it with the user
// reference or the address.
func refusedAs(kind, err error) error {
	if err == kind { //nolint:errorlint // the bare sentinel needs no wrapper
		return kind
	}

	return &enrolmentFault{reason: reasonRefused, msg: kind.Error(), kind: kind, cause: err}
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
	reasonRefused            = "refused"
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
)

// enrolmentBodyLimit is how many request body bytes an enrolment endpoint
// reads. A code is a few bytes; nothing an endpoint reads comes near it.
const enrolmentBodyLimit int64 = 4 << 10

// postedField reads name from the POST body, and only from it.
//
// Request.FormValue carries net/http's semantics, which merge the URL query
// into the form; a code in a URL has already reached access logs, proxy logs
// and the Referer the next page sends. So the query is not consulted, and a
// body is read as a form only when it declares
// "application/x-www-form-urlencoded".
//
// A value the endpoint cannot read — a body that is not such a form, multipart
// included, one that does not parse, or one without the field or with it empty
// — is ErrCredentialsMissing, never an empty value: a code nobody could read
// was not presented, so it must not be judged, or charged, as a wrong one. A
// body over the limit is ErrRequestTooLarge.
func postedField(r Request, name string) (string, error) {
	body, err := r.Body(enrolmentBodyLimit)
	if errors.Is(err, ErrRequestTooLarge) {
		return "", ErrRequestTooLarge
	}

	if err != nil {
		// The transport's failure, whose text is not the library's.
		return "", refusedAs(ErrCredentialsMissing, err)
	}

	if !declaresForm(r.Header("Content-Type")) {
		return "", ErrCredentialsMissing
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		// A body that parses only in part yields nothing: a field read from
		// the half that parsed is not what the client sent.
		return "", ErrCredentialsMissing
	}

	value := values.Get(name)
	if value == "" {
		return "", ErrCredentialsMissing
	}

	return value, nil
}

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
func (i *enrolmentInterceptor) redeemEmailCode(ex *Exchange, s *session.Session) error {
	ctx := ex.Context()
	key := EnrolmentConfirmThrottleKey(s.UserID)

	if err := i.throttled(ctx, i.confirmLimiter, key); err != nil {
		return err
	}

	code, err := postedField(ex.Request, "code")
	if err != nil {
		return err
	}

	if err := i.method.RedeemEmailCode(ctx, s.UserID, s.EnrolmentGeneration, code); err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			i.record(ctx, i.confirmLimiter, key, limiterConfirm)

			return refusedAs(mfa.ErrEmailCodeInvalid, err)
		}

		return &enrolmentFault{reason: reasonNotCompleted, msg: msgNotCompleted, cause: err}
	}

	return i.completed(ex, s)
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
