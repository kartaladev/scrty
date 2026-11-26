package httpsec

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// optionProviderCompletion names server-side completion in configuration errors.
const optionProviderCompletion = "WithOIDCProviderCompletion"

// checkCompletion refuses the wirings under which server-side completion could
// not keep its guarantees (F28). It runs from check, so every option of the chain
// has been applied, and settles the provider and its parsed login page for the
// callback.
//
// Completion replays a handoff redemption and a resume, so it needs both: the
// chain's OpenID Provider, the default handoff manager (the owed-step fallback
// conveys through it, and a consumer redeemer's contract is the redemption
// endpoint's, not this one's), and a user loader. It writes the session the
// provider's resume reads, so the login's session manager must be the provider's.
// The provider's cookies are host-only, so a callback on another origin would
// never carry them. A login page carrying its own query could never be recognised,
// because a qualifying destination carries the handle alone.
func (i *oidcInterceptor) checkCompletion(c *config, option string) error {
	op := c.oidcProvider
	if op == nil {
		return newConfigError("%s %s needs EnableOIDCProvider on the same chain: it completes "+
			"a sign-in the provider's login page started", option, optionProviderCompletion)
	}

	if i.callbackSuccess != nil {
		return newConfigError("%s %s cannot be combined with WithOIDCCallbackSuccess, which "+
			"replaces the conveyance completion falls back to", option, optionProviderCompletion)
	}

	if i.handoffRedeemerSet {
		return newConfigError("%s %s cannot be combined with WithOIDCHandoffRedeemer: "+
			"completion runs the library's own redemption checks", option, optionProviderCompletion)
	}

	if i.handoffs == nil {
		return newConfigError("%s %s needs OIDCDeps.Handoff: an owed step falls back to the "+
			"handoff to the login page", option, optionProviderCompletion)
	}

	if nilcheck.IsNil(i.users) {
		return newConfigError("%s %s needs OIDCDeps.Users to load the user it signs in",
			option, optionProviderCompletion)
	}

	login := i.sessions
	if login == nil {
		login = c.sessions
	}

	if provider := bearerSessions(c); provider == nil || login != provider {
		return newConfigError("%s %s needs OIDC login to store sessions in the manager the "+
			"provider's resume reads, the built-in bearer's", option, optionProviderCompletion)
	}

	issuer := op.provider.Issuer()

	for _, name := range i.manager.Providers() {
		raw, ok := i.manager.RedirectURL(name)
		if !ok || !origin.Same(raw, issuer) {
			return newConfigError("%s %s needs provider %q's redirect URL on the issuer's origin, "+
				"where the provider's cookies are sent", option, optionProviderCompletion, name)
		}
	}

	loginURL, err := url.Parse(op.provider.LoginURL())
	if err != nil || loginURL.RawQuery != "" || loginURL.ForceQuery || loginURL.Fragment != "" {
		return newConfigError("%s %s needs the provider's login URL without a query of its own, "+
			"so a destination carrying only the handle can be recognised", option, optionProviderCompletion)
	}

	i.provider = op
	i.loginURL = loginURL

	return nil
}

// parkedHandle reports the handle next carries when next is loginURL carrying one
// parked request's handle and nothing else (D7, step 1).
//
// next is the destination the client asked for when the login started, untrusted.
// It qualifies only when it is absolute and matches loginURL in scheme and host (as
// origin.Same compares them), in port as written, and in raw path byte for byte (an empty path being "/"), so
// a trailing slash, another case or a percent-encoded spelling of the path does not
// qualify. Its query must be exactly one req parameter, spelled so, with one
// non-empty value; it may carry no user information and no fragment. Anything else
// is not a parked request's destination, and keeps the ordinary conveyance (F27).
func parkedHandle(next string, loginURL *url.URL) (string, bool) {
	if loginURL == nil || next == "" || strings.Contains(next, "#") {
		return "", false
	}

	u, err := url.Parse(next)
	if err != nil || u.User != nil || u.Opaque != "" || !origin.Same(next, loginURL.String()) ||
		u.Port() != loginURL.Port() || rootedPath(u) != rootedPath(loginURL) {
		return "", false
	}

	// The parameter name is read as written, so an encoded spelling of it, and any
	// separator a parser might split on, keeps the destination from qualifying.
	raw, found := strings.CutPrefix(u.RawQuery, oidcprovider.HandleParam+"=")
	if !found || raw == "" || strings.ContainsAny(raw, "&;=") {
		return "", false
	}

	handle, err := url.QueryUnescape(raw)
	if err != nil || handle == "" {
		return "", false
	}

	return handle, true
}

// rootedPath is u's raw path, with an empty one read as "/": an http(s) URL with no
// path and one with "/" name the same resource (RFC 3986, section 6.2.3).
func rootedPath(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}

	return "/"
}

// completeProviderSignIn completes, on the server, a federated login whose
// destination was the provider's login page carrying handle (D7). It replays a
// handoff redemption followed by a resume, step for step. A refusal D4 maps
// returns to the login page (refuseCompletion); any other is returned for the
// chain's error handling to answer.
//
//  1. The destination was recognised by the callback (parkedHandle).
//  2. A callback not made over TLS, while the provider does not allow plain HTTP,
//     is refused as ErrOIDCUnknownHandle, as the resume endpoint refuses it, before
//     the throttle or any lookup. Then the parked request is checked
//     (precheckParked), before the user is loaded or anything is written, so a
//     handle that is unknown, expired past its grace window or bound to another
//     browser costs the source one charge and changes nothing else; one expired
//     within the window is answered at the client (D7).
//  3. The user is loaded through OIDCDeps.Users (loadCompleting): the session is
//     built from the stored details, never from the broker's principal, as a
//     redemption builds it.
//  4. The post-authentication policy decides, on the stored details, the stored
//     password-change time and the assurance the verified ID token asserted, by the
//     check a redemption runs (oidcRedemptionCheck). A denial stores nothing and
//     returns to the login page with access_denied, or with WithOIDCFailToClient
//     answers the client. A step owed falls back to the handoff to the login
//     page, carrying the handle (D8), with nothing stored either.
//
// The rest — the session, the resume and the answer — is finishProviderSignIn's.
func (i *oidcInterceptor) completeProviderSignIn(ex *Exchange, provider string, res oidc.CallbackResult, handle string) error {
	// The resume endpoint's transport guard, before the throttle or any lookup
	// (F57): completion resumes the parked request as that endpoint would, so a
	// callback the endpoint would refuse over plain HTTP is refused here too.
	if !ex.Request.Secure() && !i.provider.plainHTTPAllowed() {
		return ErrOIDCUnknownHandle
	}

	parked := i.precheckParked(ex, provider, handle)
	if parked.err != nil {
		return parked.err
	}

	if parked.answeredAt != "" {
		// Expired within its grace window: answered at the client (D7).
		i.answerParkedAtClient(ex, parkedAtCallback, provider, oidcprovider.CodeAccessDenied, parked.answeredAt)

		return nil
	}

	if res.Principal == nil || res.Principal.ID == "" {
		// The relying party never answers so; a broker that did names no one to
		// load, and is refused as a redemption refuses an unknown user.
		return i.refuseCompletion(ex, provider, handle, completionStageUser, oidc.ErrInvalidHandoff)
	}

	details, err := i.loadCompleting(ex, provider, i.users, res.Principal.ID)
	if err != nil {
		return i.refuseCompletion(ex, provider, handle, completionStageUser, err)
	}

	signIn := providerSignIn{
		handle:            handle,
		principal:         *identity.PrincipalFromDetailsAt(details, i.now()),
		passwordChangedAt: details.PasswordChangedAt,
	}

	check, out := oidcRedemptionCheck(i.engine, i.enforced, i.challengeMethods, i.now, i.log)
	signIn.out = out

	if err := check(ex.Context(), oidc.RedeemCandidate{
		Principal:         signIn.principal,
		PasswordChangedAt: signIn.passwordChangedAt,
		Provider:          res.Provider,
		Issuer:            res.Issuer,
		AMR:               slices.Clone(res.AMR),
		ACR:               res.ACR,
	}); err != nil {
		return i.refuseCompletion(ex, provider, handle, completionStageRefusal, err)
	}

	// The check ran and allowed or challenged; anything else is refused here, as
	// the redemption's guards refuse it, so nothing below acts on a decision it
	// was not made for.
	if err := guardRedemption(out, signIn.principal, signIn.passwordChangedAt); err != nil {
		// Refusal stage. Unreachable through the chain: the check that just
		// succeeded recorded an allow or a challenge for this very principal.
		return i.refuseCompletion(ex, provider, handle, completionStageRefusal, err)
	}

	if err := guardFederatedAssurance(out, res.Provider, res.Issuer, res.AMR, res.ACR); err != nil {
		// Refusal stage. Unreachable through the chain: the check was handed
		// these very values, so the evidence it decided on cannot differ.
		return i.refuseCompletion(ex, provider, handle, completionStageRefusal, err)
	}

	if out.decision.Outcome == policy.Challenge {
		// D8: the page finishes the step through the existing redemption, then
		// resumes the handle as it does today. res.Next is the login page carrying
		// the handle alone, as parkedHandle has just shown.
		return i.conveyHandoff(ex, provider, res, res.Next)
	}

	return i.finishProviderSignIn(ex, provider, res, signIn)
}

// providerSignIn is a completion the policy owes nothing: the parked request's
// handle, the principal built from the stored details, the stored
// password-change time, and the decision the post-authentication check recorded,
// which the login tail acts on rather than deciding again
// (newRedemptionLogin).
type providerSignIn struct {
	handle            string
	principal         identity.Principal
	passwordChangedAt time.Time
	out               *policyOutcome
}

// finishProviderSignIn is D7's steps 5 to 9: the session, the per-request
// judgement, the resume, its confirmation and the answer.
//
//  5. The session is built by the login tail on the decision step 4 recorded,
//     with the provider session and the asserted assurance in its one creating
//     write, after the user's held recoveries are cancelled
//     (commitFederatedLogin). Its credential is dropped: nothing a browser could
//     present leaves the server. A store that cannot write it is a dependency
//     failure, with nothing stored and nothing resumed (F26).
//  6. The stored session is judged under the chain's per-request policy, then by
//     the checks the resume endpoint applies to a sign-in (resumableSignIn). A
//     refusal ends the session and is returned. A challenge, a step the policy
//     requires before this request, ends the session and falls back to the
//     handoff to the login page carrying the handle, as an owed step does (D8).
//  7. The parked request is resumed with the sign-in the chain's assurance
//     mapping states. An error refuses. What the answer carries is read from
//     its outcome (answerFor), never from its query, which a client's
//     registered redirect URI may fill: the client's error response, such as
//     login_required for an id_token_hint naming another subject, or the device
//     code-entry page, is redirected to and carries no code; an outcome
//     completion does not know is refused, failing closed.
//  8. The sign-in is confirmed as the resume endpoint confirms one
//     (confirmSignIn), so an end that landed while the resume wrote is caught.
//  9. The browser is sent, by 303, where the resume says, carrying the
//     provider's browser-session cookie.
//
// From step 6 on, anything short of the 303 to a code or to the consent page
// ends the session step 5 stored before it answers (endCompleted), so no
// refused completion leaves a live sign-in behind (F23, F24), and takes it off
// the exchange and its context, so nothing answering the refusal reads it
// (F46). A per-request refusal whose session was ended returns to the login page
// (refuseCompletion); every other refusal is returned for the chain's error
// handling to answer, and sends no redirect.
func (i *oidcInterceptor) finishProviderSignIn(ex *Exchange, provider string, res oidc.CallbackResult, signIn providerSignIn) error {
	op := i.provider
	ctx := ex.Context()

	// The credential is dropped (step 5), so nothing delivers it either: on a
	// cookie chain no session cookie is set here, and the browser leaves with
	// the provider's own cookie alone.
	tail := i.loginTail(session.KeyBinding{})
	tail.deliver = credentialDelivery{}

	login := newRedemptionLogin(ex, tail, signIn.out)

	in := postAuthenticationInput(&signIn.principal, factor.OIDC, "", signIn.passwordChangedAt, i.now())
	in.FederatedAssurance = signIn.out.federated

	if err := login.issue(ctx, in); err != nil {
		return i.refuseCompletion(ex, provider, signIn.handle, completionStageSession, err)
	}

	issued, err := login.redeemed()
	if err != nil {
		// Session stage. Unreachable through the chain: issue has just succeeded
		// for this very login, which is what redeemed reports.
		return i.refuseCompletion(ex, provider, signIn.handle, completionStageSession, err)
	}

	// The credential is not kept: the browser is given the provider's own
	// cookie, and the session is reached through the sign-in it resumes.
	if _, err := commitFederatedLogin(ex, login, issued, federatedSession{
		provider: res.Provider, issuer: res.Issuer, sessionID: res.SessionID, idToken: res.IDToken,
	}, signIn.principal.ID); err != nil {
		return i.refuseCompletion(ex, provider, signIn.handle, completionStageSession, err)
	}

	s := ex.Session

	if ph := ex.perRequest; ph != nil {
		if err := ex.evaluatePerRequest(ph, s, &signIn.principal, signIn.passwordChangedAt, ph.now()); err != nil {
			// Returned to the login page only once the session is gone; one
			// that could not be ended answers the refusal unchanged (F25).
			if !i.endCompletedSession(ex, provider, s, false) {
				return err
			}

			return i.refuseCompletion(ex, provider, signIn.handle, completionStageRefusal, err)
		}
	}

	resumed, err := resumableSignIn(ex, s, op.resume.assurance)
	if ch := (*ChallengeError)(nil); errors.As(err, &ch) {
		// A step this request requires is answered on the login page, as an
		// owed step is (D8): the script path meets the same challenge at the
		// resume route. The session is ended first, so the fallback leaves
		// none behind, and the page's redemption stores its own (F23).
		if err := i.endCompleted(ex, provider, s, false, nil); err != nil {
			return err
		}

		return i.conveyHandoff(ex, provider, res, res.Next)
	}

	if err != nil {
		return i.endCompleted(ex, provider, s, false, err)
	}

	flow, _ := ex.Request.Cookie(oidcCookieName(op.provider, OIDCFlowCookie))
	browser, _ := ex.Request.Cookie(oidcCookieName(op.provider, OIDCBrowserSessionCookie))

	// The handle was found live and bound to this browser moments ago, so an
	// unknown handle here is a race with another resume of it, not a guess, and
	// is not charged to the source.
	out, err := op.provider.Resume(ctx, oidcprovider.ResumeInput{
		Handle:               signIn.handle,
		FlowSecret:           flow,
		SignIn:               resumed,
		BrowserSessionSecret: browser,
		IdleTimeout:          op.sessions.IdleTimeout(),
	})
	if err != nil {
		return i.endCompleted(ex, provider, s, false, oidcResumeRefusal(err))
	}

	switch answerFor(out.Outcome) {
	case answerKept:
	case answerEnded:
		// The request was answered without this sign-in: the sign-in it was
		// resumed with is of no further use, and the browser is sent where the
		// resume endpoint would send it.
		if err := i.endCompleted(ex, provider, s, true, nil); err != nil {
			return err
		}

		redirectCompleted(ex, out.RedirectTo)

		return nil
	default:
		// The resume named no outcome completion knows, so what RedirectTo
		// carries is unknown: refused, failing closed.
		i.logCallbackRecord(ex, slog.LevelError, completionReasonOutcomeUnknown, provider)

		return i.endCompleted(ex, provider, s, true, ErrOIDCReauthenticate)
	}

	if err := op.confirmSignIn(ctx, resumed); err != nil {
		return i.endCompleted(ex, provider, s, true, err)
	}

	if out.BrowserSessionSecret != "" {
		setOIDCCookie(ex.Writer, op.provider, OIDCBrowserSessionCookie, out.BrowserSessionSecret)
	}

	redirectCompleted(ex, out.RedirectTo)

	return nil
}

// redirectCompleted answers a completed sign-in with a 303 to target, where the
// resume sends the browser. The target may carry a code, so no cache keeps the
// answer and no referrer is sent from where it lands.
func redirectCompleted(ex *Exchange, target string) {
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")
	ex.Writer.SetHeader("Location", target)
	ex.Writer.WriteHeader(http.StatusSeeOther)
}

// completedAnswer is how completion answers a resume's outcome.
type completedAnswer uint8

const (
	// answerRefused ends the session and refuses, with no redirect: an outcome
	// completion does not know.
	answerRefused completedAnswer = iota
	// answerKept keeps the session and redirects: a code or the consent page.
	answerKept
	// answerEnded ends the session and redirects: the request was answered with
	// no code, by the client's error response or the device code-entry page.
	answerEnded
)

// answerFor maps outcome to its answer. It reads the outcome the resume named,
// never RedirectTo's query, which a client's registered redirect URI may fill with
// an error parameter of its own. The zero outcome, and any it does not know, are
// refused.
func answerFor(outcome oidcprovider.ResumeOutcome) completedAnswer {
	switch outcome {
	case oidcprovider.ResumeOutcomeCode, oidcprovider.ResumeOutcomeConsent:
		return answerKept
	case oidcprovider.ResumeOutcomeClientError, oidcprovider.ResumeOutcomeDeviceEntry:
		return answerEnded
	default:
		return answerRefused
	}
}

// completionReasonOutcomeUnknown keys the record of a resume that named no outcome
// completion knows.
const completionReasonOutcomeUnknown = "completion-outcome-unknown"

// completionReasonNotEnded keys the record of a completed session that could not
// be ended.
const completionReasonNotEnded = "completion-session-not-ended"

// endCompleted ends s, the session a completion stored, because the completion
// will not answer with it, and returns refusal unchanged (nil when the answer is
// the client's error response). resumed says the provider's resume has written
// for s's sign-in, a code or a browser session, which the provider ends first, as
// logout does, so a failure there cannot leave them behind a session already
// gone.
//
// The end is detached from the request, so a client hanging up cannot leave the
// session live, and bounded, so a store that hangs cannot hold the request. A
// failure to end it is recorded once at ERROR, by its reason and Go type, never
// its text, and does not replace refusal (F25): no credential for s ever left the
// server, so it is unusable until it expires either way.
//
// s is taken off the exchange and its context whether or not the end succeeded
// (F46): the completion has abandoned it, so whatever answers the request, an
// enclosing interceptor or the consumer's error handling, reads no session
// rather than one that is gone or about to be.
func (i *oidcInterceptor) endCompleted(ex *Exchange, provider string, s *session.Session, resumed bool, refusal error) error {
	i.endCompletedSession(ex, provider, s, resumed)

	return refusal
}

// endCompletedSession is endCompleted's end of s, reporting whether it succeeded.
func (i *oidcInterceptor) endCompletedSession(ex *Exchange, provider string, s *session.Session, resumed bool) bool {
	unpublishCompleted(ex, s)

	ctx, cancel := detach.Bounded(ex.Context(), detach.RevocationTimeout)
	defer cancel()

	var failed []error

	if resumed {
		if _, err := i.provider.provider.EndSignIn(ctx, oidcprovider.SignInSelector{Family: s.FamilyID}); err != nil {
			failed = append(failed, err)
		}
	}

	if _, err := i.provider.sessions.RevokeFamily(ctx, s.FamilyID); err != nil {
		failed = append(failed, err)
	}

	err := errors.Join(failed...)
	if err != nil {
		i.logCallbackRecord(ex, slog.LevelError, completionReasonNotEnded, provider,
			diag.Failure(completionReasonNotEnded, err)...)
	}

	return err == nil
}

// unpublishCompleted takes s, the session a completion stored and is ending, off
// ex and its context, where the login tail published it (preparedLogin.commit).
// A session other than s, which nothing on this path publishes, is left alone.
func unpublishCompleted(ex *Exchange, s *session.Session) {
	if ex.Session == s {
		ex.Session = nil
	}

	if published, ok := SessionFromContext(ex.Context()); ok && published == s {
		ex.SetContext(withSession(ex.Context(), nil))
	}
}

// The reasons completion's own refusal records are keyed by.
const (
	completionReasonUserUnknown     = "completion-user-unknown"
	completionReasonUserInactive    = "completion-user-inactive"
	completionReasonUserMismatch    = "completion-user-mismatch"
	completionReasonUserUnavailable = "completion-user-unavailable"
)

// msgCompletionUserUnavailable is the fixed text a loader's failure is returned
// behind.
const msgCompletionUserUnavailable = "httpsec: the user a federated sign-in completes for could not be loaded"

// loadCompleting is D7's step 3: it loads user through users (OIDCDeps.Users
// for completion, the cookie session's loader for a cookie chain's callback)
// and refuses
// an unknown, missing, disabled or mismatched one with oidc.ErrInvalidHandoff, as
// a handoff redemption refuses each (F21). The loader is the consumer's, so its
// error is walked once, bounded, before it is read (porterr.SanitizeTo); a
// failure is a dependency failure behind fixed text (diag.Wrap), recorded by its
// reason and Go type, never its text.
func (i *oidcInterceptor) loadCompleting(
	ex *Exchange, provider string, users identity.UserLoader, user identity.UserID,
) (*identity.Details, error) {
	ctx := ex.Context()

	details, err := users.LoadByUserID(ctx, user)
	err = porterr.SanitizeTo(ctx, i.log, err, porterr.ErrUnwalkable)

	switch {
	case errors.Is(err, identity.ErrUserNotFound), err == nil && details == nil:
		i.logCallbackRefusal(ex, slog.LevelDebug, completionReasonUserUnknown, provider)

		return nil, oidc.ErrInvalidHandoff
	case err != nil:
		i.logCallbackRecord(ex, slog.LevelError, completionReasonUserUnavailable, provider,
			diag.Failure(completionReasonUserUnavailable, err)...)

		return nil, diag.Wrap(err, msgCompletionUserUnavailable)
	case !details.Active:
		i.logCallbackRefusal(ex, slog.LevelDebug, completionReasonUserInactive, provider)

		return nil, oidc.ErrInvalidHandoff
	case details.ID != user:
		i.logCallbackRefusal(ex, slog.LevelError, completionReasonUserMismatch, provider)

		return nil, oidc.ErrInvalidHandoff
	}

	return details, nil
}

// precheckParked is D7's step 2: the parked request must exist, be live, be bound
// to the browser's provider flow cookie and stand at its login stage. A source
// already over the resume endpoint's limit is refused with ErrOIDCThrottled
// before the handle is looked up, as there. Provider's PendingRequest judges the
// rest alike; its unknown-handle answer is first offered to EndPending, so a
// request expired within its grace window, bound to this browser, is answered
// access_denied at the client and reported in answeredAt, uncharged (D7).
// Otherwise it is charged to the source as the resume endpoint charges it, and
// refused ErrOIDCUnknownHandle. A request past its login stage is refused as
// unknown too, uncharged, since its handle is genuine. A store that cannot
// answer is a failure, returned as the provider words it, uncharged.
//
// It writes nothing else, so every refusal here leaves no session, no login
// event and the user's held recoveries as they were (F20).
func (i *oidcInterceptor) precheckParked(ex *Exchange, provider, handle string) parkedCheck {
	op := i.provider
	ctx := ex.Context()

	src, ok := op.resume.throttle.admit(ex, op)
	if !ok {
		return parkedCheck{err: ErrOIDCThrottled}
	}

	flow, _ := ex.Request.Cookie(oidcCookieName(op.provider, OIDCFlowCookie))

	view, err := op.provider.PendingRequest(ctx, handle, flow)
	if errors.Is(err, oidcprovider.ErrUnknownHandle) {
		// PendingRequest never shows an expired request; EndPending answers one
		// within the grace window, and refuses anything else as unknown.
		res, err := op.provider.EndPending(ctx, oidcprovider.EndPendingInput{
			Handle: handle, FlowSecret: flow, Code: oidcprovider.CodeAccessDenied,
		})

		switch {
		case errors.Is(err, oidcprovider.ErrUnknownHandle):
			op.resume.throttle.charge(ctx, src)

			return parkedCheck{err: ErrOIDCUnknownHandle}
		case err != nil:
			return parkedCheck{err: err, failure: true}
		}

		target, ok := answeredAtClient(res)
		if !ok {
			// Ended, with no answer completion knows: refused, failing closed.
			i.logCallbackRecord(ex, slog.LevelError, completionReasonOutcomeUnknown, provider)

			return parkedCheck{err: ErrOIDCReauthenticate}
		}

		return parkedCheck{answeredAt: target}
	}

	if err != nil {
		return parkedCheck{err: oidcResumeRefusal(err), failure: true}
	}

	if view.Stage != oidcprovider.StageLogin {
		return parkedCheck{err: ErrOIDCUnknownHandle}
	}

	return parkedCheck{device: view.Device != nil}
}

// refuseCompletion answers err, completion's refusal at stage of the login for
// the parked request handle: one D4 maps returns to the login page
// (returnParked), and anything else is returned.
func (i *oidcInterceptor) refuseCompletion(ex *Exchange, provider, handle string, stage completionStage, err error) error {
	if code, ok := completionFailureCode(ex.Context(), stage, err); ok {
		return i.returnParked(ex, parkedAtCallback, provider, handle, code, err)
	}

	return err
}
