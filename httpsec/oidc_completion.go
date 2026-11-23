package httpsec

import (
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
)

// errProviderSignInUnfinished answers a completion the policy owes nothing, until
// D7's steps 5 to 9 complete it.
var errProviderSignInUnfinished = errors.New("httpsec: server-side completion is not finished")

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
// handoff redemption followed by a resume, step for step, and returns every
// refusal for the chain's error handling to answer.
//
//  1. The destination was recognised by the callback (parkedHandle).
//  2. The parked request is checked (precheckParked), before the user is loaded or
//     anything is written, so a handle that is unknown, expired or bound to another
//     browser costs the source one charge and changes nothing else.
//  3. The user is loaded through OIDCDeps.Users (loadCompleting): the session is
//     built from the stored details, never from the broker's principal, as a
//     redemption builds it.
//  4. The post-authentication policy decides, on the stored details, the stored
//     password-change time and the assurance the verified ID token asserted, by the
//     check a redemption runs (oidcRedemptionCheck). A denial is its reason, with
//     nothing stored. A step owed falls back to the handoff to the login page,
//     carrying the handle (D8), with nothing stored either.
//
// The rest — the session, the resume and the answer — is finishProviderSignIn's.
func (i *oidcInterceptor) completeProviderSignIn(ex *Exchange, provider string, res oidc.CallbackResult, handle string) error {
	if err := i.precheckParked(ex, handle); err != nil {
		return err
	}

	if res.Principal == nil || res.Principal.ID == "" {
		// The relying party never answers so; a broker that did names no one to
		// load, and is refused as a redemption refuses an unknown user.
		return oidc.ErrInvalidHandoff
	}

	details, err := i.loadCompleting(ex, provider, res.Principal.ID)
	if err != nil {
		return err
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
		return err
	}

	// The check ran and allowed or challenged; anything else is refused here, as
	// the redemption's guards refuse it, so nothing below acts on a decision it
	// was not made for.
	if err := guardRedemption(out, signIn.principal, signIn.passwordChangedAt); err != nil {
		return err
	}

	if err := guardFederatedAssurance(out, res.Provider, res.Issuer, res.AMR, res.ACR); err != nil {
		return err
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
func (i *oidcInterceptor) finishProviderSignIn(_ *Exchange, _ string, _ oidc.CallbackResult, _ providerSignIn) error {
	return errProviderSignInUnfinished
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

// loadCompleting is D7's step 3: it loads user through OIDCDeps.Users and refuses
// an unknown, missing, disabled or mismatched one with oidc.ErrInvalidHandoff, as
// a handoff redemption refuses each (F21). The loader is the consumer's, so its
// error is walked once, bounded, before it is read (porterr.SanitizeTo); a
// failure is a dependency failure behind fixed text (diag.Wrap), recorded by its
// reason and Go type, never its text.
func (i *oidcInterceptor) loadCompleting(ex *Exchange, provider string, user identity.UserID) (*identity.Details, error) {
	ctx := ex.Context()

	details, err := i.users.LoadByUserID(ctx, user)
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
// to the browser's provider flow cookie and stand at its login stage. Provider's
// PendingRequest judges the first three alike, and its unknown-handle answer is
// charged to the source as the resume endpoint charges it, and answered
// ErrOIDCUnknownHandle. A source already over the resume endpoint's limit is
// refused with ErrOIDCThrottled before the handle is looked up, as there. A request
// past its login stage is no login to complete: it is refused as unknown too, and
// not charged, since its handle is genuine. A store that cannot answer is a
// dependency failure, returned as the provider words it.
//
// It reads and writes nothing else, so every refusal here leaves no session, no
// login event and the user's held recoveries as they were (F20).
func (i *oidcInterceptor) precheckParked(ex *Exchange, handle string) error {
	op := i.provider

	src, ok := op.resume.throttle.admit(ex, op)
	if !ok {
		return ErrOIDCThrottled
	}

	flow, _ := ex.Request.Cookie(oidcCookieName(op.provider, OIDCFlowCookie))

	view, err := op.provider.PendingRequest(ex.Context(), handle, flow)
	if err != nil {
		if errors.Is(err, oidcprovider.ErrUnknownHandle) {
			op.resume.throttle.charge(ex.Context(), src)
		}

		return oidcResumeRefusal(err)
	}

	if view.Stage != oidcprovider.StageLogin {
		return ErrOIDCUnknownHandle
	}

	return nil
}
