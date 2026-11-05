package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"

	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// paramPostLogoutRedirectURI is where a relying party asks the browser be sent after a logout.
const paramPostLogoutRedirectURI = "post_logout_redirect_uri"

// endSessionSingleParams are the parameters an end-session request acts on, which it may give
// only once, because neither of two could be chosen. logout_hint and ui_locales are accepted and
// not acted on, so how often they are given changes nothing.
var endSessionSingleParams = []string{paramIDTokenHint, paramClientID, paramPostLogoutRedirectURI, paramState}

// EndSessionInput is one request to the end-session endpoint. It holds the browser's secrets and
// an ID token hint, so it prints and logs redacted; read its fields to use it.
type EndSessionInput struct {
	// Params are the request's parameters: a GET's query or a POST's form.
	Params url.Values
	// FlowSecret and BrowserSessionSecret are what the browser's cookies hold, and empty for
	// a cookie not sent.
	FlowSecret, BrowserSessionSecret string
}

// Format writes the redacted form under every verb.
func (EndSessionInput) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (EndSessionInput) LogValue() slog.Value { return slog.StringValue(redacted) }

// EndSessionResult is what an end-session request is answered with. It can hold the flow cookie's
// secret and a location carrying a request handle, so it prints and logs redacted; read its fields
// to use it.
type EndSessionResult struct {
	// Location is where the browser goes, by 303.
	Location string
	// FlowSecret is the flow cookie's value when the request parked, and empty when it did not.
	FlowSecret string
	// Ended selects the sign-in the request is ending by its family, and is nil when it ends none. Its
	// grants have ended. The caller still owes the rest, in this order: its first-party sessions, which
	// the provider does not hold, then EndSignIn(Ended) for its browser session.
	Ended *SignInSelector
	// User is the ended sign-in's user, and empty when Ended is nil.
	User identity.UserID
}

// Format writes the redacted form under every verb.
func (EndSessionResult) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (EndSessionResult) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogoutResult is what a logout page's answer is answered with.
type LogoutResult struct {
	// RedirectTo is where the page sends the browser.
	RedirectTo string
	// Ended selects the sign-in the answer is ending by its family, and is nil when it ends none. Its
	// grants have ended. The caller still owes the rest, in this order: its first-party sessions, which
	// the provider does not hold, then EndSignIn(Ended) for its browser session, then SpendLogout.
	Ended *SignInSelector
	// User is the ended sign-in's user, and empty when Ended is nil.
	User identity.UserID
}

// endSessionRequest is what a request's parameters say once judged. Everything in it has
// been checked: an unverified hint or an unregistered URI never reaches it.
type endSessionRequest struct {
	// subject is a valid hint's subject, and empty with no valid hint.
	subject string
	// client is the client a valid hint identifies.
	client string
	// family is the sign-in a valid hint names, and id.Nil when it names none.
	family id.ID
	// target is the registered post-logout URI a valid hint asked for, and state its state.
	target, state string
}

// EndSession answers a request to the end-session endpoint (OpenID Connect RP-Initiated Logout 1.0
// section 2), reading its parameters strictly, in this order:
//
//  1. A request whose parameters cannot be read, or whose id_token_hint fails its checks under a
//     key the provider still publishes, or whose hint's audience is not client_id, is refused with
//     ErrInvalidEndSession. It ends nothing and is never redirected (section 4). A hint is accepted
//     once expired, and one signed by a key no longer published counts as no hint.
//  2. A valid hint whose sid names the sign-in of the browser's session ends that sign-in, as a
//     logout does, without asking. WithLogoutConfirmation asks here too, and so does a provider
//     built with WithoutBrowserSessions, which has no session to compare the hint with.
//  3. Anything else ends nothing. The request is parked under a handle bound to the flow cookie, and
//     the browser goes to the logout page with HandleParam, whose answer is ConfirmLogout. That the
//     browser holds no session, or that no sign-in is live, is no error (section 4).
//
// The browser returns to post_logout_redirect_uri, with state when given, only when a valid hint
// names a client that registered exactly that URI. client_id alone confirms nothing, as section 3
// asks, so every other request ends at the logged-out page. Deps.LogoutURL and Deps.LoggedOutURL
// are the consumer's to choose. Nothing widens the rule on the URI, because it is what stops an open
// redirect.
//
// What it ends without asking is the sign-in's grants, and no more: Ended says what the caller still
// owes. An end goes grants, then first-party sessions, then browser session, because the browser
// session is what lets the browser ask again. A caller off the chain deletes the sign-in's first-party
// sessions and finishes with EndSignIn(Ended), which deletes the browser session, and clears the cookie
// only once that has succeeded.
//
// A failing store, registry or key source matches ErrDependency, and one read before anything ends
// leaves it all as it was. A failure of the grants' write leaves the browser session and the first-party
// sessions, so asking again from this browser finishes the end, and tells no one twice. While a logout
// is failing that browser session stays usable, so an authorization request from the browser can still
// be answered from it: a failed logout has not logged anyone out, and its answer says so. Nothing falls
// back on the hint or on a first-party session to finish, as that would let a token's holder end a
// sign-in from another browser, without the question section 2 requires.
func (p *Provider) EndSession(ctx context.Context, in EndSessionInput) (*EndSessionResult, error) {
	req, err := p.readEndSession(ctx, in.Params)
	if err != nil {
		return nil, err
	}

	if !p.cfg.logoutConfirmation && req.family != id.Nil {
		signIn, err := p.browserSignIn(ctx, in.BrowserSessionSecret)
		if err != nil {
			return nil, err
		}
		if signIn != nil && signIn.Family == req.family {
			ended, err := p.endFamily(ctx, req.family)
			if err != nil {
				return nil, err
			}

			return &EndSessionResult{Location: p.afterLogout(req.target, req.state), Ended: ended, User: signIn.User}, nil
		}
	}

	return p.parkLogout(ctx, req, in.FlowSecret)
}

// readEndSession judges a request's parameters. It stores nothing, and what it returns holds
// only what has been checked, so a state with no URI to carry it to is not kept.
func (p *Provider) readEndSession(ctx context.Context, params url.Values) (endSessionRequest, error) {
	for _, name := range endSessionSingleParams {
		if len(params[name]) > 1 {
			return endSessionRequest{}, ErrInvalidEndSession
		}
	}

	state := params.Get(paramState)
	raw := params.Get(paramIDTokenHint)
	if len(state) > p.cfg.bounds.State || !storable(state) || len(raw) > p.cfg.bounds.IDTokenHint {
		return endSessionRequest{}, ErrInvalidEndSession
	}
	if raw == "" {
		return endSessionRequest{}, nil
	}

	tok, verdict, err := p.judgeHintToken(ctx, raw)
	switch {
	case err != nil:
		return endSessionRequest{}, err
	case verdict == hintRefused:
		return endSessionRequest{}, ErrInvalidEndSession
	case verdict == hintUnjudged:
		return endSessionRequest{}, nil
	}

	client, ok := hintClient(tok, params.Get(paramClientID))
	if !ok {
		return endSessionRequest{}, ErrInvalidEndSession
	}

	subject, _ := tok.Subject()
	req := endSessionRequest{subject: subject, client: client, family: hintFamily(tok)}

	asked := params.Get(paramPostLogoutRedirectURI)
	registered, err := p.registeredPostLogout(ctx, client, asked)
	if err != nil {
		return endSessionRequest{}, err
	}
	if registered {
		req.target, req.state = asked, state
	}

	return req, nil
}

// hintClient is the client a hint was issued to, and false when its audience does not name
// exactly one client, or names another than the client_id given. The provider's own ID tokens
// have one audience, so nothing it issued is refused for having several.
func hintClient(tok jwt.Token, given string) (string, bool) {
	audience, _ := tok.Audience()
	if len(audience) != 1 || given != "" && audience[0] != given {
		return "", false
	}

	return audience[0], true
}

// hintFamily is the sign-in a hint names, and id.Nil when it names none. The provider states sid
// in every ID token it issues, so a token with none cannot be matched with a session, and is
// left to ask.
func hintFamily(tok jwt.Token) id.ID {
	sid, err := jwt.Get[string](tok, claimSID)
	if err != nil {
		return id.Nil
	}
	family, err := id.Parse(sid)
	if err != nil {
		return id.Nil
	}

	return family
}

// registeredPostLogout reports whether clientID registered exactly uri. It is compared whole and
// by equality, and never by the rule authorization answers redirect URIs with, which forgives a
// loopback port, because section 3 says "exactly". A client no longer registered has registered
// nothing.
func (p *Provider) registeredPostLogout(ctx context.Context, clientID, uri string) (bool, error) {
	if uri == "" || clientID == "" {
		return false, nil
	}

	rc, err := p.client(ctx, clientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return false, nil
	case err != nil:
		return false, err
	}

	return slices.Contains(rc.PostLogoutRedirectURIs, uri), nil
}

// afterLogout is where the browser goes once a request is answered.
func (p *Provider) afterLogout(target, state string) string {
	switch {
	case target == "":
		return p.loggedOutURL
	case state == "":
		return target
	default:
		return withQuery(target, url.Values{paramState: {state}})
	}
}

// parkLogout stores what a confirmation needs, and nothing a page or a stranger could read an
// identity from: never the hint itself, and never a hint's values that were not checked.
func (p *Provider) parkLogout(ctx context.Context, req endSessionRequest, flowSecret string) (*EndSessionResult, error) {
	parked := &PendingRequest{
		ClientID:           req.client,
		RedirectURI:        req.target,
		State:              req.state,
		IDTokenHintSubject: req.subject,
	}
	if req.family != id.Nil {
		parked.SignIn = &SignIn{User: identity.UserID(req.subject), Family: req.family}
	}

	handle, flow, err := p.parkAt(ctx, parked, flowSecret, StageLogout)
	if err != nil {
		return nil, err
	}

	return &EndSessionResult{Location: withQuery(p.logoutURL, url.Values{HandleParam: {handle}}), FlowSecret: flow}, nil
}

// browserSignIn is the sign-in of the browser's session, and nil when it holds none, which is an
// answer and no failure. A logout asks nothing more of it: a user since deactivated, or a sign-in
// too old to answer a request, can still be logged out.
func (p *Provider) browserSignIn(ctx context.Context, secret string) (*SignIn, error) {
	if !p.cfg.browserSessions {
		return nil, nil //nolint:nilnil // no session is an answer
	}
	digest, ok := digestEncoded(secret)
	if !ok {
		return nil, nil //nolint:nilnil // what the provider could not have minted is no session
	}

	session, err := p.stores.browserSessions.Load(ctx, digest, p.cfg.clock.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, nil //nolint:nilnil // no session is an answer
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: load the browser session")
	}

	return &session.SignIn, nil
}

// endFamily ends one sign-in's grants, and returns the selector naming it. Its browser session stays,
// because that is what lets this browser ask again: it goes last, with the EndSignIn that finishes.
func (p *Provider) endFamily(ctx context.Context, family id.ID) (*SignInSelector, error) {
	sel := SignInSelector{Family: family}
	if err := p.endGrantsOf(ctx, sel); err != nil {
		return nil, err
	}

	return &sel, nil
}

// ConfirmLogout takes the logout page's answer to a parked end-session request, from the browser
// holding the handle's flow secret. A wrong flow secret, or an unknown, expired or spent handle,
// and a handle that is no end-session request, all answer ErrUnknownHandle alike.
//
// A confirmation ends the sign-in of the browser's own session, whichever sign-in the request's
// hint named, so that holding a user's ID token ends nothing of theirs from another browser. A
// browser with no session ends nothing, and that is no error (RP-Initiated Logout section 4). Only
// a provider built with WithoutBrowserSessions ends the sign-in a valid hint names, as nothing else
// identifies one there.
//
// A confirmation then goes where EndSession would have sent it: post_logout_redirect_uri with its
// state when a valid hint asked for that URI and its client still registers it, and otherwise the
// logged-out page. A declined answer ends nothing and goes to the logged-out page, because section
// 3 returns the browser to a relying party only after a logout; the page that posted knows what it
// asked, and need not follow it.
//
// The handle is spent last, once whatever had to end has ended, so a failure leaves the page able to
// answer again. An answer ending nothing spends it here. One ending a sign-in leaves it to the caller,
// who finishes as EndSession says, with EndSignIn(Ended), and then calls SpendLogout. A failing store or
// registry matches ErrDependency, and EndSession says what a failure in ending the sign-in leaves behind.
func (p *Provider) ConfirmLogout(
	ctx context.Context, handle, flowSecret, browserSessionSecret string, confirmed bool,
) (*LogoutResult, error) {
	r, err := p.loadPending(ctx, handle, flowSecret)
	if err != nil {
		return nil, err
	}
	if r.Stage != StageLogout {
		return nil, ErrUnknownHandle
	}

	result := &LogoutResult{RedirectTo: p.loggedOutURL}
	if confirmed {
		registered, err := p.registeredPostLogout(ctx, r.ClientID, r.RedirectURI)
		if err != nil {
			return nil, err
		}
		if registered {
			result.RedirectTo = p.afterLogout(r.RedirectURI, r.State)
		}

		if result.Ended, result.User, err = p.endConfirmed(ctx, r, browserSessionSecret); err != nil {
			return nil, err
		}
	}

	// An end is not over yet: the caller still owes the sign-in's sessions, and the page may have to
	// answer again, so SpendLogout is what spends this handle.
	if result.Ended != nil {
		return result, nil
	}

	if err := p.spendStage(ctx, r, StageLogout, StageDone, nil); err != nil {
		return nil, err
	}

	return result, nil
}

// SpendLogout spends the handle of an answer that ended a sign-in, once the caller has finished that
// end (see ConfirmLogout). The logout has happened by then and its answer is owed, so nothing here is
// returned: a store that cannot spend the handle is logged, and a handle already spent by a racing
// answer is no failure. A handle left unspent lives until its deadline, and answers again only by
// ending what the browser then holds. It does not depend on the caller still listening.
func (p *Provider) SpendLogout(ctx context.Context, handle, flowSecret string) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()

	r, err := p.loadPending(detached, handle, flowSecret)
	if err == nil {
		err = p.spendStage(detached, r, StageLogout, StageDone, nil)
	}
	if err != nil && !errors.Is(err, ErrUnknownHandle) {
		p.logFailedAfterSpend(ctx, "oidcprovider: an answered logout's handle could not be spent", err)
	}
}

// endConfirmed ends what a confirmation may: the sign-in of the browser's session, or, with no
// browser sessions kept, the sign-in a valid hint named. It returns nil when none ended.
func (p *Provider) endConfirmed(
	ctx context.Context, r *PendingRequest, browserSessionSecret string,
) (*SignInSelector, identity.UserID, error) {
	signIn := r.SignIn
	if p.cfg.browserSessions {
		var err error
		if signIn, err = p.browserSignIn(ctx, browserSessionSecret); err != nil {
			return nil, "", err
		}
	}
	if signIn == nil {
		return nil, "", nil
	}

	ended, err := p.endFamily(ctx, signIn.Family)
	if err != nil {
		return nil, "", err
	}

	return ended, signIn.User, nil
}
