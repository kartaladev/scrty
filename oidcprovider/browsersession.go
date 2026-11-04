package oidcprovider

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// isSilent reports a prompt=none request, which no page may ever answer.
func isSilent(req *PendingRequest) bool { return slices.Contains(req.Prompt, promptNone) }

// refuseAtRedirectURI answers a request at its redirect URI, leaving nothing behind.
func (p *Provider) refuseAtRedirectURI(req *PendingRequest, code string) AuthorizeResult {
	refusal := redirectRefusal{code: code, redirectURI: req.RedirectURI, state: req.State}

	return AuthorizeResult{Location: refusal.location(p.issuer)}
}

// answerFromSession answers a validated request from the browser's session, and says false
// when there is none that can answer it, which leaves the request to the login page. Its
// client needs no judging again: validate has just read it, and judged the request against
// it. A request this parks is judged at its consent stage, as every resume is.
//
// A hint is judged after the user, because a request that session cannot answer may still
// be answered by whoever signs in, and before consent, so that a client's silent request
// does not learn what another subject gave it.
func (p *Provider) answerFromSession(
	ctx context.Context, in AuthorizeInput, req *PendingRequest, rc *RegisteredClient,
) (AuthorizeResult, bool, error) {
	now := p.cfg.clock.Now()
	s, digest, err := p.sessionSignIn(ctx, in.BrowserSessionSecret, req, now)
	if err != nil || digest == nil {
		return AuthorizeResult{}, false, err
	}

	if req.IDTokenHintSubject != "" && string(s.User) != req.IDTokenHintSubject {
		return p.refuseAtRedirectURI(req, CodeLoginRequired), true, nil
	}

	remembered, err := p.rememberedConsent(ctx, s.User, req.ClientID)
	if err != nil {
		return AuthorizeResult{}, false, err
	}
	switch {
	case !consentNeeded(rc, req, remembered):
		return p.issueFromSession(ctx, in, req, rc, s, digest, now)
	case isSilent(req):
		return p.refuseAtRedirectURI(req, CodeConsentRequired), true, nil
	default:
		res, err := p.parkAtConsent(ctx, in, req, s, digest, now)

		return res, err == nil, err
	}
}

// sessionSignIn returns the sign-in of the session that can answer req, and that session's
// digest, which is nil when none can. prompt=login and max_age=0 ask for an authentication
// that has not happened yet, which no session can have, and prompt=select_account for a
// choice only the consumer's page can offer, so they ask no store and load no one. Only what the provider could have minted is looked up.
//
// Everything that says there is no session is an answer. A store or user loader failing is
// not one, and fails.
func (p *Provider) sessionSignIn(ctx context.Context, secret string, req *PendingRequest, now time.Time) (SignIn, []byte, error) {
	if !p.cfg.browserSessions || wantsNewAuthentication(req) {
		return SignIn{}, nil, nil
	}
	digest, ok := digestEncoded(secret)
	if !ok {
		return SignIn{}, nil, nil
	}

	session, err := p.stores.browserSessions.Load(ctx, digest, now)
	switch {
	case errors.Is(err, ErrNotFound):
		return SignIn{}, nil, nil
	case err != nil:
		return SignIn{}, nil, dependencyFailure(ctx, err, "oidcprovider: load the browser session")
	}

	s := session.SignIn
	if judgeSignIn(s, now) != nil || !freshEnough(req, s, now) {
		return SignIn{}, nil, nil //nolint:nilerr // a sign-in that could not resume is no session, and no failure
	}

	active, err := p.userActive(ctx, s.User)
	if err != nil || !active {
		return SignIn{}, nil, err
	}

	return s, digest, nil
}

// wantsNewAuthentication reports a request only a sign-in made after it can answer, or one
// the consumer's page must choose: prompt=select_account asks the user to pick an account,
// which only that page can offer, so no session answers in its place. freshEnough compares
// the first kind with the time a request was parked, which this one has none of yet, so
// they are decided here and never reach it.
func wantsNewAuthentication(req *PendingRequest) bool {
	return slices.Contains(req.Prompt, promptLogin) || slices.Contains(req.Prompt, promptSelect) ||
		req.MaxAge != nil && *req.MaxAge == 0
}

// userActive reports whether the session's user still exists and may sign in, as a refresh
// asks. A record naming someone else counts as no such user.
func (p *Provider) userActive(ctx context.Context, user identity.UserID) (bool, error) {
	details, err := p.users.LoadByUserID(ctx, user)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return false, nil
	case err != nil:
		return false, dependencyFailure(ctx, err, "oidcprovider: load the browser session's user")
	}

	return details != nil && details.ID == user && details.Active, nil
}

// issueFromSession answers with a code for everything the request asked. The session is
// touched only once the code is written, which makes it the last look at the session: one
// gone by then has ended, so the code is not released, and no one ever holds its secret. Any
// other failure to touch only shortens the session, and is logged.
func (p *Provider) issueFromSession(
	ctx context.Context, in AuthorizeInput, req *PendingRequest, rc *RegisteredClient, s SignIn, digest []byte, now time.Time,
) (AuthorizeResult, bool, error) {
	target, err := p.issueCode(ctx, req, rc, s, req.Scopes)
	if err != nil {
		return AuthorizeResult{}, false, err
	}

	err = p.stores.browserSessions.Touch(ctx, digest, now.Add(browserSessionIdle(in.IdleTimeout)))
	switch {
	case errors.Is(err, ErrNotFound):
		return AuthorizeResult{}, false, nil
	case err != nil:
		p.logFailedAfterSpend(ctx, "oidcprovider: a browser session's use could not be recorded", err)
	}

	return AuthorizeResult{Location: target}, true, nil
}

// parkAtConsent parks the request with its login stage already answered by the session's
// sign-in, and sends the browser to the consent page, which answers from the same cookie.
func (p *Provider) parkAtConsent(
	ctx context.Context, in AuthorizeInput, req *PendingRequest, s SignIn, digest []byte, now time.Time,
) (AuthorizeResult, error) {
	handle, flow, err := p.parkRequest(ctx, req, in.FlowSecret)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if err := p.stores.pendingRequests.Advance(ctx, req.HandleDigest, StageLogin, StageConsent, &s); err != nil {
		return AuthorizeResult{}, dependencyFailure(ctx, err, "oidcprovider: move the request to its consent stage")
	}
	p.touchBrowserSession(ctx, digest, in.IdleTimeout, now)

	return AuthorizeResult{Location: withQuery(p.consentURL, url.Values{HandleParam: {handle}}), FlowSecret: flow}, nil
}
