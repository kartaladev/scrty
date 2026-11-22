package oidcprovider

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
)

// defaultBrowserSessionIdle is the idle timeout of a browser session when a resume names
// none. It is a session manager's own default, as a test pins, so a chain left to its
// defaults keeps the two together.
const defaultBrowserSessionIdle = 30 * time.Minute

// clockSkewLeeway is how far ahead of the provider's clock a sign-in may claim to have
// authenticated and still count as having done so now. Replicas' clocks differ a little,
// and a sign-in made on one is presented to another. Further ahead than this, the claim is
// not clock skew and the sign-in is refused.
const clockSkewLeeway = 60 * time.Second

// DeviceResultParam is the query parameter a device request's last resume adds to the
// code-entry URL (WithDeviceAuthorization), keeping any query the URL already has, so the
// entry page can tell the user how their answer ended. It carries one of DeviceResultApproved,
// DeviceResultDenied or DeviceResultExpired, and nothing else is added. An entry URL whose own
// query already carries it is refused by New with an error matching ErrConfig, so the value
// the page reads is always the provider's.
const DeviceResultParam = "result"

// The values DeviceResultParam carries.
const (
	// DeviceResultApproved says the user approved the device, which may now poll for tokens.
	DeviceResultApproved = "approved"
	// DeviceResultDenied says the user denied the device.
	DeviceResultDenied = "denied"
	// DeviceResultExpired says the device authorization expired before the user answered,
	// so nothing was approved, and the user starts again on the device.
	DeviceResultExpired = "expired"
)

// ConsentAnswer is what the consumer's consent page answered.
type ConsentAnswer struct {
	// Deny refuses the request. A denial names no scopes.
	Deny bool

	// Scopes are the scopes granted: some of those requested, and openid whenever it was
	// requested. A repeated scope counts once.
	Scopes []string
}

// ResumeInput is what the resume endpoint hands the provider. It holds the handle and the
// browser's secrets, so it prints and logs redacted; read its fields to use it.
type ResumeInput struct {
	// Handle is the pending request's handle, from the consumer's page.
	Handle string

	// FlowSecret is the value of the browser's flow cookie.
	FlowSecret string

	// SignIn is the sign-in the request's Authorization header proved, already through
	// the chain's policy: a session that owes a step, or that only a late renewal may
	// recover, never gets this far, because the provider cannot see either. It is nil when
	// the request carried none, which only a consent answer resting on the browser session
	// may do.
	SignIn *SignIn

	// BrowserSessionSecret is the value of the browser-session cookie, or empty. At the
	// login stage it is the session the resume replaces. At the consent stage it stands in
	// for a SignIn that is nil.
	BrowserSessionSecret string

	// IdleTimeout is how long a browser session lives without use, which is the sign-in
	// manager's IdleTimeout. The provider holds no manager, so the chain states it. Zero
	// means a session manager's default of 30 minutes, and a negative value is refused with
	// an error matching ErrConfig.
	IdleTimeout time.Duration

	// Answer is the consent page's answer, and nil at the login stage.
	Answer *ConsentAnswer
}

// Format writes the redacted form under every verb.
func (ResumeInput) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (ResumeInput) LogValue() slog.Value { return slog.StringValue(redacted) }

// ResumeResult says where the browser goes next. It may carry a code and a secret, so it
// prints and logs redacted; read its fields to use it.
type ResumeResult struct {
	// RedirectTo is where the page sends the browser: the consent page carrying the
	// handle, or the client's redirect URI carrying a code or an error, with state and iss.
	RedirectTo string

	// BrowserSessionSecret is the value to set the browser-session cookie to, and is empty
	// unless a login stage resumed with browser sessions on.
	BrowserSessionSecret string
}

// Format writes the redacted form under every verb.
func (ResumeResult) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (ResumeResult) LogValue() slog.Value { return slog.StringValue(redacted) }

// Resume answers a pending request's current stage. A nil Answer resumes the login stage,
// and an Answer resumes the consent stage.
//
// It refuses with ErrUnknownHandle, the same error in every case, when the handle is
// unknown, expired, already spent, at another stage, or not bound to the flow secret; when
// its client has since been removed; and when a consent stage is answered by a user other
// than the one who signed in. It refuses with ErrReauthenticate when there is no sign-in,
// when one cannot be judged or has passed its absolute deadline, and when prompt=login or
// max_age is not met by the time the user last authenticated, which at each stage is the
// presented sign-in's and never the time of a renewal. It refuses with ErrConsentMalformed
// when an answer does not fit the request. A sign-in naming no user fails matching
// token.ErrNoSubject. A request is judged at every resume against the client as it is
// read then: one whose redirect URI the client no longer registers, or whose client lost
// the authorization_code grant, or is left with no scope or without openid it asked for, is
// an unknown handle too, and the scopes and resources the client may no longer ask for are
// left out of what is granted. A failing store fails matching ErrDependency. None of these spends
// the stage, so the page may finish what is missing and resume again. Nor do they carry a
// handle, secret or code.
//
// Each stage is spent by one conditional write, which everything else is arranged around:
// whatever the answer needs is written before it, so a failure leaves the stage unspent,
// and nothing is shown or recorded as the user's until it has succeeded. Of any number of
// racing resumes, one is answered. The others are unknown handles, and what they wrote on
// the way is a code and a session no one was ever given the secret of, which expire.
//
// A code carries the facts of the sign-in that was presented when it was issued, never a
// value from the current time. An end of the sign-in can reach only a code already written, so a
// caller that read SignIn before calling this must read it again after, and hand out nothing if
// it has gone: the chain's resume endpoint does. A browser session standing in for a sign-in is
// looked at here, after the code is written. Consent is remembered only from a grant, and offline access
// only when offline_access is among the scopes granted. A store failing to remember it
// costs the user a later question, and not the answer they were owed, so it is logged.
//
// A request parked by EnterUserCode answers a device authorization, and no code is ever
// issued for it. It is judged against the client's GrantDeviceCode instead of a redirect URI,
// and against the device authorization, which must still be live by the provider's clock,
// claimed by this browser and unanswered: one answered already, through this request or
// another the same browser parked by entering the code again, is an unknown handle. Its login
// stage always goes on to the consent page, whatever the client or remembered consent would
// skip. Its consent answer approves or denies the device authorization, then spends the
// stage, then remembers an approval's consent, and sends the browser to the code-entry URL
// with DeviceResultParam added: DeviceResultApproved or DeviceResultDenied. At either stage,
// a device authorization expired by then (at its ExpiresAt or after) approves nothing and
// answers DeviceResultExpired, leaving the stage as it was.
func (p *Provider) Resume(ctx context.Context, in ResumeInput) (ResumeResult, error) {
	if in.IdleTimeout < 0 {
		return ResumeResult{}, fmt.Errorf("%w: ResumeInput.IdleTimeout: must not be negative", ErrConfig)
	}

	r, err := p.loadPending(ctx, in.Handle, in.FlowSecret)
	if err != nil {
		return ResumeResult{}, err
	}

	var resume func(context.Context, ResumeInput, *PendingRequest, *RegisteredClient) (ResumeResult, error)
	switch {
	case r.Stage == StageLogin && in.Answer == nil:
		resume = p.resumeLogin
	case r.Stage == StageConsent && in.Answer != nil:
		resume = p.resumeConsent
	default:
		return ResumeResult{}, ErrUnknownHandle
	}

	rc, err := p.client(ctx, r.ClientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return ResumeResult{}, ErrUnknownHandle
	case err != nil:
		return ResumeResult{}, err
	}

	r, dropped, ok := rejudge(r, rc)
	if !ok {
		return ResumeResult{}, ErrUnknownHandle
	}
	if in.Answer != nil && !in.Answer.Deny && len(dropped) > 0 {
		in.Answer = &ConsentAnswer{Scopes: slices.DeleteFunc(slices.Clone(in.Answer.Scopes), func(scope string) bool {
			return slices.Contains(dropped, scope)
		})}
	}

	if r.DeviceAuthorizationID != id.Nil {
		record, err := p.claimedDevice(ctx, r)
		switch {
		case errors.Is(err, errDeviceGone):
			return p.deviceResult(DeviceResultExpired), nil
		case err != nil:
			return ResumeResult{}, err
		case in.Answer != nil:
			return p.resumeDeviceConsent(ctx, in, r, rc, record)
		}
	}

	return resume(ctx, in, r, rc)
}

// rejudge judges a parked request against the client as it is read now, which may not be
// the client it was parked for. It returns the request to answer, with the scopes and
// resources the client may no longer ask for left out, as a refresh leaves out the scopes a
// client has lost, and the scopes it left out. It says false for a request that cannot be
// answered: its redirect URI is no longer one the client registers, the client lost the
// authorization_code grant, no scope is left, or openid was asked for and is gone. The
// caller refuses that as an unknown handle, with no redirect, because nothing says where a
// redirect could safely go. A client that lost the refresh grant is left holding no
// offline_access.
//
// A request answering a device authorization has no redirect URI, and is judged by the
// device grant instead: a client that lost GrantDeviceCode cannot be answered, and one
// that names a redirect URI as well is no request the provider parks. A code-flow request
// is never judged by the device grant.
func rejudge(r *PendingRequest, rc *RegisteredClient) (*PendingRequest, []string, bool) {
	if r.DeviceAuthorizationID != id.Nil {
		if r.RedirectURI != "" || !slices.Contains(rc.GrantTypes, GrantDeviceCode) {
			return nil, nil, false
		}
	} else if !rc.MatchRedirectURI(r.RedirectURI) || !slices.Contains(rc.GrantTypes, GrantAuthorizationCode) {
		return nil, nil, false
	}

	refreshes := slices.Contains(rc.GrantTypes, GrantRefreshToken)
	var dropped []string
	kept := slices.DeleteFunc(slices.Clone(r.Scopes), func(scope string) bool {
		gone := !slices.Contains(rc.Scopes, scope) || scope == scopeOffline && !refreshes
		if gone {
			dropped = append(dropped, scope)
		}

		return gone
	})
	if len(kept) == 0 || slices.Contains(r.Scopes, scopeOpenID) && !slices.Contains(kept, scopeOpenID) {
		return nil, nil, false
	}

	judged := *r
	judged.Scopes = kept
	judged.Resources = slices.DeleteFunc(slices.Clone(r.Resources), func(resource string) bool {
		return !slices.Contains(rc.Resources, resource)
	})

	return &judged, dropped, true
}

// resumeLogin answers the login stage. Only a sign-in can: a browser session stands in at
// the consent stage alone.
func (p *Provider) resumeLogin(ctx context.Context, in ResumeInput, r *PendingRequest, rc *RegisteredClient) (ResumeResult, error) {
	if in.SignIn == nil {
		return ResumeResult{}, ErrReauthenticate
	}
	s := *in.SignIn
	now := p.cfg.clock.Now()
	if err := judgeSignIn(s, now); err != nil {
		return ResumeResult{}, err
	}
	if !freshEnough(r, s, now) {
		return ResumeResult{}, ErrReauthenticate
	}

	// A hint is judged after freshness, because this refusal ends the request, and one
	// the page can cure should come first.
	if r.IDTokenHintSubject != "" && string(s.User) != r.IDTokenHintSubject {
		return p.refuseRequest(ctx, r, StageLogin, CodeLoginRequired)
	}

	remembered, err := p.rememberedConsent(ctx, s.User, r.ClientID)
	if err != nil {
		return ResumeResult{}, err
	}

	target, to := withQuery(p.consentURL, url.Values{HandleParam: {in.Handle}}), StageConsent
	if !consentNeeded(rc, r, remembered) {
		to = StageDone
		if target, err = p.issueCode(ctx, r, rc, s, r.Scopes); err != nil {
			return ResumeResult{}, err
		}
	}

	secret, err := p.putBrowserSession(ctx, s, in.IdleTimeout, now)
	if err != nil {
		return ResumeResult{}, err
	}
	if err := p.spendStage(ctx, r, StageLogin, to, &s); err != nil {
		return ResumeResult{}, err
	}
	p.dropBrowserSession(ctx, in.BrowserSessionSecret, secret)

	return ResumeResult{RedirectTo: target, BrowserSessionSecret: secret}, nil
}

// resumeConsent answers the consent stage, for the user who signed in at the login stage.
// A code is bound to the sign-in presented now, so what it states about the user has been
// judged now, and an end of that sign-in can reach it: the login stage's may have ended
// since. So freshness is judged again, except for a denial, which grants nothing.
//
// The consent is remembered last, once this answer is the one that won. Remembering it
// sooner would keep a grant that lost to a denial racing it.
func (p *Provider) resumeConsent(ctx context.Context, in ResumeInput, r *PendingRequest, rc *RegisteredClient) (ResumeResult, error) {
	if r.SignIn == nil {
		return ResumeResult{}, ErrUnknownHandle
	}
	now := p.cfg.clock.Now()
	s, session, err := p.consentSignIn(ctx, in, now)
	if err != nil {
		return ResumeResult{}, err
	}
	if err := judgeSignIn(s, now); err != nil {
		return ResumeResult{}, err
	}
	if s.User != r.SignIn.User {
		return ResumeResult{}, ErrUnknownHandle
	}

	if in.Answer.Deny {
		if len(in.Answer.Scopes) > 0 {
			return ResumeResult{}, ErrConsentMalformed
		}
		res, err := p.refuseRequest(ctx, r, StageConsent, CodeAccessDenied)
		if err == nil {
			p.reportConsent(ctx, event.ConsentDenied, s.User, r.ClientID)
			p.touchBrowserSession(ctx, session, in.IdleTimeout, now)
		}

		return res, err
	}

	granted, ok := grantedScopesOf(r, in.Answer.Scopes)
	if !ok {
		return ResumeResult{}, ErrConsentMalformed
	}
	if !freshEnough(r, s, now) {
		return ResumeResult{}, ErrReauthenticate
	}

	target, err := p.issueCode(ctx, r, rc, s, granted)
	if err != nil {
		return ResumeResult{}, err
	}
	if err := p.confirmBrowserSession(ctx, session, in.IdleTimeout, now); err != nil {
		return ResumeResult{}, err
	}
	if err := p.spendStage(ctx, r, StageConsent, StageDone, nil); err != nil {
		return ResumeResult{}, err
	}
	p.reportConsent(ctx, event.ConsentGiven, s.User, r.ClientID)

	offline := slices.Contains(granted, scopeOffline)
	err = p.stores.consents.Give(ctx, s.User, r.ClientID, granted, offline, now)
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		p.logFailedAfterSpend(ctx, "oidcprovider: a consent the user gave could not be remembered", err)
	}

	return ResumeResult{RedirectTo: target}, nil
}

// claimedDevice reads the device authorization a device request answers, which must still be
// live (liveDevice), claimed and not yet answered, by the browser the request is bound to. A
// record answered already, through this request or a sibling the same browser parked by
// entering the code again, is ErrUnknownHandle, as is a claim bound to another flow, which
// the provider never parks.
func (p *Provider) claimedDevice(ctx context.Context, r *PendingRequest) (*DeviceAuthorization, error) {
	record, err := p.liveDevice(ctx, r)
	if err != nil {
		return nil, err
	}
	if record.State != DeviceClaimed || !hmac.Equal(record.ClaimFlowDigest, r.FlowDigest) {
		return nil, ErrUnknownHandle
	}

	return record, nil
}

// resumeDeviceConsent answers the consent stage of a device request: it approves or denies
// the device authorization instead of issuing a code, and sends the browser back to the
// code-entry page with DeviceResultParam saying how it ended. The sign-in is judged as
// resumeConsent judges it.
//
// The device record is decided first, by one conditional write that also judges its expiry
// by now, and the stage is spent after it. Of two answers racing through sibling requests,
// one decides; the other finds the record decided and is an unknown handle. A decision that
// lost to expiry is DeviceResultExpired. If the stage cannot be spent once the record is
// decided, the decision stands and the answer is a dependency failure: the code's re-entry
// is refused, and resuming again finds the record decided, so nothing is decided twice or
// remembered for it.
//
// An approval records the approving sign-in and the grant family the exchange will create,
// minted now so that an end of the sign-in reaches it before the exchange. When it rests on
// the browser session, the session is looked at once the record is decided, as resumeConsent
// looks once the code is written. A session gone by then has ended, or a look that failed
// could not exclude that, and an approval cannot be withheld from the device as a code is from
// the browser, so a revocation is recorded for its family, which the exchange will find, and
// the stage is left unspent. Consent is remembered last, for an approval alone.
func (p *Provider) resumeDeviceConsent(
	ctx context.Context, in ResumeInput, r *PendingRequest, rc *RegisteredClient, record *DeviceAuthorization,
) (ResumeResult, error) {
	if r.SignIn == nil {
		return ResumeResult{}, ErrUnknownHandle
	}
	now := p.cfg.clock.Now()
	s, session, err := p.consentSignIn(ctx, in, now)
	if err != nil {
		return ResumeResult{}, err
	}
	if err := judgeSignIn(s, now); err != nil {
		return ResumeResult{}, err
	}
	if s.User != r.SignIn.User {
		return ResumeResult{}, ErrUnknownHandle
	}

	approval, err := p.deviceApproval(ctx, in.Answer, r, rc, s, now)
	if err != nil {
		return ResumeResult{}, err
	}

	err = p.cfg.device.store.Decide(ctx, record.ID, approval, now)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound) && record.expiredAt(now):
		return p.deviceResult(DeviceResultExpired), nil
	case errors.Is(err, ErrNotFound):
		return ResumeResult{}, ErrUnknownHandle
	case err != nil:
		return ResumeResult{}, dependencyFailure(ctx, err, "oidcprovider: decide the device authorization")
	}

	p.deviceDecided(ctx, record, approval, s.User)

	if approval == nil {
		if err := p.spendStage(ctx, r, StageConsent, StageDone, nil); err != nil {
			return ResumeResult{}, err
		}
		p.reportConsent(ctx, event.ConsentDenied, s.User, r.ClientID)
		p.touchBrowserSession(ctx, session, in.IdleTimeout, now)

		return p.deviceResult(DeviceResultDenied), nil
	}

	if err := p.confirmBrowserSession(ctx, session, in.IdleTimeout, now); err != nil {
		p.withdrawDeviceApproval(ctx, approval.GrantFamily, now)

		return ResumeResult{}, err
	}
	if err := p.spendStage(ctx, r, StageConsent, StageDone, nil); err != nil {
		return ResumeResult{}, err
	}
	p.reportConsent(ctx, event.ConsentGiven, s.User, r.ClientID)

	err = p.stores.consents.Give(ctx, s.User, r.ClientID, approval.GrantedScopes, approval.Offline, now)
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		p.logFailedAfterSpend(ctx, "oidcprovider: a consent the user gave could not be remembered", err)
	}

	return p.deviceResult(DeviceResultApproved), nil
}

// deviceApproval reads a consent answer of a device request into what Decide records: nil for
// a denial, which must name no scope, and otherwise the approval of the scopes granted, under
// the sign-in s, with a grant family minted now. The grant ends with its sign-in as the
// client's EndGrantsWithSignIn says, a public web client's default included, and survives that
// end without offline_access only under DeviceGrantsOutliveSignIn.
func (p *Provider) deviceApproval(
	ctx context.Context, answer *ConsentAnswer, r *PendingRequest, rc *RegisteredClient, s SignIn, now time.Time,
) (*DeviceApproval, error) {
	if answer.Deny {
		if len(answer.Scopes) > 0 {
			return nil, ErrConsentMalformed
		}

		return nil, nil //nolint:nilnil // a denial records no approval, and is no failure
	}

	granted, ok := grantedScopesOf(r, answer.Scopes)
	if !ok {
		return nil, ErrConsentMalformed
	}
	if !freshEnough(r, s, now) {
		return nil, ErrReauthenticate
	}
	family, err := idgen.New(p.cfg.ids)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	if err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: mint a grant family")
	}
	offline := slices.Contains(granted, scopeOffline)

	return &DeviceApproval{
		User:              s.User,
		GrantedScopes:     granted,
		SignIn:            cloneSignIn(s),
		GrantFamily:       family,
		Offline:           offline,
		EndsWithSignIn:    rc.EndGrantsWithSignIn,
		SurvivesSignInEnd: rc.DeviceGrantsOutliveSignIn && !offline,
	}, nil
}

// deviceDecided reports a device authorization's decision by user: approval is nil for a denial.
// It is the one place every decision passes, right after Decide succeeds and before the stage is
// spent or the session confirmed, because the device can exchange the decision whatever becomes of
// the stage. Decide's compare-and-set lets one resume through, and a resume that finds the record
// decided reaches no decision, so it is reported once. The consent event follows the stage spend.
func (p *Provider) deviceDecided(ctx context.Context, record *DeviceAuthorization, approval *DeviceApproval, user identity.UserID) {
	name := event.DeviceAuthorizationApproved
	if approval == nil {
		name = event.DeviceAuthorizationDenied
	}
	p.reportDevice(ctx, name, user, record.ClientID)
}

// withdrawDeviceApproval records a revocation for the grant family of an approval whose
// sign-in could not be confirmed after the decision, so that the exchange, which creates its
// grant over any revocation recorded for the family, refuses it. It runs whatever became of
// the caller, within its own budget. A failure is logged: the approval then stands, and an
// end of its sign-in reaches it only if that end came after the decision.
func (p *Provider) withdrawDeviceApproval(ctx context.Context, family id.ID, now time.Time) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	_, err := p.stores.grants.Revoke(detached, family, CauseSignInEnded, now)
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		p.logFailedAfterSpend(ctx, "oidcprovider: a device approval whose sign-in could not be confirmed could not be withdrawn", err)
	}
}

// deviceResult sends the browser back to the code-entry page with DeviceResultParam set to
// result, keeping the page's own query.
func (p *Provider) deviceResult(result string) ResumeResult {
	entry := *p.cfg.device.entryURL
	query := entry.Query()
	query.Set(DeviceResultParam, result)
	entry.RawQuery = query.Encode()

	return ResumeResult{RedirectTo: entry.String()}
}

// consentSignIn returns who is answering: the sign-in given, or the browser session's in
// its place, with that session's digest. Nothing else stands in, so anything else is a
// browser that must authenticate.
func (p *Provider) consentSignIn(ctx context.Context, in ResumeInput, now time.Time) (SignIn, []byte, error) {
	if in.SignIn != nil {
		return *in.SignIn, nil, nil
	}
	if !p.cfg.browserSessions {
		return SignIn{}, nil, ErrReauthenticate
	}
	digest, ok := digestEncoded(in.BrowserSessionSecret)
	if !ok {
		return SignIn{}, nil, ErrReauthenticate
	}

	session, err := p.stores.browserSessions.Load(ctx, digest, now)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return SignIn{}, nil, ErrReauthenticate
	case err != nil:
		return SignIn{}, nil, dependencyFailure(ctx, err, "oidcprovider: load the browser session")
	case session == nil:
		// A store reports a missing session with ErrNotFound, so an answer of nothing breaks
		// its contract: it says nothing of the session, and is answered as the store failing.
		return SignIn{}, nil, dependencyFailure(ctx, errNoRecord, "oidcprovider: load the browser session")
	}

	active, err := p.userActive(ctx, session.SignIn.User)
	switch {
	case err != nil:
		return SignIn{}, nil, err
	case !active:
		return SignIn{}, nil, ErrReauthenticate
	}

	return session.SignIn, digest, nil
}

// confirmBrowserSession takes the last look at the session an answer rests on, and records
// its use, once the code is written and before the stage is spent: an end before this look
// is caught by it, and one after finds the code. A session gone by now has ended, so the
// answer is a browser that must authenticate, and the code written is one no one was given,
// which expires. An answer resting on no session (digest nil) needs no look. Any failure other
// than the session being gone is a dependency failure, since nothing is spent yet to lose.
func (p *Provider) confirmBrowserSession(ctx context.Context, digest []byte, idle time.Duration, now time.Time) error {
	if digest == nil {
		return nil
	}
	err := p.stores.browserSessions.Touch(ctx, digest, now.Add(browserSessionIdle(idle)))
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrReauthenticate
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: touch the browser session")
	}

	return nil
}

// grantedScopesOf returns the scopes an answer granted, once each and in the request's
// order, and false when the answer does not fit the request: a scope not asked for, nothing
// at all, or openid left out when it was asked for.
func grantedScopesOf(r *PendingRequest, answered []string) ([]string, bool) {
	for _, scope := range answered {
		if !slices.Contains(r.Scopes, scope) {
			return nil, false
		}
	}
	granted := slices.DeleteFunc(slices.Clone(r.Scopes), func(scope string) bool {
		return !slices.Contains(answered, scope)
	})
	if len(granted) == 0 || slices.Contains(r.Scopes, scopeOpenID) && !slices.Contains(granted, scopeOpenID) {
		return nil, false
	}

	return granted, true
}

// touchBrowserSession records a use of the session an answer rested on. digest is nil when
// it rested on none. The answer is already owed, so a failure only shortens the session.
func (p *Provider) touchBrowserSession(ctx context.Context, digest []byte, idle time.Duration, now time.Time) {
	if digest == nil {
		return
	}
	err := p.stores.browserSessions.Touch(ctx, digest, now.Add(browserSessionIdle(idle)))
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		p.logFailedAfterSpend(ctx, "oidcprovider: a browser session's use could not be recorded", err)
	}
}

// judgeSignIn refuses what is no sign-in the provider could state facts about. No
// identifier is a server-side failure, because the chain should never have got this far.
// The rest is a sign-in that has ended, or one a code could not honestly carry: without
// its family, no end of the sign-in could reach the code. A sign-in claiming to have
// authenticated more than clockSkewLeeway ahead of now is no clock skew, and is refused
// whatever the request asks; within it, the time counts as now.
func judgeSignIn(s SignIn, now time.Time) error {
	if s.User == "" {
		return fmt.Errorf("oidcprovider: resume: %w", token.ErrNoSubject)
	}
	if s.Family == id.Nil || s.AuthenticatedAt.IsZero() || !now.Before(s.AbsoluteExpiresAt) ||
		s.AuthenticatedAt.After(now.Add(clockSkewLeeway)) {
		return ErrReauthenticate
	}

	return nil
}

// freshEnough judges prompt=login and max_age by when the user last authenticated. For
// prompt=login, and for max_age=0, which means the same, that must be after the request
// was parked. Otherwise it must be no more than max_age seconds ago. validate holds max_age
// to 32 bits, so the conversion cannot overflow.
func freshEnough(r *PendingRequest, s SignIn, now time.Time) bool {
	afterParking := s.AuthenticatedAt.After(r.ParkedAt)
	if slices.Contains(r.Prompt, promptLogin) && !afterParking {
		return false
	}

	switch {
	case r.MaxAge == nil:
		return true
	case *r.MaxAge == 0:
		return afterParking
	default:
		return now.Sub(s.AuthenticatedAt) <= time.Duration(*r.MaxAge)*time.Second
	}
}

// spendStage makes the one conditional write a stage is spent by. Losing it means the
// stage is gone, which is the same answer as any other spent stage.
func (p *Provider) spendStage(ctx context.Context, r *PendingRequest, from, to Stage, s *SignIn) error {
	err := p.stores.pendingRequests.Advance(ctx, r.HandleDigest, from, to, s)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrUnknownHandle
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: spend the stage")
	}

	return nil
}

// refuseRequest ends the request with a refusal the client hears of.
func (p *Provider) refuseRequest(ctx context.Context, r *PendingRequest, from Stage, code string) (ResumeResult, error) {
	if err := p.spendStage(ctx, r, from, StageDone, nil); err != nil {
		return ResumeResult{}, err
	}
	refusal := redirectRefusal{code: code, redirectURI: r.RedirectURI, state: r.State}

	return ResumeResult{RedirectTo: refusal.location(p.issuer)}, nil
}

// putBrowserSession stores a new session for the sign-in and returns its secret, which
// the store never sees. Under WithoutBrowserSessions it does nothing.
func (p *Provider) putBrowserSession(ctx context.Context, s SignIn, idle time.Duration, now time.Time) (string, error) {
	if !p.cfg.browserSessions {
		return "", nil
	}

	secret, digest, err := p.mintSecret(ctx)
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: mint a browser session")
	}
	err = p.stores.browserSessions.Put(ctx, &BrowserSession{
		Digest:            digest,
		SignIn:            cloneSignIn(s),
		IdleExpiresAt:     now.Add(browserSessionIdle(idle)),
		AbsoluteExpiresAt: s.AbsoluteExpiresAt,
	})
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: store the browser session")
	}

	return secret, nil
}

func browserSessionIdle(idle time.Duration) time.Duration {
	if idle == 0 {
		return defaultBrowserSessionIdle
	}

	return idle
}

// dropBrowserSession deletes the session a resume replaced, once the resume has won. It
// runs after the stage is spent, so a failure must not cost the answer: the old secret then
// lives out its own deadlines, in a browser about to be given a newer one.
func (p *Provider) dropBrowserSession(ctx context.Context, old, replacement string) {
	if replacement == "" || old == "" {
		return
	}
	digest, ok := digestEncoded(old)
	if !ok {
		return
	}
	err := p.stores.browserSessions.Delete(ctx, digest)
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		p.logFailedAfterSpend(ctx, "oidcprovider: the replaced browser session could not be deleted", err)
	}
}

// logFailedAfterSpend records a write that failed once the answer was already owed. It
// names the error's type alone, because a store's text is not the provider's to repeat.
func (p *Provider) logFailedAfterSpend(ctx context.Context, message string, err error) {
	p.cfg.logger.LogAttrs(ctx, slog.LevelError, message, slog.String("error_type", fmt.Sprintf("%T", err)))
}
