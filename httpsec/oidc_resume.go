package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// oidcResumeFlow names the resume endpoint's rate-limit buckets and sampler keys.
const oidcResumeFlow = "oidc-resume"

// How many unknown handles one source may present before it is refused unread. They are
// proposed values: a handle cannot be guessed, so a source past them is scanning, and a
// page's retries and a browser's back button have room.
const (
	defaultOIDCResumeLimit  = 30
	defaultOIDCResumeWindow = time.Minute
)

// oidcResumeGroup serves the resume endpoint. It answers behind the bearer and the
// gates, and reads the sign-in from ex.Session.
type oidcResumeGroup struct {
	oidcGroupBase

	throttle  oidcClientThrottle
	bodyLimit int64

	// assurance states the amr and acr of a sign-in, and assuranceSet that a consumer
	// replaced it.
	assurance    func(*session.Session) (amr []string, acr string)
	assuranceSet bool
}

// bind takes the provider's state, and the default the options replace.
func (g *oidcResumeGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
	g.assurance = defaultOIDCSignInAssurance
}

func (g *oidcResumeGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCResume], inner: true, handle: g.serve},
	}
}

func (g *oidcResumeGroup) settle(c *config) error {
	return g.throttle.settleAt(c, oidcResumeFlow, defaultOIDCResumeLimit, defaultOIDCResumeWindow)
}

func (g *oidcResumeGroup) wire(ch *Chain) {
	g.throttle.wire(ch)
}

func (g *oidcResumeGroup) flushRefusalLogs() error {
	g.throttle.flush()

	return nil
}

// WithOIDCResumeLimiter counts the unknown handles presented at the resume endpoint, per
// source. A source past its limit is refused with ErrOIDCThrottled, which wraps
// ratelimit.ErrThrottled and answers 429, before its handle is looked up. A limiter that
// cannot answer, and a source that cannot be attributed, are refused the same way: the
// limit fails closed.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-resume", or else an in-memory limiter of 30 per source a minute. A deployment of
// more than one replica supplies a factory or a limiter its replicas share, or the limit
// is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read
// as no limit while the consumer believed they had replaced one.
func WithOIDCResumeLimiter(limiter ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCResumeLimiter", "limiter", limiter); err != nil {
			return err
		}

		op.resume.throttle.limiter = limiter

		return nil
	}
}

// WithOIDCResumeBodyLimit reads at most limit bytes of a resume's body.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of
// zero or less is refused, because it would refuse every resume.
func WithOIDCResumeBodyLimit(limit int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("WithOIDCResumeBodyLimit takes a positive bound, and %d would refuse "+
				"every resume", limit)
		}

		op.resume.bodyLimit = limit

		return nil
	}
}

// oidcResumeRequest is the document a page posts: the handle alone at the login stage,
// and with the scopes granted or a denial at the consent stage.
type oidcResumeRequest struct {
	Handle string   `json:"req"`
	Scopes []string `json:"scopes"`
	Deny   bool     `json:"deny"`
}

// answer is the consent answer the document holds, and nil when it holds none.
func (d oidcResumeRequest) answer() *oidcprovider.ConsentAnswer {
	if !d.Deny && d.Scopes == nil {
		return nil
	}

	return &oidcprovider.ConsentAnswer{Deny: d.Deny, Scopes: d.Scopes}
}

// oidcResumeDocument is a successful answer: where the page sends the browser.
type oidcResumeDocument struct {
	RedirectTo string `json:"redirect_to"`
}

// serve answers a request to the resume endpoint. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but POST is refused, and so is a request not made over TLS, each with
//     nothing read from it;
//  3. the source is asked before anything else is read, so a throttled source costs no
//     parsing and no handle lookup. A source over the limit, a limiter that cannot answer
//     and a source that cannot be attributed are all refused with ErrOIDCThrottled, which
//     answers 429: this endpoint is called by a page, and a 401 there reads as "sign the
//     user in", which the page may answer by repeating the call;
//  4. a credential that is not a complete sign-in is refused before the handle is looked
//     at, so nothing about the handle is told to it, and the handle stays unspent;
//  5. the provider judges the handle and answers the stage, spending it only on success.
//
// Only an unknown handle is charged to the source. Freshness and a malformed answer are
// the page's to cure, and a failure is no verdict on anyone.
//
// A 401 it returns is challenged on its way out of the provider's outer router (challengeOIDCSignIn).
//
// The sign-in is read a second time once the provider has written what the resume leaves, before
// any of it is handed out (confirmSignIn).
func (g *oidcResumeGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return ErrOIDCUnknownHandle
	}

	src, ok := g.throttle.admit(ex, g.op)
	if !ok {
		return ErrOIDCThrottled
	}

	signIn, err := g.resumeSignIn(ex)
	if err != nil {
		return err
	}

	doc, err := readOIDCResumeRequest(ex.Request, g.bodyLimit)
	if err != nil {
		return err
	}

	flow, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))
	browser, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCBrowserSessionCookie))

	// With no sign-in, only a browser session answering a consent can be heard.
	answer := doc.answer()
	if signIn == nil && (answer == nil || browser == "") {
		return ErrAuthenticationRequired
	}

	ctx := ex.Context()

	res, err := g.op.provider.Resume(ctx, oidcprovider.ResumeInput{
		Handle:               doc.Handle,
		FlowSecret:           flow,
		SignIn:               signIn,
		BrowserSessionSecret: browser,
		IdleTimeout:          g.op.sessions.IdleTimeout(),
		Answer:               answer,
	})
	if err != nil {
		if errors.Is(err, oidcprovider.ErrUnknownHandle) {
			g.throttle.charge(ctx, src)
		}

		return oidcResumeRefusal(err)
	}

	// A denial grants nothing, so nothing it wrote could outlive the sign-in.
	if signIn != nil && !doc.Deny {
		if err := g.confirmSignIn(ctx, signIn); err != nil {
			return err
		}
	}

	if res.BrowserSessionSecret != "" {
		setOIDCCookie(ex.Writer, g.op.provider, OIDCBrowserSessionCookie, res.BrowserSessionSecret)
	}

	return writeSuccessDocument(ex, oidcResumeDocument{RedirectTo: res.RedirectTo})
}

// confirmSignIn reads the sign-in again, now that the code and the browser session of the resume
// are written and neither has left. The chain read it before those writes, so an end landing in
// between reached neither of them. An end before this read is caught by it, and one after finds
// them written and ends them with the rest.
//
// What is read is the sign-in, one session family with a live head, and not the identifier that was
// presented: that identifier may rightly have stopped answering. A renewal leaves it superseded and
// the family live, a strict rotation makes it load as gone at once, and a signed bearer's jti names
// it just the same. Loading it again would also be a verdict with effects, reuse revoking the family
// of a window that closed while this request ran.
//
// The list is read from the chain's session manager, the built-in bearer's, which is the only one the
// chain has (WithSessions refuses any other). A session a consumer's own bearer published from another
// manager is not in it, so it reads as ended: what this resume wrote is ended and ErrOIDCReauthenticate
// answered. A consumer's bearer must publish sessions of the chain's manager.
//
// Gone, the sign-in has ended or passed a deadline, and the provider ends whatever this resume left
// of it, with ErrOIDCReauthenticate answered. A store that cannot say fails closed, with the failure
// answered and nothing ended: the sign-in cannot be confirmed live, and it may be. What was written
// is then a code and a session no one was given the secret of, which expire. The stage stays spent,
// so a resume that reached the client must start again, and one bound for the consent page may
// answer it with the sign-in, which is read again then.
func (g *oidcResumeGroup) confirmSignIn(ctx context.Context, signIn *oidcprovider.SignIn) error {
	live, err := g.op.sessions.ListSignIns(ctx, signIn.User, nil)
	if err != nil {
		return err
	}

	if slices.ContainsFunc(live, func(s session.SignIn) bool { return s.Handle == signIn.Family }) {
		return nil
	}

	if _, err := g.op.provider.EndSignIn(ctx, oidcprovider.SignInSelector{Family: signIn.Family}); err != nil {
		return err
	}

	return ErrOIDCReauthenticate
}

// resumeSignIn is the sign-in the request's bearer authenticated, and nil when the
// request presented no credential at all.
//
// The sign-in comes in the Authorization header and nowhere else. A request with more
// than one Authorization line is refused, as the token endpoint refuses it, because the
// lines may be read differently by whatever stands in front of the chain. A session that
// a consumer's interceptor published from the query, a cookie or a header of its own is
// refused even when the interceptor recorded the credential with
// Exchange.RecordPresentedToken: recording says which credential authenticated, and the
// resume endpoint still wants it presented where the protocol puts it. A consumer's own
// bearer reaches this endpoint by reading the Authorization header.
//
// The session must be one the chain's manager holds, the built-in bearer's. A consumer's bearer
// publishing one from another manager is not refused here, but confirmSignIn reads it as ended.
//
// The provider's SignIn cannot say that a session owes a step, so that is judged here. The
// gates ahead of this endpoint refuse such a session first on a chain enabling them, and
// this holds the line on one that does not. A session only a late renewal may recover is
// never published on this path, so it does not arrive.
//
// Anything else that authenticated, an API key or Basic credentials, is no sign-in, and
// neither is an Authorization header nothing on the chain read. Neither falls back to the
// browser session, because whoever sent it believed they were presenting a credential.
func (g *oidcResumeGroup) resumeSignIn(ex *Exchange) (*oidcprovider.SignIn, error) {
	lines := ex.Request.HeaderValues(oidcAuthorizationHeader)
	if len(lines) > 1 {
		return nil, ErrAuthenticationRequired
	}

	s := ex.Session
	if s == nil || ex.bearerCredential == "" {
		if ex.Authentication != nil || s != nil || len(lines) > 0 {
			return nil, ErrAuthenticationRequired
		}

		return nil, nil //nolint:nilnil // no credential is an answer, which only a consent may rest on
	}

	if len(lines) == 0 {
		return nil, ErrAuthenticationRequired
	}

	if err := fullSessionOnly(s); err != nil {
		return nil, err
	}

	if err := raisedChallengeRefusal(ex, s); err != nil {
		return nil, err
	}

	signIn := oidcSignInOf(s, g.assurance)

	return &signIn, nil
}

// readOIDCResumeRequest reads the document a page posts. It must be declared as JSON,
// which a cross-site form cannot send, on top of what CSRF protection judges. A body that
// is neither says nothing the provider could judge.
func readOIDCResumeRequest(r Request, limit int64) (oidcResumeRequest, error) {
	body, err := r.Body(limit)
	if err != nil {
		return oidcResumeRequest{}, err
	}

	if !declaresJSON(r.Header("Content-Type")) {
		return oidcResumeRequest{}, ErrOIDCConsentMalformed
	}

	var doc oidcResumeRequest
	if err := json.Unmarshal(body, &doc); err != nil {
		return oidcResumeRequest{}, ErrOIDCConsentMalformed
	}

	return doc, nil
}

// oidcResumeRefusal is the public refusal a provider's error stands for, or the error
// itself when it is a failure.
func oidcResumeRefusal(err error) error {
	switch {
	case errors.Is(err, oidcprovider.ErrUnknownHandle):
		return ErrOIDCUnknownHandle
	case errors.Is(err, oidcprovider.ErrReauthenticate):
		return ErrOIDCReauthenticate
	case errors.Is(err, oidcprovider.ErrConsentMalformed):
		return ErrOIDCConsentMalformed
	default:
		return err
	}
}

// oidcSignInOf is the sign-in s states. Its amr and acr are what assure says of s: the
// group's default, or the consumer's replacement.
func oidcSignInOf(s *session.Session, assure func(*session.Session) ([]string, string)) oidcprovider.SignIn {
	amr, acr := assure(s)

	return oidcprovider.SignIn{
		User:              s.UserID,
		Family:            s.FamilyID,
		AuthenticatedAt:   s.AuthenticatedAt,
		AMR:               amr,
		ACR:               acr,
		AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		ExternalIssuer:    s.ExternalIssuer,
		ExternalSessionID: s.ExternalSessionID,
	}
}
