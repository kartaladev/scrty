package httpsec

import (
	"encoding/json"
	"errors"
	"net/http"
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
}

// bind takes the provider's state, and the default the options replace.
func (g *oidcResumeGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
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
// source. A source past its limit is refused with ratelimit.ErrThrottled before its
// handle is looked up.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-resume", or else an in-memory limiter of 30 per source a minute. A deployment of
// more than one replica supplies a factory or a limiter its replicas share, or the limit
// is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read
// as no limit while the consumer believed they had replaced one.
func WithOIDCResumeLimiter(l ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCResumeLimiter", "limiter", l); err != nil {
			return err
		}

		op.resume.throttle.limiter = l

		return nil
	}
}

// WithOIDCResumeBodyLimit reads at most n bytes of a resume's body.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of
// zero or less is refused, because it would refuse every resume.
func WithOIDCResumeBodyLimit(n int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if n <= 0 {
			return newConfigError("WithOIDCResumeBodyLimit takes a positive bound, and %d would refuse "+
				"every resume", n)
		}

		op.resume.bodyLimit = n

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
//     parsing and no handle lookup;
//  4. a credential that is not a complete sign-in is refused before the handle is looked
//     at, so nothing about the handle is told to it, and the handle stays unspent;
//  5. the provider judges the handle and answers the stage, spending it only on success.
//
// Only an unknown handle is charged to the source. Freshness and a malformed answer are
// the page's to cure, and a failure is no verdict on anyone.
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
		return ratelimit.ErrThrottled
	}

	signIn, err := oidcResumeSignIn(ex)
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

	if res.BrowserSessionSecret != "" {
		setOIDCCookie(ex.Writer, g.op.provider, OIDCBrowserSessionCookie, res.BrowserSessionSecret)
	}

	return writeSuccessDocument(ex, oidcResumeDocument{RedirectTo: res.RedirectTo})
}

// oidcResumeSignIn is the sign-in the request's bearer authenticated, and nil when the
// request presented no credential at all.
//
// The provider's SignIn cannot say that a session owes a step, so that is judged here. The
// gates ahead of this endpoint refuse such a session first on a chain enabling them, and
// this holds the line on one that does not. A session only a late renewal may recover is
// never published on this path, so it does not arrive.
//
// Anything else that authenticated, an API key or Basic credentials, is no sign-in, and
// neither is an Authorization header nothing on the chain read. Neither falls back to the
// browser session, because whoever sent it believed they were presenting a credential.
func oidcResumeSignIn(ex *Exchange) (*oidcprovider.SignIn, error) {
	s := ex.Session
	if s == nil || ex.bearerCredential == "" {
		if ex.Authentication != nil || s != nil || len(ex.Request.HeaderValues(oidcAuthorizationHeader)) > 0 {
			return nil, ErrAuthenticationRequired
		}

		return nil, nil //nolint:nilnil // no credential is an answer, which only a consent may rest on
	}

	if err := fullSessionOnly(s); err != nil {
		return nil, err
	}

	if err := raisedChallengeRefusal(ex, s); err != nil {
		return nil, err
	}

	signIn := oidcSignInOf(s)

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

// oidcSignInOf is the sign-in s states. Its assurance is what the session records of a
// federated login, read as the relying-party path reads it (sessionFederatedAssurance),
// so a session whose first factor is not federated asserts none.
func oidcSignInOf(s *session.Session) oidcprovider.SignIn {
	assured := sessionFederatedAssurance(s)

	return oidcprovider.SignIn{
		User:              s.UserID,
		Family:            s.FamilyID,
		AuthenticatedAt:   s.AuthenticatedAt,
		AMR:               assured.AMR(),
		ACR:               assured.ACR(),
		AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		ExternalIssuer:    s.ExternalIssuer,
		ExternalSessionID: s.ExternalSessionID,
	}
}
