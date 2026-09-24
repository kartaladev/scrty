package httpsec

import (
	"context"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=authenticator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate Authenticator
//go:generate mockgen -destination=attemptstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy AttemptStore

// The conventions form login follows when the consumer names none. They are
// constants rather than bare literals so a consumer who wants to follow the
// convention elsewhere — a client, a test, a reverse proxy rule — names the
// same thing this package does.
const (
	// DefaultLoginPath is the path form login answers POST requests on.
	DefaultLoginPath = "/login"

	// DefaultLoginUsernameParam is the form field, and JSON member, the
	// submitted identifier is read from.
	DefaultLoginUsernameParam = "username"

	// DefaultLoginPasswordParam is the form field, and JSON member, the
	// submitted password is read from.
	DefaultLoginPasswordParam = "password"

	// DefaultLoginBodyLimit is how many request body bytes a login may carry.
	// The endpoint is unauthenticated, so an unbounded read there is a
	// memory-exhaustion path that costs an attacker no credential at all.
	DefaultLoginBodyLimit int64 = 64 << 10
)

// LoginResult is what a successful login produced, handed to whatever writes
// the response.
type LoginResult struct {
	// Token is the access token issued for the new session.
	Token string

	// Session is the session the login opened.
	Session *session.Session
}

// LoginResponder writes the response to a successful login.
//
// With none supplied, the library writes a JSON document carrying the access
// token, an empty refresh token field and the session's idle expiry; a
// consumer replaces that whole response with WithLoginResponder.
//
// It is called instead of the downstream handler, because a login is the
// library's own endpoint and the application has no route behind it. An error
// it returns leaves the chain as the request's refusal.
type LoginResponder func(ex *Exchange, result LoginResult) error

// formLogin answers a login on its own path and passes everything else
// through.
type formLogin struct {
	authn    authenticate.Authenticator
	sessions *session.Manager
	tokens   token.Generator
	attempts policy.AttemptStore

	// engine and log are handed over once the chain exists, because an option
	// applied after EnableFormLogin may still replace either.
	engine *policy.Engine
	log    *slog.Logger

	now func() time.Time

	path          string
	usernameParam string
	passwordParam string
	bodyLimit     int64
	respond       LoginResponder
}

// wire takes the settings the chain resolved. It runs once, after every option
// has been applied, so a logger or an engine wired after EnableFormLogin is
// still the one this interceptor uses.
func (l *formLogin) wire(c *Chain) {
	l.engine = c.engine
	l.log = c.logger
}

// Intercept answers a login on the configured path and passes everything else
// through untouched.
func (l *formLogin) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost || ex.Request.Path() != l.path {
		return next(ex)
	}

	username, password, err := l.bind(ex.Request)
	if err != nil {
		return err
	}

	ctx := ex.Context()
	now := l.now()

	// Before the credential is checked, so a locked account is refused without
	// its password ever being tested. Testing it first would make the refusal
	// an oracle: a locked account would answer differently for a right guess
	// than for a wrong one.
	pre := evaluatePhase(ctx, l.engine, policy.PreAuthentication, &policy.Input{
		Username: username,
		Now:      now,
	})
	if pre.Outcome == policy.Deny {
		return policyDenyReason(pre)
	}

	auth, err := l.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	if err != nil {
		l.recordFailure(ctx, username, now)

		return err
	}

	l.resetFailures(ctx, username)

	ex.Authentication = auth

	tok, err := completeLogin(ex, loginTailDeps{
		engine:   l.engine,
		sessions: l.sessions,
		tokens:   l.tokens,
	}, postAuthenticationInput(
		auth.Principal, factor.Password, username, auth.PasswordChangedAt, now))
	if err != nil {
		return err
	}

	// A login is answered here, not by the application's handler: the handler
	// behind the chain serves the application, and there is no application
	// route for the library's own endpoint.
	return l.respond(ex, LoginResult{Token: tok, Session: ex.Session})
}

// bind reads the submitted identifier and password out of the request.
//
// The body is read under the bound first, because everything after it parses
// what was read: an unauthenticated endpoint that parses before it bounds has
// already spent the memory the bound exists to cap.
func (l *formLogin) bind(r Request) (string, []byte, error) {
	body, err := r.Body(l.bodyLimit)
	if err != nil {
		return "", nil, err
	}

	username, password := l.bindForm(r, body)

	// The JSON body is read only when the form yielded neither field, so a
	// form login is never re-read as JSON and a client that sent both is not
	// silently judged on the one it did not mean.
	if username == "" && password == "" {
		username, password, err = l.bindJSON(r, body)
		if err != nil {
			return "", nil, err
		}
	}

	if username == "" || password == "" {
		return "", nil, ErrCredentialsMissing
	}

	return username, []byte(password), nil
}

// bindForm reads the credentials out of the parsed POST body, and only out of
// it.
//
// Request.FormValue carries net/http's semantics, which merge the URL query
// into the form. A credential accepted from a query string is a credential
// already written into every access log, proxy log and browser history that
// saw the URL, and into the Referer the next page sends. A login is a body, so
// the query is not consulted here at all — Request.FormValue keeps its own
// semantics for the consumer interceptors that legitimately read a query
// parameter.
//
// A body that does not declare itself a form is left to bindJSON, and one that
// does not parse yields no credential rather than half of one: a pair the
// client did not send is not a pair this endpoint invents.
func (l *formLogin) bindForm(r Request, body []byte) (string, string) {
	if !declaresForm(r.Header("Content-Type")) {
		return "", ""
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", ""
	}

	return values.Get(l.usernameParam), values.Get(l.passwordParam)
}

// declaresForm reports whether a content type names the URL-encoded form
// media type, ignoring parameters such as a charset.
func declaresForm(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return media == "application/x-www-form-urlencoded"
}

// bindJSON reads the credentials from a body that declares itself JSON.
//
// A body that declares another media type is not read as JSON even when it
// would parse: what a body is, is what the request says it is, and guessing
// would let a client reach this path without saying so.
func (l *formLogin) bindJSON(r Request, body []byte) (string, string, error) {
	if len(body) == 0 || !declaresJSON(r.Header("Content-Type")) {
		return "", "", nil
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		// The client's mistake, and reported as one: it says nothing about the
		// account, because no account has been looked at yet.
		return "", "", ErrCredentialsMissing
	}

	username, _ := fields[l.usernameParam].(string)
	password, _ := fields[l.passwordParam].(string)

	return username, password, nil
}

// declaresJSON reports whether a content type names JSON, ignoring parameters
// such as a charset and accepting the +json structured suffix.
func declaresJSON(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return media == "application/json" || strings.HasSuffix(media, "+json")
}

// recordFailure counts one failed attempt, logging a store that could not.
//
// Bookkeeping, not the decision: a store that cannot record must not turn a
// wrong password into a server fault, and must not turn it into a success
// either. The refusal the caller returns is the same eitherway.
func (l *formLogin) recordFailure(ctx context.Context, username string, now time.Time) {
	if err := l.attempts.RecordFailure(ctx, username, now); err != nil {
		l.log.LogAttrs(ctx, slog.LevelError, msgAttemptNotRecorded,
			slog.String("error", err.Error()))
	}
}

// resetFailures clears what a successful login supersedes, logging a store
// that could not: an account whose failures outlive the login that cleared
// them locks a user who has just proved they are not guessing.
func (l *formLogin) resetFailures(ctx context.Context, username string) {
	if err := l.attempts.Reset(ctx, username); err != nil {
		l.log.LogAttrs(ctx, slog.LevelError, msgAttemptsNotReset,
			slog.String("error", err.Error()))
	}
}

// The records a broken attempt store is reported with. They are constants
// because the outcome they accompany is deliberately unchanged, so the record
// is the only place an operator learns the lockout count has stopped moving.
const (
	msgAttemptNotRecorded = "httpsec: a failed login attempt could not be recorded"
	msgAttemptsNotReset   = "httpsec: failed login attempts could not be cleared"
)

// evaluatePhase asks the engine for a phase's decision, allowing when no engine
// is wired.
//
// With no engine every phase allows, which is the documented default of
// WithPolicyEngine: a consumer who registers no policies rests on
// authentication alone rather than on a phase that refuses everything.
func evaluatePhase(
	ctx context.Context,
	e *policy.Engine,
	phase policy.Phase,
	in *policy.Input,
) policy.Decision {
	if e == nil {
		return policy.Decision{Outcome: policy.Allow}
	}

	return e.EvaluatePhase(ctx, phase, in)
}

// writeLoginResult is the response a login succeeds with when the consumer
// supplies none: a JSON document carrying the access token, an empty refresh
// token field and the session's idle expiry.
//
// The refresh token field is present and empty rather than absent, so a client
// written against this document does not have to be changed when a capability
// that issues refresh tokens starts filling it.
func writeLoginResult(ex *Exchange, result LoginResult) error {
	body := loginDocument{AccessToken: result.Token}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	//nolint:gosec // G117: the access token is the document's purpose, not a leak of one
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(encoded)

	return err
}

// loginDocument is the default success body. Its member names are the
// documented contract of that default: a consumer who wants other names
// replaces the whole responder rather than having this one reshaped.
type loginDocument struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ValidUntil   time.Time `json:"valid_until"`
}
