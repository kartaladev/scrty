package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/token"
)

// msgRecoveryLogsSuppressed is the record the recovery endpoints' own sampler
// writes for a key whose counts are about to be discarded.
const msgRecoveryLogsSuppressed = "httpsec: recovery logs suppressed"

// errRecoveredUserMissing refuses a completed recovery that carries no user:
// the recovery stands, but no credential names a principal it does not know.
// The core fills the user on every completed recovery, so this guards a
// broken invariant rather than an expected outcome.
var errRecoveredUserMissing = errors.New("httpsec: the completed recovery carries no user")

// textRecoveryUnreadable is the text a recovery body the transport failed to
// deliver is refused behind: the transport's own text is not the library's.
const textRecoveryUnreadable = "httpsec: the recovery request could not be read"

// recoverySingleFields are the complete endpoint's fields that carry one value.
// A client that sends one of them twice has sent a request whose meaning
// depends on which value a reader picks, so it is refused rather than read.
var recoverySingleFields = []string{
	RecoveryUsernameParam,
	RecoverySavedCodeParam,
	RecoveryIssuedCodeParam,
	RecoveryPasswordParam,
	RecoveryMFAMethodParam,
	RecoveryMFACodeParam,
}

// recoveryInterceptor answers the account-recovery endpoints.
type recoveryInterceptor struct {
	deps     RecoveryDeps
	coreOpts []recovery.Option
	tokens   token.Generator

	// issueCredential issues the recovered session's credential as the
	// chain's bearer mode decides, settled at assembly (resolve).
	issueCredential credentialIssuer

	// recoverer is built at assembly (resolve), from deps, coreOpts and the
	// chain's form login.
	recoverer *recovery.Recoverer

	completePath string
	startPath    string
	// startEnabled is whether the start endpoint is answered: only when the
	// core enables issued codes, the one thing it sends.
	startEnabled bool
	finishPath   string
	cancelPath   string
	// holds is whether the finish and cancel endpoints are answered: only
	// when the core may hold a recovery (recovery.Recoverer.Holds).
	holds     bool
	codesPath string
	// codesEnabled is whether the saved-code endpoints are answered: only
	// when the core enables saved codes. The recovery gate serves them.
	codesEnabled bool
	// freshness is how recent a session's latest authentication must be for
	// it to regenerate the user's saved codes.
	freshness time.Duration

	limiter      ratelimit.Limiter
	startLimiter ratelimit.Limiter
	guard        sourceGuard
	startGuard   sourceGuard

	countRefusals bool
	respond       RecoveryResponder
	respondHold   RecoveryHoldResponder
	respondCodes  RecoveryCodesResponder
	respondCount  RecoveryCountResponder

	// logInterval is the window the endpoints' own records are sampled over,
	// and sampler the sampler built from it once the chain's logger is known.
	logInterval time.Duration
	log         *slog.Logger
	sampler     *logsample.Sampler

	now func() time.Time
}

// check reports the wiring faults only the assembled configuration can see:
// the paths against each other and against the chain's login and logout, a
// chain with no way to bind the recovered session, and a recovery with no
// token generator to issue its credential through.
//
// It runs once every option has been applied, so a form login, a logout or a
// binding route enabled after EnableAccountRecovery still counts.
func (i *recoveryInterceptor) check(c *config, option string) error {
	if err := i.checkPaths(c, option); err != nil {
		return err
	}

	if !c.hasRecoveryBinding() {
		return newConfigError("%s needs a way to bind the recovered session: enable "+
			"EnableMFAEnrolment, EnablePasskeys with the passkey method on EnableMFA, or a "+
			"password-change resolve endpoint (WithPasswordChangeEndpoint), or a "+
			"recovery-pending session could never become a full one", option)
	}

	if c.sessionBearer {
		return checkTokenGenerator(c, option, "WithRecoveryTokens", i.tokens)
	}

	if i.tokens == nil && c.formLogin() == nil {
		return newConfigError("%s needs a token generator: supply WithRecoveryTokens, or enable "+
			"EnableFormLogin, whose generator it uses by default", option)
	}

	return nil
}

// endpointPaths are every path the recovery endpoints answer, named for a
// configuration error.
func (i *recoveryInterceptor) endpointPaths() []struct{ name, path string } {
	return []struct{ name, path string }{
		{"complete", i.completePath},
		{"start", i.startPath},
		{"finish", i.finishPath},
		{"cancel", i.cancelPath},
		{"codes", i.codesPath},
	}
}

// checkPaths refuses a recovery path that is empty, lacks a leading "/", or
// collides with another recovery path, the login path or the logout path.
// A collision with a passkey path is the passkey endpoints' check.
func (i *recoveryInterceptor) checkPaths(c *config, option string) error {
	paths := i.endpointPaths()

	taken := map[string]string{}
	if l := c.formLogin(); l != nil {
		taken[l.path] = "the login path"
	}
	if c.logoutPath != "" {
		taken[c.logoutPath] = "the logout path"
	}

	for _, p := range paths {
		if !strings.HasPrefix(p.path, "/") {
			return newConfigError("%s was given the %s path %q, which does not start with \"/\" "+
				"and so matches no request", option, p.name, p.path)
		}

		if other, ok := taken[p.path]; ok {
			return newConfigError("%s was given %q as its %s path, which is already %s: whichever "+
				"endpoint matched first would swallow the other", option, p.path, p.name, other)
		}

		taken[p.path] = "the recovery " + p.name + " path"
	}

	return nil
}

// formLogin returns the chain's form login, or nil when it has none.
func (c *config) formLogin() *formLogin {
	var found *formLogin

	_ = eachInterceptor(c, func(l *formLogin) error {
		if found == nil {
			found = l
		}

		return nil
	})

	return found
}

// hasRecoveryBinding reports whether the chain can bind a recovery-pending
// session: an enrolment path, passkey registration with the passkey method on
// the MFA slot to prove the new passkey at, or a password-change resolve
// endpoint.
func (c *config) hasRecoveryBinding() bool {
	found := c.passkeysOf() != nil && c.hasPasskeyMethod()

	_ = eachInterceptor(c, func(*enrolmentInterceptor) error {
		found = true

		return nil
	})

	_ = eachInterceptor(c, func(p *passwordChangeGate) error {
		if p.change != nil {
			found = true
		}

		return nil
	})

	return found
}

// wireAccountRecovery builds what the recovery endpoints cannot build until
// every option has been applied: the Recoverer, whose password check is the
// chain's form login and whose logger is the chain's, and the two source
// guards, whose limiters and logger are the chain's.
func (c *config) wireAccountRecovery() error {
	return eachInterceptor(c, func(i *recoveryInterceptor) error {
		return i.resolve(c)
	})
}

// resolve settles the interceptor's remaining collaborators against the
// assembled configuration.
func (i *recoveryInterceptor) resolve(c *config) error {
	const option = "EnableAccountRecovery"

	login := c.formLogin()

	if i.tokens == nil && login != nil {
		i.tokens = login.tokens
	}

	i.issueCredential = c.credentialIssuer(i.tokens)

	// The chain's logger, clock and limiter factory first, so a
	// recovery.WithLogger, recovery.WithClock or limiter option the consumer
	// passed replaces them; the password check last, so the chain's own always
	// wins. The factory is handed over only when the consumer configured one:
	// without it the core builds its own in-memory default, on the core's
	// logger and clock, which are the chain's unless the consumer replaced
	// them.
	opts := make([]recovery.Option, 0, len(i.coreOpts)+4)
	opts = append(opts, recovery.WithLogger(c.logger), recovery.WithClock(c.clock))

	if c.limiterFactory != nil {
		opts = append(opts, recovery.WithUserLimiterFactory(c.limiterFactory))
	}

	opts = append(opts, i.coreOpts...)

	if login != nil {
		opts = append(opts, recovery.WithPasswordCheck(login.checkPassword))
	}

	r, err := recovery.NewRecoverer(recovery.Deps(i.deps), opts...)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrConfig, option, err)
	}

	i.recoverer = r
	i.startEnabled = r.Enabled(recovery.ProofIssued)
	i.holds = r.Holds()
	i.codesEnabled = r.Enabled(recovery.ProofSaved)
	c.recoverer = r

	if i.holds {
		c.cancelHeldAtLogin(r.CancelPending)
	}

	i.guard, err = c.resolveSourceGuard(option, recoveryFlow, i.limiter,
		defaultRecoveryFailureLimit, defaultRecoveryFailureWindow, i.logInterval)
	if err != nil {
		return err
	}

	i.startGuard, err = c.resolveSourceGuard(option, recoveryStartFlow, i.startLimiter,
		defaultRecoveryStartLimit, defaultRecoveryStartWindow, i.logInterval)
	if err != nil {
		return err
	}

	return nil
}

// cancelHeldAtLogin hands cancel to every first factor that ends its login
// through completeLogin, so each cancels the user's held recoveries as soon as
// its first factor has authenticated, before the policy phase and before it
// creates the session: form login, magic link, OIDC and passwordless
// passkey login.
func (c *config) cancelHeldAtLogin(cancel heldRecoveryCanceller) {
	_ = eachInterceptor(c, func(l *formLogin) error {
		l.cancelHeld = cancel

		return nil
	})

	_ = eachInterceptor(c, func(i *magicLinkInterceptor) error {
		i.cancelHeld = cancel

		return nil
	})

	_ = eachInterceptor(c, func(i *oidcInterceptor) error {
		i.cancelHeld = cancel

		return nil
	})

	_ = eachInterceptor(c, func(i *passwordlessInterceptor) error {
		i.cancelHeld = cancel

		return nil
	})
}

// wire takes the chain's logger once every option has been applied, and
// builds the endpoints' own log sampler, whose reporter writes through it.
func (i *recoveryInterceptor) wire(c *Chain) {
	i.log = c.logger
	i.sampler = logsample.New(i.logInterval, logsample.WithReporter(i.reportSuppressed))
}

// reportSuppressed writes what the sampler held back for key and is about to
// forget. It runs on whichever request or flush evicted the key, and that
// request's context has nothing to do with the counts, so it is written
// without one.
func (i *recoveryInterceptor) reportSuppressed(key string, suppressed int) {
	i.log.LogAttrs(context.Background(), slog.LevelWarn, msgRecoveryLogsSuppressed,
		slog.String("key", key), slog.Int("suppressed", suppressed))
}

// flushRefusalLogs reports what the endpoints' own sampler and both source
// guards are holding back.
func (i *recoveryInterceptor) flushRefusalLogs() error {
	if i.sampler != nil {
		i.sampler.Flush()
	}

	if i.guard != nil {
		i.guard.Flush()
	}

	if i.startGuard != nil {
		i.startGuard.Flush()
	}

	return nil
}

// Intercept answers the recovery endpoints and passes everything else through.
//
// Every endpoint is POST-only on its exact path: a start sends mail, a
// completion or finish spends credentials, and a cancel ends a recovery, so
// none is something a link, an image tag or a mail scanner's prefetch may
// trigger. The start endpoint exists only when the core enables issued codes,
// and the finish and cancel endpoints only when it may hold a recovery;
// otherwise their paths reach the application like any other.
func (i *recoveryInterceptor) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost {
		return next(ex)
	}

	switch path := ex.Request.Path(); {
	case path == i.completePath:
		return i.complete(ex)
	case path == i.startPath && i.startEnabled:
		return i.start(ex)
	case path == i.finishPath && i.holds:
		return i.finish(ex)
	case path == i.cancelPath && i.holds:
		return i.cancel(ex)
	default:
		return next(ex)
	}
}

// complete answers a POST to the complete path.
//
// The source is checked first, so an unattributable or throttled source is
// refused before the body is read and before any proof is looked at, with the
// same refusal a wrong code gets. Then the body is read, and a request that
// cannot be read as one recovery is refused as malformed, counted nowhere.
// Then the recovery runs, and a failure counts against the source unless
// countsAgainstRecoverySource exempts it.
//
// A recovery that succeeds or is held is answered with Cache-Control:
// no-store, set here before the responder runs: the response carries a
// credential, codes shown once, or a completion token. A consumer responder
// may still replace the header.
func (i *recoveryInterceptor) complete(ex *Exchange) error {
	ctx := ex.Context()

	src, err := sourceThrottled(ctx, i.guard, ex.Request.ClientIP(), recoveryFlow, i.sampler, i.log, i.now())
	if err != nil {
		return recovery.ErrRefused
	}

	req, err := readRecoveryRequest(ex.Request)
	if err != nil {
		return err
	}

	req.Source = src.Addr()

	res, err := i.recoverer.Recover(ctx, req)
	if err != nil {
		if countsAgainstRecoverySource(i.countRefusals, err) {
			recordSourceFailure(ctx, i.guard, src)
		}

		// The recovery's error, unchanged: the core already answers every
		// refused proof with one refusal, and a consumer check's error is the
		// consumer's own to read.
		return err
	}

	return i.answer(ex, res)
}

// answer writes the response to a recovery that completed or was held, for
// the complete and finish endpoints alike, so a finished recovery is answered
// exactly as one that completed at once.
//
// Cache-Control: no-store is set before the responder runs: the response
// carries a credential, codes shown once, or a completion token. A consumer
// responder may still replace the header.
func (i *recoveryInterceptor) answer(ex *Exchange, res *recovery.Result) error {
	ctx := ex.Context()

	if res.Held != nil {
		ex.Writer.SetHeader("Cache-Control", "no-store")

		return i.respondHold(ex, *res.Held)
	}

	tok, err := i.issue(ctx, res)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Cache-Control", "no-store")

	ex.Session = res.Session
	ex.SetContext(withSession(ctx, res.Session))

	return i.respond(ex, RecoveryResult{Token: tok, Recovery: res})
}

// issue issues the credential for the recovery-pending session a recovery
// produced, as the chain's bearer mode decides: an access token, or the
// session's own identifier. A token names a principal, minted from the user
// details the recovery itself loaded (recovery.Result.Details), never by
// loading the user again: a second lookup could fail after the saved codes
// were replaced, and the new codes would be lost with the response.
func (i *recoveryInterceptor) issue(ctx context.Context, res *recovery.Result) (string, error) {
	if res.Details == nil {
		return "", errRecoveredUserMissing
	}

	return i.issueCredential(ctx, res.Session, identity.PrincipalFromDetails(res.Details))
}

// countsAgainstRecoverySource decides whether a failed recovery is recorded
// against the source that made it.
//
// A malformed request is counted nowhere: it is the client's mistake, checked
// before any proof, and says nothing about a guess. A refusal after the
// recovery codes passed is counted unless the consumer turned that off. Every
// other failure is counted: a refused code, an unknown or throttled user, and
// any dependency outage the recovery met.
//
// That includes an error matching authenticate.ErrUnavailable, which the
// password proof returns when its user store could not answer. No password
// was compared, and the recovery counts nothing against the user's recovery
// limit, but the source pays, because its limit is what bounds the password
// work an outage costs. A load the caller's own cancellation ended
// is not that error: the password proof refuses it, marked as a refusal after
// the codes passed, so it is counted as such a refusal is, though nothing is
// recorded against the account or the user's recovery limit.
func countsAgainstRecoverySource(countRefusals bool, err error) bool {
	if errors.Is(err, recovery.ErrMalformed) {
		return false
	}

	if recovery.RefusedAfterValidCode(err) {
		return countRefusals
	}

	return true
}

// readRecoveryRequest reads a recovery out of the POST body, and only out of
// it.
//
// A recovery carries credentials, and a credential accepted from a query
// string is one already written into every access log, proxy log and browser
// history that saw the URL, so the query is never consulted. The body is read
// as a URL-encoded form only, under recoveryBodyLimit; a body over it is
// ErrRequestTooLarge. A body that is not such a form, that does not parse, or
// that carries a single-valued field more than once is recovery.ErrMalformed.
// A body with no proofs at all reads as an empty recovery, which the core
// refuses as malformed in turn.
func readRecoveryRequest(r Request) (recovery.Request, error) {
	values, err := readRecoveryForm(r)
	if err != nil || values == nil {
		return recovery.Request{}, err
	}

	for _, name := range recoverySingleFields {
		if len(values[name]) > 1 {
			return recovery.Request{}, recovery.ErrMalformed
		}
	}

	req := recovery.Request{
		Username:  values.Get(RecoveryUsernameParam),
		Saved:     values.Get(RecoverySavedCodeParam),
		Issued:    values.Get(RecoveryIssuedCodeParam),
		MFAMethod: values.Get(RecoveryMFAMethodParam),
		MFACode:   values.Get(RecoveryMFACodeParam),
		Lost:      values[RecoveryLostParam],
	}

	if p := values.Get(RecoveryPasswordParam); p != "" {
		req.Password = []byte(p)
	}

	return req, nil
}

// readRecoveryForm reads a recovery endpoint's URL-encoded body, and only it:
// under recoveryBodyLimit, where a body over it is ErrRequestTooLarge, and one
// that is not such a form or does not parse is recovery.ErrMalformed. An empty
// body reads as nil values.
func readRecoveryForm(r Request) (url.Values, error) {
	body, err := r.Body(recoveryBodyLimit)
	if errors.Is(err, ErrRequestTooLarge) {
		return nil, ErrRequestTooLarge
	}

	if err != nil {
		return nil, refusedAs(recovery.ErrMalformed, textRecoveryUnreadable, err)
	}

	if len(body) == 0 {
		return nil, nil
	}

	if !declaresForm(r.Header("Content-Type")) {
		return nil, recovery.ErrMalformed
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, recovery.ErrMalformed
	}

	return values, nil
}

// writeRecoveryResult is the response a completed recovery succeeds with when
// the consumer supplies no responder.
//
// It carries the access token, the session's idle expiry, the new saved codes
// or null, and how many saved codes the user holds and whether that is low,
// as the core counted them (recovery.Result.Remaining): after a reissue, the
// new set. It is never cached: it carries a credential and, possibly, codes
// shown only once.
func writeRecoveryResult(ex *Exchange, result RecoveryResult) error {
	body := recoveryDocument{AccessToken: result.Token}

	if s := recoverySession(result.Recovery); s != nil {
		body.ExpiresAt = s.IdleExpiresAt
	}

	if res := result.Recovery; res != nil {
		body.RecoveryCodes = res.Codes
		body.Remaining = res.Remaining.N
		body.Low = res.Remaining.Low
	}

	ex.Writer.SetHeader("Cache-Control", "no-store")

	return writeSuccessDocument(ex, body)
}

// recoveryDocument is the default success body. Its member names are the
// documented contract of that default: a consumer who wants other names
// replaces the whole responder.
type recoveryDocument struct {
	AccessToken   string    `json:"access_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	RecoveryCodes []string  `json:"recovery_codes"`
	Remaining     int       `json:"remaining"`
	Low           bool      `json:"low"`
}

// writeRecoveryHold is the response a held recovery is answered with when the
// consumer supplies no responder: 202, with the completion token and the
// instant it can be presented. It is never cached, since the token finishes
// the recovery.
func writeRecoveryHold(ex *Exchange, hold recovery.Hold) error {
	encoded, err := json.Marshal(recoveryHoldDocument{
		CompletionToken: hold.CompletionToken,
		CompletableAt:   hold.CompletableAt,
	})
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(http.StatusAccepted)
	_, err = ex.Writer.Write(encoded)

	return err
}

// recoveryHoldDocument is the default hold body.
type recoveryHoldDocument struct {
	CompletionToken string    `json:"completion_token"`
	CompletableAt   time.Time `json:"completable_at"`
}

//go:generate mockgen -destination=onetimestore_mock_test.go -package=httpsec_test -typed -mock_names=Store=MockOnetimeStore github.com/kartaladev/scrty/token/onetime Store

// start answers a POST to the start path.
//
// It answers identically whatever happened, and never passes the request on:
// 202 with an empty body and no cookie, for a code sent, an unknown or
// disabled username, a lookup that failed, a reached issuance limit, a token
// store or sender that failed, a body that could not be read, and a source
// that is throttled or cannot be attributed. The core logs each cause
// server-side; nothing here tells them apart.
//
// Every start is counted against its source, whatever it did, because what
// the guard bounds is how often one source asks for mail to be sent. A source
// over its allowance, or one that cannot be attributed, starts nothing.
func (i *recoveryInterceptor) start(ex *Exchange) error {
	ctx := ex.Context()

	src, err := sourceThrottled(ctx, i.startGuard, ex.Request.ClientIP(), recoveryStartFlow,
		i.sampler, i.log, i.now())
	if err == nil {
		recordSourceFailure(ctx, i.startGuard, src)

		// An empty username names no account, so there is nothing to start:
		// a body that could not be read is not a question about one.
		if username := readRecoveryStart(ex.Request); username != "" {
			i.recoverer.Start(ctx, username)
		}
	}

	ex.Writer.WriteHeader(http.StatusAccepted)

	return nil
}

// readRecoveryStart reads the submitted username from a URL-encoded form or a
// JSON body, and only from the body.
//
// Every failure degrades to an empty username rather than an error: a
// different answer for a malformed request is still a different answer, and a
// scanner would use it. That includes a body over the bound and a username
// given more than once.
func readRecoveryStart(r Request) string {
	body, err := r.Body(recoveryBodyLimit)
	if err != nil || len(body) == 0 {
		return ""
	}

	declared := r.Header("Content-Type")

	if declaresForm(declared) {
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values[RecoveryUsernameParam]) != 1 {
			return ""
		}

		return values.Get(RecoveryUsernameParam)
	}

	if !declaresJSON(declared) {
		return ""
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		return ""
	}

	username, _ := fields[RecoveryUsernameParam].(string)

	return username
}

//go:generate mockgen -destination=recordstore_mock_test.go -package=httpsec_test -typed -mock_names=RecordStore=MockRecordStore github.com/kartaladev/scrty/recovery RecordStore

// finish answers a POST to the finish path of a held recovery.
//
// The body is read exactly as the complete endpoint reads its own: a
// URL-encoded form of at most 16 KiB, never the query, with the completion
// token given once. A request that cannot be read so, or carries no token, is
// recovery.ErrMalformed. Then the core finishes the recovery, and its error is
// returned unchanged: recovery.ErrNotYetCompletable before the hold is over,
// recovery.ErrRefused for a token that is unknown, spent, of another purpose
// or past its window, or whose recovery was cancelled.
//
// A finish that succeeds is answered exactly as a completion is: the access
// token for the recovery-pending session, through the recovery responder,
// with Cache-Control: no-store.
//
// No source guard stands in front of it. The completion token is a 256-bit
// one-time secret handed only to the client that presented both proofs, so
// there is nothing a source could guess, and the endpoint checks no proof a
// throttle would protect. A per-source allowance would add only a way for
// someone behind the same address to spend it and lock the user out of their
// own finish.
func (i *recoveryInterceptor) finish(ex *Exchange) error {
	token, err := readHoldToken(ex.Request, RecoveryCompletionTokenParam)
	if err != nil {
		return err
	}

	if token == "" {
		return recovery.ErrMalformed
	}

	res, err := i.recoverer.Finish(ex.Context(), token)
	if err != nil {
		return err
	}

	return i.answer(ex, res)
}

// cancel answers a POST to the cancel path of a held recovery.
//
// It answers 204 with an empty body whatever happened: a recovery cancelled,
// a token that is garbage, spent, of another purpose (a completion token
// included) or missing, a body that cannot be read, and a store that failed.
// The core logs each cause server-side and returns nothing, so nothing here
// could tell them apart even by accident, and the endpoint reveals nothing
// about which tokens or recoveries exist. For the same reason it has no source
// guard: a refusal would be an answer of its own.
func (i *recoveryInterceptor) cancel(ex *Exchange) error {
	if token, err := readHoldToken(ex.Request, RecoveryCancelTokenParam); err == nil && token != "" {
		i.recoverer.Cancel(ex.Context(), token)
	}

	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}

// readHoldToken reads the single field name out of a finish or cancel body, by
// the same rules the complete endpoint reads its own: a URL-encoded form under
// recoveryBodyLimit, never the query. A body over the bound is
// ErrRequestTooLarge; one that is not such a form, does not parse, or carries
// the field more than once is recovery.ErrMalformed. An empty body, or one
// without the field, reads as an empty token.
func readHoldToken(r Request, name string) (string, error) {
	values, err := readRecoveryForm(r)
	if err != nil {
		return "", err
	}

	if len(values[name]) > 1 {
		return "", recovery.ErrMalformed
	}

	return values.Get(name), nil
}
