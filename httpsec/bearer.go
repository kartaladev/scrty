package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=verifier_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/token Verifier
//go:generate mockgen -destination=userloader_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/identity UserLoader

// DefaultBearerScheme is the Authorization scheme bearer tokens are presented
// under when the consumer names none. It is matched without regard to case,
// as RFC 7235 requires of an authentication scheme.
const DefaultBearerScheme = "Bearer"

// bearerToken authenticates a token against a live session and a live user.
type bearerToken struct {
	verifier token.Verifier
	sessions *session.Sessions
	users    identity.UserLoader

	// log is the chain's logger, and sampler the chain's refusal-log sampler,
	// both handed over by wire.
	log     *slog.Logger
	sampler *refusalSampler

	// resolver is the resolution core the bearer joins once its token has
	// verified, built by wire over the bearer's own session manager and user
	// loader and the chain's engine, enforcer set and enrolment lifetime.
	resolver sessionResolver

	now func() time.Time

	scheme           string
	allowEmptyScheme bool

	// dpop is the chain's DPoP verifier, handed over at assembly, and nil
	// while DPoP is off.
	dpop *dpopVerifier

	// subject is what the token's subject is read as: the user identifier by
	// default, and the username under WithBearerUsernameSubject.
	subject token.SubjectMode
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *bearerToken) wire(c *Chain) {
	b.log = c.logger
	b.sampler = c.sampler
	b.resolver = sessionResolver{
		sessions: b.sessions,
		users:    b.users,
		log:      c.logger,
		phase: perRequestPhase{
			engine:            c.engine,
			sessions:          b.sessions,
			enrolmentLifetime: c.enrolmentLifetime,
			enforced:          c.enforced,
			now:               b.now,
		},
	}
}

// Intercept authenticates a bearer token against a live session and a live
// user.
//
// It writes no WWW-Authenticate header itself. With EnableDPoP the chain's
// challenge interceptor adds the DPoP and Bearer challenges to the refusals
// that come back through it; a consumer's WithErrorHandler can remove them
// from the response headers.
//
// A token the verifier rejects is recorded at debug with the verifier's own
// text, kept on purpose: it names the check the token failed (expired, wrong
// signature, wrong audience), which is what an operator chasing a rejected
// client needs, and it is the library's protocol-failure text rather than a
// store's. A token that could not be checked because the verification keys
// were unavailable is a dependency failure, and one whose request ended while
// it was verified is a hang-up, neither refused nor an outage (notVerified).
// Every dependency failure that is recorded is recorded by a fixed reason and
// its error's Go type, never its text, and every one returned comes back
// behind fixed text, its error still matching through errors.Is and
// errors.As. A consumer who wants a store's full error logs it inside their
// own implementation.
func (b *bearerToken) Intercept(ex *Exchange, next Next) error {
	// A credential the resource server accepted as an access token is not
	// this mode's to judge again.
	if ex.accessTokenClaimed {
		return next(ex)
	}

	presented, underDPoP, ok := presentedBearer(ex.Request.Header("Authorization"),
		b.scheme, b.allowEmptyScheme, b.dpop)
	if !ok {
		return next(ex)
	}

	ctx := ex.Context()

	claims, err := b.verifier.Verify(ctx, presented)
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)

	if err != nil {
		return b.notVerified(ex, err)
	}

	// The token's binding is judged before its session is looked up, so a
	// stolen bound token costs no store read, and a token whose binding the
	// chain cannot honour is never taken for a plain bearer token.
	cnf := claims.Confirmation()
	proof, err := b.admitBinding(ex, underDPoP, presented, cnf)
	if err != nil {
		return err
	}

	// The session's own binding must be the token's, so a token reported
	// without its cnf (a consumer's Verifier, NewClaims) does not unbind a
	// bound sign-in. The subject is judged next, so a wrong sender is answered
	// as that whatever the token names. The proof is recorded only then, last,
	// so a refused subject consumes none.
	//
	// All of it is judged here rather than after resolution because this step
	// is also the only one a session a late renewal may recover goes through:
	// resolution returns early for it and hands this step on to the renewal
	// endpoint (session_renewal.go), so a token naming another user could
	// otherwise renew that session. That holds in either subject mode, so under
	// usernames the user is loaded here, and the record returned for whichever
	// of the two carries on.
	subject := claims.Subject()

	resolver := b.resolver
	resolver.admit = func(ex *Exchange, s *session.Session) (*identity.Details, error) {
		if s.KeyBinding.JKT != cnf.JKT {
			if b.dpop == nil {
				return nil, ErrInvalidDPoPProof
			}

			return nil, b.dpop.refuse(ex.Context(), reasonProofBinding)
		}

		if s.KeyBinding.X5TS256 != cnf.X5TS256 {
			return nil, ErrCertificateBinding
		}

		details, err := b.admitSubject(ex.Context(), subject, s)
		if err != nil {
			return nil, err
		}

		if err := recordProof(ex.Context(), b.dpop, proof); err != nil {
			return nil, err
		}

		return details, nil
	}

	// The session identifier is the token's jti, which is how a token issued at
	// login finds the session it was issued for.
	if err := resolver.resolve(ex, claims.ID()); err != nil {
		ex.recordThrottledBearer(err, presented)

		return err
	}

	ex.RecordPresentedToken(presented)

	return next(ex)
}

// admitSubject judges a verified token's subject against the session it names.
//
// A token with no subject identifies nobody and is refused in either mode, with
// no user loaded. By default the subject must be the user reference s records,
// which needs no load either, and the returned record is nil.
//
// Under WithBearerUsernameSubject the subject is a username, which only the user
// store can resolve. It is loaded here and must be the user s records. The record
// is returned, so neither resolution nor a late renewal's endpoint loads it a second
// time. A load that fails is answered as resolution answers one (classifyReload).
//
// The refusal is ErrAuthenticationRequired and revokes nothing: nothing has been
// recorded on s, and the session's own user can still use it.
func (b *bearerToken) admitSubject(ctx context.Context, subject string, s *session.Session) (*identity.Details, error) {
	if subject == "" {
		return nil, ErrAuthenticationRequired
	}

	if b.subject != token.SubjectUsername {
		if identity.UserID(subject) != s.UserID {
			return nil, ErrAuthenticationRequired
		}

		return nil, nil
	}

	details, err := b.users.LoadByUsername(ctx, subject)
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)

	if err != nil {
		return nil, classifyReload(ctx, err)
	}

	if !ownsSession(s, details) {
		return nil, ErrAuthenticationRequired
	}

	return details, nil
}

// notVerified answers a token the verifier did not accept, with err.
//
// Only a token the verifier rejected (token.ErrInvalid) is refused, with
// authenticate.ErrAuthenticationFailed joined rather than wrapped: an
// operator's log records which check the token failed, while a caller still
// matches the one uniform failure. The cause reaches the record, never the
// client. The refusal is reported as event.AuthnLoginFail on a request a
// sink watches.
//
// A verdict wins over a hang-up: a rejection is classified first, so an err
// that matches token.ErrInvalid is a refusal, answered and reported as one,
// even when the request's own context ended beside it and err carries that
// context's error too.
//
// A request whose own context ended while its token was verified, and whose
// err is that context's error or the cause it was cancelled with
// (hangup.ByCaller) with no rejection, is a hang-up: neither a refusal, since
// no verdict was reached, nor an outage, since nothing failed, and nothing is
// reported.
// It is returned behind fixed text of its own, or as the context's error
// itself when the verifier returns it bare, matching the context's error
// either way, and recorded at debug with no error text. It is told by the
// request's own context, never by err alone: a key source that times out on a
// deadline of its own while the request still waits is an outage.
//
// Anything else, a key source that could not supply the keys above all, is a
// dependency failure: the check never happened, and answering it as a refused
// token would send every client back to authenticate during an outage. It is
// returned behind fixed text with err reachable, which the default status
// mapping answers with 500, and recorded at ERROR by a fixed reason and err's
// type, never its text, which a consumer's key source may word with the key it
// could not reach. The record is sampled per window, since during an outage
// every request writes one.
func (b *bearerToken) notVerified(ex *Exchange, err error) error {
	ctx := ex.Context()

	if errors.Is(err, token.ErrInvalid) {
		b.log.LogAttrs(ctx, slog.LevelDebug, msgBearerNotVerified,
			slog.String("error", err.Error())) //nolint:forbidigo // stated exception (design decision 6): token verification text at debug

		// A verdict wins over a hang-up: the token was refused, so the
		// refusal is reported even when the request's own context ended
		// beside it.
		emitEvent(ctx, event.Event{Name: event.AuthnLoginFail, Outcome: event.OutcomeFailure})

		return errors.Join(authenticate.ErrAuthenticationFailed, err)
	}

	if hangup.ByCaller(ctx, err) {
		b.log.LogAttrs(ctx, slog.LevelDebug, msgBearerVerificationEnded)

		return diag.Wrap(err, textVerificationEnded, ctx.Err())
	}

	logSampled(ctx, b.sampler, b.log, slog.LevelError, b.now(),
		bearerFlow+sampleKeySeparator+reasonVerificationKeys, msgBearerKeysUnavailable,
		diag.Failure(reasonVerificationKeys, err)...)

	return diag.Wrap(err, textVerificationKeysUnavailable)
}

// admitBinding judges a verified token's confirmation claim: a binding the
// chain cannot honour is refused, a certificate binding is judged against the
// request's certificate, and with DPoP on, the proof presented with it is
// verified, its ath over the token, and must come from the bound key
// (admitBinding). It returns the verified proof, which is recorded once the
// session's own binding has been judged.
//
// A token bound to a certificate is judged without verifying a proof: with
// certificate binding on, one presented under the DPoP scheme is refused for
// that alone, since it is not bound to a DPoP key. With certificate binding off
// it is refused for its binding (ErrCertificateBinding) whatever the scheme.
func (b *bearerToken) admitBinding(ex *Exchange, underDPoP bool, tok string, cnf token.Confirmation) (*dpopProof, error) {
	if cnf.X5TS256 != "" || len(cnf.Other) > 0 {
		if underDPoP && ex.certBinding() != nil && cnf.JKT == "" && len(cnf.Other) == 0 {
			return nil, b.dpop.refuse(ex.Context(), reasonProofBinding)
		}

		return nil, admitBinding(ex, b.dpop, nil,
			keyBinding{jkt: cnf.JKT, x5tS256: cnf.X5TS256, other: len(cnf.Other) > 0})
	}

	proof, err := presentedProof(ex.Context(), b.dpop, ex.Request, underDPoP, tok)
	if err != nil {
		return nil, err
	}

	return proof, admitBinding(ex, b.dpop, proof, keyBinding{jkt: cnf.JKT})
}

// presentedCredential reports the credential an Authorization header carries
// under scheme, and whether the header is claimed at all. Both bearer modes
// extract through it, so they claim exactly the same headers.
//
// The scheme is compared without regard to case, as RFC 7235 requires, which is
// deliberately unlike the exact match Basic authentication makes: a bearer
// credential's scheme is the one this chain issues credentials under, whereas
// "Basic" names a scheme whose neighbours share the header. A header naming the
// scheme with nothing after it is not claimed.
func presentedCredential(header, scheme string, allowEmptyScheme bool) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}

	got, rest, found := strings.Cut(header, " ")
	if !found {
		// A bare credential is indistinguishable from another scheme's opaque
		// token, so it is claimed only where the consumer said this header
		// carries nothing else.
		if allowEmptyScheme {
			return header, true
		}

		return "", false
	}

	if !strings.EqualFold(got, scheme) {
		return "", false
	}

	if presented := strings.TrimSpace(rest); presented != "" {
		return presented, true
	}

	return "", false
}

// msgBearerNotVerified reports a token that did not verify. It is at debug
// because a stream of expired tokens is ordinary traffic.
const msgBearerNotVerified = "httpsec: a bearer token did not verify" //nolint:gosec // G101: a log message naming what failed, not a credential

// What a bearer token that could not be checked, because the verification keys
// could not be obtained, is recorded and returned with.
const (
	// bearerFlow names the bearer's sampler keys.
	bearerFlow = "bearer"

	reasonVerificationKeys          = "verification-keys"
	msgBearerKeysUnavailable        = "httpsec: a bearer token could not be checked; the verification keys are unavailable" //nolint:gosec // G101: a log message naming what failed, not a credential
	textVerificationKeysUnavailable = "httpsec: verification keys unavailable"
)

// What a bearer token whose request ended while it was verified is recorded
// and returned with. The text is its own, so an error handler that logs by
// text does not report a client that left as a key outage.
const (
	msgBearerVerificationEnded = "httpsec: the request ended while its bearer token was verified" //nolint:gosec // G101: a log message naming what happened, not a credential
	textVerificationEnded      = "httpsec: the request ended while its token was verified"
)

// BearerTokenDeps are the collaborators bearer authentication is wired to.
//
// All three are required. The session manager and the user loader are what make
// a bearer token a reference to live state rather than a self-contained grant:
// without them a revoked session and a revoked role would both be honoured for
// the rest of the token's life.
type BearerTokenDeps struct {
	// Verifier checks the presented token and reports its claims. A
	// token.Generator given here is checked against the bearer's subject mode
	// like any other the chain is given; one hidden behind a verifier that does
	// not itself implement token.Generator cannot be seen.
	Verifier token.Verifier

	// Sessions loads the session the token's jti names.
	Sessions *session.Sessions

	// Users reloads the session's user, so the roles the request is judged on
	// are the ones the store holds now: by the user reference the session
	// records, or under WithBearerUsernameSubject by the username the token's
	// subject names.
	Users identity.UserLoader
}

// BearerTokenOption configures bearer authentication.
type BearerTokenOption func(*bearerToken) error

// EnableBearerToken authenticates bearer tokens at the bearer slot.
//
// Default: the scheme DefaultBearerScheme, matched without regard to case, and
// a token presented with no scheme at all is ignored. Requests carrying another
// scheme, or no Authorization header, pass through untouched.
//
// Default: a token's subject is the user identifier, as token.NewGenerator
// writes it. A token whose subject is not the user reference its session
// records, or that has no subject, is refused with ErrAuthenticationRequired,
// before any user reload and before any DPoP proof is recorded. The session is
// not revoked, its activity is not recorded and the per-request phase does not
// run. WithBearerUsernameSubject reads the subject as a username instead. New
// fails with a configuration error when any token generator the chain is given,
// the bearer's own Verifier included, reports a mode other than the bearer's
// (token.Generator.SubjectMode), and when two signed bearers on the chain
// disagree on the mode, whatever their schemes. A generator outside the chain, or
// hidden behind a verifier that does not itself implement token.Generator, cannot
// be seen, and its tokens are refused as above.
//
// Refusals and failures are kept apart. A token the verifier rejects
// (token.ErrInvalid) is refused with authenticate.ErrAuthenticationFailed, a
// 401, joined to the verifier's error. A session that is missing, expired or
// undecryptable, a superseded identifier presented after its window, and a user
// who no longer exists, is not the session's or is not active, are refused
// with ErrAuthenticationRequired, a 401. A failure of a dependency is not a
// refusal: a verification key source that cannot supply its keys, a session
// store or cipher outage while the session loads, and a user store outage
// while the user reloads each fail the request with fixed library text, the
// dependency's error reachable through errors.Is and errors.As, and matching
// neither ErrAuthenticationRequired nor authenticate.ErrAuthenticationFailed.
// The default status mapping answers them with 500; a consumer who wants
// another answer, 503 with Retry-After for example, matches the cause in the
// handler given to WithErrorHandler. A request whose own context ended while
// its session loaded or its user reloaded fails with an error matching that
// context's error, and is neither refused nor reported as an outage; so does
// one whose context ended while its token was verified, with fixed text of
// its own (or the context's error itself, when the verifier returns it bare)
// and no ERROR record. A verification key source that times out on a
// deadline of its own while the request is still live is an outage.
//
// A token the verifier rejects is recorded at debug with the verifier's own
// text, kept on purpose: it is the library's own protocol-failure text, not a
// dependency's, and names the check the token failed (expired, wrong
// signature, wrong audience), which an operator chasing a rejected client
// needs. A verification key source that cannot supply its keys is recorded at
// ERROR, sampled per window. That record, and those for an unreadable session
// and a failed save while marking a challenge, carry a fixed reason and the
// error's Go type, never its text, and a failed save is returned wrapped in
// fixed library text, its error still matching through errors.Is and
// errors.As. A consumer who wants a dependency's full error logs it inside
// their own implementation of the port: the token.Verifier's key source, or
// the stores and loader of BearerTokenDeps.
func EnableBearerToken(deps BearerTokenDeps, opts ...BearerTokenOption) Option {
	const option = "EnableBearerToken"

	return func(c *config) error {
		b := &bearerToken{
			verifier: deps.Verifier,
			sessions: deps.Sessions,
			users:    deps.Users,
			now:      c.now,
			scheme:   DefaultBearerScheme,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(b); err != nil {
				return err
			}
		}

		c.bindingVerifiers = append(c.bindingVerifiers, option)

		c.enable(option, func() error {
			if err := requireDep(option, "token verifier", deps.Verifier); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", deps.Sessions); err != nil {
				return err
			}
			if err := requireDep(option, "user loader", deps.Users); err != nil {
				return err
			}
			if err := b.checkOtherBearers(c, option); err != nil {
				return err
			}

			// A generator given as the verifier is one more generator the chain
			// is given. One hidden behind a verifier that does not itself implement
			// token.Generator cannot be seen.
			if g, ok := deps.Verifier.(token.Generator); ok {
				return checkSubjectGenerator(c, option, "BearerTokenDeps.Verifier", g)
			}

			return nil
		})

		c.useSessions(deps.Sessions)
		c.wire(b.wire)
		// The renewal endpoint may be enabled after this option, so it is
		// handed to the core once every option has been applied.
		c.wire(func(*Chain) { b.resolver.renewal = c.renewal })
		// EnableDPoP may come after this option too.
		c.wire(func(*Chain) { b.dpop = c.dpop })
		c.register(b, OrderBearerToken)

		return nil
	}
}

// checkOtherBearers refuses a chain with another signed bearer that reads the
// subject differently from b. No generator could agree with both, and a request
// goes through both when their schemes overlap, so the second would refuse every
// token the first accepts.
//
// It runs in validate, once every option has been applied, so the order of the
// bearers does not matter.
func (b *bearerToken) checkOtherBearers(c *config, option string) error {
	return eachInterceptor(c, func(other *bearerToken) error {
		if other.subject == b.subject {
			return nil
		}

		return newConfigError("%s was enabled twice with different subject modes, one reading the "+
			"subject as %s and the other as %s, whatever their schemes: no token generator could agree "+
			"with both; use WithBearerUsernameSubject on both or on neither",
			option, subjectModeName(b.subject), subjectModeName(other.subject))
	})
}

// WithBearerScheme presents tokens under scheme instead.
//
// Default: DefaultBearerScheme. The scheme is matched without regard to case
// either way. An empty scheme is refused: it would claim every Authorization
// header, including those of the schemes at neighbouring slots. Use
// WithBearerAllowEmptyScheme to accept a bare token as well.
func WithBearerScheme(scheme string) BearerTokenOption {
	return func(b *bearerToken) error {
		if strings.TrimSpace(scheme) == "" {
			return newConfigError("WithBearerScheme was given no scheme, which would claim " +
				"every Authorization header")
		}

		if strings.ContainsAny(scheme, " \t") {
			return newConfigError("WithBearerScheme was given %q, and a scheme is the one token "+
				"before the credential, so it can hold no space", scheme)
		}

		b.scheme = scheme
		return nil
	}
}

// WithBearerAllowEmptyScheme also accepts a token presented with no scheme.
//
// Default: off, so an Authorization header carrying a bare credential is left
// for whichever interceptor claims it. Turn it on for clients that send the
// token alone; it does not stop the configured scheme being accepted.
//
// The line it does not cross: a bare credential is indistinguishable from
// another scheme's opaque token, so a chain that enables this and another
// credential-bearing scheme hands both to whichever slot runs first. Enable it
// only where bearer tokens are the one thing that header carries.
func WithBearerAllowEmptyScheme() BearerTokenOption {
	return func(b *bearerToken) error {
		b.allowEmptyScheme = true
		return nil
	}
}

// WithBearerUsernameSubject reads a token's subject as a username, and reloads
// the user by that username.
//
// Default: the subject is the user identifier, the token must name the user
// reference its session records, and the user is reloaded by that reference.
//
// It is for a consumer whose tokens carry the name. It must agree with
// token.WithUsernameSubject on the generator, which New enforces for every
// generator the chain is given, the bearer's own Verifier included, by failing
// with a configuration error. It must also agree with
// authenticate.WithJWTUsernameSubject on any standalone JWT authenticator
// reading the same tokens, and with a generator hidden behind a verifier that
// does not itself implement token.Generator, neither of which New can see. Two
// signed bearers on one chain must agree too, whatever their schemes, or New
// fails: migrating subjects means one mode at a time.
//
// The line it does not cross: the user the username names must own the session,
// and this is judged once the session has loaded and its key binding has been
// checked, before any DPoP proof is recorded, on a live session and on one only a
// late renewal may recover alike. A username since given to someone else is
// refused rather than authenticating them on the first owner's session, a refused
// username consumes no proof, and a renamed user's live tokens are refused until they sign
// in again; that is the cost the default avoids. A token with no subject is refused
// here too, and a user with no identifier owns no session.
//
// A request loads the user once, as under the default, and so does a late
// renewal: the record loaded by this username is the one the renewal uses. Every
// other renewal loads twice, in every mode: once to resolve the request, and once
// at the renewal endpoint.
func WithBearerUsernameSubject() BearerTokenOption {
	return func(b *bearerToken) error {
		b.subject = token.SubjectUsername
		return nil
	}
}

// WithoutBearerChallenge stops the chain adding a WWW-Authenticate challenge to
// the 401s it answers on a chain with a built-in bearer.
//
// Default: such a 401 outside the OpenID Provider's endpoints carries Bearer,
// Bearer error="invalid_token" for a Bearer token a built-in bearer refused,
// or DPoP's challenge with EnableDPoP (with optional DPoP, DPoP and Bearer). A
// scheme the response names already is not added again. A chain with no
// built-in bearer refuses this option.
//
// Two limits are accepted: an error handler that changes a 401's status must
// clear the challenge itself, and an interceptor ordered before the bearer that
// refuses a valid token sends invalid_token.
func WithoutBearerChallenge() Option {
	return func(c *config) error {
		c.withoutBearerChallenge = true

		return nil
	}
}

// bearerInvalidTokenChallenge is the challenge for a Bearer token a built-in
// bearer refused (RFC 6750 section 3.1).
const bearerInvalidTokenChallenge = `Bearer error="invalid_token"` //nolint:gosec // G101: a challenge, and no credential

// bearerChallenge answers the 401s of a chain with a built-in bearer with the
// challenge RFC 9110 section 15.5.2 requires. With DPoP on, DPoP's challenge
// interceptor runs it in its place, so one interceptor answers a request.
type bearerChallenge struct {
	// dpop is the chain's DPoP verifier, nil while DPoP is off.
	dpop *dpopVerifier

	// readsBearerScheme is whether a built-in bearer reads the Bearer scheme,
	// which invalid_token is defined for.
	readsBearerScheme bool

	// provider is the chain's OpenID Provider, nil without one. Its endpoints
	// answer their own challenges.
	provider *oidcEndpoints
}

// wireBearerChallenge puts the bearer challenge on a chain with a built-in
// bearer, unless WithoutBearerChallenge turned it off, and refuses that
// option on a chain without one.
func (c *config) wireBearerChallenge() error {
	if !hasBuiltInBearer(c) {
		if c.withoutBearerChallenge {
			return newConfigError("WithoutBearerChallenge was given, but the chain has no built-in bearer " +
				"(EnableBearerToken, EnableSessionBearer), so there is no challenge to turn off")
		}

		return nil
	}

	if c.withoutBearerChallenge {
		return nil
	}

	b := &bearerChallenge{
		dpop:              c.dpop,
		readsBearerScheme: bearerReadsScheme(c, DefaultBearerScheme),
		provider:          c.oidcProvider,
	}

	if c.dpop == nil {
		c.register(b, orderDPoPChallenge)

		return nil
	}

	return eachInterceptor(c, func(d *dpopChallenge) error {
		d.bearer = b

		return nil
	})
}

// hasBuiltInBearer reports whether the chain authenticates bearer tokens with a
// built-in bearer of either mode.
func hasBuiltInBearer(c *config) bool {
	var found bool

	_ = eachInterceptor(c, func(*sessionBearer) error {
		found = true

		return nil
	})
	_ = eachInterceptor(c, func(*bearerToken) error {
		found = true

		return nil
	})

	return found
}

// Intercept runs the rest of the chain and challenges a 401 coming back from
// it. It publishes the challenge on the request, so a guard behind the chain
// answers its own 401 alike.
//
// A challenge for a scheme something inside the chain already set on the
// response is not added again. The consumer's error handler runs afterwards
// and finds the challenge set; it replaces it with Header().Set.
func (b *bearerChallenge) Intercept(ex *Exchange, next Next) error {
	ctx := guardauth.WithChallenger(ex.Context(), b.guardChallenge)
	if b.dpop != nil && b.dpop.cfg.Nonce {
		ctx = context.WithValue(ctx, dpopResponseKey{}, ex.Writer)
	}

	ex.SetContext(ctx)

	watch := &challengeWatch{ResponseWriter: ex.Writer}
	err := watch.run(ex, next)
	if err == nil {
		return nil
	}

	var (
		out   error
		abort error
	)

	switch {
	case b.provider != nil && b.provider.answersPath(ex.Request.Path()):
		// The provider's endpoints challenge as they always have: DPoP's own
		// refusals alone, and the resume and consents through their router.
		if b.dpop == nil {
			return err
		}

		out, abort = b.dpop.challenge(ex.Context(), ex.Writer, err)
	default:
		out, abort = b.challenge(ex.Context(), ex.Writer, err, b.refusedBearerToken(ex), watch.set)
	}

	// Every challenge on the exchange reads the same refused error, so the
	// abort is reported once for the exchange.
	if abort != nil {
		ex.reportQuietlyOnce(ex.Context(), err, abort)
	}

	return out
}

// guardChallenge is the challenge a guard behind the chain answers its refusal
// with. A guard runs only once the chain let the request through, so no token
// was refused.
func (b *bearerChallenge) guardChallenge(ctx context.Context, w guardauth.HeaderWriter, err error) (out, abort error) {
	return b.challenge(ctx, w, err, false, 0)
}

// challenge sets on w the challenge err calls for, and returns the error the
// request fails with and the abort that stopped a walk of err, nil when none
// did; it reports nothing.
//
// DPoP's own refusals get DPoP's challenge (dpopVerifier.challenge). Any other
// error whose status is 401 gets, unless set already names its scheme:
//
//   - with DPoP on: DPoP's code-less challenge, and Bearer beside it unless
//     DPoP is required;
//   - otherwise: Bearer error="invalid_token" when invalidToken, else Bearer.
//
// Nothing the request carried is written into a challenge.
func (b *bearerChallenge) challenge(
	ctx context.Context,
	w guardauth.HeaderWriter,
	err error,
	invalidToken bool,
	set challengeSchemes,
) (out, abort error) {
	if b.dpop != nil {
		answered, out, abort := b.dpop.challengeAnswered(ctx, w, err, set)
		if abort != nil || answered {
			return out, abort
		}
	}

	status, _, abort := lookup(err)
	if abort != nil {
		return err, abort
	}

	if status != http.StatusUnauthorized {
		return err, nil
	}

	addBearer := func(value string) {
		if set&schemeBearer == 0 {
			w.AddHeader(headerWWWAuthenticate, value)
		}
	}

	switch {
	case b.dpop != nil:
		if set&schemeDPoP == 0 {
			w.AddHeader(headerWWWAuthenticate, dpopScheme+" algs="+strconv.Quote(b.dpop.algorithmNames()))
		}

		if !b.dpop.cfg.Require {
			addBearer(DefaultBearerScheme)
		}
	case invalidToken:
		addBearer(bearerInvalidTokenChallenge)
	default:
		addBearer(DefaultBearerScheme)
	}

	return err, nil
}

// refusedBearerToken reports whether the request presented a token a built-in
// bearer refused: one Authorization line under the Bearer scheme, which a
// built-in bearer reads, and no session published.
func (b *bearerChallenge) refusedBearerToken(ex *Exchange) bool {
	if !b.readsBearerScheme || ex.Session != nil {
		return false
	}

	lines := ex.Request.HeaderValues("Authorization")
	if len(lines) != 1 {
		return false
	}

	_, ok := presentedCredential(lines[0], DefaultBearerScheme, false)

	return ok
}

// answersPath reports whether path is one of the provider's endpoints, which
// answer their own challenges.
func (op *oidcEndpoints) answersPath(path string) bool {
	if _, ok := op.outer.routes[path]; ok {
		return true
	}

	if _, ok := op.inner.routes[path]; ok {
		return true
	}

	return op.restsOnSignIn(path)
}

// challengeSchemes is the set of challenge schemes a response already names.
type challengeSchemes uint8

const (
	schemeBearer challengeSchemes = 1 << iota
	schemeDPoP
)

// challengeWatch is the exchange's writer while the rest of the chain runs,
// noting the challenge schemes set on the response, so none is added twice.
type challengeWatch struct {
	ResponseWriter

	set challengeSchemes
}

// run runs next with w as the exchange's writer, and puts the writer back
// however next ends.
func (w *challengeWatch) run(ex *Exchange, next Next) error {
	ex.Writer = w

	defer func() { ex.Writer = w.ResponseWriter }()

	return next(ex)
}

func (w *challengeWatch) SetHeader(name, value string) {
	if strings.EqualFold(name, headerWWWAuthenticate) {
		w.set = schemesIn(value)
	}

	w.ResponseWriter.SetHeader(name, value)
}

func (w *challengeWatch) AddHeader(name, value string) {
	if strings.EqualFold(name, headerWWWAuthenticate) {
		w.set |= schemesIn(value)
	}

	w.ResponseWriter.AddHeader(name, value)
}

// schemesIn is the Bearer and DPoP schemes a WWW-Authenticate value names. A
// piece of the comma-separated list whose first word holds no "=" is a scheme.
// A quoted parameter holding a comma may read as one too, which can only
// withhold a challenge, never repeat one.
func schemesIn(value string) challengeSchemes {
	var set challengeSchemes

	for piece := range strings.SplitSeq(value, ",") {
		word, _, _ := strings.Cut(strings.TrimSpace(piece), " ")
		switch {
		case strings.Contains(word, "="):
		case strings.EqualFold(word, DefaultBearerScheme):
			set |= schemeBearer
		case strings.EqualFold(word, dpopScheme):
			set |= schemeDPoP
		}
	}

	return set
}
