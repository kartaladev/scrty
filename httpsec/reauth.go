package httpsec

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/onetime"
)

// DefaultReauthenticationPrefix is the prefix the re-authentication endpoints
// answer under when the consumer names none (WithReauthenticationPrefix):
//
//   - GET  /reauth/methods, the method listing;
//   - POST /reauth/begin/<method>, a second-factor method's begin step;
//   - POST /reauth/verify/<method>, a second-factor re-proof;
//   - POST /reauth/password, a password re-proof.
//
// It is a constant rather than a bare literal so a client, a test or a proxy
// rule naming the same endpoints names the same thing this package does.
const DefaultReauthenticationPrefix = "/reauth"

// The paths of the re-authentication endpoints, each under the prefix.
const (
	reauthMethodsSuffix  = "/methods"
	reauthBeginSuffix    = "/begin"
	reauthVerifySuffix   = "/verify"
	reauthPasswordSuffix = "/password"
)

// The re-proof challenge defaults. They are the MFA slot's values, kept as
// re-authentication's own, because one option never silently governs two
// subsystems: changing the MFA challenge lifetime does not change this one.
const (
	defaultReauthChallengeTTL   = DefaultMFAChallengeTTL
	defaultReauthChallengeLimit = DefaultMFAChallengeLimit
)

// ReauthenticationResult is what a successful re-proof produced, handed to
// whatever writes the response.
type ReauthenticationResult struct {
	// Token is the credential issued for the rotated session: an access
	// token from WithReauthenticationTokens, or, with EnableSessionBearer on,
	// the rotated session's own identifier.
	Token string

	// Session is the re-authenticated session, carrying its new handle and its
	// refreshed authentication time.
	Session *session.Session
}

// ReauthenticationResponder writes the response to a successful re-proof, at
// the verify and password endpoints.
//
// With none supplied (WithReauthenticationResponder), the library answers 200
// with the JSON document a login answers with, carrying the rotated session's
// credential and its idle expiry, marked Cache-Control: no-store.
//
// It is called instead of the downstream handler, because the endpoints are
// the library's own and the application has no route behind them. The session
// it receives carries the handle rotation produced, which is the only place
// that handle is available. An error it returns leaves the chain as the
// request's refusal. A consumer's responder owns its headers: the library adds
// none to what it writes.
type ReauthenticationResponder func(ex *Exchange, r ReauthenticationResult) error

// ReauthenticationMethods is how the session's user may re-prove, under the
// factor policy (see EnableReauthentication).
type ReauthenticationMethods struct {
	// Methods are the configured second-factor methods the user is enrolled
	// on, in the order EnableMFA was given them, whatever their channel. It is
	// empty, never nil, when there are none.
	Methods []MFAMethod

	// Password reports that the password endpoint accepts this user: the user
	// holds no second factor, form login is enabled, and second-factor-only
	// re-proof (RequireSecondFactorForReauthentication) is off.
	Password bool
}

// ReauthenticationMethodsResponder writes the response to a method listing. m
// is the same decision every re-proof endpoint applies to the session's user.
//
// It is called instead of the downstream handler, because the listing is the
// library's own. An error it returns leaves the chain as the request's
// refusal. It runs on the request carrying the session, so a consumer may
// filter m, for example to drop the password for a user who has none. A
// consumer's responder owns its headers: the library adds none to what it
// writes.
type ReauthenticationMethodsResponder func(ex *Exchange, m ReauthenticationMethods) error

// msgReauthMethodsUnavailable is the fixed text a re-proof request is refused
// with when the user's enrolments could not be looked up. The failure is the
// consumer's enrolment store's, and its own text stays out.
const msgReauthMethodsUnavailable = "httpsec: the re-authentication methods could not be looked up"

// reauthInterceptor is the re-authentication endpoints: the method listing,
// and the second-factor and password re-proofs.
//
// It holds no factor of its own. A second factor is verified by the MFA
// slot's methods under its throttle, and a password by the form login's
// password path, so a re-proof is held to the limits that already guard the
// same secrets.
type reauthInterceptor struct {
	// prefix is where the endpoints answer, with no trailing slash.
	prefix string

	// tokens issues the rotated session's credential in the signed-token
	// mode, and issue is the issuer the chain's bearer mode decides on,
	// settled at assembly.
	tokens token.Generator
	issue  credentialIssuer

	// respond answers a successful re-proof, beginRespond a successful begin
	// and methodsRespond the listing.
	respond        ReauthenticationResponder
	beginRespond   MFABeginResponder
	methodsRespond ReauthenticationMethodsResponder

	// challengeTTL, challengeCap and challengeStore are what the re-proof
	// challenges of challenge methods are issued with. A nil store is the
	// default in-memory one, built at assembly.
	challengeTTL   time.Duration
	challengeCap   int
	challengeStore onetime.Store

	// challenges holds one re-proof challenge manager per challenge method of
	// the MFA slot, keyed by name, and sweeps spaces each one's inline sweeps
	// of its expired challenges; both are built once every option has been
	// applied (settle).
	challenges map[string]*onetime.Tokens
	sweeps     map[string]*sweepClock

	// secondFactorOnly refuses the password to every user
	// (RequireSecondFactorForReauthentication).
	secondFactorOnly bool

	// mfa and login are the chain's MFA slot and form login, nil when the
	// chain has none, found once every option has been applied (settle).
	mfa   *mfaInterceptor
	login *formLogin

	// sessions rotates a re-proved session, now reads the chain's clock, and
	// log and sampler are the chain's, handed over once the chain exists.
	sessions *session.Sessions
	now      func() time.Time
	log      *slog.Logger
	sampler  *logsample.Sampler
}

// reauthPaths are the endpoints' paths under one prefix.
type reauthPaths struct {
	methods, begin, verify, password string
}

// paths are the endpoints' paths under the configured prefix.
func (i *reauthInterceptor) paths() reauthPaths {
	return reauthPaths{
		methods:  i.prefix + reauthMethodsSuffix,
		begin:    i.prefix + reauthBeginSuffix,
		verify:   i.prefix + reauthVerifySuffix,
		password: i.prefix + reauthPasswordSuffix,
	}
}

// Intercept dispatches a re-proof request to its endpoint, and passes every
// other request on untouched.
//
// Only GET on the listing path is the listing, and only POST at or under the
// begin and verify paths, or on the password path, is a re-proof: proving a
// factor is a change, and one a link could trigger is one another site could
// trigger for a caller who never asked. Every POST at or under the begin and
// verify paths is that endpoint's, including one naming no method, so it is
// refused as unknown rather than passed to the application.
func (i *reauthInterceptor) Intercept(ex *Exchange, next Next) error {
	r := ex.Request
	p := i.paths()

	switch r.Method() {
	case http.MethodGet:
		if r.Path() == p.methods {
			return i.list(ex)
		}
	case http.MethodPost:
		switch path := r.Path(); {
		case underPrefix(path, p.begin):
			return i.begin(ex)
		case underPrefix(path, p.verify):
			return i.verify(ex)
		case path == p.password:
			return i.reprove(ex)
		}
	}

	return next(ex)
}

// admit refuses a request no re-proof endpoint may serve, and returns the
// session it may. It reads nothing from the request, counts nothing and
// changes nothing.
//
// Only a full session is served: one with a resolved caller, whose second
// factor is satisfied or was never asked for, that owes no password change and
// carries no confinement marker, judged by the check passkey management and
// saved-code regeneration also make (fullSession). Everything else is refused
// with ErrAuthenticationRequired. On a chain in the default order a session owing a
// challenge, or confined to enrolment or recovery, never gets here, because
// its gate (598 to 650) refuses it first; this refusal covers a consumer who
// registered an interceptor that publishes a session past those gates. A
// request on which the policy phase raised a challenge of the consumer's own
// (Exchange.RaisedChallenge) is refused the same way: the gate enforcing it is
// the consumer's, and a pending challenge of any kind is not a full session. A
// session that is still fresh is served: re-proving early is harmless, and
// throttled like any other attempt.
func (i *reauthInterceptor) admit(ex *Exchange) (*session.Session, error) {
	s := ex.Session
	if s == nil {
		return nil, ErrAuthenticationRequired
	}

	// The re-proof hands back a credential issued for somebody, and a session
	// whose first factor published no caller names nobody.
	if ex.Authentication == nil || ex.Authentication.Principal == nil {
		return nil, ErrAuthenticationRequired
	}

	if !fullSession(s) || ex.RaisedChallenge() != policy.ChallengeNone {
		return nil, ErrAuthenticationRequired
	}

	return s, nil
}

// offered is the factor policy as the listing applies it: how the user of s
// may re-prove, asking every method. The endpoints reach the same answer
// without it: the password endpoint through passwordOffered, which stops at
// the first enrolled method and judges the password by the same rule
// (passwordPermitted); begin and verify by looking up only the method the
// request names, refusing it when the user is not enrolled. So the listing
// never offers what an endpoint refuses, and no endpoint accepts what the
// listing did not offer.
//
// methods are the MFA slot's configured methods the user is enrolled on, in
// configuration order, whatever their channel: the same-channel rule of a
// login's second factor does not apply to a re-proof, which is one factor
// presented alongside the live session secret, so a passkey login re-proves
// with the passkey. password is passwordPermitted's answer for a user holding
// those methods.
//
// The first lookup that fails refuses the request, behind fixed text with the
// store's error reachable through errors.Is and errors.As. It never falls back
// to the password, or an outage of the enrolment store would downgrade every
// user who had enrolled.
func (i *reauthInterceptor) offered(ctx context.Context, s *session.Session) ([]mfa.Method, bool, error) {
	methods := []mfa.Method{}

	if i.mfa != nil {
		for _, m := range i.mfa.methods {
			enrolled, err := m.Enrolled(ctx, s.UserID)
			if err != nil {
				return nil, false, diag.Wrap(err, msgReauthMethodsUnavailable)
			}

			if enrolled {
				methods = append(methods, m)
			}
		}
	}

	return methods, i.passwordPermitted(len(methods) > 0), nil
}

// passwordOffered is the factor policy as the password endpoint applies it:
// whether the user of s may re-prove with the password. It reaches the same
// answer as offered, but looks the methods up in configuration order and stops
// at the first one the user is enrolled on, since that alone refuses the
// password; offered, which the listing needs, asks every method. Both judge
// the password by passwordPermitted.
//
// A lookup that fails before an enrolled method is found refuses the request
// as offered does, behind fixed text with the store's error reachable, and
// never falls back to the password.
func (i *reauthInterceptor) passwordOffered(ctx context.Context, s *session.Session) (bool, error) {
	if i.mfa != nil {
		for _, m := range i.mfa.methods {
			enrolled, err := m.Enrolled(ctx, s.UserID)
			if err != nil {
				return false, diag.Wrap(err, msgReauthMethodsUnavailable)
			}

			if enrolled {
				return i.passwordPermitted(true), nil
			}
		}
	}

	return i.passwordPermitted(false), nil
}

// passwordPermitted is the factor policy's password rule, the one the listing
// (offered) and the password endpoint (passwordOffered) both apply, so the two
// cannot drift: the password is accepted only from a user who holds no second
// factor, while form login is enabled and second-factor-only re-proof
// (RequireSecondFactorForReauthentication) is off. A user who holds a second
// factor never re-proves with the weaker password.
func (i *reauthInterceptor) passwordPermitted(holdsSecondFactor bool) bool {
	return !holdsSecondFactor && i.login != nil && !i.secondFactorOnly
}

// list answers the method listing for the session's user, from the factor
// policy every re-proof endpoint applies.
func (i *reauthInterceptor) list(ex *Exchange) error {
	s, err := i.admit(ex)
	if err != nil {
		return err
	}

	methods, password, err := i.offered(ex.Context(), s)
	if err != nil {
		return err
	}

	listed := ReauthenticationMethods{Methods: make([]MFAMethod, 0, len(methods)), Password: password}
	for _, m := range methods {
		listed.Methods = append(listed.Methods, MFAMethod{
			Name:    m.Name(),
			Channel: m.Channel(),
			Begins:  isChallengeMethod(m),
		})
	}

	return i.methodsRespond(ex, listed)
}

// writeReauthMethods is the listing's response when the consumer supplies no
// responder: 200 and a JSON document, {"methods":[{"name":…,"channel":…,
// "begins":…}],"password":…}, an empty list as [] rather than null, marked
// Cache-Control: no-store because it describes the user's factors. It is
// written by writeMethodsDocument, the writer the MFA listing uses, with the
// password member this listing adds.
func writeReauthMethods(ex *Exchange, m ReauthenticationMethods) error {
	return writeMethodsDocument(ex, m.Methods, &m.Password)
}

// writeReauthResult is the response a re-proof succeeds with when the
// consumer supplies no responder: the document a login and a second factor
// answer with, carrying the rotated session's credential and validity, marked
// Cache-Control: no-store.
func writeReauthResult(ex *Exchange, r ReauthenticationResult) error {
	body := loginDocument{AccessToken: r.Token}
	if r.Session != nil {
		body.ValidUntil = r.Session.IdleExpiresAt
	}

	return writeSuccessDocument(ex, body)
}
