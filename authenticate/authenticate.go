package authenticate

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -source=authenticate.go -package=authenticate_test -destination=mocks_test.go -typed -exclude_interfaces=DecoyVerifier

// ErrConfig is wrapped by every error a constructor in this package returns for
// a configuration it will not accept.
//
// Wiring mistakes are reported here, before any traffic, rather than at the
// first request: a manager with no providers, a provider given as nil, and a
// password provider whose encoder cannot produce its reference hash are all
// mistakes in how the library was assembled, and a component that accepted them
// would fail later, on a request, looking like a runtime fault.
var ErrConfig = errors.New("authenticate: invalid configuration")

// ErrUnsupportedCredentials is the answer a provider gives for credentials it
// does not handle, and the only error a FirstOf treats as "ask the next one".
//
// It is not a failure to authenticate. A provider returns it before looking at
// the secret at all, so returning it says nothing about the caller, and a
// manager that stopped here would refuse a caller some later provider could
// have resolved.
var ErrUnsupportedCredentials = errors.New("authenticate: unsupported credentials")

// ErrAuthenticationFailed is the one failure every refusal reads as.
//
// An unknown username, a wrong password and a correct password for an inactive
// account all return it, bare and alike, because telling them apart turns the
// login endpoint into an oracle for which accounts exist and which are
// disabled. What distinguishes them is written to the log, where the operator
// can see it and the caller cannot. A user store that could not answer is not a
// refusal and returns ErrUnavailable instead.
//
// A load that the caller's own cancellation or deadline ended is not an
// outage either: the store did not fail, the caller left. It returns this
// error joined with the context's error, and with its cause when that
// differs, so it matches both ErrAuthenticationFailed and ctx.Err(). A caller
// that counts refusals can count it, and can tell from the error that no
// password was compared. httpsec's form login, Basic authentication and
// account recovery's password proof charge it to the request's source only,
// on a context with the caller's cancellation stripped: they record no
// failure for the username, and a recovery counts nothing against the user's
// recovery limit.
var ErrAuthenticationFailed = errors.New("authenticate: authentication failed")

// ErrUnavailable reports that the user store could not answer, so the
// credential was never judged.
//
// The password provider returns it, bare, when its user loader fails with
// anything other than identity.ErrUserNotFound. The one exception is a load the
// caller's own context ended: when ctx has ended and the loader's error is, or
// wraps, ctx's error or its cause, the provider returns ErrAuthenticationFailed
// joined with the context's error instead. ErrUnavailable itself never matches
// ErrAuthenticationFailed, so logs, metrics and a consumer's error handler can
// tell an outage from a refusal: no credential was refused, and a caller that
// counts failed logins against an account must not count this one. An outage
// counted against the account would lock or hold real accounts for failures
// their owners never made. It carries none of the loader's error text; the
// provider logs the failure at error level, naming its Go type, for the
// operator.
//
// The provider spends the same password work for it as for an unknown
// username, so the timing does not change. A store can fail for some rows
// only, in a partial outage or for one account's corrupt row, so the error
// alone could tell a prober which usernames exist; that is why the default
// answer below is the refusal's own. A partial outage can still differ in
// timing, when a found user's load waits on a lock a miss never reaches.
//
// By default httpsec answers it exactly as a wrong password: 401 through
// httpsec.StatusForError, with Basic authentication's WWW-Authenticate
// challenge. Form login, Basic authentication and account recovery's password
// proof charge it once to the request's source, on a context with the
// caller's cancellation stripped, so the source limit bounds the password work
// an outage costs; they record no failure for the username, count nothing
// against the user's recovery limit, and clear nothing. An API key's owner
// check returns it too, answered 401 and not counted against the source,
// because the key was verified. A consumer's own error handler, which replaces
// the default response, may match it and answer 503, at a cost: with locks
// concealed, a held or locked account then answers an outage differently from
// a free one, revealing its lock state, and in a partial outage, where a found
// user's load reads more than a miss does, a known user answers differently
// from an unknown one. There is no option to count it against the account.
var ErrUnavailable = errors.New("authenticate: the user store is unavailable")

// ErrNoEligibleAuthenticator reports that every provider skipped the presented
// credentials, so none of them judged the caller at all.
//
// It is distinct from ErrAuthenticationFailed because it is a statement about
// the manager's own configuration rather than about the caller: credentials of
// a kind nothing here handles mean a provider is missing, not that the secret
// was wrong.
var ErrNoEligibleAuthenticator = errors.New("authenticate: no eligible authenticator")

// Authenticator resolves presented credentials to an authenticated caller.
//
// It is the port a consumer implements to add an authentication method of their
// own. FirstOf is itself an Authenticator, so a FirstOf composes into another
// FirstOf without a wrapper.
type Authenticator interface {
	// Authenticate resolves c, or reports why it could not.
	//
	// Credentials of a kind this provider does not handle return
	// ErrUnsupportedCredentials and nothing else, so a FirstOf can offer them to
	// the next provider. Every refusal of credentials this provider does handle
	// returns an error matching ErrAuthenticationFailed, and carries no detail
	// that would let a caller tell one refusal from another. A dependency that
	// could not answer, so that the credentials were never judged, is not a
	// refusal: the built-in password provider returns ErrUnavailable for it.
	Authenticate(ctx context.Context, c identity.Credentials) (*Authentication, error)
}

// Authentication is what a successful authentication produced.
//
// A provider fills it; a FirstOf decides whether it may be returned at all. It
// never carries the password hash: the outward identity is Principal, which
// identity builds without one.
type Authentication struct {
	// ID identifies this authentication event.
	//
	// It comes from a replaceable id.Generator so a consumer can correlate the
	// event with records of their own. It is not a credential and must never be
	// used as one: pkg/id identifiers embed a timestamp and a partly
	// predictable counter.
	ID id.ID

	// Credentials are the credentials the caller presented, already wiped. They
	// are kept so a caller can read which kind of credential resolved the
	// request; the secret they held is gone by the time this is returned.
	Credentials identity.Credentials

	// Principal is the resolved caller. A FirstOf never returns an
	// Authentication whose Principal is absent, so a caller that saw no error
	// may read it without a check.
	Principal *identity.Principal

	// Time is when the authentication succeeded.
	Time time.Time

	// PasswordChangedAt is when the user's password was last changed, as the
	// user loader reported it, and the zero time when that is unknown or the
	// credentials were not a password.
	//
	// It is carried here so a password-age policy can decide on a stale
	// credential without loading the user a second time.
	PasswordChangedAt time.Time
}

// contextKey is this package's own key type for context values.
//
// It is unexported and has no exported methods, so nothing outside this package
// can construct a value of it. That is what stops another package's key from
// colliding with this one and overwriting, or reading, the authentication a
// request carries.
type contextKey struct{}

// authenticationKey is the one key under which a request's authentication
// travels.
var authenticationKey contextKey

// WithAuthentication returns a copy of ctx carrying a.
//
// An authentication interceptor calls this once a FirstOf has resolved the
// caller, and everything downstream reads the result back rather than
// authenticating again.
//
// Attaching nothing is allowed and attaches nothing a reader will accept: see
// AuthenticationFromContext.
func WithAuthentication(ctx context.Context, a *Authentication) context.Context {
	return context.WithValue(ctx, authenticationKey, a)
}

// AuthenticationFromContext returns the authentication ctx carries, reporting
// whether one was present.
//
// It reports false for a context carrying nothing and for one carrying a nil
// result, so a caller that checks the second return value is never handed a nil
// to dereference, and a caller that ignores it gets nothing it could mistake for
// an authenticated caller. Returning a zero-valued Authentication instead would
// hand over exactly such a mistake: a result with no principal that no refusal
// ever produced.
func AuthenticationFromContext(ctx context.Context) (*Authentication, bool) {
	a, ok := ctx.Value(authenticationKey).(*Authentication)
	if !ok || a == nil {
		return nil, false
	}

	return a, true
}

// DecoyVerifier spends the password work a real verification would, on a
// refusal made before any password was checked. It reports nothing about the
// outcome; handled says only whether creds are of a kind it verifies, so a
// FirstOf can find the right delegate without calling Authenticate.
//
// It is optional: an Authenticator that does not implement it simply cannot
// spend a decoy, and a caller that needs the work to be indistinguishable from
// a real verification may warn that its authenticator offers none.
type DecoyVerifier interface {
	VerifyDecoy(ctx context.Context, creds identity.Credentials) (handled bool)
}
