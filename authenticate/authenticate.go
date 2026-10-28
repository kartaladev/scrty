package authenticate

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -source=authenticate.go -package=authenticate_test -destination=mocks_test.go -typed

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
// An unknown username, a wrong password, a correct password for an inactive
// account and a user store that is down all return it, bare and alike, because
// telling them apart turns the login endpoint into an oracle for which accounts
// exist and which are disabled. What distinguishes them is written to the log,
// where the operator can see it and the caller cannot.
var ErrAuthenticationFailed = errors.New("authenticate: authentication failed")

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
	// that would let a caller tell one refusal from another.
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
