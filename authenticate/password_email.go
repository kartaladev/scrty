package authenticate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/porterr"
)

//go:generate mockgen -destination=emailloader_mock_test.go -package=authenticate_test -typed github.com/kartaladev/scrty/identity EmailLoader

// The refusal reasons only login by email can record. Like the others, each is
// a sampler key of its own.
const (
	// reasonIdentifierConflict names an identifier that is one user's username
	// and another user's verified email.
	reasonIdentifierConflict = "identifier-conflict"
	// reasonEmailMismatch names an email loader that returned a user whose
	// email is not verified, or is not the one asked for: a store breaking the
	// email loader's contract.
	reasonEmailMismatch = "email-mismatch"
	// reasonResolvedMismatch names a resolved identifier put on the context
	// for credentials it was not resolved for: a wiring fault in the caller.
	reasonResolvedMismatch = "resolved-mismatch"
	// reasonNoUsername names a loader that returned an account with no
	// username: a store breaking the loader contract.
	reasonNoUsername = "user-without-username"
)

// WithEmailLogin lets a user log in with their verified email in place of their
// username.
//
// The default is off: the provider loads the presented identifier as a
// username and nothing else, so an email is just an unknown username. With it
// on, the user loader given to NewUsernamePasswordAuthenticator must also
// implement identity.EmailLoader, or construction fails with ErrConfig.
//
// The identifier is loaded as a username first, so a login by username keeps
// its exact path. Only when that reports identity.ErrUserNotFound, and only
// when the identifier contains "@", is it loaded as an email, through the
// email loader, whose contract is to match verified emails of live users,
// ignoring case. A verified email always contains "@", so an identifier without
// one is never looked up as an email.
//
// A username that is also a different user's verified email names two
// accounts. scrty's own stores refuse to write such data, but a consumer's
// store may hold it, so when the username lookup finds a user and the
// identifier contains "@", the provider also loads it as an email; when that
// finds a different user, the attempt is refused with the uniform failure,
// after the same password work as an unknown username, and reported as a
// scrty_identifier_conflict event on a request whose chain reports events,
// and as an "identifier-conflict" refusal record.
//
// An email lookup that fails is an outage, exactly as a username lookup that
// fails: ErrUnavailable, after the same password work.
func WithEmailLogin() PasswordOption {
	return func(a *UsernamePasswordAuthenticator) { a.emailLogin = true }
}

// resolution is what resolving an identifier came to.
type resolution int

const (
	// resolvedNone is an identifier that names no user.
	resolvedNone resolution = iota
	// resolvedUser is an identifier that names exactly one user.
	resolvedUser
	// resolvedConflict is an identifier that names two users.
	resolvedConflict
	// resolvedUnavailable is a lookup the store could not answer.
	resolvedUnavailable
	// resolvedEnded is a lookup the caller's own context ended.
	resolvedEnded
)

// ResolvedIdentifier is the account an identifier resolved to, as
// ResolveIdentifier found it.
//
// A login endpoint resolves the identifier before its pre-authentication phase,
// so the account's lockout and holds key on Key whichever identifier was typed,
// and hands the result to the provider through WithResolved, so the user is
// loaded once per attempt.
//
// Only a value ResolveIdentifier returned is honoured, and only by the provider
// that returned it: its unexported fields record both, and a value built by
// hand, or by another provider, is ignored and the provider loads the user
// itself.
//
// A resolution is good for one attempt: the one whose identifier it resolved.
// It holds the user as loaded when it was made, and the provider authenticates
// against that record without loading again, so one kept and presented later
// would be judged on a stale record (a changed password, a disabled account).
// Resolve again for every attempt.
type ResolvedIdentifier struct {
	// Key is the resolved user's username, or the identifier as presented when
	// it resolved to no single user: unknown, conflicting, without a username
	// (a loader breaking its contract), or not looked up because the store was
	// unavailable. A found account is always keyed on its username, never on
	// the identifier as typed.
	Key string

	// Details is the resolved user, or nil when the identifier resolved to no
	// single user. It is a copy without the password hash. Its slices are
	// shared with the loaded record and must be treated as read-only.
	Details *identity.Details

	by        *UsernamePasswordAuthenticator
	presented string
	outcome   resolution
	details   *identity.Details
	err       error
}

// resolvedKey is the context key a ResolvedIdentifier travels under.
type resolvedKey struct{}

// WithResolved returns a copy of ctx carrying r, so the provider that resolved
// it authenticates r's user without loading it again.
//
// r is for one attempt; see ResolvedIdentifier.
//
// The provider honours r only when it returned r itself and the credentials it
// is asked to authenticate name the identifier r was resolved from, or the
// username of the user it resolved to, as recorded when r was made; a Key
// rewritten afterwards is not consulted. For credentials naming anything else
// it refuses with ErrAuthenticationFailed, after the same password work as an
// unknown username, and records a
// "resolved-mismatch" refusal: authenticating one account after keying the
// lockout on another would bypass the lockout.
func WithResolved(ctx context.Context, r ResolvedIdentifier) context.Context {
	return context.WithValue(ctx, resolvedKey{}, r)
}

// resolvedFrom returns the resolution ctx carries, when a resolved it.
func (a *UsernamePasswordAuthenticator) resolvedFrom(ctx context.Context) (ResolvedIdentifier, bool) {
	r, ok := ctx.Value(resolvedKey{}).(ResolvedIdentifier)
	if !ok || r.by == nil || r.by != a {
		return ResolvedIdentifier{}, false
	}

	return r, true
}

// ResolveIdentifier resolves identifier to the account it names, as Authenticate
// would, without verifying any password.
//
// The identifier is loaded as a username; with WithEmailLogin, as WithEmailLogin
// describes, as a verified email too. An identifier that names no user, or two,
// returns a nil error and a ResolvedIdentifier whose Details is nil and whose Key
// is the identifier as presented. So does one the loader answers with an account
// that has no username, a breach of its contract that is recorded as a warning:
// no account is named, so none is authenticated. A conflict is recorded and reported here,
// once.
//
// A lookup the store could not answer returns ErrUnavailable, and one the
// caller's own context ended returns the uniform failure joined with the
// context's error, as Authenticate does. The ResolvedIdentifier is usable either
// way: handed to Authenticate through WithResolved, it returns the same error
// after the same password work, without loading again.
//
// Without WithEmailLogin, Authenticate needs no prior resolution: it loads the
// username itself, as it always has.
func (a *UsernamePasswordAuthenticator) ResolveIdentifier(ctx context.Context, identifier string) (ResolvedIdentifier, error) {
	r := a.resolve(ctx, identifier)

	return r, r.err
}

// resolve loads identifier as a username and, with login by email, as an email.
// It records outages, hang-ups, contract breaches and conflicts; an unknown
// identifier is recorded by whoever refuses it.
func (a *UsernamePasswordAuthenticator) resolve(ctx context.Context, identifier string) ResolvedIdentifier {
	none := ResolvedIdentifier{Key: identifier, by: a, presented: identifier, outcome: resolvedNone}

	details, err := a.users.LoadByUsername(ctx, identifier)
	// The loader is the consumer's, and so is its error. One whose chain
	// cannot be walked becomes a fault matching ErrUnavailable, so it takes
	// the outage branch and is never read as an unknown user or a hang-up.
	err = porterr.SanitizeTo(ctx, a.logger, err, ErrUnavailable)
	if err != nil && !errors.Is(err, identity.ErrUserNotFound) {
		return a.loadFailed(ctx, none, err)
	}

	mayBeEmail := a.emails != nil && strings.Contains(identifier, "@")

	if err == nil && details != nil {
		if mayBeEmail {
			if r, conflicted := a.checkConflict(ctx, none, details); conflicted {
				return r
			}
		}

		return a.found(ctx, none, details)
	}

	if !mayBeEmail {
		return none
	}

	details, err = a.emails.LoadByEmail(ctx, identifier)
	err = porterr.SanitizeTo(ctx, a.logger, err, ErrUnavailable)
	if err != nil && !errors.Is(err, identity.ErrUserNotFound) {
		return a.loadFailed(ctx, none, err)
	}
	if err != nil || details == nil {
		return none
	}

	// The loader's contract is to return only a verified email equal to the
	// one asked for, ignoring case. A store that breaks it would log the
	// caller into someone else's account, so its answer is checked, not
	// trusted.
	//
	// The refusal is recorded twice, on purpose: this "email-mismatch" record
	// warns about the consumer's loader, and the "unknown-user" record the
	// provider writes when it refuses the unresolved identifier is the
	// attempt's own record. Folding them into one would lose either the
	// warning or the attempt.
	if !details.EmailVerified() || !strings.EqualFold(details.Email, identifier) {
		a.refuse(ctx, slog.LevelWarn, reasonEmailMismatch, identifier,
			slog.String("reason", reasonEmailMismatch))

		return none
	}

	return a.found(ctx, none, details)
}

// checkConflict loads identifier, already found as byUsername's username, as an
// email too, and reports whether the attempt ends here: a conflict, or a lookup
// that failed.
func (a *UsernamePasswordAuthenticator) checkConflict(
	ctx context.Context,
	none ResolvedIdentifier,
	byUsername *identity.Details,
) (ResolvedIdentifier, bool) {
	other, err := a.emails.LoadByEmail(ctx, none.presented)
	err = porterr.SanitizeTo(ctx, a.logger, err, ErrUnavailable)
	if err != nil && !errors.Is(err, identity.ErrUserNotFound) {
		// Unknown whether the identifier names a second user: refuse rather
		// than guess.
		return a.loadFailed(ctx, none, err), true
	}
	if err != nil || other == nil {
		return ResolvedIdentifier{}, false
	}
	if other.ID == byUsername.ID && other.Username == byUsername.Username {
		// The user's username is their own email.
		return ResolvedIdentifier{}, false
	}
	// Checked, not trusted, as on the email-login path: a user the email
	// loader returns unverified, or under another email, names no second
	// account, and refusing on it would let a store's broken answer lock a
	// user out of their own username. Nothing is recorded: the attempt goes
	// on, and a refusal record on a login that may succeed would mislead.
	if !other.EmailVerified() || !strings.EqualFold(other.Email, none.presented) {
		return ResolvedIdentifier{}, false
	}

	a.refuse(ctx, slog.LevelWarn, reasonIdentifierConflict, none.presented,
		slog.String("reason", reasonIdentifierConflict))
	// No user is named: the event reports a refused login, and a refused
	// login names no user.
	eventsink.Send(ctx, event.Event{
		Name:    event.IdentifierConflict,
		At:      time.Now(),
		Outcome: event.OutcomeFailure,
		Factor:  factor.Password,
	})

	none.outcome = resolvedConflict

	return none, true
}

// found is the resolution naming details. An account with no username breaks
// the loader's contract and is refused as an unknown identifier: the account's
// lockout is keyed on its username, and keying it on the identifier as typed
// would give every case variant of one email a failure budget of its own.
func (a *UsernamePasswordAuthenticator) found(ctx context.Context, none ResolvedIdentifier, details *identity.Details) ResolvedIdentifier {
	if details.Username == "" {
		// The identifier stays out of the record's text; refuse adds it only
		// when the consumer opted into logging usernames.
		a.refuse(ctx, slog.LevelWarn, reasonNoUsername, none.presented,
			slog.String("reason", reasonNoUsername))

		return none
	}

	r := none
	r.outcome = resolvedUser
	r.details = details
	r.Key = details.Username

	// The copy handed outward carries no hash, and changing it changes
	// nothing the provider authenticates against.
	outward := *details
	outward.Password = nil
	r.Details = &outward

	return r
}

// loadFailed records a lookup that failed with err, which is not a miss, and
// returns the resolution that replays it.
func (a *UsernamePasswordAuthenticator) loadFailed(ctx context.Context, none ResolvedIdentifier, err error) ResolvedIdentifier {
	r := none

	// A load the caller's own cancellation or deadline ended judged nothing,
	// and the store did not fail: the caller left. See Authenticate.
	if hangup.ByCaller(ctx, err) {
		a.refuse(ctx, slog.LevelDebug, reasonCallerEnded, none.presented,
			diag.Failure(reasonCallerEnded, err)...)
		r.outcome = resolvedEnded
		r.err = endedByCaller(ctx)

		return r
	}

	// diag.Failure names the failure and the error's Go type, never its text:
	// the store's error can quote a value the library never saw.
	a.refuse(ctx, slog.LevelError, reasonUserLoadFailed, none.presented,
		diag.Failure(reasonUserLoadFailed, err)...)
	r.outcome = resolvedUnavailable
	r.err = ErrUnavailable

	return r
}

// names reports whether username is what r was resolved from, or the username
// of the user it resolved to. It reads only the state recorded when r was
// made: Key is exported and writable, so a caller that rewrote it could
// otherwise point a carrier resolved for one account at credentials for
// another.
func (r ResolvedIdentifier) names(username string) bool {
	if username == r.presented {
		return true
	}

	return r.details != nil && r.details.Username != "" && username == r.details.Username
}

// IdentifierResolver is the port for the identifier-resolution step: what a
// login endpoint runs before its pre-authentication phase, so the account's
// lockout and holds key on the account an identifier names, whichever
// identifier was typed.
//
// UsernamePasswordAuthenticator implements it, with or without WithEmailLogin,
// and so does FirstOf, by forwarding to its one member that logs in by email.
// Use ResolverOf to find the resolver an authenticator exposes.
//
// A consumer's own implementation must return, as Key, the username of the
// account the authenticator will then authenticate for that identifier, and the
// identifier as presented only when it names no single account. The login
// endpoints lock, count, hold and clear failures under Key, so a Key naming any
// other account would judge one account's lockout while another is
// authenticated, which is the bypass resolution exists to close. scrty cannot
// check a consumer's resolver against its authenticator; this is that
// implementation's contract.
//
// An identifier that names no single account is not an error: it returns a
// nil error and the identifier as presented as Key. An error means the
// resolution could not be made, and the login endpoints refuse the attempt on
// it without asking the authenticator, since the account whose lockout would
// judge it is unknown: a caller that ended its own request is refused as one,
// and any other error as ErrUnavailable, after the same decoy password work.
type IdentifierResolver interface {
	// ResolveIdentifier resolves identifier to the account it names. The
	// result is handed to the authenticator through WithResolved, for one
	// attempt. See UsernamePasswordAuthenticator.ResolveIdentifier.
	ResolveIdentifier(ctx context.Context, identifier string) (ResolvedIdentifier, error)

	// EmailLogin reports whether resolution can name an account by something
	// other than its username, so the identifier as typed is not a safe key.
	// When it reports false, resolving is unnecessary: the identifier is its
	// own key.
	EmailLogin() bool
}

// EmailLogin reports whether WithEmailLogin is on. When it is off,
// ResolveIdentifier still works, as a username-only lookup, but a caller has
// no reason to run it: the identifier as typed is the account's key.
func (a *UsernamePasswordAuthenticator) EmailLogin() bool { return a.emailLogin }

var _ IdentifierResolver = (*UsernamePasswordAuthenticator)(nil)

// ResolverOf returns the identifier resolver a exposes, and whether there is
// one a caller must run before authenticating.
//
// It reports true when a implements IdentifierResolver and its EmailLogin
// reports true: a password provider with WithEmailLogin, or a FirstOf with
// such a member at any depth. It reports false for an authenticator whose
// identifiers are their own keys, which needs no resolution, and for one that
// exposes no resolver at all.
//
// A consumer's own Authenticator that wraps a provider with login by email
// hides it unless it implements IdentifierResolver too, forwarding both
// methods; nothing outside the wrapper can see through it.
func ResolverOf(a Authenticator) (IdentifierResolver, bool) {
	if nilcheck.IsNil(a) {
		return nil, false
	}

	r, ok := a.(IdentifierResolver)
	if !ok || !r.EmailLogin() {
		return nil, false
	}

	return r, true
}
