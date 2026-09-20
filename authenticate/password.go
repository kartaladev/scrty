package authenticate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
)

//go:generate mockgen -destination=userloader_mock_test.go -package=authenticate_test -typed github.com/kartaladev/scrty/identity UserLoader
//go:generate mockgen -destination=encoder_mock_test.go -package=authenticate_test -typed github.com/kartaladev/scrty/password Encoder
//go:generate mockgen -destination=idgenerator_mock_test.go -package=authenticate_test -typed github.com/kartaladev/scrty/pkg/id Generator

// referencePassword is the input the reference hash is produced from.
//
// Its value is of no consequence and it is not a secret: nothing is ever
// authenticated against it, and it exists only so that a username the store
// does not know still costs one full verification. Only the hash it produces is
// kept.
const referencePassword = "scrty reference password"

// PasswordOption configures the username-and-password provider.
//
// A nil option is skipped, so a consumer who builds the slice conditionally
// need not filter it first.
type PasswordOption func(*passwordAuthenticator)

// WithPasswordEncoder replaces the password encoder.
//
// The default is scrty's default encoder, Argon2id with this library's
// parameters. Supply this when the stored hashes were produced by another
// algorithm, or by the same one with different parameters.
//
// A nil encoder is a configuration error rather than a silent return to the
// default: a caller passing one meant to supply an encoder, and hashing under
// an algorithm they did not choose would fail to verify every credential their
// store holds.
func WithPasswordEncoder(enc password.Encoder) PasswordOption {
	return func(a *passwordAuthenticator) { a.enc = enc; a.encSet = true }
}

// WithPasswordIDGenerator replaces the generator that names each successful
// authentication.
//
// The default is id.NewV7Generator, whose identifiers strictly increase, so a
// consumer's own records can be ordered by the authentication that produced
// them. Supply this when those records are keyed by identifiers of the
// consumer's own kind, so the two sides agree without a translation table.
//
// A nil generator is a configuration error rather than a silent return to the
// default, for the same reason a nil encoder is: the caller meant to inject
// one, and correlation that quietly used another generator's identifiers would
// look like it worked until the records were joined.
func WithPasswordIDGenerator(g id.Generator) PasswordOption {
	return func(a *passwordAuthenticator) { a.ids = g; a.idsSet = true }
}

// WithPasswordAuthenticatorLogInterval sets how often one refusal reason may be
// recorded.
//
// The default is one minute. It governs this provider's refusal logs and
// nothing else: an option that also moved, say, a rate limiter's or a policy's
// interval would make one number mean two things, and tuning either would
// silently retune the other.
//
// An interval of zero or less records every refusal. That is the documented
// override for a deployment that ships its logs somewhere that wants the whole
// stream — and the stated cost is that an attacker choosing the traffic then
// chooses the log volume.
func WithPasswordAuthenticatorLogInterval(d time.Duration) PasswordOption {
	return func(a *passwordAuthenticator) { a.logEvery = d; a.logEverySet = true }
}

// WithPasswordAuthenticatorLogger replaces the logger. The default is
// slog.Default().
//
// A nil logger is ignored rather than refused: unlike a port the provider
// cannot work without, a nil logger has an obvious safe reading — the caller
// does not want to choose this component's logger — and refusing it would make
// configuring logging mandatory.
func WithPasswordAuthenticatorLogger(l *slog.Logger) PasswordOption {
	return func(a *passwordAuthenticator) {
		if l != nil {
			a.logger = l
		}
	}
}

// RefusalLogFlusher reports every refusal a component has suppressed but not
// yet counted in a written record.
//
// Sampling keeps a burst of refusals from burying every other record, but the
// count of what it held back is only written when the same reason recurs. A
// caller flushes at shutdown, or before reading the logs of an incident, so a
// burst that stopped is still accounted for rather than silently discarded.
//
// The constructors here return Authenticator, so a consumer reaches this with a
// type assertion. The error is part of the contract for implementations whose
// reporter can fail; this package's own always reports none.
type RefusalLogFlusher interface {
	FlushRefusalLogs() error
}

// The reasons a refusal is recorded under. They are the sampler's keys, so each
// is held back independently: a flood of unknown usernames cannot bury the one
// record saying the user store is down.
const (
	reasonUnknownUser     = "unknown-user"
	reasonUserLoadFailed  = "user-load-failed"
	reasonWrongPassword   = "wrong-password"
	reasonAccountInactive = "account-inactive"
)

// defaultRefusalLogInterval is how often one refusal reason is recorded when no
// interval is configured.
const defaultRefusalLogInterval = time.Minute

// passwordAuthenticator resolves a username and password against a user loader.
//
// Every field is fixed at construction, so it is safe for concurrent use.
type passwordAuthenticator struct {
	users identity.UserLoader

	enc    password.Encoder
	encSet bool

	ids    id.Generator
	idsSet bool

	logger      *slog.Logger
	logEvery    time.Duration
	logEverySet bool

	// refusals holds back repeated refusal records. Its reporter writes to the
	// same logger, so nothing it suppresses is lost.
	refusals *logsample.Sampler

	// reference is the hash an unknown username is verified against, so that
	// path costs the same as a known one. It is produced once, at construction.
	reference []byte
}

// NewUsernamePasswordAuthenticator returns a provider that resolves
// identity.UsernamePassword credentials against users.
//
// The user loader is required and has no default. scrty never substitutes an
// empty or in-memory user store for one that was not supplied: a provider that
// did would refuse every caller while looking correctly wired.
//
// Defaults: scrty's default password encoder, and id.NewV7Generator for the
// identifier each success carries. WithPasswordEncoder and
// WithPasswordIDGenerator name and replace them.
//
// The reference hash every unknown username is verified against is produced
// here, by the configured encoder, and construction fails when it cannot be. A
// literal hash in the source would be in one algorithm's format, and an encoder
// for another algorithm reports no match for it without doing any work — which
// is precisely the timing difference this reference hash exists to remove.
func NewUsernamePasswordAuthenticator(users identity.UserLoader, opts ...PasswordOption) (Authenticator, error) {
	if nilcheck.IsNil(users) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("user loader"))
	}

	a := &passwordAuthenticator{users: users}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}

	if a.encSet && nilcheck.IsNil(a.enc) {
		return nil, fmt.Errorf("%w: the password encoder is nil", ErrConfig)
	}
	if a.enc == nil {
		enc, err := password.NewArgon2idEncoder()
		if err != nil {
			return nil, fmt.Errorf("%w: building the default password encoder: %w", ErrConfig, err)
		}
		a.enc = enc
	}

	if a.idsSet && nilcheck.IsNil(a.ids) {
		return nil, fmt.Errorf("%w: the authentication identifier generator is nil", ErrConfig)
	}
	if a.ids == nil {
		a.ids = id.NewV7Generator()
	}

	if a.logger == nil {
		a.logger = slog.Default()
	}
	if !a.logEverySet {
		a.logEvery = defaultRefusalLogInterval
	}
	a.refusals = logsample.New(a.logEvery, logsample.WithReporter(a.reportSuppressed))

	reference, err := a.enc.Encode(referencePassword)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding the timing-equalisation reference hash: %w", ErrConfig, err)
	}
	a.reference = reference

	return a, nil
}

// Authenticate resolves a username and password against the user loader.
//
// Every refusal returns the bare ErrAuthenticationFailed, with nothing wrapped
// and nothing added, so an unknown username, a wrong password and a user store
// that is down are one answer rather than three. What separates them goes to
// the log, where an operator sees it and a caller does not.
//
// A username the store does not know is still verified, against the reference
// hash built at construction. Returning early there would make the unknown-user
// path measurably faster than the wrong-password one, which turns the login
// endpoint into a way to enumerate accounts without ever guessing a password.
//
// Only *identity.UsernamePassword is handled; anything else is skipped. That is
// the stated limit: a consumer whose transport carries a password in a type of
// its own converts to identity.NewUsernamePassword, or writes an Authenticator
// of its own. Accepting any credential that merely looked like a username and a
// password would mean guessing at where the secret is and whether cleanup wipes
// it, and a wrong guess there leaves the password resident after a success.
func (a *passwordAuthenticator) Authenticate(ctx context.Context, c identity.Credentials) (*Authentication, error) {
	creds, ok := c.(*identity.UsernamePassword)
	if !ok {
		return nil, ErrUnsupportedCredentials
	}

	// The encoder port takes a string, so this copy of the secret cannot be
	// wiped the way the credential's own buffer can. It is confined to this
	// call and dies with it; widening its lifetime would widen what a memory
	// dump reaches.
	presented := string(creds.Password)

	details, err := a.users.LoadByUsername(ctx, creds.Username)
	if err != nil || details == nil {
		// Deliberately unused: the verification is the point, not its verdict.
		_ = a.enc.Match(presented, a.reference)

		switch {
		case err == nil, errors.Is(err, identity.ErrUserNotFound):
			// Routine: someone mistyped a username, or is guessing at them.
			a.refuse(ctx, slog.LevelDebug, reasonUnknownUser, creds.Username)
		default:
			// Not routine: the store could not answer, so nobody can log in
			// and an operator has something to fix.
			a.refuse(ctx, slog.LevelError, reasonUserLoadFailed, creds.Username,
				slog.String("error", err.Error()))
		}

		return nil, ErrAuthenticationFailed
	}

	if !a.enc.Match(presented, details.Password) {
		a.refuse(ctx, slog.LevelDebug, reasonWrongPassword, creds.Username)

		return nil, ErrAuthenticationFailed
	}

	// Only now. Reading Active first would answer "is this account disabled?"
	// for any username, without the password — which is the same enumeration
	// the reference hash above exists to prevent, by another route.
	if !details.Active {
		// Worth an operator's attention: whoever this is holds the account's
		// current password, so a disabled account is all that is stopping them.
		a.refuse(ctx, slog.LevelWarn, reasonAccountInactive, creds.Username)

		return nil, ErrAuthenticationFailed
	}

	// Named before the wipe, so a generator that cannot mint an identifier
	// leaves the caller holding the credentials it presented rather than a
	// wiped buffer and an error.
	eventID, err := a.ids.NewID()
	if err != nil {
		return nil, fmt.Errorf("authenticate: naming the authentication: %w", err)
	}

	// The caller is authenticated, so nothing needs the secret again. Wiping
	// here rather than leaving it to the caller means the shortest possible
	// window in which a heap dump, a core file or a crash report could carry
	// it. Refusals deliberately do not wipe: the caller still owns credentials
	// nothing accepted, and may want to present them to another provider.
	//
	// The error is reported rather than ignored: a cleanup that could not wipe
	// leaves the secret resident, and a caller relying on the wipe must hear
	// about it. It is not an authentication failure — the caller was resolved.
	if err := creds.Cleanup(); err != nil {
		return nil, fmt.Errorf("authenticate: wiping the presented password: %w", err)
	}

	return &Authentication{
		ID:                eventID,
		Credentials:       creds,
		Principal:         identity.PrincipalFromDetails(details),
		Time:              time.Now(),
		PasswordChangedAt: details.PasswordChangedAt,
	}, nil
}

// refuse records one refusal, through the sampler.
//
// The record never carries the presented password, and never says more than the
// reason it is keyed by: what a refusal reveals belongs in the log, not in the
// error, and a record that quoted the secret would move the secret into every
// system the logs are shipped to.
func (a *passwordAuthenticator) refuse(ctx context.Context, level slog.Level, reason, username string, extra ...slog.Attr) {
	write, suppressed := a.refusals.Allow(reason, time.Now())
	if !write {
		return
	}

	attrs := append([]slog.Attr{
		slog.String("reason", reason),
		slog.String("username", username),
		slog.Int("suppressed", suppressed),
	}, extra...)

	a.logger.LogAttrs(ctx, level, "authentication refused", attrs...)
}

// reportSuppressed writes the count of refusals the sampler held back and is
// about to forget.
//
// Without it, a burst that never recurs takes its count with it, and the logs
// say one refusal happened where there were fifty. It runs on the goroutine
// whose Allow or FlushRefusalLogs call triggered it, so it only logs.
func (a *passwordAuthenticator) reportSuppressed(reason string, suppressed int) {
	a.logger.LogAttrs(context.Background(), slog.LevelInfo, "authentication refusals suppressed",
		slog.String("reason", reason),
		slog.Int("suppressed", suppressed))
}

// FlushRefusalLogs reports every refusal held back but not yet counted, then
// forgets every reason, so the next refusal of each is written.
//
// It reports no error: this provider's reporter only writes a log record, which
// cannot fail in a way it could report. The error is in the signature because
// RefusalLogFlusher is implemented by components whose reporters can.
func (a *passwordAuthenticator) FlushRefusalLogs() error {
	a.refusals.Flush()

	return nil
}

var _ Authenticator = (*passwordAuthenticator)(nil)
var _ RefusalLogFlusher = (*passwordAuthenticator)(nil)
