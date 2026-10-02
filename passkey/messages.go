package passkey

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
)

// Notice is what a passkey notice says about the change it reports.
type Notice struct {
	// Name is the passkey's name, as stored.
	Name string
	// At is when the change happened.
	At time.Time
	// Repudiation is where a user who did not make the change should turn:
	// what WithRepudiationContact configured.
	Repudiation string
	// SessionsEnded reports whether the change ended sessions: the user's
	// other sessions for a removal, all of them for a suspension.
	SessionsEnded bool
}

// Messages renders the subject and plain-text body of every message the
// manager sends. The library sets each message's recipient itself, from the
// contact resolver; a Messages implementation never chooses it.
//
// The default texts are plain English and name no brand. Replace them with
// WithMessages.
type Messages interface {
	// Registered renders the notice that a passkey became active.
	Registered(n Notice) (subject, body string)
	// Removed renders the notice that a passkey was removed.
	Removed(n Notice) (subject, body string)
	// Suspended renders the notice that a passkey was suspended as a
	// suspected clone. It should tell the user to remove the passkey and
	// register a new one.
	Suspended(n Notice) (subject, body string)
	// EmailCode renders the message carrying the code that confirms a passkey
	// registered from an enrolment-only session, usable until until.
	EmailCode(code string, until time.Time) (subject, body string)
}

// WithMessages replaces the subject and body of every message the manager
// sends: the binding, removal and suspension notices and the emailed code.
// The default texts are plain English and name no brand. The recipient is
// still set by the library. A nil Messages is a configuration error.
func WithMessages(msgs Messages) Option {
	return func(m *Manager) {
		m.messages = msgs
		m.messagesSet = true
	}
}

// WithContactResolver replaces how a user's contact address — where the
// notices and the emailed code go — is taken from their loaded details. The
// default is mfa.UsernameAsAddress. A registration from an enrolment-only
// session uses its RegistrationContext's resolver instead, when it has one. A
// nil resolver is a configuration error.
func WithContactResolver(r mfa.ContactResolver) Option {
	return func(m *Manager) {
		m.contact = r
		m.contactSet = true
	}
}

// defaultMessages are the library's own texts: plain English, naming no
// brand, and carrying no challenge, code, credential ID or public key.
type defaultMessages struct {
	repudiation string
}

func (defaultMessages) Registered(n Notice) (string, string) {
	return "A passkey was added to your account",
		"A passkey named \"" + n.Name + "\" was added to your account on " + n.At.UTC().Format(emailTimeLayout) + ".\n\n" +
			"If you did not add it, contact " + n.Repudiation + " at once.\n"
}

func (defaultMessages) Removed(n Notice) (string, string) {
	ended := ""
	if n.SessionsEnded {
		ended = "Your other sessions were signed out.\n\n"
	}

	return "A passkey was removed from your account",
		"The passkey named \"" + n.Name + "\" was removed from your account on " +
			n.At.UTC().Format(emailTimeLayout) + ". It can no longer be used to sign in.\n\n" + ended +
			"If you did not remove it, contact " + n.Repudiation + " at once.\n"
}

func (defaultMessages) Suspended(n Notice) (string, string) {
	ended := ""
	if n.SessionsEnded {
		ended = "All your sessions were signed out.\n\n"
	}

	return "A passkey on your account was suspended",
		"The passkey named \"" + n.Name + "\" was suspended on " + n.At.UTC().Format(emailTimeLayout) +
			" because it may have been copied. It can no longer be used to sign in.\n\n" +
			"Remove it from your account and register a new passkey.\n\n" + ended +
			"If you need help, contact " + n.Repudiation + ".\n"
}

func (d defaultMessages) EmailCode(code string, until time.Time) (string, string) {
	return "Your passkey confirmation code",
		"Your code to finish adding a passkey to your account is " + code + ".\n\n" +
			"It can be used until " + until.UTC().Format(emailTimeLayout) + ".\n\n" +
			"If you did not ask for it, contact " + d.repudiation + ".\n"
}

// noticeKind names a notice, in the messages it is rendered by and in the
// sampler key of its failure records.
type noticeKind uint8

const (
	noticeRegistered noticeKind = iota + 1
	noticeRemoved
	noticeSuspended
)

// String is the notice's name in a failure record's key.
func (k noticeKind) String() string {
	switch k {
	case noticeRegistered:
		return "registered"
	case noticeRemoved:
		return "removed"
	case noticeSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// notify queues the notice kind about c to c's user, at the address resolve
// gives, or the manager's resolver when resolve is nil. The library sets the
// recipient; the Messages only render the texts. sessionsEnded tells the
// notice whether the change ended sessions (Notice.SessionsEnded).
//
// A notice is owed whatever the request does next, so it is sent under a
// context the caller cannot cancel. Its failure — loading the user, resolving
// the address or queueing — is written through the sampler at error level,
// naming the credential by its library identifier only, and does not undo
// the change it reports.
func (m *Manager) notify(
	ctx context.Context, kind noticeKind, c *Credential, resolve mfa.ContactResolver, sessionsEnded bool,
) {
	ctx = context.WithoutCancel(ctx)

	if err := m.sendNotice(ctx, kind, c, resolve, sessionsEnded); err != nil {
		m.sampled(ctx, slog.LevelError, "notice|"+kind.String(), msgNoticeNotQueued,
			append(diag.Failure(kind.String(), err), credentialAttr(c.ID))...)
	}
}

// sendNotice renders and queues one notice, and returns why it could not.
func (m *Manager) sendNotice(ctx context.Context, kind noticeKind, c *Credential, resolve mfa.ContactResolver, sessionsEnded bool) error {
	to, err := m.contactOf(ctx, c.User, resolve)
	if err != nil {
		return err
	}

	n := Notice{Name: c.Name, At: m.clock.Now(), Repudiation: m.repudiation, SessionsEnded: sessionsEnded}

	var subject, body string

	switch kind {
	case noticeRegistered:
		subject, body = m.messages.Registered(n)
	case noticeRemoved:
		subject, body = m.messages.Removed(n)
	default:
		subject, body = m.messages.Suspended(n)
	}

	return m.sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body})
}

// contactOf loads user and resolves their contact address by resolve, or by
// the manager's resolver when resolve is nil.
func (m *Manager) contactOf(ctx context.Context, user identity.UserID, resolve mfa.ContactResolver) (string, error) {
	details, err := m.users.LoadByUserID(ctx, user)
	if err != nil {
		return "", diag.Wrap(err, "passkey: could not load the user")
	}

	if resolve == nil {
		resolve = m.contact
	}

	to, err := resolve(ctx, details)
	if err != nil {
		return "", diag.Wrap(err, "passkey: could not resolve the user's contact address")
	}

	return to, nil
}
